"""USC - logika parowania backendu z pluginem USC na unRAID (wizard).

Uzywa hasla roota TYLKO przejsciowo, w ramach jednego requestu HTTP - nigdy
nie jest zapisywane na dysk, do bazy, ani logowane. Po zakonczeniu funkcji
Python usuwa zmienna (garbage collector), nic wiecej nie trzeba robic.

Klucze SSH generowane sa lokalnie w tym kontenerze (ssh-keygen) do
/app/keys (wspoldzielony wolumen z kolektorem) i instalowane w
authorized_keys na unRAID przez polaczenie autoryzowane haslem.
"""
import os
import re
import json
import subprocess
import paramiko

KEYS_DIR = "/app/keys"
PLUGIN_SCRIPTS = "/usr/local/emhttp/plugins/unraid-security-center/scripts"

KEY_SPECS = [
    ("usc_collector_key", "tail -n0 -F /var/log/syslog"),
    ("usc_smart_key", f"/bin/bash {PLUGIN_SCRIPTS}/usc_smart_dump.sh"),
    ("usc_ops_key", f"/bin/bash {PLUGIN_SCRIPTS}/usc_dispatch.sh"),
]


class PairingError(Exception):
    pass


def connect_with_password(host: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, username="root", password=password,
            timeout=10, banner_timeout=10, auth_timeout=10,
            look_for_keys=False, allow_agent=False,
        )
    except paramiko.AuthenticationException as e:
        raise PairingError("Nieprawidlowe haslo roota unRAID.") from e
    except (paramiko.SSHException, OSError) as e:
        raise PairingError(f"Nie udalo sie polaczyc z {host}: {e}") from e
    return client


def check_plugin_installed(client: paramiko.SSHClient) -> bool:
    _, stdout, _ = client.exec_command(f"test -x {PLUGIN_SCRIPTS}/usc_dispatch.sh")
    return stdout.channel.recv_exit_status() == 0


def ensure_key_pair(name: str) -> tuple[str, str]:
    """Generuje klucz ed25519 jesli nie istnieje. Zwraca (priv_path, pub_path)."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv = os.path.join(KEYS_DIR, name)
    pub = f"{priv}.pub"
    if os.path.exists(priv) and os.path.exists(pub):
        return priv, pub
    if os.path.exists(priv) and not os.path.exists(pub):
        # odtworz publiczny z prywatnego
        result = subprocess.run(["ssh-keygen", "-y", "-f", priv], capture_output=True, text=True)
        with open(pub, "w") as f:
            f.write(result.stdout)
        return priv, pub
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-C", name, "-q"],
        check=True,
    )
    os.chmod(priv, 0o600)
    return priv, pub


def install_authorized_key(client: paramiko.SSHClient, pubkey: str, command: str) -> bool:
    """Zwraca True jesli klucz zostal dodany, False jesli juz istnial."""
    check_cmd = f"grep -qF {_shq(pubkey)} /root/.ssh/authorized_keys 2>/dev/null"
    _, stdout, _ = client.exec_command(check_cmd)
    if stdout.channel.recv_exit_status() == 0:
        return False
    line = (
        f'command="{command}",no-port-forwarding,no-X11-forwarding,'
        f'no-agent-forwarding,no-pty {pubkey} # USC-managed'
    )
    append_cmd = f"mkdir -p /root/.ssh && echo {_shq(line)} >> /root/.ssh/authorized_keys"
    _, stdout, stderr = client.exec_command(append_cmd)
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise PairingError(f"Nie udalo sie zapisac authorized_keys: {stderr.read().decode()}")
    return True


def _shq(value: str) -> str:
    """Bezpieczne cytowanie dla pojedynczej komendy shell (single-quote escape)."""
    return "'" + value.replace("'", "'\\''") + "'"


def verify_key(host: str, priv_path: str, test_command: str | None = None) -> bool:
    """Probuje polaczyc kluczem prywatnym - potwierdza ze dziala."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        key = paramiko.Ed25519Key.from_private_key_file(priv_path)
        client.connect(
            hostname=host, username="root", pkey=key,
            timeout=10, banner_timeout=10, auth_timeout=10,
            look_for_keys=False, allow_agent=False,
        )
        if test_command:
            _, stdout, _ = client.exec_command(test_command, timeout=10)
            stdout.read()
        return True
    except Exception:
        return False
    finally:
        client.close()


def create_or_fetch_api_key(client: paramiko.SSHClient) -> str:
    cmd = "/usr/local/sbin/unraid-api apikey --create --name 'USC ReadOnly' --roles VIEWER --json"
    _, stdout, stderr = client.exec_command(cmd, timeout=20)
    out = stdout.read().decode()
    err = stderr.read().decode()
    m = re.search(r'"key"\s*:\s*"([a-f0-9]{32,})"', out)
    if not m:
        raise PairingError(f"Nie udalo sie utworzyc/pobrac klucza API unRAID: {out} {err}".strip())
    return m.group(1)


def unpair(host: str) -> dict:
    """Usuwa parowanie: wpisy USC z authorized_keys + klucz API unRAID (przez
    'unpair' w dyspozytorze, wywolane kluczem ops), potem lokalne pliki
    kluczy z wolumenu. Nie wymaga hasla - uzywa juz zainstalowanego klucza
    ops. Zwraca slownik z wynikiem kazdego etapu."""
    steps: list[dict] = []
    ops_priv = os.path.join(KEYS_DIR, "usc_ops_key")

    if not os.path.exists(ops_priv):
        steps.append({"name": "Usuwanie wpisow na unRAID", "ok": False,
                      "detail": "Brak lokalnego klucza ops - nic do zrobienia po stronie unRAID."})
    else:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            key = paramiko.Ed25519Key.from_private_key_file(ops_priv)
            client.connect(hostname=host, username="root", pkey=key, timeout=10,
                            banner_timeout=10, auth_timeout=10, look_for_keys=False, allow_agent=False)
            _, stdout, stderr = client.exec_command("unpair", timeout=15)
            out = stdout.read().decode()
            ok = "USC_UNPAIR_OK" in out
            steps.append({
                "name": "Usuwanie wpisow na unRAID",
                "ok": ok,
                "detail": "Wpisy authorized_keys i klucz API usunięte." if ok else f"Nie udało się: {out} {stderr.read().decode()}",
            })
        except Exception as e:
            steps.append({"name": "Usuwanie wpisow na unRAID", "ok": False, "detail": str(e)})
        finally:
            client.close()

    removed = []
    for name, _cmd in KEY_SPECS:
        for suffix in ("", ".pub"):
            p = os.path.join(KEYS_DIR, f"{name}{suffix}")
            if os.path.exists(p):
                os.remove(p)
                removed.append(f"{name}{suffix}")
    steps.append({
        "name": "Usuwanie lokalnych plikow kluczy",
        "ok": True,
        "detail": f"Usunięto {len(removed)} plików." if removed else "Nic do usunięcia (już puste).",
    })

    return {"steps": steps}


def run_pairing(host: str, password: str) -> dict:
    """Pelny przebieg parowania. Zwraca slownik z krokami i wynikiem."""
    steps: list[dict] = []
    client = connect_with_password(host, password)
    try:
        plugin_ok = check_plugin_installed(client)
        steps.append({
            "name": "Plugin na unRAID",
            "ok": plugin_ok,
            "detail": "Znaleziono." if plugin_ok else (
                "Nie znaleziono 'unRaid Security Center Plugin' - zainstaluj go "
                "najpierw (docs/INSTALL.md krok 1), potem spróbuj ponownie."
            ),
        })
        if not plugin_ok:
            return {"success": False, "steps": steps, "unraid_host": host, "unraid_api_key": None}

        for name, command in KEY_SPECS:
            priv, pub = ensure_key_pair(name)
            with open(pub) as f:
                pubkey = f.read().strip()
            added = install_authorized_key(client, pubkey, command)
            steps.append({
                "name": f"Klucz SSH: {name}",
                "ok": True,
                "detail": "Zainstalowany." if added else "Już był zainstalowany.",
            })

        ops_priv = os.path.join(KEYS_DIR, "usc_ops_key")
        ops_works = verify_key(host, ops_priv, "echo ping")
        steps.append({
            "name": "Weryfikacja klucza ops",
            "ok": ops_works,
            "detail": "Działa." if ops_works else "Nie odpowiada - sprawdź ręcznie.",
        })

        api_key = create_or_fetch_api_key(client)
        steps.append({"name": "Klucz API unRAID (VIEWER)", "ok": True, "detail": "Gotowy."})

        return {"success": True, "steps": steps, "unraid_host": host, "unraid_api_key": api_key}
    finally:
        client.close()
