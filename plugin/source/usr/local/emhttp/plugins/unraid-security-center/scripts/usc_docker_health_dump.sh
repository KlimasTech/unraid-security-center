#!/bin/bash
# unRaid Security Center Plugin - zrzut zdrowia kontenerow Docker.
#
# RestartCount, OOMKilled, Health.Status - dane ktorych GraphQL API unRAID
# NIE udostepnia (tylko state/status/autoStart). Jeden JSON na linie (JSONL).
for id in $(docker ps -aq 2>/dev/null); do
  docker inspect "$id" --format '{"name":"{{.Name}}","restart_count":{{.RestartCount}},"oom_killed":{{.State.OOMKilled}},"health_status":"{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}","state":"{{.State.Status}}","exit_code":{{.State.ExitCode}},"started_at":"{{.State.StartedAt}}"}' 2>/dev/null
done
