FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY collector.py .
# Klucze SSH NIE sa wbudowane w obraz - generowane w panelu (wizard
# "Polacz z unRAID" na /wizard) albo przez scripts/usc_pair.sh, zapisywane
# do wspoldzielonego wolumenu usc-keys-data (montowanego tu jako /app/keys).
RUN mkdir -p /app/keys

CMD ["python", "-u", "collector.py"]
