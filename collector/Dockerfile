FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY collector.py .
COPY keys/usc_collector_key /app/keys/usc_collector_key
COPY keys/usc_smart_key /app/keys/usc_smart_key
COPY keys/usc_ops_key /app/keys/usc_ops_key
RUN chmod 600 /app/keys/usc_collector_key /app/keys/usc_smart_key /app/keys/usc_ops_key

CMD ["python", "-u", "collector.py"]
