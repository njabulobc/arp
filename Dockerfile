# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies for scapy and packet capture
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
COPY requirements.lock requirements.lock
COPY tools/generate_lock.py tools/generate_lock.py

# Generate lock file with hashes when missing and install dependencies
RUN if grep -q "TODO_REPLACE_WITH_REAL_HASH" requirements.lock; then \
        tools/generate_lock.py --requirements requirements.txt --output requirements.lock; \
    fi \
    && python -m pip install --upgrade pip \
    && python -m pip install --require-hashes -r requirements.lock

COPY . .

RUN chmod +x /app/docker/entrypoint.sh /app/tools/generate_lock.py

VOLUME ["/app/logs", "/app/state"]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
