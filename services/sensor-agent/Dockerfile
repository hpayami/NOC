FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10002 agent
WORKDIR /srv
COPY pyproject.toml ./
COPY agent ./agent
RUN pip install --no-cache-dir .
# Suricata itself is not installed here: the agent runs next to the engine (host or sidecar) and
# needs its command socket, rules directory and eve.json mounted in.
USER agent
CMD ["noc-sensor-agent"]
