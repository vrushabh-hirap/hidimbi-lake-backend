# ---------------------------------------------------------------------------
# backend_lake/Dockerfile — the Render service that gives you the LAKE API URL.
#
# Render settings:
#   Language:                     Docker
#   Dockerfile Path:              backend_lake/Dockerfile
#   Docker Build Context Dir:     backend_lake
#   Health Check Path:            /healthz
#   Environment: HIDIMBI_ROLE=app, plus the secrets (see RENDER_DEPLOY.md)
#
# Everything this service needs is in THIS folder, so the build context can be
# the folder itself — small, fast, and no path-prefix ambiguity.
# ---------------------------------------------------------------------------
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HIDIMBI_ROLE=app \
    HIDIMBI_EXPOSE_INTERNAL=1 \
    CONFIG_PATH=/app/config.json

WORKDIR /app

# curl is used by Render's health checks; postgresql-client is handy for
# debugging from the Render shell.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# server.py   = Lake API + Observatory + whistle + SSRF courier
# flag_service.py = the internal Keeper's index served on :8100
COPY server.py flag_service.py ./
COPY config.json ./
COPY private_key.pem public_key.pem ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 8000 8100

ENTRYPOINT ["/app/entrypoint.sh"]
