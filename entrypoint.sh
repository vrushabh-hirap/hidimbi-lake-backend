#!/bin/sh
# ---------------------------------------------------------------------------
# backend_lake/entrypoint.sh
#
# This container runs TWO processes:
#   :8000  the Lake API + Observatory + SSRF courier   (PUBLIC — Render routes here)
#   :8100  the Keeper's internal index                 (NOT published by Render)
#
# 8100 is what makes stage 21's SSRF mandatory: a player cannot reach it from
# the internet, but the courier running inside this same container can.
# ---------------------------------------------------------------------------
set -e

: "${PORT:=8000}"

echo "[*] Lake API starting on :$PORT"

# The internal index is only registered when HIDIMBI_EXPOSE_INTERNAL=1.
if [ "${HIDIMBI_EXPOSE_INTERNAL:-1}" = "1" ]; then
  echo "[*] Keeper's internal index on :8100 (unpublished)"
  uvicorn flag_service:app --host 0.0.0.0 --port 8100 --log-level warning &
fi

exec uvicorn server:app --host 0.0.0.0 --port "$PORT" --log-level info
