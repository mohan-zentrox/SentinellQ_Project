#!/bin/sh
# Container entrypoint: schema first, then serve.
#
# `alembic upgrade head` is idempotent -- on an already-current database it
# is a no-op -- so this is safe to run on every container start, including
# replica restarts. SENTINELIQ_AUTO_CREATE_SCHEMA is forced off in the image
# so the Alembic history is the only thing that ever creates tables here.
set -e

echo "[entrypoint] waiting for database..."
python - <<'PYWAIT'
import sys, time
from sqlalchemy import create_engine, text
from app.core.config import get_settings

url = get_settings().database_url
deadline = time.monotonic() + 60
last = None
while time.monotonic() < deadline:
    try:
        create_engine(url, pool_pre_ping=True).connect().execute(text("SELECT 1"))
        print("[entrypoint] database reachable")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - any connection error is a retry
        last = exc
        time.sleep(1)
print(f"[entrypoint] database unreachable after 60s: {last}", file=sys.stderr)
sys.exit(1)
PYWAIT

echo "[entrypoint] running migrations..."
alembic upgrade head

echo "[entrypoint] starting: $*"
exec "$@"
