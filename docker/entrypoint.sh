#!/bin/sh
set -e

# Host-mounted folders keep the host's ownership, so fix them before dropping root.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/staticfiles /app/media
    chown -R app:app /app/staticfiles /app/media
    exec setpriv --reuid=app --regid=app --init-groups "$0" "$@"
fi

if [ "${DJANGO_SKIP_SETUP:-0}" != "1" ]; then
    python - <<'PY'
import os, sys, time
import psycopg2

for attempt in range(30):
    try:
        psycopg2.connect(
            dbname=os.getenv("POSTGRES_DB", "clan"),
            user=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
            host=os.getenv("POSTGRES_HOST", "db"),
            port=os.getenv("POSTGRES_PORT", "5432"),
        ).close()
        break
    except psycopg2.OperationalError:
        print("Waiting for PostgreSQL...", flush=True)
        time.sleep(2)
else:
    sys.exit("PostgreSQL is not reachable")
PY
    python manage.py migrate --noinput
    python manage.py collectstatic --noinput
fi

exec "$@"
