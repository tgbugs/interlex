#!/usr/bin/env bash
# Stand up ONE PostgreSQL server with two databases side by side and run the
# behavioral parity test between them. Requires Docker only.
#
#   * interlex_pguri_c_parity   : `uri` from the pguri C extension
#   * interlex_pguri_sql_parity : `uri` from sql/pguri_sql.sql
#
# One server is enough: pguri's `uri` is a base type owned by an extension in
# its own database and ours is a domain in another, so they cannot collide.
#
# The SQL side is installed by a NON-SUPERUSER role, which is the constraint
# that decides whether it can be used on a managed instance at all.
#
#   ./test/pguri_sql/run-parity.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

IMAGE=interlex-pguri-sql-parity
PG=pg-parity
PGPW=parity

cleanup() { docker rm -f "${PG}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> building ${IMAGE} (compiles pguri; first run is slow)"
docker build -t "${IMAGE}" "${HERE}"

echo "==> starting ${PG}"
docker rm -f "${PG}" >/dev/null 2>&1 || true
docker run -d --name "${PG}" -e POSTGRES_PASSWORD="${PGPW}" \
    -p 55432:5432 "${IMAGE}" >/dev/null
until docker exec "${PG}" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2

echo "==> running parity test (pguri C vs sql/pguri_sql.sql)"
set +e
MSYS_NO_PATHCONV=1 \
docker run --rm --network host \
    -e ILX_PARITY_SUPERUSER=postgres \
    -e ILX_PARITY_HOST=127.0.0.1 -e ILX_PARITY_PORT=55432 \
    -e ILX_PARITY_PASSWORD="${PGPW}" \
    -e ILX_PARITY_SUPERUSER_INSTALL="${ILX_PARITY_SUPERUSER_INSTALL:-}" \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -v "${REPO_ROOT}":/interlex -w /interlex \
    python:3.14-slim bash -lc \
    "pip install --quiet --root-user-action=ignore psycopg2-binary pytest && \
     pytest -x -s test/pguri_sql/parity.py && \
     echo '--- standalone diff report ---' && \
     python test/pguri_sql/parity.py"
status=$?
set -e
exit "${status}"
