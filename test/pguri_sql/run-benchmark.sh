#!/usr/bin/env bash
# Stand up ONE PostgreSQL server with two databases (pguri C vs
# sql/pguri_sql.sql) and run the performance benchmark comparing them.
# Requires Docker only.
#
#   ./test/pguri_sql/run-benchmark.sh
#   BENCH_N=100000 ./test/pguri_sql/run-benchmark.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

IMAGE=interlex-pguri-sql-parity
PG=pg-bench
PGPW=parity
BENCH_N="${BENCH_N:-20000}"
BENCH_REPS="${BENCH_REPS:-5}"

cleanup() { docker rm -f "${PG}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> building ${IMAGE}"
docker build -t "${IMAGE}" "${HERE}"

echo "==> starting ${PG}"
docker rm -f "${PG}" >/dev/null 2>&1 || true
docker run -d --name "${PG}" -e POSTGRES_PASSWORD="${PGPW}" \
    -p 55433:5432 "${IMAGE}" >/dev/null
until docker exec "${PG}" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2

echo "==> benchmark (N=${BENCH_N}) : pguri C vs sql/pguri_sql.sql"
set +e
MSYS_NO_PATHCONV=1 \
docker run --rm --network host \
    -e ILX_PARITY_SUPERUSER=postgres \
    -e ILX_PARITY_HOST=127.0.0.1 -e ILX_PARITY_PORT=55433 \
    -e ILX_PARITY_PASSWORD="${PGPW}" \
    -e BENCH_N="${BENCH_N}" -e BENCH_REPS="${BENCH_REPS}" \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -v "${REPO_ROOT}":/interlex -w /interlex \
    python:3.14-slim bash -lc \
    "pip install --quiet --root-user-action=ignore psycopg2-binary && \
     python test/pguri_sql/benchmark.py"
status=$?
set -e
exit "${status}"
