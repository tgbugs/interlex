# PostgreSQL with the pguri C extension, so the parity test can compare it
# against sql/pguri_sql.sql.

FROM postgres:18

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        git ca-certificates make gcc pkg-config \
        postgresql-server-dev-18 liburiparser-dev liburiparser1; \
    git clone --depth 1 https://github.com/petere/pguri.git /tmp/pguri; \
    make -C /tmp/pguri PG_CONFIG=/usr/bin/pg_config; \
    make -C /tmp/pguri PG_CONFIG=/usr/bin/pg_config install; \
    rm -rf /tmp/pguri /var/lib/apt/lists/*
