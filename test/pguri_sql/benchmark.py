#!/usr/bin/env python3
"""Performance benchmark: pguri (C) vs sql/pguri_sql.sql.

Loads an identical table of N generated URIs into two databases on one server --
one with the pguri C extension, one with the SQL implementation -- and times
every function pguri exports, plus sorting, DISTINCT, a uri_host filter and
index builds. Timing is server-side (EXPLAIN (ANALYZE, TIMING OFF), best of
several runs), so client round-trips do not skew it.

    ./test/pguri_sql/run-benchmark.sh          # Docker, self-contained
    BENCH_N=100000 python test/pguri_sql/benchmark.py   # against your own server

It self-skips (exit 77) if pguri is unavailable.
"""

import os
import sys
from pathlib import Path
from time import perf_counter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

# reuse the parity test's db setup / connection helpers
from test.pguri_sql.parity import (  # noqa: E402
    psycopg2, _SkipReason, _setup_c_db, _setup_sql_db, _connect, _drop_db,
    DB_C, DB_SQL,
)

N = int(os.environ.get('BENCH_N', '20000'))
REPS = int(os.environ.get('BENCH_REPS', '6'))
WARMUP = int(os.environ.get('BENCH_WARMUP', '1'))

# Five URI shapes (varied components) generated deterministically server-side so
# both databases benchmark the exact same data.
#
# No IPv6 literals here on purpose. They exercise the most expensive branch in
# the SQL implementation (bracket parsing, int[] group expansion) while pguri C
# parses them
# at the same cost as anything else, so including them at 20% inflated every
# cold-path ratio by roughly 2x versus what interlex actually stores --
# uri_normalize read 14.7x on the old mix and 6.1x on interlex-shaped data.
# IPv6 correctness is covered where it belongs, in the corpus parity test.
GEN_SELECT = """
SELECT (ARRAY[
    'http://uri.interlex.org/base/ilx_' || lpad(g::text, 7, '0'),
    'https://user:pw@example.com:8443/a/b/' || g || '?x=' || g || '#f' || g,
    'http://purl.obolibrary.org/obo/UBERON_' || lpad(g::text, 7, '0'),
    'http://uri.interlex.org/tgbugs/uris/readable/thing' || g,
    'ftp://ftp.example.org/pub/file' || g || '.txt'
])[1 + (g % 5)] AS u
FROM generate_series(1, {n}) g
""".format(n=N)

# label -> query whose execution forces the work; count(...) makes each call run
# while returning a single row.
BENCH = [
    ('parse text -> uri',      "SELECT count(u::uri) FROM t_txt"),
    ('uri_scheme',             "SELECT count(uri_scheme(u)) FROM t_uri"),
    ('uri_userinfo',           "SELECT count(uri_userinfo(u)) FROM t_uri"),
    ('uri_host',               "SELECT count(uri_host(u)) FROM t_uri"),
    ('uri_host_inet',          "SELECT count(uri_host_inet(u)) FROM t_uri"),
    ('uri_port',               "SELECT count(uri_port(u)) FROM t_uri"),
    ('uri_path',               "SELECT count(uri_path(u)) FROM t_uri"),
    ('uri_path_array',         "SELECT count(uri_path_array(u)) FROM t_uri"),
    ('uri_query',              "SELECT count(uri_query(u)) FROM t_uri"),
    ('uri_fragment',           "SELECT count(uri_fragment(u)) FROM t_uri"),
    ('uri_normalize',          "SELECT count(uri_normalize(u)) FROM t_uri"),
    # pguri's text<->text helpers (uriparser's UriEscapeEx / UriUnescapeInPlaceEx)
    ('uri_escape',             "SELECT count(uri_escape(u::text)) FROM t_uri"),
    ('uri_unescape',           "SELECT count(uri_unescape(u::text)) FROM t_uri"),
    # the comparison and hash support functions, called directly rather than
    # through a sort or a hash aggregate
    ('uri_cmp',                "SELECT count(uri_cmp(u, u)) FROM t_uri"),
    ('uri_hash',               "SELECT count(uri_hash(u)) FROM t_uri"),
    ('uri_eq (function)',      "SELECT count(*) FROM t_uri WHERE uri_eq(u, u)"),
    ('= (operator)',           "SELECT count(*) FROM t_uri WHERE u = u"),
    ('ORDER BY (btree cmp)',   "SELECT count(*) FROM (SELECT u FROM t_uri ORDER BY u) q"),
    ('DISTINCT (hash/eq)',     "SELECT count(*) FROM (SELECT DISTINCT u FROM t_uri) q"),
    ('WHERE uri_host(u)=lit',  "SELECT count(*) FROM t_uri WHERE uri_host(u) = 'uri.interlex.org'"),
]

INDEX_BENCH = [
    ('btree index build', 'CREATE INDEX t_uri_btree ON t_uri USING btree (u)', 'DROP INDEX IF EXISTS t_uri_btree'),
    ('hash index build',  'CREATE INDEX t_uri_hash  ON t_uri USING hash  (u)', 'DROP INDEX IF EXISTS t_uri_hash'),
]


def _load(conn):
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute('DROP TABLE IF EXISTS t_uri; DROP TABLE IF EXISTS t_txt;')
        cur.execute('CREATE TABLE t_txt (u text)')
        cur.execute('INSERT INTO t_txt (u) ' + GEN_SELECT)
        cur.execute('CREATE TABLE t_uri (u uri)')
        cur.execute('INSERT INTO t_uri (u) SELECT u::uri FROM t_txt')
        cur.execute('ANALYZE t_txt'); cur.execute('ANALYZE t_uri')


def _exec_time(conn, sql):
    """Best-of-REPS server-side execution time (ms) via EXPLAIN ANALYZE."""
    best = None
    with conn.cursor() as cur:
        for i in range(WARMUP + REPS):
            cur.execute('EXPLAIN (ANALYZE, TIMING OFF) ' + sql)
            et = None
            for (line,) in cur.fetchall():
                if line.startswith('Execution Time:'):
                    et = float(line.split(':', 1)[1].strip().split()[0])
            if i >= WARMUP and et is not None:
                best = et if best is None else min(best, et)
    return best


def _ddl_time(conn, create_sql, drop_sql):
    best = None
    with conn.cursor() as cur:
        for i in range(WARMUP + max(1, REPS // 2)):
            cur.execute(drop_sql)
            t0 = perf_counter(); cur.execute(create_sql); dt = (perf_counter() - t0) * 1000
            cur.execute(drop_sql)
            if i >= WARMUP:
                best = dt if best is None else min(best, dt)
    return best


def main():
    if psycopg2 is None:
        print('psycopg2 not importable'); return 77
    try:
        _setup_c_db(); _setup_sql_db()
    except _SkipReason as e:
        print('SKIP:', e); return 77
    except psycopg2.OperationalError as e:
        print('SKIP: cannot reach PostgreSQL:', e); return 77

    conn_c, conn_sql = _connect(DB_C), _connect(DB_SQL)
    conn_c.autocommit = True
    conn_sql.autocommit = True
    try:
        ver = _one(conn_c, 'SHOW server_version')
        print('PostgreSQL {}   N = {:,} rows   best of {} (warmup {})\n'.format(
            ver, N, REPS, WARMUP))
        print('loading data ...', flush=True)
        _load(conn_c); _load(conn_sql)

        rows = []
        for label, sql in BENCH:
            c = _exec_time(conn_c, sql)
            t = _exec_time(conn_sql, sql)
            rows.append((label, c, t))
        for label, create_sql, drop_sql in INDEX_BENCH:
            c = _ddl_time(conn_c, create_sql, drop_sql)
            t = _ddl_time(conn_sql, create_sql, drop_sql)
            rows.append((label, c, t))

        _print_table(rows)
    finally:
        conn_c.close(); conn_sql.close()
        _drop_db(DB_C); _drop_db(DB_SQL)
    return 0


def _one(conn, sql):
    with conn.cursor() as cur:
        cur.execute(sql); return cur.fetchone()[0]


def _print_table(rows):
    print('\n{:<24} {:>12} {:>12} {:>10} {:>14}'.format(
        'operation', 'pguri C ms', 'pguri_sql', 'SQL/C', 'C ns/row'))
    print('-' * 76)
    for label, c, t in rows:
        ratio = '{:.1f}x'.format(t / c) if (c and t) else 'n/a'
        ns = '{:.0f}'.format(c / N * 1e6) if (c and 'index' not in label) else ''
        cc = '{:9.2f}'.format(c) if c is not None else '   n/a'
        tt = '{:9.2f}'.format(t) if t is not None else '   n/a'
        print('{:<24} {:>12} {:>12} {:>10} {:>14}'.format(label, cc, tt, ratio, ns))
    print('\nLower is faster. SQL/C > 1 means sql/pguri_sql.sql is that many times '
          'slower than the C extension.\nSQL/C < 1 means it is FASTER -- expect that on '
          'anything going through the btree or\nhash machinery, since pguri '
          're-parses both URIs on every comparison.')


if __name__ == '__main__':
    raise SystemExit(main())
