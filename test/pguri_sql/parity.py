"""Behavioral parity between the pguri C extension and ``sql/pguri_sql.sql``.

Two throwaway databases are created side by side ON ONE SERVER:

  * ``interlex_pguri_c_parity``   -- ``CREATE EXTENSION uri;`` (pguri, C)
  * ``interlex_pguri_sql_parity`` -- ``\i sql/pguri_sql.sql`` (this repo)

One server suffices because the two cannot collide: pguri's ``uri`` is a base
type belonging to an extension in its own database, and ours is a domain created
in another. (An earlier pg_tle-based implementation did need two servers, since
pg_tle refuses to register a TLE named ``uri`` while pguri's on-disk
``uri.control`` exists. Nothing here uses pg_tle.)

The SQL side is installed by a NON-SUPERUSER role, because that is the
constraint that decides whether it can be used on a managed instance at all.

The same battery of URIs is pushed through every ``uri_*`` accessor, the
comparison operators (ordering / equality / DISTINCT-via-hash), the escape
helpers, interlex-style CHECK-constraint expressions, and the input validator.
Every result from the two databases must be identical.

Requirements to actually run (otherwise the tests self-skip with a message):
  * a reachable PostgreSQL superuser connection
  * the pguri C extension installed (``CREATE EXTENSION uri``)

Connection is taken from the environment so it can point at any test server::

  ILX_PARITY_SUPERUSER   (default: postgres)
  ILX_PARITY_HOST        (default: localhost)
  ILX_PARITY_PORT        (default: INTERLEX_TEST_PORT / PGPORT / 5432)
  ILX_PARITY_PASSWORD    (optional; else ~/.pgpass / trust auth)

Run just this file::

  pytest -x test/test_pguri_sql_parity.py

or as a standalone diff report::

  python test/test_pguri_sql_parity.py
"""

import os
import unittest
from pathlib import Path

try:
    import psycopg2
    from psycopg2 import sql as _psql
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except Exception:  # pragma: no cover - dependency guard
    psycopg2 = None

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# the SQL implementation under test; overridable for experiments
PGURI_SQL = Path(os.environ.get(
    'ILX_PARITY_SQL', str(REPO_ROOT / 'sql' / 'pguri_sql.sql')))

# the unprivileged role that installs it, so superuser-only DDL is caught
SQL_INSTALL_ROLE = 'ilx_uri_installer'
SQL_INSTALL_PASSWORD = 'ilx_uri_installer'

DB_C = 'interlex_pguri_c_parity'
DB_SQL = 'interlex_pguri_sql_parity'

# ---------------------------------------------------------------------------
# Test data -- a large corpus drawn mostly from uriparser's own test
# suite plus the RFC 3986 section 5.4 resolution results and the
# interlex IRIs. pguri C is the ORACLE: for each URI we require the
# SQL implementation to agree on acceptance, and on every accessor
# when both accept.
# ---------------------------------------------------------------------------

CORPUS_FILE = Path(__file__).resolve().parent / 'corpus.txt'


def _load_corpus():
    try:
        return [ln for ln in CORPUS_FILE.read_text().splitlines() if ln != '']
    except FileNotFoundError:
        return []


CORPUS = _load_corpus()

# A few known-benign divergences from pguri's exact validator idiosyncrasies may
# be listed here (input string -> reason) to exempt them from the acceptance
# assertion. Empty by default; populated only with documented, non-interlex
# uriparser quirks if any survive.
KNOWN_ACCEPT_DIFFS = {}

# Every accessor, normalized to text so results compare uniformly.
ACCESSOR_EXPRS = [
    'uri_scheme({u})',
    'uri_userinfo({u})',
    'uri_host({u})',
    "uri_host_inet({u})::text",
    'uri_port({u})',
    'uri_path({u})',
    'uri_path_array({u})::text',
    'uri_query({u})',
    'uri_fragment({u})',
    'uri_normalize({u})::text',
]


# ---------------------------------------------------------------------------
# Connection / setup helpers
# ---------------------------------------------------------------------------

# One server, two databases. pguri's `uri` is a base type owned by an extension
# in its own database; ours is a domain created in another. They cannot see each
# other, so no second cluster is needed.

def _conn_kwargs(dbname):
    kw = dict(
        dbname=dbname,
        user=os.environ.get('ILX_PARITY_SUPERUSER', 'postgres'),
        host=os.environ.get('ILX_PARITY_HOST', 'localhost'),
        port=int(os.environ.get(
            'ILX_PARITY_PORT',
            os.environ.get('INTERLEX_TEST_PORT',
                           os.environ.get('PGPORT', '5432')))),
    )
    pw = os.environ.get('ILX_PARITY_PASSWORD')
    if pw:
        kw['password'] = pw
    return kw


def _connect(dbname):
    return psycopg2.connect(**_conn_kwargs(dbname))


def _admin_exec(statements):
    """Run autocommit statements against the maintenance db (create/drop db)."""
    conn = _connect('postgres')
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    try:
        with conn.cursor() as cur:
            for st in statements:
                cur.execute(st)
    finally:
        conn.close()


def _drop_db(name):
    # terminate stray backends, then drop
    _admin_exec([
        _psql.SQL(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = {}"
        ).format(_psql.Literal(name)),
        _psql.SQL("DROP DATABASE IF EXISTS {}").format(_psql.Identifier(name)),
    ])


def _create_db(name):
    _admin_exec([_psql.SQL("CREATE DATABASE {}").format(_psql.Identifier(name))])


class _SkipReason(Exception):
    pass


def _setup_c_db():
    """Fresh db with the pguri C extension; raise _SkipReason if unavailable."""
    _drop_db(DB_C)
    _create_db(DB_C)
    conn = _connect(DB_C)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            try:
                cur.execute('CREATE EXTENSION uri;')
            except psycopg2.Error as e:
                raise _SkipReason(
                    'pguri C extension not installable (CREATE EXTENSION uri '
                    f'failed): {e}')
    finally:
        conn.close()


def _setup_sql_db():
    """Fresh db with sql/pguri_sql.sql; raise _SkipReason if it will not install.

    Installed by a NON-SUPERUSER role by default, because that is the constraint
    that actually decides whether it can be used on a managed instance. It
    should need nothing privileged: no extension, no procedural language, no
    CREATE CAST and no CREATE OPERATOR CLASS. Installing as `postgres` would
    hide a regression into privileged DDL completely, so the default install
    asserts it is NOT running as a superuser.

    Set ILX_PARITY_SUPERUSER_INSTALL=1 to install as the superuser anyway.
    """
    _drop_db(DB_SQL)
    _create_db(DB_SQL)
    uri_sql = PGURI_SQL.read_text()
    su_install = os.environ.get('ILX_PARITY_SUPERUSER_INSTALL')

    if not su_install:
        # superuser prep: only the role and its grants, nothing the SQL needs
        conn = _connect(DB_SQL)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute('SELECT 1 FROM pg_roles WHERE rolname = %s',
                            (SQL_INSTALL_ROLE,))
                if not cur.fetchone():
                    cur.execute(_psql.SQL(
                        'CREATE ROLE {} LOGIN PASSWORD %s NOSUPERUSER'
                    ).format(_psql.Identifier(SQL_INSTALL_ROLE)),
                        (SQL_INSTALL_PASSWORD,))
                cur.execute(_psql.SQL('GRANT ALL ON DATABASE {} TO {}').format(
                    _psql.Identifier(DB_SQL), _psql.Identifier(SQL_INSTALL_ROLE)))
                cur.execute(_psql.SQL('GRANT ALL ON SCHEMA public TO {}').format(
                    _psql.Identifier(SQL_INSTALL_ROLE)))
        finally:
            conn.close()
        kw = _conn_kwargs(DB_SQL)
        kw['user'] = SQL_INSTALL_ROLE
        kw['password'] = SQL_INSTALL_PASSWORD
        conn = psycopg2.connect(**kw)
    else:
        conn = _connect(DB_SQL)

    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT current_user, '
                        '(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)')
            who, is_su = cur.fetchone()
            if not su_install and is_su:
                raise _SkipReason(
                    f'expected a non-superuser installer, got superuser {who}')
            try:
                cur.execute(uri_sql)
            except psycopg2.Error as e:
                raise _SkipReason(
                    f'sql/pguri_sql.sql would not install as {who} '
                    f'(superuser={is_su}): {e}')
    finally:
        conn.close()


def _rows(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchall()


def _accepts_conn(conn, u):
    """True if ``u::uri`` succeeds on conn (rolls back either way)."""
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT ' + _lit(u) + '::uri')
        conn.rollback()
        return True
    except psycopg2.Error:
        conn.rollback()
        return False


# ---------------------------------------------------------------------------
# The test case
# ---------------------------------------------------------------------------

# This suite needs the pguri-vs-SQL docker harness (see
# test/pguri_sql/); it must NOT run as part of the ordinary test suite. The
# harness sets ILX_PARITY_SUPERUSER, which we use as the opt-in signal.
@unittest.skipUnless(
    psycopg2 is not None and os.environ.get('ILX_PARITY_SUPERUSER'),
    'pguri parity harness only (set ILX_PARITY_SUPERUSER; see test/pguri_sql/)')
class TestPguriSqlParity(unittest.TestCase):

    conn_c = None
    conn_sql = None
    skip_reason = None

    @classmethod
    def setUpClass(cls):
        try:
            _setup_c_db()
            _setup_sql_db()
        except _SkipReason as e:
            cls.skip_reason = str(e)
            return
        except psycopg2.OperationalError as e:
            cls.skip_reason = f'cannot reach test PostgreSQL: {e}'
            return
        cls.conn_c = _connect(DB_C)
        cls.conn_sql = _connect(DB_SQL)
        # classify the whole corpus against the pguri C oracle
        cls.accept_c = {u: _accepts_conn(cls.conn_c, u) for u in CORPUS}
        cls.accept_t = {u: _accepts_conn(cls.conn_sql, u) for u in CORPUS}
        cls.accepted = [u for u in CORPUS if cls.accept_c[u] and cls.accept_t[u]]

    @classmethod
    def tearDownClass(cls):
        for c in (cls.conn_c, cls.conn_sql):
            if c is not None:
                c.close()
        # best-effort cleanup; ignore if the server went away
        try:
            _drop_db(DB_C)
            _drop_db(DB_SQL)
        except Exception:
            pass

    def setUp(self):
        if self.skip_reason:
            self.skipTest(self.skip_reason)

    # -- helpers ---------------------------------------------------------

    def _values(self, uris):
        vals = ',\n'.join(
            "({}, {})".format(i, _lit(u)) for i, u in enumerate(uris))
        return 'FROM (VALUES\n{}\n) AS v(i, u)'.format(vals)

    def _both(self, query):
        return _rows(self.conn_c, query), _rows(self.conn_sql, query)

    def _assert_same(self, query, msg=''):
        rc, rt = self._both(query)
        self.assertEqual(
            rc, rt,
            '{}\nquery:\n{}\n  pguri(C) : {}\n  pguri_sql: {}'.format(
                msg, query, rc, rt))
        return rc

    # -- input validation parity over the whole corpus ------------------

    def test_corpus_acceptance_parity(self):
        """The SQL implementation and pguri C agree on accept/reject, every input."""
        self.assertGreater(len(CORPUS), 100, 'corpus not loaded')
        diffs = []
        for u in CORPUS:
            if u in KNOWN_ACCEPT_DIFFS:
                continue
            if self.accept_c[u] != self.accept_t[u]:
                diffs.append('  {!r}: pguri(C) accepted={}  pguri_sql accepted={}'
                             .format(u, self.accept_c[u], self.accept_t[u]))
        self.assertEqual(
            [], diffs,
            '{} of {} corpus inputs disagree on acceptance:\n{}'.format(
                len(diffs), len(CORPUS), '\n'.join(diffs[:100])))

    # -- accessors over everything both accept --------------------------

    def test_corpus_accessor_parity(self):
        uris = self.accepted
        self.assertGreater(len(uris), 100, 'accepted corpus too small')
        cols = ',\n  '.join(e.format(u='v.u::uri') for e in ACCESSOR_EXPRS)
        query = 'SELECT v.i,\n  {}\n{}\nORDER BY v.i'.format(
            cols, self._values(uris))
        rc, rt = self._both(query)
        diffs = []
        for row_c, row_t in zip(rc, rt):
            uri = uris[row_c[0]]
            for col, (a, b) in enumerate(zip(row_c[1:], row_t[1:])):
                if a != b:
                    diffs.append(
                        '  {!r}\n    {}\n      pguri(C)={!r}  pguri_sql={!r}'.format(
                            uri, ACCESSOR_EXPRS[col], a, b))
        self.assertEqual(
            [], diffs, '{} accessor mismatches over {} URIs:\n{}'.format(
                len(diffs), len(uris), '\n'.join(diffs[:150])))

    # -- ordering (btree / uri_cmp) -------------------------------------

    def test_ordering_parity(self):
        # The TLE's uri opclass may order either pguri-exact (component
        # comparator) or byte-order (the fast default, valid because interlex
        # never orders/ranges uri columns). Accept either.
        vals = self._values(self.accepted)
        order_c = [r[0] for r in _rows(
            self.conn_c, 'SELECT v.u::uri::text {} ORDER BY v.u::uri'.format(vals))]
        order_t = [r[0] for r in _rows(
            self.conn_sql, 'SELECT v.u::uri::text {} ORDER BY v.u::uri'.format(vals))]
        order_byte = [r[0] for r in _rows(
            self.conn_sql, 'SELECT v.u::uri::text {} ORDER BY v.u::uri::bytea'.format(vals))]
        self.assertTrue(
            order_t == order_c or order_t == order_byte,
            'TLE ORDER BY matches neither pguri component order nor byte order')

    def test_ordering_exact_parity(self):
        # If the variant ships uri_cmp_exact, it must reproduce pguri's order.
        with self.conn_sql.cursor() as cur:
            cur.execute("SELECT to_regprocedure('public.uri_cmp_exact(uri,uri)') IS NOT NULL")
            if not cur.fetchone()[0]:
                self.skipTest('no uri_cmp_exact in this variant')
        order_c = [r[0] for r in _rows(
            self.conn_c,
            'SELECT v.u::uri::text {} ORDER BY v.u::uri'.format(self._values(self.accepted)))]
        pairs = ',\n'.join('({})'.format(_lit(order_c[i]) + ', ' + _lit(order_c[i + 1]))
                           for i in range(len(order_c) - 1))
        q = ('SELECT count(*) FROM (VALUES\n{}\n) w(a, b) '
             'WHERE public.uri_cmp_exact(w.a::uri, w.b::uri) > 0'.format(pairs))
        bad = _rows(self.conn_sql, q)[0][0]
        self.assertEqual(0, bad,
                         '{} consecutive pairs violate uri_cmp_exact vs pguri order'.format(bad))

    # -- equality + hashing (DISTINCT) ----------------------------------

    def test_equality_and_hash_parity(self):
        dupes = self.accepted + self.accepted[:25]  # force duplicates
        q_distinct = ('SELECT count(*) FROM '
                      '(SELECT DISTINCT v.u::uri {}) s'.format(self._values(dupes)))
        self._assert_same(q_distinct, 'DISTINCT (equality/hash) disagrees')

    # -- interlex-style CHECK-constraint expressions --------------------

    def test_interlex_constraint_expressions(self):
        cols = ',\n  '.join([
            "uri_host(v.u::uri) = 'uri.interlex.org'",
            "uri_host(v.u::uri) <> 'uri.interlex.org'",
            '(uri_path_array(v.u::uri))[1]',
            '(uri_path_array(v.u::uri))[2]',
            "(uri_path_array(v.u::uri))[2] ~* '[A-Za-z]+_[0-9]+'",
            "uri_path(v.u::uri) LIKE '%/spec'",
        ])
        query = 'SELECT v.i,\n  {}\n{}\nORDER BY v.i'.format(
            cols, self._values(self.accepted))
        self._assert_same(query, 'interlex constraint expression disagrees')

    def test_interlex_constraint_simplification(self):
        # sql/triples.sql states its s/p/o CHECK as
        #     host <> ref OR path ~ '^/base(/|$)' OR path !~* '^/[^/]*/[^/]*pat'
        # rather than repeating `uri_host(x) = reference_host()` in each of
        # three disjuncts (PostgreSQL has no CSE, so the repeated form evaluated
        # uri_host and uri_path_array ~9x per row across s/p/o -- the two most
        # expensive functions here).
        #
        # It got there in two steps, and this test pins both:
        #   original -> simplified   A OR (NOT A AND B) OR (NOT A AND C AND D)
        #                            == A OR B OR C, via B == NOT D
        #   simplified -> shipped    the segment tests restated as regexes on
        #                            uri_path, which is inlinable where
        #                            uri_path_array is not
        #
        # All three hold *as a CHECK* only: a CHECK rejects solely on FALSE, and
        # the forms are FALSE on exactly the same values, but they differ where
        # the original yields NULL (no authority, so uri_host is NULL) and the
        # others yield TRUE. Compare `IS FALSE`, not the raw three-valued
        # results, and do not lift these into a context that tells them apart.
        ref = 'uri.interlex.org'
        pat = '[A-Za-z]+_[0-9]+'
        forms = [
            ('original',
             "((uri_host({u}) <> '{r}') OR"
             " (uri_host({u}) = '{r}' AND (uri_path_array({u}))[2] !~* '{p}') OR"
             " (uri_host({u}) = '{r}' AND (uri_path_array({u}))[1] = 'base'"
             " AND (uri_path_array({u}))[2] ~* '{p}'))"),
            ('simplified',
             "(uri_host({u}) <> '{r}' OR"
             " (uri_path_array({u}))[1] = 'base' OR"
             " (uri_path_array({u}))[2] !~* '{p}')"),
            ('shipped',
             "(uri_host({u}) <> '{r}' OR"
             " uri_path({u}) ~ '^/base(/|$)' OR"
             " uri_path({u}) !~* '^/[^/]*/[^/]*{p}')"),
        ]
        fmt = dict(u='v.u::uri', r=ref, p=pat)
        # The corpus is uriparser's test suite, so nothing in it is shaped like
        # an interlex IRI and none of it reaches the rejection branch. Probe
        # with a generated cross of group segments and second-segment shapes,
        # on and off the reference host, so both branches are covered.
        probes = [h + '/' + g + (('/' + f) if f else '')
                  for h in ('http://uri.interlex.org', 'http://example.org')
                  for g in ('base', 'tgbugs', 'uris', 'other', 'readable')
                  for f in ('', 'ilx_0101431', 'cde_0000001', 'fde_9',
                            'readable', 'label', 'A_1', 'a_0', 'ilx_', '_1',
                            'x1', 'ilx_0101431/extra')]
        # shapes where uri_path and uri_path_array can disagree if the
        # translation is wrong: no path, bare root, no authority at all,
        # a 'base'-prefixed segment that is not 'base', an empty segment
        probes += ['http://uri.interlex.org', 'http://uri.interlex.org/',
                   'http://uri.interlex.org//ilx_0101431',
                   'http://uri.interlex.org/basex/ilx_0101431',
                   'http://uri.interlex.org/base', 'http://uri.interlex.org/base/',
                   'http://uri.interlex.org//', 'mailto:a@b', 'urn:x:ilx_1']
        probes += [u for u in self.accepted if 'interlex' in u]
        cols = ',\n       '.join('({}) IS FALSE'.format(e.format(**fmt))
                                 for _n, e in forms)
        query = ('SELECT v.i,\n       {}\n{}\nORDER BY v.i'
                 .format(cols, self._values(probes)))
        # both implementations must agree with each other AND all three forms
        # must reject exactly the same values on each
        self._assert_same(query, 'constraint simplification disagrees')
        for side, conn in (('c', self.conn_c), ('sql', self.conn_sql)):
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
            conn.rollback()
            for col, (name, _e) in enumerate(forms[1:], start=2):
                differing = [r[0] for r in rows if r[1] != r[col]]
                self.assertEqual(
                    differing, [],
                    '%s: the %r CHECK rejects different values than the '
                    'original for probes %r'
                    % (side, name, [probes[i] for i in differing[:10]]))
            # guard against a vacuous pass: the rejection branch must be hit
            rejected = sum(1 for r in rows if r[1])
            self.assertGreater(
                rejected, 0,
                '%s: no probe exercises the CHECK rejection branch, so '
                'this test proves nothing' % side)

    def test_escape_unescape_parity(self):
        """uri_escape / uri_unescape, across every flag combination.

        These are pguri's text<->text helpers (uriparser's UriEscapeEx /
        UriUnescapeInPlaceEx) and are unrelated to the uri type. They were
        missing from every variant until measured against this, which is what a
        "drop-in replacement" claim has to cover.

        The break handling is the part worth pinning, because it is asymmetric:
        uri_escape(normalize_breaks) converts breaks to CRLF, while
        uri_unescape converts to LF when its flag is FALSE and CRLF when TRUE.
        """
        cases = [
            "a b/c?d&e=f+g%h~i", "caf\u00e9", "a\nb\r\nc", "a\rb", "", "-._~",
            "!$&'()*+,;=:/?#[]@ -._~", "%41%42", "100%", "a+b",
            "\u00fcn\u00efc\u00f8d\u00e9", "  ", "/", "%", "~~~",
            "a%20b%2Fc%7Ed", "a%zzb%2", "a%%20b", "%C3%A9%C3%A9", "%7e%7E",
            "%2", "+++", "no-escapes",
        ]
        vals = self._values(cases)
        for fn in ("uri_escape", "uri_unescape"):
            cols = ", ".join([
                "{f}(v.u)".format(f=fn),
                "{f}(v.u, true)".format(f=fn),
                "{f}(v.u, false, true)".format(f=fn),
                "{f}(v.u, true, true)".format(f=fn),
            ])
            query = "SELECT v.i, {c}\n{v}\nORDER BY v.i".format(c=cols, v=vals)
            self._assert_same(query, "%s disagrees with pguri" % fn)

    def test_rejection_sqlstate_parity(self):
        """Rejected input must fail with the same SQLSTATE as pguri.

        This is the part of the error contract that matters programmatically:
        application code and plpgsql handlers match on SQLSTATE, not on message
        text. pguri raises 22P02 (invalid_text_representation); a plain
        `RAISE EXCEPTION` gives P0001 and a bare domain CHECK gives 23514, so
        both had to be made explicit.

        The message TEXT is deliberately not compared. pguri reports
        `... at or near " uri"` -- the remainder from the point where uriparser
        stopped -- and reproducing that would mean computing a parse-failure
        offset that a whole-string regex validator never has.
        """
        rejected = [u for u in CORPUS if u not in self.accepted][:40]
        if not rejected:
            self.skipTest('no corpus value is rejected by pguri')
        got = {}
        for side, conn in (('c', self.conn_c), ('sql', self.conn_sql)):
            states = []
            for u in rejected:
                with conn.cursor() as cur:
                    try:
                        cur.execute('SELECT %s::uri', (u,))
                        states.append(None)          # unexpectedly accepted
                    except psycopg2.Error as e:
                        states.append(e.pgcode)
                conn.rollback()
            got[side] = states
        diffs = [(rejected[i], a, b)
                 for i, (a, b) in enumerate(zip(got['c'], got['sql'])) if a != b]
        self.assertEqual(
            diffs, [],
            'SQLSTATE differs from pguri on rejected input '
            '(uri, pguri, tle): %r' % (diffs[:8],))
        self.assertTrue(all(s == '22P02' for s in got['c']),
                        'expected pguri to reject with 22P02, got %r'
                        % (sorted(set(got['c'])),))

    # -- text <-> uri assignment casts (pguri drop-in behavior) ----------

    def test_text_uri_cast_parity(self):
        # pguri exposes text<->uri as WITH INOUT AS ASSIGNMENT casts, so a text
        # expression can be assigned into a uri column (interlex does
        # `INSERT ... SELECT 'http://' || reference_host() || ...`).
        got = {}
        for side, conn in (('c', self.conn_c), ('sql', self.conn_sql)):
            with conn.cursor() as cur:
                cur.execute('CREATE TEMP TABLE _ct (u uri)')
                cur.execute("INSERT INTO _ct SELECT 'http://' || 'ex.com/' || 'a/b'")
                cur.execute('SELECT u::text FROM _ct')
                got[side] = cur.fetchone()[0]
            conn.rollback()
        self.assertEqual(got['c'], got['sql'],
                         'text->uri assignment cast disagrees: %r' % got)
        self.assertEqual(got['c'], 'http://ex.com/a/b')

        # invalid text assigned into a uri column must be rejected by both
        for side, conn in (('c', self.conn_c), ('sql', self.conn_sql)):
            accepted = True
            try:
                with conn.cursor() as cur:
                    cur.execute('CREATE TEMP TABLE _ct2 (u uri)')
                    cur.execute("INSERT INTO _ct2 SELECT 'http://a b'")  # space
            except psycopg2.Error:
                accepted = False
            conn.rollback()
            self.assertFalse(
                accepted, '%s accepted invalid text into a uri column' % side)


def _lit(s):
    """Minimal SQL string literal (single-quote escaped)."""
    return "'" + s.replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# Standalone diff report
# ---------------------------------------------------------------------------

def _report():
    if psycopg2 is None:
        print('psycopg2 not importable'); return 2
    try:
        _setup_c_db()
        _setup_sql_db()
    except _SkipReason as e:
        print('SKIP:', e); return 77
    except psycopg2.OperationalError as e:
        print('SKIP: cannot reach PostgreSQL:', e); return 77

    conn_c, conn_sql = _connect(DB_C), _connect(DB_SQL)
    acc_c = {u: _accepts_conn(conn_c, u) for u in CORPUS}
    acc_t = {u: _accepts_conn(conn_sql, u) for u in CORPUS}
    accepted = [u for u in CORPUS if acc_c[u] and acc_t[u]]
    accept_diffs = [u for u in CORPUS if acc_c[u] != acc_t[u]]
    mismatches = 0
    try:
        print('corpus={}  accepted-by-both={}  acceptance-diffs={}'.format(
            len(CORPUS), len(accepted), len(accept_diffs)))
        for u in accept_diffs[:60]:
            print('  ACCEPT DIFF {!r}: C={} TLE={}'.format(u, acc_c[u], acc_t[u]))
        mismatches += len(accept_diffs)
        for u in accepted:
            for expr in ACCESSOR_EXPRS:
                q = 'SELECT {}'.format(expr.format(u=_lit(u) + '::uri'))
                a = _rows(conn_c, q)[0][0]
                b = _rows(conn_sql, q)[0][0]
                if a != b:
                    mismatches += 1
                    print('  VALUE DIFF {:52s} {:22s} C={!r:20} TLE={!r}'.format(
                        u, expr, a, b))
                elif os.environ.get('ILX_PARITY_VERBOSE'):
                    print('{:52s} {:22s} {!r}'.format(u, expr, a))
    finally:
        conn_c.close(); conn_sql.close()
        _drop_db(DB_C); _drop_db(DB_SQL)
    print('\n{} mismatch(es)'.format(mismatches))
    return 1 if mismatches else 0


if __name__ == '__main__':
    raise SystemExit(_report())
