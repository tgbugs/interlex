"""

example db cleanup in the event that our finallys fail


#+begin_src bash
psql -U postgres -h localhost -p 5432
#+end_src

#+begin_src sql
select 'DROP DATABASE ' || quote_ident(datname) || ';' FROM pg_database WHERE datname LIKE 'interlex_test_flow%' AND datistemplate = FALSE;
\gexec
#+end_src

"""

import unittest
import os
import base64
import secrets
import idlib
from urllib.parse import quote as url_quote
from sqlalchemy import create_engine
from sqlalchemy.sql import text as sql_text
from interlex import config, endpoints, auth as iauth
from interlex.uri import make_paths, uriStructure, route_methods, run_uri
from interlex.auth import hash_password
from interlex.core import dbUri, getScopedSession, remove_terminals
from interlex.utils import log
from interlex.config import auth
from interlex.ingest import run_cmd
from interlex.dbstuff import Stuff
from .setup_testing_db import getSession
from .common import working_dir


class TestUserFlows(unittest.TestCase):

    def test_user_new(self):
        pass

    def test_login(self):
        pass


class TestAuthBoundaries(unittest.TestCase):
    # FIXME probably goes in test auth
    def test_not_logged_in(self): pass
    def test_session_login(self): pass
    def test_token_login(self): pass
    def test_orcid_login(self): pass
    def test_ses_tok_login(self): pass
    def test_ses_tok_login(self): pass


test_db_port = auth.get('test-port')
test_db_host = auth.get('test-host')
test_databases = []


def cleanup_dbs(dbs):
    postgres_engine = create_engine(dbUri(dbuser='postgres', host=test_db_host, port=test_db_port, database='postgres'), echo=True)
    with postgres_engine.connect() as conn:
        conn.execute(sql_text('ROLLBACK'))
        for database in dbs:
            conn.execute(sql_text(f'DROP DATABASE IF EXISTS {database}'))


def combinatorics():
    endpoints._email_mock = True
    endpoints._orcid_mock = True
    endpoints._reset_mock = True
    import rsa
    _pub, _priv = rsa.newkeys(2048)  # keep it short for testing
    iauth._orcid_mock_public_key = _pub.save_pkcs1()
    iauth._orcid_mock_private_key = _priv.save_pkcs1()
    #session = getSession(echo=False)
    _session = None
    user = 'tgbugs-test-1', 'tgbugs-test-2'
    own_role = 'pending', 'owner', 'banned', 'admin'
    group = '<group>', # 'org-test-1', 'org-test-2', *user
    other = group
    user_role = 'admin', 'owner', 'contributor', 'curator', 'view', 'pending'

    test_user = 'tgbugs-test-1'
    test_org = 'org-test-1'
    class StatusSuccess: pass
    _success = StatusSuccess()
    class StatusError: pass
    _error = StatusError()
    class StatusFail: pass
    _fail = StatusFail()

    def impossible(r):
        breakpoint()
        raise Exception('sigh, apparently not')
    def success(r): return r is _success
    def error(r): return r is _error
    def fail(r): return r is _fail

    def not_error(r): return r is _error

    def sw_apitok(nodes):
        for n in nodes:
            if n.startswith('api-token'):
                return True

    def priv(nodes): return 'priv' in nodes
    def role(nodes): return 'role' in nodes
    def privu_un(nodes): return '*priv' in nodes and 'user-new' in nodes
    def ops_un(nodes): return 'ops' in nodes and 'user-new' in nodes
    def user_new(nodes): return 'user-new' in nodes

    def GET(m): return m == 'GET'

    def owner(r): return r == 'owner'
    def not_owner(r): return r != 'owner'
    def pending(r): return r == 'pending'
    def admin(r): return r == 'admin'
    def not_admin(r): return r != 'admin'

    def null(v): return v is None
    def not_null(v): return v is not None
    def true(v): return True

    def orcid_user(g):
        # FIXME this is a hack that isn't actually correct
        # closer to maybe orcid user ...
        return not_group(g)

    current_auth_user = None
    def is_user(g):
        nonlocal current_auth_user
        user = list(_session.execute(sql_text('select * from users as u join groups as g on u.id = g.id where g.groupname = :g'), params=dict(g=g)))
        current_auth_user = g if user else None
        return current_auth_user

    def same_user(g): return is_user(g) and g == current_auth_user
    def diff_user(g): return is_user(g) and g != current_auth_user
    def is_org(g):
        return list(_session.execute(sql_text('select * from orgs as o join groups as g on o.id = g.id where g.groupname = :g'), params=dict(g=g)))
    def not_group(g):
        return not list(_session.execute(sql_text('select * from groups where groupname = :g'), params=dict(g=g)))

    #dict(node=, auth_user=, own_role=, group=, user_role=, method=, scope=, outcome=)

    # invariants
    # priv -> auth_user -> org user_role != owner -> fail
    # priv -> auth_user != user -> fail
    # priv/api-token -> auth_user own_role != owner -> fail
    # priv/api-token -> org -> fail
    # priv/role -> auth_user own_role != owner -> fail

    invars = [
        dict(nodes=privu_un,  auth_user=orcid_user,                                                                                      outcome=success),  # orcid only users can start a privu new user proc
        dict(nodes=ops_un,    auth_user=orcid_user,                                                                                      outcome=fail),     # orcid only users can't start an ops new user proc
        dict(nodes=user_new,  auth_user=is_user,                                                                                         outcome=fail),     # existing users can't start any new user proc

        dict(nodes=priv,      auth_user=null,                                                                                            outcome=fail),
        dict(nodes=priv,      auth_user=is_user, own_role=admin,     group=diff_user, user_role=true,      method=true, scope=admin,     outcome=success),
        dict(nodes=priv,      auth_user=is_user, own_role=admin,     group=diff_user, user_role=true,      method=true, scope=not_admin, outcome=fail),
        dict(nodes=priv,      auth_user=is_user, own_role=not_admin, group=diff_user, user_role=not_null,  method=true, scope=not_null,  outcome=fail),

        dict(nodes=priv,      auth_user=is_user, own_role=owner,     group=same_user, user_role=null,      method=true, scope=not_null,  outcome=success),
        dict(nodes=sw_apitok, auth_user=is_user, own_role=not_owner, group=same_user, user_role=null,      method=true, scope=not_null,  outcome=fail),
        dict(nodes=role,      auth_user=is_user, own_role=pending,   group=same_user, user_role=null,      method=true, scope=not_null,  outcome=fail),
        dict(nodes=priv,      auth_user=is_user, own_role=owner,     group=is_org,    user_role=not_owner, method=true, scope=not_null,  outcome=fail),
        dict(nodes=priv,      auth_user=is_user, own_role=owner,     group=is_org,    user_role=owner,     method=true, scope=not_null,  outcome=success),
        dict(nodes=sw_apitok, auth_user=is_user, own_role=owner,     group=is_org,    user_role=owner,     method=true, scope=not_null,  outcome=fail),
        dict(nodes=sw_apitok, auth_user=is_user, own_role=owner,     group=is_org,    user_role=owner,     method=true, scope=not_null,  outcome=fail),

        # some impossible start states for the record
        dict(                                    own_role=pending,                    user_role=not_null,                               outcome=impossible),  # should be impossible to have own_role=pending and user_role=not_null
        dict(                                    own_role=not_admin,                                                   scope=admin,     outcome=impossible),  # should be impossible to have own_role=not_admin and scope=admin
        dict(                 auth_user=is_org,                                                                                         outcome=impossible),  # should be impossible to have auth_user=is_org
    ]

    keys = 'nodes', 'method', 'auth_user', 'own_role', 'group', 'user_role', 'scope'
    def check_invariants(scenario):
        bads = []
        for inv in invars:
            do_check = all([inv[k](scenario[k]) for k in keys if k in inv])
            if do_check:
                if not inv['outcome'](scenario['outcome']):
                    bads.append(inv)

        return bads

    test_password = base64.b64encode(secrets.token_bytes(15)).decode()
    #test_orcid = 'https://orcid.org/' + idlib.systems.orcid.genorcid()
    test_email_f = 'test-user-{n}@example.org'

    def mtest_org(scen):
        return 'org-test-' + base64.b64encode(secrets.token_bytes(6)).decode()  # FIXME shouldn't we disallow org.* ? and group. for groupnames ?? nah i think those are ok, blocking user and test still relevant though

    def mtest_user(scen):
        return 'tgbugs-test-' + base64.urlsafe_b64encode(secrets.token_bytes(6)).decode()

    def msame_user(scen):
        return scen['auth_user']

    scen_reg = [
        dict(auth_user=mtest_user, register='orcid-first',      missing=set()),
        dict(auth_user=mtest_user, register='orcid-second',     missing=set()),

        dict(auth_user=mtest_user, register='orcid-first',      missing={'user', 'email'}),
        dict(auth_user=mtest_user, register='orcid-first',      missing={'email',}),

        dict(auth_user=mtest_user, register='orcid-first-pass', missing={'user', 'email'}),
        dict(auth_user=mtest_user, register='orcid-first-pass', missing={'email'}),

        dict(auth_user=mtest_user, register='orcid-second',     missing={'orcid', 'email'}),  # TODO both orders orcid -> email email -> orcid
        dict(auth_user=mtest_user, register='orcid-second',     missing={'orcid',}),
        dict(auth_user=mtest_user, register='orcid-second',     missing={'email',}),

    ]

    scen_log = [
        # i.e. successful login with orcid by someone, and then someone tries to log in to their account and fails
        dict(auth_user=mtest_user, register='orcid-first', auth='orcid-fail', missing={'user', 'email'})
    ]

    _group = '<group>'
    scen_auth = [
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='owner',   group=msame_user, user_role=None, method='GET', scope='user-only', auth='orcid', register='orcid-first',      missing=set()),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='owner',   group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-first-pass', missing=set()),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='owner',   group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-second',     missing=set()),
        dict(nodes=('', 'u', '*priv', 'user-new'),     auth_user=mtest_user, own_role='owner',   group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-second',     missing=set()),

        dict(nodes=('', 'u', '*priv', 'user-new'),     auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='orcid', register='orcid-first',      missing={'user', 'email'}),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='orcid', register='orcid-first',      missing={'user', 'email'}),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='orcid', register='orcid-first',      missing={'email'}),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-first-pass', missing={'email'}),

        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-second',     missing={'orcid', 'email'}),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-second',     missing={'orcid'}),
        dict(nodes=('', _group, 'priv', 'api-tokens'), auth_user=mtest_user, own_role='pending', group=msame_user, user_role=None, method='GET', scope='user-only', auth='login', register='orcid-second',     missing={'email'}),
        ]
    more = [



    ]

    scnid = iter(range(len(scen_auth) * 2))
    def scen_sql(scen):
        user = scen['auth_user']
        yield None, None

    # prepare single db
    if True:
        database = f'interlex_test_flows_{os.getpid()}_{next(scnid)}'
        test_databases.append(database)  # for teardown
        argv = '/bin/sh', 'bin/interlex-dbsetup', str(test_db_port), database
        run_cmd(argv, working_dir, '/dev/stderr')

    def prepare_scen(scen, scen_type):
        this_scen_id = next(scnid)
        # validate scen
        if 'scope' in scen and scen['scope'] and auth is None:
            # FIXME other stuff can slip by this e.g. scopes that cannot be achieved via login
            raise TypeError('scope provided without auth method to achieve it')
        if 'auth' in scen and scen['auth'] == 'login' and 'register' in scen and scen['register'] not in ('orcid-second', 'orcid-first-pass'):
            if scen['register'] == 'orcid-first':
                msg = 'auth=login requires password OR change to auth=orcid'
            else:
                msg = 'auth=login requires password'

            raise TypeError(msg)

        if 'auth_user' in scen:
            scen['auth_user'] = scen['auth_user'](scen)

        if 'group' in scen:
            scen['group'] = scen['group'](scen)

        # prepare fresh db for each scenario (now overkill)
        if False:
            #database = f'interlex_test_flows_{os.getpid()}_{this_scen_id}'
            test_databases.append(database)  # for teardown
            argv = '/bin/sh', 'bin/interlex-dbsetup', str(test_db_port), database
            run_cmd(argv, working_dir, '/dev/stderr')

        db_kwargs = dict(dbuser='interlex-admin', host=test_db_host, port=test_db_port, database=database)
        try:
            session = getScopedSession(dburi=dbUri(**db_kwargs))
            dbstuff = Stuff(session)

            # create user
            user = None
            test_email = test_email_f.format(n=this_scen_id)
            test_argon = hash_password(test_password)
            orcid_meta = endpoints.Ops._make_orcid_meta()
            if scen_type in 'reg':
                return database, orcid_meta, this_scen_id

            kls = idlib.systems.orcid.OrcidSandbox if config.orcid_sandbox else idlib.Orcid
            orcid = kls._id_class(prefix='orcid', suffix=orcid_meta['orcid']).iri
            if scen['register'].startswith('orcid-first'):
                # this tests partially completely workflows in the database
                # we also want to run scen_reg through the app as well
                endpoints.Ops._insert_orcid_meta(session, orcid_meta)
                session.commit()
            elif scen['register'] == 'orcid-second':
                user = scen['auth_user']
                dbstuff.user_new(user, test_email, test_argon)  # orcid=orcid here should error on fk constraint
                session.commit()
            else:
                msg = f'unknown register workflow {scen["register"]}'
                raise NotImplementedError(msg)

            # execute database only steps to get to the desired state for the scenario
            missing = scen['missing']
            if 'own_role' not in scen:
                # FIXME logic bad upstairs ...
                pass
            elif scen['own_role'] == 'pending':
                if not missing:
                    msg = 'pending must specify what is missing'
                    raise ValueError(msg)

                if 'user' in missing:
                    if 'email' not in missing:
                        msg = 'if user is missing then email must be missing'
                        raise ValueError(msg)
                    elif scen['register'] == 'orcid-second':
                        msg = 'pending orcid-second already has user'
                        raise ValueError(msg)
                elif scen['register'].startswith('orcid-first'):
                    user = scen['auth_user']
                    # XXX how we get the orcid in the route handler is left as an exercise for the reader ... (session)
                    if scen['register'] == 'orcid-first-pass':
                        dbstuff.user_new(user, test_email, test_argon, orcid)
                    else:
                        dbstuff.user_new(user, test_email, None, orcid)

                    session.commit()

                if 'orcid' in missing:
                    if scen['register'].startswith('orcid-first'):
                        msg = 'pending orcid-first already has orcid'
                        raise ValueError(msg)

                    orcid_meta = None
                elif scen['register'] == 'orcid-second':
                    # XXX how we get user in route handler is likewise left as an exercies, likely from session
                    endpoints.Ops._insert_orcid_meta(session, orcid_meta, user=user)
                    session.commit()

            elif scen['own_role'] == 'owner':
                # FIXME sigh code duplication
                if scen['register'] == 'orcid-second':
                    # XXX how we get user in route handler is likewise left as an exercies, likely from session
                    endpoints.Ops._insert_orcid_meta(session, orcid_meta, user=user)
                    session.commit()
                else:
                    user = scen['auth_user']
                    # XXX how we get the orcid in the route handler is left as an exercise for the reader ... (session)
                    if scen['register'] == 'orcid-first-pass':
                        dbstuff.user_new(user, test_email, test_argon, orcid)
                    else:
                        dbstuff.user_new(user, test_email, None, orcid)
            else:
                raise NotImplementedError(scen['own_role'])

            if ('own_role' in scen and scen['own_role'] == 'owner') or ('email' not in missing and 'user' not in missing):
                test_token = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode()
                if user is None:
                    breakpoint()
                dbstuff.email_verify_start(user, test_email, test_token, delay_seconds=0)
                session.commit()  # must commit so that verify time is > start time, otherwise equal timestamps will prevent completion
                dbstuff.email_verify_complete(test_token)
                session.commit()

                #dbstuff.orcid_associate('uh no idea what goes here')
                #dbstuff.user_new

            #breakpoint()
            #for sql, params in scen_sql(scen):
                #if sql is not None:
                    #session.execute(sql_text(sql), params=params)
                    #session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            conn = session.connection()
            conn.close()
            conn.engine.dispose()

        return database, orcid_meta, this_scen_id

    # FIXME probably better to do each test sequentially and not make all dbs first ...
    scendbs = [(scen, prepare_scen(scen, 'reg'), 'reg') for scen in scen_reg] + [(scen, prepare_scen(scen, 'log'), 'log') for scen in scen_log] + [(scen, prepare_scen(scen, 'auth'), 'auth') for scen in scen_auth]

    # FIXME source appropriately
    parent_child, node_methods, path_to_route, path_names = uriStructure()

    def fixresp(resp):
        # match the things we need from requests response object
        resp.ok = resp.status_code < 400
        resp.url = resp.request.url
        resp.content = resp.data
        return resp

    scheme = 'http'
    host = 'localhost'
    port = ':8505'
    url_prefix = f'{scheme}://{host}{port}'

    def do_get(client,url, headers=None):
        resps = []

        if headers is None:
            headers = {}

        resp = fixresp(client.get(url, headers=headers))
        if 'Set-Cookie' in resp.headers:
            headers['Cookie'] = resp.headers['Set-Cookie']

        resps.append(resp)
        while resp.status_code == 302:
            loc = resp.headers['Location']
            if loc.startswith('/'):
                url = url_prefix + loc
            else:
                url = loc

            try:
                resp = fixresp(client.get(url, headers=headers))
            except Exception as e:
                breakpoint()
                raise e

            if 'Set-Cookie' in resp.headers:
                headers['Cookie'] = resp.headers['Set-Cookie']

            resp.history = list(resps)
            resps.append(resp)

        return resp

    def run_scen(scen, scen_type, sid, db, orcid_meta):
        nonlocal _session
        if 'nodes' in scen:
            route = '/'.join(remove_terminals([path_to_route(n) for n in scen['nodes']]))
            filled = route.replace('<group>', scen['group'])
            url = url_prefix + filled

        app = run_uri(db_kwargs=dict(dbuser='interlex-user', host=test_db_host, port=test_db_port, database=db))
        app.testing = True
        session = app.extensions['sqlalchemy'].session
        try:
            client = app.test_client()

            if 'method' in scen:
                method = getattr(client, scen['method'].lower())

            headers = {}
            if scen_type == 'reg' and scen['register'] is not None:
                # FIXME this isn't quite set up correctly for testing these
                if scen['register'].startswith('orcid-first'):
                    # 1
                    #start = url_quote(f'{scheme}://{host}{port}/base/ilx_0101431')
                    start = url_quote(f'{scheme}://{host}{port}/{scen["auth_user"]}/priv/settings')  # XXX hack since brain doesn't exist atm
                    url = url_prefix + '/u/ops/orcid-new' + '?freiri=' + start
                    code = endpoints.Ops._make_orcid_code()
                    endpoints._orcid_mock = code
                    endpoints._orcid_mock_codes[code] = orcid_meta
                    # somehow the cookie isn't being read or something?
                    # checking flask.session it is clear that the cookie is present and has what we need
                    # XXX because we were missing a call to session.commit() (duh)
                    resp1 = do_get(client, url)
                    if resp1.status_code == 302:
                        url_next = url_prefix + resp1.headers['Location']
                    elif resp1.status_code == 200:
                        # have to post to the endpoint the redirect sent us to
                        # though I'm not 100% sure if there is a way to know
                        # that from the html that comes back
                        url_next = resp1.url
                    else:
                        url_next = None

                    if not resp1.ok:
                        with app.app_context():
                            breakpoint()
                            ''

                    # 2
                    url = (url_prefix + f'/u/priv/user-new') if url_next is None else url_next  # resp1 is the get to this endpoint, now we post
                    user = scen['auth_user']
                    email = test_email_f.format(n=sid)
                    # ok, don't need to pass headers because the client does maintain the session
                    # but that means we need a new client when we want to potentially separate
                    # browser, computer, etc.
                    #headers = {}
                    # due to the extra redirect to
                    #headers['Cookie'] = resp1.request.headers['Cookie']
                    data = {'username': user, 'email': email}
                    if scen['register'] == 'orcid-first-pass':
                        data['password'] = test_password
                    resp2 = fixresp(client.post(url, data=data, headers=headers))
                    if resp1.status_code == 303:
                        url_next = url_prefix + resp1.headers['Location']
                    else:
                        url_next = None

                    if not resp2.ok:
                        with app.app_context():
                            breakpoint()
                            ''

                    # 3
                    ever_same = True
                    if config.email_verify:
                        client2 = client if ever_same else app.test_client()
                        token = endpoints._email_mock_tokens[email]
                        url = url_prefix + '/u/ops/email-verify?t=' + token
                        resp3 = do_get(client2, url)
                        if not resp3.ok:
                            with app.app_context():
                                breakpoint()
                                ''

                if scen['register'] == 'orcid-second':
                    # 1
                    #start = url_quote(f'{scheme}://{host}{port}/base/ilx_0101431')
                    start = url_quote(f'{scheme}://{host}{port}/{scen["auth_user"]}/priv/settings')  # XXX hack since brain doesn't exist atm
                    url = url_prefix + '/u/ops/user-new' + '?freiri=' + start
                    user = scen['auth_user']
                    email = test_email_f.format(n=sid)
                    data = {'username': user, 'email': email, 'password': test_password}
                    resp1 = fixresp(client.post(url, data=data))
                    if resp1.status_code == 303:
                        url_next = url_prefix + resp1.headers['Location']
                    else:
                        url_next = None

                    if not resp1.ok:
                        with app.app_context():
                            breakpoint()
                            ''

                    # 2
                    url = (url_prefix + f'/{user}/priv/orcid-assoc') if url_next is None else url_next
                    #headers = {}
                    #headers['Cookie'] = resp1.headers['Set-Cookie']
                    code = endpoints.Ops._make_orcid_code()
                    endpoints._orcid_mock = code
                    endpoints._orcid_mock_codes[code] = orcid_meta
                    resp2 = do_get(client, url)

                    if not resp2.ok:
                        with app.app_context():
                            breakpoint()
                            ''

                    # 3
                    ever_same = False
                    if config.email_verify:
                        client2 = client if ever_same else app.test_client()
                        token = endpoints._email_mock_tokens[email]
                        url = url_prefix + '/u/ops/email-verify?t=' + token
                        # TODO inserting random delays between steps is fun if you
                        # do it here the 10 second mock lifetime will trigger!
                        resp3 = do_get(client2, url)
                        if not resp3.ok:
                            with app.app_context():
                                breakpoint()
                                ''

                # start common flow

                # 4
                url = url_prefix + f'/{user}/priv/api-token-new'  # FIXME TODO api-token-web-new ?
                data = {'token-type': 'personal', 'scope': 'settings-all', 'note': 'testing token'}
                resp4 = fixresp(client.post(url, data=data, headers=headers))
                if not resp4.ok:
                    with app.app_context():
                        breakpoint()
                        ''

                # 5
                url = url_prefix + f'/{user}/priv/settings'
                resp5 = do_get(client, url)
                if not resp5.ok:
                    with app.app_context():
                        breakpoint()
                        ''

                with app.app_context():
                    #breakpoint()
                    ''

                return

            if scen_type == 'log':
                # TODO
                breakpoint()
                return

            if scen['auth'] is not None:
                if scen['auth'] == 'login':
                    lheaders = {'Authorization': 'Basic ' + base64.b64encode((scen['auth_user'] + ':' + test_password).encode()).decode()}
                    lurl = url_prefix + '/u/ops/user-login'
                    lresp = fixresp(client.get(lurl, headers=lheaders))
                    headers['Cookie'] = lresp.headers['Set-Cookie']
                elif scen['auth'] == 'orcid':
                    code = endpoints.Ops._make_orcid_code()
                    endpoints._orcid_mock = code
                    endpoints._orcid_mock_codes[code] = orcid_meta
                    lurl = url_prefix + '/u/ops/orcid-login'
                    lresps = []
                    lheaders = {}
                    lresp = fixresp(client.get(lurl, headers=lheaders))
                    # XXX have to manually resolve location
                    lresps.append(lresp)
                    while lresp.status_code == 302:
                        loc = lresp.headers['Location']
                        if loc.startswith('/'):
                            lurl = url_prefix + loc
                        else:
                            lurl = loc

                        lresp = fixresp(client.get(lurl))
                        if 'Set-Cookie' in lresp.headers:
                            lheaders['Cookie'] = lresp.headers['Set-Cookie']
                        lresps.append(lresp)

                    if 'Cookie' in lheaders:
                        headers['Cookie'] = lheaders['Cookie']

                    #breakpoint()

                elif scen['auth'] == 'orcid-fail':  # XXX not quite the right place to test this, it is more in the scen_log set ?
                    pass

                #breakpoint()

            resp = fixresp(method(url, headers=headers))
            scen['outcome'] = _success if resp.ok else _fail  # FIXME
            with app.app_context():
                _session = session
                # FIXME have to check invariants in here because we need the session for some of our predicates
                bad = check_invariants(scen)
                if bad:
                    breakpoint()

                return bad

            _session = None

        except Exception as e:
            # rollbacks should all happen internally
            log.exception(e)
            with app.app_context():
                breakpoint()
                'derp'

            return [dict(outcome=not_error)]
        finally:
            endpoints._orcid_mock = True
            with app.app_context():
                session.close()
                conn = session.connection()
                conn.close()
                conn.engine.dispose()

    # run_scen mutates scen in place to add outcomes outcomes
    bads = []
    for scen, (db, orcid_meta, sid), scen_type in scendbs:
        bad = run_scen(scen, scen_type, sid, db, orcid_meta)
        if bad:
            bads.append((scen, bad, db))

    if bads:
        breakpoint()

    assert not bads

    options = {
        #'<group>': group,
    }

    paths = list(make_paths(parent_child, options=options, limit=10))
    tpaths = [p for p in paths if 'priv' in p]
    tmethods = [route_methods(n, node_methods, path_names) for n in tpaths]
    tpm = [(p, m) for p, m in zip (tpaths, tmethods)]
    breakpoint()

    any = object()
    same = object()

    succ_200 = object()
    succ_201 = object()
    fail_400 = object()
    fail_401 = object()
    fail_404 = object()

    dict(user=any, own_role='pending', group=same, user_role=None, rule_prefix='/<group>/priv/', )

    outcomes = [
    ]


if __name__ == '__main__':
    # config.email_verify = False
    try:
        combinatorics()
    finally:
        if test_databases:
            cleanup_dbs(test_databases)

