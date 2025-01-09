import unittest
import os
import base64
import secrets
import idlib
from sqlalchemy import create_engine
from sqlalchemy.sql import text as sql_text
from interlex.uri import make_paths, uriStructure, route_methods, run_uri
from interlex.core import dbUri, getScopedSession
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
    #session = getSession(echo=False)
    user = 'tgbugs-test-1', 'tgbugs-test-2'
    own_role = 'pending', 'owner', 'banned', 'admin'
    group = '<group>', # 'org-test-1', 'org-test-2', *user
    other = group
    user_role = 'admin', 'owner', 'contributor', 'curator', 'view', 'pending'

    test_user = 'tgbugs-test-1'
    test_org = 'org-test-1'
    _success = object()
    _fail = object()

    def impossible(r): raise Exception('sigh, apparently not')
    def success(r): return r is _success
    def fail(r): return r is _fail

    def sw_apitok(nodes):
        for n in nodes:
            if n.startswith('api-token'):
                return True

    def priv(nodes): return 'priv' in nodes
    def role(nodes): return 'role' in nodes
    def GET(m): return m == 'GET'

    def owner(r): return r == 'owner'
    def not_owner(r): return r != 'owner'
    def pending(r): return r == 'pending'
    def admin(r): return r == 'admin'
    def not_admin(r): return r != 'admin'

    def null(v): return v is None
    def not_null(v): return v is not None
    def true(v): return True

    current_auth_user = None
    def is_user(g):
        nonlocal current_auth_user
        user = list(session.execute('select * from users where id = idFromGroupname(:g)', params=dict(g=g)))
        current_auth_user = g if user else None
        return current_auth_user

    def same_user(g): return is_user(g) and g == current_auth_user
    def diff_user(g): return is_user(g) and g != current_auth_user
    def is_org(g):
        return list(session.execute('select * from orgs where id = idFromGroupname(:g)', params=dict(g=g)))
    def not_group(g): return not list(session.execute('select * from groups where groupname = :g', params=dict(g=g)))

    #dict(node=, auth_user=, own_role=, group=, user_role=, method=, scope=, outcome=)

    # invariants
    # priv -> auth_user -> org user_role != owner -> fail
    # priv -> auth_user != user -> fail
    # priv/api-token -> auth_user own_role != owner -> fail
    # priv/api-token -> org -> fail
    # priv/role -> auth_user own_role != owner -> fail

    invars = [
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

    keys = 'node', 'method', 'auth_user', 'own_role', 'group', 'user_role', 'scope'
    def check_invariants(scenario):
        bads = []
        for inv in invars:
            do_check = [k for k in keys if k in inv and inv[k](scenario[k])]
            if do_check:
                if not inv['outcome'](scenario['outcome']):
                    bads.append(inv)

        return bads

    test_password = base64.b64encode(secrets.token_bytes(15)).decode()
    test_orcid = 'https://orcid.org/' + idlib.systems.orcid.genorcid()
    test_email = 'test-user@example.org'

    scenarios = [
        dict(nodes=('', 'priv', 'api-tokens'), auth_user=test_user, own_role='owner',   group=test_user, user_role=None, method='GET', scope='user-only', auth=None),
        dict(nodes=('', 'priv', 'api-tokens'), auth_user=test_user, own_role='pending', group=test_user, user_role=None, method='GET', scope='user-only', auth=None),
    ]

    scnid = iter(range(len(scenarios) * 2))
    def scen_sql(scen):
        user = scen['auth_user']
        yield None, None

    def prepare_scen(scen):
        database = f'interlex_test_flows_{os.getpid()}_{next(scnid)}'
        test_databases.append(database)  # for teardown
        argv = '/bin/sh', 'bin/interlex-dbsetup', str(test_db_port), database
        run_cmd(argv, working_dir, '/dev/stderr')

        db_kwargs = dict(dbuser='interlex-admin', host=test_db_host, port=test_db_port, database=database)
        try:
            session = getScopedSession(dburi=dbUri(**db_kwargs))
            dbstuff = Stuff(session)

            # create user
            dbstuff.user_new(scen['auth_user'], test_password, test_orcid, test_email)
            # get various auth things
            if scen['own_role'] == 'pending':
                pass
            elif scen['own_role'] == 'owner':
                test_token = base64.urlsafe_b64encode(secrets.token_bytes(24))
                dbstuff.email_verify_start(test_user, test_email, test_token, delay_seconds=0)
                session.commit()  # must commit so that verify time is > start time, otherwise equal timestamps will prevent completion
                dbstuff.email_verify_complete(test_token)
                session.commit()

                #dbstuff.orcid_associate('uh no idea what goes here')
                #dbstuff.user_new

            breakpoint()
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

        return database

    scendbs = [(scen, prepare_scen(scen)) for scen in scenarios]

    # FIXME source appropriately
    scheme = 'http'
    host = 'localhost'
    port = ':8505'
    url_prefix = f'{scheme}://{host}{port}'
    def run_scen(scen, db):
        route = remove_terminals([path_to_route(n) for n in scen['nodes']])
        filled = route.replace('<group>', scen['group'])
        url = url_prefix + route

        app = run_uri(db_kwargs=dict(dbuser='interlex-user', host=test_db_host, port=test_db_port, database=db))
        client = app.test_client()

        method = getattr(client, scen['method'].lower())
        headers = {''}
        resp = method(url, headers=headers)
        scen['outcome'] = _success if resp.ok else _fail  # FIXME

    options = {
        #'<group>': group,
    }

    parent_child, node_methods, path_to_route, path_names = uriStructure()
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
    try:
        combinatorics()
    finally:
        if test_databases:
            cleanup_dbs(test_databases)

