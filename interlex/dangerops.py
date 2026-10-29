import secrets, base64
from sqlalchemy.sql import text as sql_text
from interlex import endpoints, auth as iauth, config
from interlex.uri import run_uri
from interlex.utils import log
from interlex.config import auth, test_http_host, test_http_port
from interlex.dbstuff import Stuff

# FIXME TODO these are things that could be in dbstuff but that are
# isolated here because they are dangerous and not normal workflows


if iauth._orcid_mock_public_key is None:
    import rsa
    _pub, _priv = rsa.newkeys(2048)  # keep it short for testing
    iauth._orcid_mock_public_key = _pub.save_pkcs1()
    iauth._orcid_mock_private_key = _priv.save_pkcs1()


def make_test_user(username, password, db_kwargs, email=None,
                   orcid=None, orcid_name=None, do_orcid=True, make_admin=False):
    """ you probably shouldn't be using this """
    log.info(db_kwargs)
    app = run_uri(echo=True, test=True, db_kwargs=db_kwargs)
    client = app.test_client()
    scheme = 'http'
    host = test_http_host
    port = test_http_port

    _port = f':{port}' if port else ''
    prefix = f'{scheme}://{host}{_port}'

    if email is None:
        diff = secrets.token_hex(6)
        email = f'email-{diff}@example.org'

    data = {'username': username, 'password': password, 'email': email}
    url = f'{prefix}/u/ops/user-new'
    resp = client.post(url, data=data)
    if resp.status_code >= 400:
        raise ValueError(f'{resp} {resp.text}')

    url_settings = f'{prefix}/{username}/priv/settings'
    resp2 = client.get(url_settings)
    if resp2.status_code >= 400:
        raise ValueError(f'{resp2} {resp2.text}')

    user = username
    test_email = data['email']
    test_token = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode()

    # auto verify and set privs
    with app.app_context():
        session = app.extensions['sqlalchemy'].session
        dbstuff = Stuff(session)
        dbstuff.email_verify_start(user, test_email, test_token, delay_seconds=0)
        session.commit()  # must commit so that verify time is > start time, otherwise equal timestamps will prevent completion
        dbstuff.email_verify_complete(test_token)
        session.commit()

        if do_orcid:
            # this is not the best way to handle this, the actual orcid association
            # is still needed but must be deferred at the point where we run this
            orcid_meta = endpoints.Ops._make_orcid_meta(expires_in_seconds=None)
            if orcid is not None:
                orcid_meta['orcid'] = orcid.identifier.suffix
            if orcid_name is not None:
                orcid_meta['name'] = orcid_name

            endpoints.Ops._insert_orcid_meta(session, orcid_meta, user=user)
            session.commit()

        if make_admin:
            args = dict(groupname=user)
            sql = "INSERT INTO user_permissions (group_id, user_id, user_role) VALUES (0, idFromGroupname(:groupname), 'admin');"
            session.execute(sql_text(sql), params=args)
            session.commit()


def revoke_admin(user, db_kwargs):
    log.info(db_kwargs)
    app = run_uri(echo=True, test=True, db_kwargs=db_kwargs)
    with app.app_context():
        session = app.extensions['sqlalchemy'].session
        args = dict(groupname=user)
        sql = "UPDATE user_permissions SET user_role = 'deleted' WHERE group_id = 0 AND user_id = idFromusername(:groupname);"
        session.execute(sql_text(sql), params=args)
        session.commit()


def register_first_admin():
    import sys
    from getpass import getpass
    import idlib
    db_kwargs = {k:auth.get(f'db-{k}') for k in ('host', 'port', 'database')}
    log.info(db_kwargs)
    try:
        username = sys.argv[1]
        email = sys.argv[2]
        _orcid = sys.argv[3]
        orcid_name = sys.argv[4]
    except IndexError:
        msg = 'username, email, orcid, and orcid-name are required'
        raise ValueError(msg)

    msg = f'\nSet password for new admin user {username}'
    print(msg)
    a = getpass()
    b = getpass()
    if a == b:
        password = a
    else:
        raise ValueError('passwords do not match')

    kls = idlib.systems.orcid.OrcidSandbox if config.orcid_sandbox else idlib.Orcid
    try:
        orcid = kls(_orcid)
    except idlib.systems.orcid.OrcidId.OrcidMalformedError as e:
        msg = f'this system is configured to use {config.orcid_host}'
        raise TypeError(msg) from e

    make_test_user(username, password, db_kwargs, email=email,
                   orcid=orcid, orcid_name=orcid_name, make_admin=True)


def example_main():
    raise NotImplementedError('just look no run')
    # test on testing
    db_kwargs = {k:auth.get(f'test-{k}') for k in ('host', 'port', 'database')}
    make_test_user('some-testadmin', 'password', db_kwargs, make_admin=True)
    revoke_admin('some-testadmin', db_kwargs)

    # run on prod
    db_kwargs = {k:auth.get(f'db-{k}') for k in ('host', 'port', 'database')}
    make_test_user('some-testadmin', 'password', db_kwargs, make_admin=True)
    revoke_admin('some-testadmin', db_kwargs)
