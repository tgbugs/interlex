import os
import orthauth as oa
from orthauth.utils import sxpr_to_python
from pyontutils.config import auth as pauth

auth = oa.configure_here('auth-config.py', __name__, include=pauth)


class QuietString(str):
    # confirmed that this works with requests headers, data, and json
    # when the value goes out on the wire, it looks like concat works
    # but string formatting via f'{s}', '{}'.format(s), '%s' % s does
    # not likely because they use str() internally, by concat i mean
    # ''.join((s,)), s + s, etc. s.encode() also works

    def __repr__(self):
        return '[redacted]'

    def __str__(self):
        # str(qs) does not work, but str.__str__(qs) does
        # this means that the caste has to be made when it
        # passes out of our scope unfortunately or we have
        # to see whether other callers do things like use
        # format strings, or log etc.
        return '[redacted]'


# basics
use_real_frag_pref = auth.get('use-real-frag-pref')
debug = auth.get('debug')
ilx_pattern = auth.get('ilx-pattern')
orcid_sandbox = auth.get('orcid-sandbox')
email_verify = auth.get('email-verify')

# ops for transition
_existing_user_map_path = auth.get_path('existing-user-map')
if _existing_user_map_path:
    with open(_existing_user_map_path, 'rt') as f:
        _tmp = f.read()
    existing_user_map = {int(d['guid']): (d['user'], d['email']) for d in sxpr_to_python(_tmp)}
else:
    existing_user_map = {}

# ports
port_api = auth.get('port-api')
port_uri = auth.get('port-uri')
port_curies = auth.get('port-curies')
port_alt = auth.get('port-alt')

## WARNING if you change one of these update the file in bin/
port_guni_uri = auth.get('port-guni-uri')        # interlex-uri
port_guni_curies = auth.get('port-guni-curies')  # interlex-curies
port_guni_alt = auth.get('port-guni-alt')        # interlex-alt

# dev
dev_remote_hosts = auth.get_list('dev-remote-hosts')

redirect_allow_hosts = auth.get_list('redirect-allow-hosts')

# testing
test_host = auth.get('test-host')
test_port = port_uri
test_stress_port = port_guni_uri
test_database = auth.get('test-database')
test_database_port = auth.get('test-port')  # a bit of naming confusion just for good measure

# db
user = auth.get('db-user')
database = auth.get('db-database')
database_host = auth.get('db-host')
database_port = auth.get('db-port')

# mq
vhost = auth.get('mq-vhost')
broker_url = auth.get('mq-broker-url')
broker_backend = auth.get('mq-broker-backend')
accept_content = auth.get('mq-accept-content')

# orcid
orcid_prod_client_id = auth.get('orcid-client-id')  # isn't secret, gets passed in url visible to user
orcid_prod_client_secret = QuietString(auth.get('orcid-client-secret'))
orcid_sandbox_client_id = auth.get('orcid-sandbox-client-id')
orcid_sandbox_client_secret = QuietString(auth.get('orcid-sandbox-client-secret'))


def _set_orcid():
    # FIXME TODO figure out if there is some sane way to reload the whole config ...
    global orcid_host, orcid_client_id, orcid_client_secret
    orcid_host = 'sandbox.orcid.org' if orcid_sandbox else 'orcid.org'
    orcid_client_id = orcid_sandbox_client_id if orcid_sandbox else orcid_prod_client_id
    orcid_client_secret = orcid_sandbox_client_secret if orcid_sandbox else orcid_prod_client_secret


orcid_host, orcid_client_id, orcid_client_secret = None, None, None
_set_orcid()
