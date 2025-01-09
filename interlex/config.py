import os
import orthauth as oa
from pyontutils.config import auth as pauth

auth = oa.configure_here('auth-config.py', __name__, include=pauth)

# basics
debug = auth.get('debug')
ilx_pattern = auth.get('ilx-pattern')

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
orcid_client_id = auth.get('orcid-client-id')
orcid_client_secret = auth.get('orcid-client-secret')
