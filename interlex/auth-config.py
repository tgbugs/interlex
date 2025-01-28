{'config-search-paths': ['{:user-config-path}/interlex/config.yaml',],
 'auth-variables': {
     # basics
     'debug': {
         'default': False,
         'environment-variables': 'INTERLEX_DEBUG',},
     'ilx-pattern': '<regex("((ilx|cde|fde)_[0-9]{7})|(pde_[0-9]{8})"):frag_pref_id>',

     'orcid-sandbox': {
         'default': True,
         'environment-variables': 'INTERLEX_ORCID_SANDBOX',},

     'email-verify': {
         'default': True,
         'environment-variables': 'INTERLEX_EMAIL_VERIFY',},

     'interlex-api-key': {
         'default': None,
         'environment-variables': 'INTERLEX_API_KEY',},

     'interlex-test-api-key': {
         'default': None,
         'environment-variables': 'INTERLEX_TEST_API_KEY',},

     # ports
     'port-api': 8500,
     'port-uri': 8505,
     'port-curies': 8510,
     'port-alt': 8515,
     'port-guni-uri': 8606,
     'port-guni-curies': 8612,
     'port-guni-alt': 8618,

     # database connection logic XXX don't need once we use orthauth
     'dev-remote-hosts': [],

     # testing
     'test-api-user': {
         'default': None,
         'environment-variables': 'INTERLEX_TEST_API_USER',},
     'test-host': 'localhost',
     'test-database': {
         'default': '__interlex_testing',
         'environment-variables': 'INTERLEX_TEST_DATABASE',},
     'test-port': {
         'default': 5432,
         'environment-variables': 'INTERLEX_TEST_PORT',},

     # alt
     'alt-db-user': {
         'default': 'nif_eelg_secure',
         'environment-variables': 'INTERLEX_ALT_DB_USER'},
     'alt-db-host': {
         'default': 'nif-mysql.crbs.ucsd.edu',
         'environment-variables': 'INTERLEX_ALT_DB_HOST'},
     'alt-db-port': {
         'default': 3306,
         'environment-variables': 'INTERLEX_ALT_DB_PORT'},
     'alt-db-database': {
         'default': 'nif_eelg',
         'environment-variables': 'INTERLEX_ALT_DB_DATABASE'},

     # db
     'db-user': {
         'default': 'interlex-user',
         'environment-variables': 'INTERLEX_DB_USER'},
     'db-host': {
         'default': 'localhost',
         'environment-variables': 'INTERLEX_DB_HOST'},
     'db-port': {
         'default': 5432,
         'environment-variables': 'INTERLEX_DB_PORT'},
     'db-database': {
         # we don't set a default here to prevent
         # accidental operations on a default db
         'default': None,
         'environment-variables': 'INTERLEX_DB_DATABASE INTERLEX_DATABASE',},

     # mq
     'mq-vhost': 'interlex',
     'mq-broker-url': {
         'default': 'amqp://guest:guest@localhost:5672//',
         'environment-variables': 'CELERY_BROKER_URL BROKER_URL',},
     'mq-broker-backend': {
         'default': 'rpc://',
         'environment-variables': 'CELERY_BROKER_BACKEND BROKER_BACKEND',},
     'mq-accept-content': ('pickle', 'json'),

     # fl
     'fl-session-secret-key': None,

     # smtp
     'smtp-host': {
         'default': None,
         'environment-variables': 'INTERLEX_SMTP_HOST',},
     'smtp-port': {
         'default': 25,
         'environment-variables': 'INTERLEX_SMTP_PORT',},
     'smtp-local-hostname': None,  # not sure if need

     # orcid oauth client
     'orcid-client-id': {
         'default': None,
         'environment-variables': 'INTERLEX_ORCID_CLIENT_ID',},
     'orcid-client-secret':{
         'default': None,
         'environment-variables': 'INTERLEX_ORCID_CLIENT_SECRET',},
     'orcid-sandbox-client-id': {
         'default': None,
         'environment-variables': 'INTERLEX_ORCID_SANDBOX_CLIENT_ID',},
     'orcid-sandbox-client-secret':{
         'default': None,
         'environment-variables': 'INTERLEX_ORCID_SANDBOX_CLIENT_SECRET',},

 }}
