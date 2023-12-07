{'config-search-paths': ['{:user-config-path}/interlex/config.yaml',],
 'auth-variables': {
     # basics
     'debug': {
         'default': False,
         'environment-variables': 'INTERLEX_DEBUG',},
     'ilx-pattern': '<regex("((ilx|cde|fde)_[0-9]{7})|(pde_[0-9]{8})"):frag_pref_id>',

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
     'test-host': 'localhost',
     'test-database': {
         'default': '__interlex_testing',
         'environment-variables': 'INTERLEX_TEST_DATABASE',},

     # alt
     'alt-db-user': 'nif_eelg_secure',
     'alt-db-host': 'nif-mysql.crbs.ucsd.edu',
     'alt-db-port': 3306,
     'alt-db-database': 'nif_eelg',

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
 }}
