{'config-search-paths': ['{:user-config-path}/interlex/config.yaml',],
 'auth-variables': {
     # basics
     'debug': {
         'default': False,
         'environment-variables': 'INTERLEX_DEBUG',},
     'ilx-pattern': 'ilx_<regex("[0-9]{7}"):id>',  # FIXME abstract this probably

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
     'test-database': '__interlex_testing',

     # db
     'db-user': 'interlex-user',
     'db-database': {
         # we don't set a default here to prevent
         # accidental operations on a default db
         'default': None,
         'environment-variables': 'INTERLEX_DATABASE',},

     # mq
     'mq-vhost': 'interlex',
     'mq-broker-url': {
         'default': 'amqp://guest:guest@localhost:5672//',
         'environment-variables': 'CELERY_BROKER_URL BROKER_URL',},
     'mq-broker-backend': {
         'default': 'rpc://',
         'environment-variables': 'CELERY_BROKER_BACKEND BROKER_BACKEND',},
     'mq-accept-content': ('pickle', 'json'),}}
