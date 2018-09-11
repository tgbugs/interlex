import os

debug = False
ilx_pattern = 'ilx_<regex("[0-9]{7}"):id>'


# ports
port_api = 8500
port_uri = 8505
port_curies = 8510
port_alt = 8515

## WARNING if you change one of these update the file in bin/
port_guni_uri = 8606       # interlex-uri
port_guni_curies = 8612    # interlex-curies
port_guni_alt = 8618       # interlex-alt

# testing
test_host = 'localhost'
test_port = port_uri
test_stress_port = port_guni_uri
test_database = '__interlex_testing'

# db
user = 'interlex-user'
database = os.environ.get('INTERLEX_DATABASE', test_database)

# mq
vhost = 'interlex'
broker_url = os.environ.get('CELERY_BROKER_URL',
                            os.environ.get('BROKER_URL',
                                           'amqp://guest:guest@localhost:5672//'))
broker_backend = os.environ.get('CELERY_BROKER_BACKEND',
                                os.environ.get('BROKER_BACKEND',
                                               'rpc://'))
accept_content = ('pickle', 'json')
