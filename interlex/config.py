import os

debug = False
ilx_pattern = 'ilx_<regex("[0-9]{7}"):id>'

user = 'interlex-user'
database = os.environ.get('INTERLEX_DATABASE')
vhost = 'interlex'
broker_url = os.environ.get('CELERY_BROKER_URL',
                            os.environ.get('BROKER_URL',
                                           'amqp://guest:guest@localhost:5672//'))
broker_backend = os.environ.get('CELERY_BROKER_BACKEND',
                                os.environ.get('BROKER_BACKEND',
                                               'rpc://'))
accept_content = ('pickle', 'json')
