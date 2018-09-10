import os

database = os.environ.get('INTERLEX_DATABASE')
ilx_pattern = 'ilx_<regex("[0-9]{7}"):id>'
debug = False
