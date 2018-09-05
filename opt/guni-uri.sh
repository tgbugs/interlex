gunicorn -b localhost:8606 -n interlex_uri -w 8 -k gevent -t 30 --preload --log-level debug interlex.uri_server:app

#for pypy3, has issues dealing with accidental embed don't use yet

#~/.local/bin/gunicorn -b localhost:8606 -n interlex_uri -w 8 -k tornado -t 30 --preload --log-level debug interlex.uri_server:app
