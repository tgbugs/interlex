gunicorn -b localhost:8606 -n interlex_uri -w 4 -k gevent -t 30 --preload --log-level debug interlex.uri_server:app
