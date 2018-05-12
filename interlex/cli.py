#!/usr/bin/env python3.6
#!/usr/bin/env pypy3
""" InterLex python implementaiton

Usage:
    interlex api [options]
    interlex uri [options]
    interlex curies [options]
    interlex test [options]
    interlex sync [options]
    interlex dbsetup [options]
    interlex post curies [options] <user>
    interlex post ontology [options] <user>
    interlex post ontology [options] <user> <name>

Options:
    -d --debug              enable debug mode
    -l --local              run against local

    -a --api=API            SciGraph api endpoint
    -k --key=APIKEY         apikey for SciGraph instance
    -f --input-file=FILE    don't use SciGraph, load an individual file instead
    -o --outgoing           if not specified defaults to incoming
    -b --both               if specified goes in both directions

"""

from urllib.parse import urlparse
import requests
from pyontutils.core import PREFIXES as uPREFIXES
from interlex.core import printD, InterLexLoad
from IPython import embed

port_api = 8500
port_uri = 8505
port_curies = 8510

def main():
    from docopt import docopt
    args = docopt(__doc__, version='interlex 0.0.0')
    if args['test']:
        from core import test
        if args['--debug']:
            embed()
        else:
            test()
    elif args['post']:
        user = args['<user>']
        name = args['<name>']
        if args['--local']:
            host = f'localhost:{port_uri}'
            scheme = 'http'
        else:
            host = 'uri.olympiangods.org'
            scheme = 'https'
        if args['curies']:
            url = f'{scheme}://{host}/{user}/curies/'  # https duh
            #printD(url, args)
            # FIXME /curies redirects to get...
            resp = requests.post(url, json=uPREFIXES)
            printD(resp.text)
        elif args['ontology']:
            j = {'name':'http://purl.obolibrary.org/obo/uberon.owl'}
            if name is not None:
                ontology_iri = name
            else:
                ontology_iri = 'http://ontology.neuinfo.org/NIF/ttl/NIF-GrossAnatomy.ttl'
            u = urlparse(ontology_iri)
            j = {'name':ontology_iri}
            url = f'{scheme}://{host}/{user}/ontologies/' + u.path[1:]
            resp = requests.post(url, json=j)
            printD(resp.text)

    elif args['sync']:
        from flask_sqlalchemy import SQLAlchemy
        from interlex.uri import run_uri
        from interlex.load import TripleLoader
        app = run_uri()
        db = SQLAlchemy(app)
        ltl = type('TripleLoader', (TripleLoader,), {})
        Loader = ltl(db.session)
        il = InterLexLoad(Loader)
        il.setup()
        # il.load()  # do this one yourself
        self = il
        embed()

    elif args['dbsetup']:
        #dburi = dbUri()
        # app.config['SQLALCHEMY_DATABASE_URI']
        #engine, insp = database()
        #meta = MetaData(engine)
        #db = SQLAlchemy()
        #meta.reflect()
        # Session = sessionmaker(engine)
        # TODO use sessions to manage transations for safety
        sql_new_id = 'INSERT INTO interlex_ids DEFAULT VALUES RETURNING id'

        sql_group = 'INSERT INTO groups (groupname) VALUES (%s) RETURNING id'
        args_group = 'tgbugs'
        engine.execute(sql_group, args_group)
        sql_new_user = 'INSERT INTO new_users (id, putative_orcid, putative_email) VALUES (%s, %s, %s)'
        args_new_user = 1, 'https://orcid.org/0000-0002-7509-4801', 'tgbugs@gmail.com'
        engine.execute(sql_new_user, args_new_user)

        # TODO use a trigger for this, should never do this from python...
        sql = 'INSERT INTO users (id, username, orcid) VALUES (%s, %s, %s)'
        args = 1, 'tgbugs', 'https://orcid.org/0000-0002-7509-4801'
        engine.execute(sql, args)

        embed()

    else:
        if args['api']:
            from core import run_api
            app = run_api()
            port = port_api
        elif args['uri']:
            from uri import run_uri
            app = run_uri()
            port = port_uri
        elif args['curies']:
            from core import run_curies
            app = run_curies()
            port = port_curies

        app.debug = args['--debug']
        app.run(host='localhost', port=port, threaded=True)  # FIXME gunicorn

if __name__ == '__main__':
    main()
