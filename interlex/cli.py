#!/usr/bin/env python3.6
#!/usr/bin/env pypy3
""" InterLex python implementaiton

Usage:
    interlex api [options]
    interlex uri [options]
    interlex curies [options]
    interlex dbsetup [options]
    interlex sync [options]
    interlex post curies [options] <user>
    interlex post curies [options] <user> <filename>
    interlex post ontology [options] <user>
    interlex post ontology [options] <user> <name>
    interlex post ontology [options] <user> <name> <filename>

Commands:
    api             start a server running the api endpoint (WARNING: OLD)
    uri             start a server for uri.interlex.org
    curies          start a server for curies.interlex.org

    dbsetup         run some initial setup BROKEN must uncomment things and change info
    sync            run sync with the old mysql database

    post curies     post curies for a given user
    post ontology   post an ontology file by uploading or url

Options:
    -d --debug              enable debug mode
    -l --local              run against local
    -g --gunicorn           run against local gunicorn

    -f --input-file=FILE    load an individual file

    -a --api=API            SciGraph api endpoint
    -k --key=APIKEY         apikey for SciGraph instance

"""

from pathlib import Path
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
    if args['post']:
        user = args['<user>']
        name = args['<name>']
        filename = args['<filename>']
        if args['--local']:
            host = f'localhost:{port_uri}'
            scheme = 'http'
        elif args['--gunicorn']:
            host = f'localhost:8606'
            scheme = 'http'
        else:
            host = 'uri.olympiangods.org'
            scheme = 'https'

        if args['curies']:
            url = f'{scheme}://{host}/{user}/curies/'  # https duh
            #printD(url, args)
            # FIXME /curies redirects to get...
            if filename:
                path = Path(filename).resolve().actual()
                ext = path.suffix[1:]
                with open(path.as_posix(), 'rt') as f:
                    if ext == 'json':
                        data = json.load(f)
                    elif ext == 'ttl':
                        graph = rdflib.Graph().parse(f, format='ttl')
                        # TODO allow <url> a ilxr:Curies typed record
                        data = {k:str(v) for k, v in graph.namespaces()}
                    elif ext == 'yml' or ext == 'yaml':
                        data = yaml.load(f)
                    else:
                        raise TypeError(f'Don\'t know how to handle {ext} files')

                resp = requests.post(url, json=data)
            else:
                resp = requests.post(url, json=uPREFIXES)
            printD(resp.text)

        elif args['ontology']:
            if filename:
                url = f'{scheme}://{host}/{user}/upload'  # use smart endpoint
                mimetypes = {'ttl':'text/turtle'}  # TODO put this somewhere more practical
                path = Path(filename).resolve().absolute()
                mimetype = mimetypes.get(path.suffix[1:], None)
                with open(path.as_posix(), 'rb') as f:
                    files = {'file':(path.name, f, mimetype)}
                    data = {'create':True}
                    resp = requests.post(url,
                                         data=data,
                                         files=files,
                                        )
            else:
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
            from interlex.core import run_api
            app = run_api()
            port = port_api
        elif args['uri']:
            from interlex.uri import run_uri
            app = run_uri(echo=args['--debug'])
            port = port_uri
        elif args['curies']:
            from interlex.core import run_curies
            app = run_curies()
            port = port_curies

        app.debug = args['--debug']
        app.run(host='localhost', port=port, threaded=True)  # FIXME gunicorn

if __name__ == '__main__':
    main()
