#!/usr/bin/env python3.6
#!/usr/bin/env pypy3
""" InterLex python implementaiton

Usage:
    interlex api [options]
    interlex uri [options]     [<database>]
    interlex curies [options]
    interlex alt [options]
    interlex dbsetup [options] [<database>]
    interlex debug [options]   [<database>]
    interlex sync [options]
    interlex post ontology [options] <ontology-filename> ...
    interlex post triples  [options] (<reference-name> <triples-filename>) ...
    interlex post curies   [options] [<curies-filename>]
    interlex post resource [options] <rdf-iri>
    interlex post class  [options] <rdfs:subClassOf> <rdfs:label> [<definition:>] [<synonym:> ...]
    interlex post entity [options] <rdf:type> <rdfs:sub*Of> <rdfs:label> [<definition:>] [<synonym:> ...]
    interlex post triple [options] <subject> <predicate> <object>
    interlex id     [options] <match-curie-or-iri> ...
    interlex label  [options] <match-label> ...
    interlex term   [options] <match-label-or-synonym> ...
    interlex search [options] <match-full-text> ...

Commands:
    api             start a server running the api endpoint (WARNING: OLD)
    uri             start a server for uri.interlex.org connected to <database>
    curies          start a server for curies.interlex.org
    alt             start a server for alternate interlex webservices

    dbsetup         step through creation of a user (currently tgbugs)
    sync            drop into a debug repl with a database connection
    sync            run sync with the old mysql database

    post ontology   post an ontology file by uploading directly to interlex
    post triples    post an file with triples, but no ontology header to a specific reference name (want?)
    post curies     post curies for a given user
    post resource   post a link to an rdf 'file' for interlex to retrieve
    post class
    post entity
    post triple

    id              get the interlex record for a curie or iri
    label           get all interlex records where the rdfs:label matches a string
    term            get all interlex records where any label or synonym matches a string
    search          get all interlex records where the search index returns a match for a string

Examples:
    export INTERLEX_API_KEY=$(cat path/to/my/api/key)
    interlex post triple ILX:1234567 rdfs:label "not-a-term"
    interlex post triple ILX:1234567 definition: "A meaningless example term"
    interlex post entity -r ilxtr:myNewProperty owl:AnnotationProperty _ 'my annotation property' 'use for stuff'
    interlex post class -r ilxtr:myNewClass ilxtr:myExistingClass 'new class' 'some new thing'
    interlex id -u base -n tgbugs ilxtr:brain

Options:
    -g --group=GROUP        the group whose data should be returned [default: api]
    -u --user=USER          alias for --group
    -n --names-group=NG     the group whose naming conventions should be used [default: api]

    -r --readable           user/uris/readable iri/curie
    -l --limit=LIMIT        limit the number of results [default: 10]

    -f --input-file=FILE    load an individual file

    -p --port=PORT          manually set the port to use in the context of the current command
    -o --local              run against local
    -n --gunicorn           run against local gunicorn
    -d --debug              enable debug mode

"""

import os
from pathlib import Path
from urllib.parse import urlparse
import requests
from pyontutils.utils import setPS1
from pyontutils.core import PREFIXES as uPREFIXES
from interlex.core import printD, InterLexLoad
from IPython import embed

port_api = 8500
port_uri = 8505
port_curies = 8510
port_alt = 8515

def main():
    from docopt import docopt, parse_defaults
    defaults = {o.name:o.value if o.argcount else None for o in parse_defaults(__doc__)}
    args = docopt(__doc__, version='interlex 0.0.0')
    print(args)
    if args['post']:
        if args['--group'] == defaults['--group']:
            # NOTE: there is a security consideration here
            # if someone obtains a random api key then they
            # can use it to retrieve the user who it belongs to
            # of course they would be able to do this anyway by
            # just trying multiple users, other groups don't seem
            # to worry about this, since if you lost an api key
            # you are in trouble anyway
            if args['--user']:
                group = args['--user']
            else:
                raise NotImplemented('right now we still need a user')
        elif args['--user']:
            raise AssertionError('Only one of --user or --group may be provided.')
        else:
            group = args['--group']

        # FIXME obviously allowing the group name as the default password is unspeakably dump
        api_key = os.environ.get('INTERLEX_API_KEY', group)  # FIXME
        headers = {'Authorization': 'Bearer ' + api_key}
        if args['--local']:
            host = f'localhost:{port_uri}'
            scheme = 'http'
        elif args['--gunicorn']:
            host = f'localhost:8606'
            scheme = 'http'
        elif args['--port']:
            host = 'localhost:' + args['--port']
            scheme = 'http'
        else:
            host = 'uri.olympiangods.org'
            scheme = 'https'

        if args['curies']:  # FIXME post should smart update? or switch to patch?
            filename = args['<curies-filename>']
            url = f'{scheme}://{host}/{group}/curies/'  # https duh
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

                resp = requests.post(url, json=data, headers=headers)
            else:
                resp = requests.post(url, json=uPREFIXES, headers=headers)

            printD(resp.status_code, resp.text)

        elif args['ontology']:
            for filename in args['<ontology-filename>']:
                if filename:
                    url = f'{scheme}://{host}/{group}/upload'  # use smart endpoint
                    mimetypes = {'ttl':'text/turtle'}  # TODO put this somewhere more practical
                    path = Path(filename).resolve().absolute()
                    mimetype = mimetypes.get(path.suffix[1:], None)
                    with open(path.as_posix(), 'rb') as f:
                        files = {'file':(path.name, f, mimetype)}
                        data = {'create':True}
                        resp = requests.post(url,
                                             data=data,
                                             files=files,
                                             headers=headers)
                printD(resp.text)

        elif args['triples']:
            for reference_name, filename in zip(args['<reference-name>'], args['<triples-filename>']):
                raise NotImplemented

        elif args['resource']:
            ontology_iri = args['<rdf-iri>']
            u = urlparse(ontology_iri)
            j = {'name':ontology_iri}
            url = f'{scheme}://{host}/{group}/ontologies/' + u.path[1:]
            resp = requests.post(url, json=j, headers=headers)
            printD(resp.text)


    elif args['debug']:
        from flask_sqlalchemy import SQLAlchemy
        from interlex.uri import run_uri
        from interlex.load import TripleLoader
        from interlex.dump import Queries as _Q
        app = run_uri(database=args['database'])
        db = SQLAlchemy(app)
        session = db.session
        queries = _Q(session)
        embed()

    elif args['sync']:
        from flask_sqlalchemy import SQLAlchemy
        from interlex.uri import run_uri
        from interlex.load import TripleLoader
        app = run_uri()
        db = SQLAlchemy(app)
        ltl = type('TripleLoader', (TripleLoader,), {})
        Loader = ltl(db.session)
        il = InterLexLoad(Loader, do_cdes=False)
        il.setup()
        # il.load()  # do this one yourself
        self = il
        embed()

    elif args['dbsetup']:
        from flask_sqlalchemy import SQLAlchemy
        from interlex.uri import run_uri
        app = run_uri(database=args['<database>'])
        db = SQLAlchemy(app)
        session = db.session
        sql_verify_user = (
            'INSERT INTO user_emails (user_id, email, email_primary) VALUES (:id, :email, :email_primary);'
            'INSERT INTO user_orcid (user_id, orcid) VALUES (:id, :orcid);'
        )
        args_verify_user = dict(id=1,
                             orcid='https://orcid.org/0000-0002-7509-4801',
                             email='tgbugs@gmail.com', email_primary=True)
        session.execute(sql_verify_user, args_verify_user)
        session.commit()
        embed()

    else:
        if args['api']:
            from interlex.core import run_api, __file__
            app = run_api()
            port = port_api
        elif args['uri']:
            from interlex.uri import run_uri, __file__
            app = run_uri(echo=args['--debug'], database=args['<database>'])
            port = port_uri
        elif args['curies']:
            from interlex.core import run_curies, __file__
            app = run_curies()
            port = port_curies
        elif args['alt']:
            from interlex.alt import run_alt, __file__
            app = run_alt()
            port = port_alt

        port = args['--port'] if args['--port'] else port
        setPS1(__file__)
        app.debug = args['--debug']
        app.run(host='localhost', port=port, threaded=True)  # FIXME gunicorn

if __name__ == '__main__':
    main()
