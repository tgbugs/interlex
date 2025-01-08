#!/usr/bin/env python3
#!/usr/bin/env pypy3
""" InterLex python implementaiton

Usage:
    interlex server [uri curies alt api] [options] [<database>]
    interlex shell  [alt]  [options] [<database>]
    interlex dbsetup       [options] [<database>]
    interlex sync          [options] [<database>]
    interlex get           [options]
    interlex post ontology [options] <ontology-filename> ...
    interlex post triples  [options] (<reference-name> <triples-filename>) ...
    interlex post curies   [options] [<curies-filename>]
    interlex post curies   [options] (<curie-prefix> <iri-namespace>) ...
    interlex post resource [options] <rdf-iri>
    interlex post class    [options] <rdfs:subClassOf> <rdfs:label> [<definition:>] [<synonym:> ...]
    interlex post entity   [options] <rdf:type> <rdfs:sub*Of> <rdfs:label> [<definition:>] [<synonym:> ...]
    interlex post triple   [options] <subject> <predicate> <object>
    interlex post login    [options]
    interlex post signup   [options] <email> <orcid>
    interlex id     [options] <match-curie-or-iri> ...
    interlex label  [options] <match-label> ...
    interlex term   [options] <match-label-or-synonym> ...
    interlex search [options] <match-full-text> ...
    interlex ops password  [options]
    interlex ops resource  [options] <rdf-iri>
    interlex ops ontology  [options] <ontology-filename> ...

Commands:
    server api      start a server running the api endpoint (WARNING: OLD)
    server uri      start a server for uri.interlex.org connected to <database>
    server curies   start a server for curies.interlex.org
    server alt      start a server for alternate interlex webservices

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

    ops resource
    ops ontology
    ops password

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
    -t --test               run with config used for testing
    --production            run with config used for production

    -g --group=GROUP        the group whose data should be returned [default: api]
    -u --user=USER          alias for --group
    -n --names-group=NG     the group whose naming conventions should be used [default: api]

    -r --readable           user/uris/readable iri/curie
    -l --limit=LIMIT        limit the number of results [default: 10]

    -f --input-file=FILE    load an individual file

    -p --port=PORT          manually set the port to use in the context of the current command
    -o --local              run against local
    -c --gunicorn           run against local gunicorn
    -d --debug              enable debug mode

    --do-cdes               when running sync include the cdes

"""

import os
import base64
from pathlib import Path
from urllib.parse import urlparse
import requests
from pyontutils import clifun as clif
from pyontutils.utils import setPS1
from pyontutils.namespaces import PREFIXES as uPREFIXES
from interlex.utils import printD, log as _log

log = _log.getChild('cli')


class Options(clif.Options):
    pass


class Main(clif.Dispatcher):
    def get(self):
        raise NotImplementedError

    def shell(self):
        shell = Shell(self)
        shell('shell')

    def sync(self):
        from interlex.config import auth
        from interlex.uri import run_uri
        #from interlex.load import TripleLoaderFactory
        from interlex.sync import InterLexLoad
        from interlex.core import getScopedSession, dbUri

        kwargs = {k:auth.get(f'db-{k}') for k in ('user', 'host', 'port', 'database')}
        kwargs['dbuser'] = kwargs.pop('user')
        _session = getScopedSession(dburi=dbUri(**kwargs), query_cache_size=0)
        class db:
            session = _session

        il = InterLexLoad(db, do_cdes=self.options.do_cdes)
        il.setup()
        il.load()  # do this one yourself  WARNING high memory usage ~ 17 gigs
        self = il
        breakpoint()
        pass

    def dbsetup(self):
        from interlex.uri import run_uri
        from sqlalchemy.sql import text as sql_text
        app = run_uri()  # database init happens inside run_uri now
        db = app.extensions['sqlalchemy']
        session = db.session
        sql_verify_user = (
            'INSERT INTO user_emails (user_id, email, email_primary) VALUES (:id, :email, :email_primary);'
            'INSERT INTO user_orcid (user_id, orcid) VALUES (:id, :orcid);'
        )
        args_verify_user = dict(id=1,
                             orcid='https://orcid.org/0000-0002-7509-4801',
                             email='tgbugs@gmail.com', email_primary=True)
        with app.app_context():
            session.execute(sql_text(sql_verify_user), args_verify_user)
            session.commit()

        breakpoint()

    def post(self):
        post = Post(self)
        post('post')

    def server(self):
        server = Server(self)
        server('server')

    def ops(self):
        ops = Ops(self)
        ops('ops')


class Shell(clif.Dispatcher):
    def default(self):
        from interlex.uri import run_uri
        from interlex.core import IdentityBNode
        from interlex.load import TripleLoaderFactory
        from interlex.dump import TripleExporter
        from interlex.endpoints import Endpoints
        te = TripleExporter()
        def tripit(query_result):
            return [te.triple(*r) for r in query_result]

        app = run_uri()
        # not sure why this is needed here but not
        # runonce is called ...
        app.config['SQLALCHEMY_ECHO'] = self.options.debug
        db = app.extensions['sqlalchemy']
        endpoints = Endpoints(db)
        session = db.session
        queries = endpoints.queries

        def diffthing():
            h1, h2 = (''.join(sorted(r for s in f('tgbugs')
                                     for rp in s
                                     for r in rp))
                      for f in (queries.dumpSciGraphNt, queries.dumpAllNt))

            with open('/tmp/d1.nt', 'wt') as f1, open('/tmp/d2.nt', 'wt') as f2:
                f1.write(h1), f2.write(h2)


            os.system('diff -u /tmp/d2.nt /tmp/d1.nt > /tmp/wut.patch')

        breakpoint()

    def alt(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm.session import sessionmaker
        from interlex.alt import dbUri
        from interlex.dump import MysqlExport
        engine = create_engine(dbUri(), echo=True)  # FIXME dburi from config pls
        Session = sessionmaker()
        Session.configure(bind=engine)
        session = Session()
        queries = MysqlExport(session)
        breakpoint()


class Server(clif.Dispatcher):
    def api(self):
        from interlex.config import port_api
        from interlex.core import run_api, __file__
        app = run_api()
        port = port_api
        self._server(app, port, __file__)

    def uri(self):
        from interlex.config import port_uri
        from interlex.uri import run_uri, __file__
        app = run_uri(echo=self.options.debug)
        port = port_uri
        self._server(app, port, __file__)

    def curies(self):
        from interlex.config import port_curies
        from interlex.core import run_curies, __file__
        app = run_curies()
        port = port_curies
        self._server(app, port, __file__)

    def alt(self):
        from interlex.config import port_alt
        from interlex.alt import run_alt, __file__
        app = run_alt()
        port = port_alt
        self._server(app, port, __file__)

    def _server(self, app, port, __file__):
        port = self.options.port if self.options.port else port
        setPS1(__file__)
        app.debug = self.options.debug
        app.run(host='localhost', port=port, threaded=True)  # FIXME gunicorn


class Post(clif.Dispatcher):

    def _post(self):
        if self.options.group == self.options._defaults['--group']:
            # NOTE: there is a security consideration here
            # if someone obtains a random api key then they
            # can use it to retrieve the user who it belongs to
            # of course they would be able to do this anyway by
            # just trying multiple users, other groups don't seem
            # to worry about this, since if you lost an api key
            # you are in trouble anyway
            if self.options.user:
                group = self.options.user
            else:
                raise NotImplementedError('right now we still need a user')
        elif self.options.user:
            raise AssertionError('Only one of --user or --group may be provided.')
        else:
            group = self.options.group

        # FIXME obviously allowing the group name as the default password is unspeakably dumb
        api_key = os.environ.get('INTERLEX_API_KEY', group)  # FIXME
        headers = {'Authorization': 'Bearer ' + api_key}
        if self.options.local:
            from interlex.config import port_uri
            host = f'localhost:{port_uri}'
            scheme = 'http'
        elif self.options.gunicorn:
            from interlex.config import port_guni_uri
            host = f'localhost:{port_guni_uri}'
            scheme = 'http'
        elif self.options.port:
            host = 'localhost:' + self.options.port
            scheme = 'http'
        else:
            host = 'uri.olympiangods.org'
            scheme = 'https'

        out = scheme, host, group, headers
        if self.options.debug:
            printD(out[:-1])

        return out

    def login(self):
        from getpass import getpass
        scheme, host, group, headers = self._post()
        url = f'{scheme}://{host}/ops/ops/login'  # https duh
        # TODO ORCID on the front end
        s = requests.Session()  # use session to auto handle cookies
        group_pass = base64.b64encode((group + ':' + getpass()).encode()).decode()
        resp = s.post(url, headers={'Authorization': 'Basic ' + group_pass})
        #resp = s.post(url, data={'username': username, 'password': getpass()})
        resp.headers
        #s.cookies.set("COOKIE_NAME", "the cookie works", domain="example.com")
        log.debug(resp.text)
        log.debug(resp.headers)
        url_test = f'{scheme}://{host}/{group}/priv/settings'  # https duh
        resp_test = s.get(url_test)
        breakpoint()

    def signup(self):
        from getpass import getpass
        scheme, host, group, headers = self._post()
        username = group
        url = f'{scheme}://{host}/base/ops/user-new'  # https duh
        s = requests.Session()
        resp = s.post(url, data={
            'username': username,
            'password': getpass(),
            'email': self.options.email,
            'orcid': self.options.orcid,})

        if not resp.ok:
            from pprint import pprint
            if resp.status_code < 500:
                pprint(resp.json())

        else:
            # TODO orcid flow
            # TODO email flow
            pass

        breakpoint()
        pass

    def change_password(self):
        breakpoint()
        pass

    def curies(self):  # FIXME post should smart update? or switch to patch?
        scheme, host, group, headers = self._post()
        filename = self.options.curies_filename
        url = f'{scheme}://{host}/{group}/curies'  # https duh
        #printD(url, args)
        # FIXME /curies redirects to get...
        if filename:
            path = Path(filename).resolve()
            ext = path.suffix[1:]
            with open(path.as_posix(), 'rt') as f:
                if ext == 'json':
                    data = json.load(f)
                elif ext == 'ttl':
                    from pyontutils.core import OntResPath
                    orp = OntResPath(path)
                    graph = orp.metadata().graph
                    #graph = OntGraph().parse(f, format='ttl')
                    # TODO allow <url> a ilxr:Curies typed record
                    data = {k:str(v) for k, v in graph.namespaces()}
                elif ext == 'yml' or ext == 'yaml':
                    data = yaml.load(f)
                else:
                    raise TypeError(f"Don't know how to handle {ext} files")

            resp = requests.post(url, json=data, headers=headers)
        elif self.options.curie_prefix:
            # FIXME curie syntax validation? in the db?
            data = {cp:ip for cp, ip in zip(self.options.curie_prefix,
                                            self.options.iri_namespace)}
            resp = requests.post(url, json=data, headers=headers)

        else:
            resp = requests.post(url, json=uPREFIXES, headers=headers)

        printD(resp.status_code, resp.text)

    def ontology(self):
        scheme, host, group, headers = self._post()
        for filename in self.options.ontology_filename:
            if filename:
                url = f'{scheme}://{host}/{group}/upload'  # use smart endpoint
                mimetypes = {'ttl':'text/turtle'}  # TODO put this somewhere more practical
                path = Path(filename).resolve().absolute()
                mimetype = mimetypes.get(path.suffix[1:], None)
                form_key = 'ontology-file'  # TODO this could be used to suggest endpoints or something?
                # though, that could also be a security vuln?
                with open(path.as_posix(), 'rb') as f:
                    files = {form_key:(path.name, f, mimetype)}
                    data = {'create':True}
                    resp = requests.post(url,
                                            data=data,
                                            files=files,
                                            headers=headers)
            printD(resp.text)

    def triples(self):
        scheme, host, group, headers = self._post()
        for reference_name, filename in zip(self.options.reference_name,
                                            self.options.triples_filename):
            raise NotImplementedError

    def resource(self):
        scheme, host, group, headers = self._post()
        ontology_iri = self.options.rdf_iri
        u = urlparse(ontology_iri)
        j = {'name':ontology_iri}
        #url = f'{scheme}://{host}/{group}/ontologies/' + u.path[1:]
        url = f'{scheme}://{host}/{group}/request-ingest'
        resp = requests.post(url, json=j, headers=headers)
        printD(resp.text)

    def class_(self):
        raise NotImplementedError()

    def triple(self):
        raise NotImplementedError()

    def entity(self):
        raise NotImplementedError()


class Ops(clif.Dispatcher):

    _post = Post._post

    def resource(self):
        # direct call to load a resource for simpler debug
        if self.options.user is None:
            raise ValueError('need user')

        from interlex.uri import run_uri
        app = run_uri()

        scheme, host, group, headers = self._post()
        ontology_iri = self.options.rdf_iri

        u = urlparse(ontology_iri)
        j = {'name':ontology_iri}
        #url = f'{scheme}://{host}/{group}/ontologies/' + u.path[1:]

        filename = None
        with app.test_request_context(
                f'/{group}/ontologies/' + u.path[1:],
                method='POST',
                json=j,
                headers=headers,):
            f = app.view_functions['Ontologies.ontologies /<group>/ontologies/<filename>.<extension>']
            resp = f(group=group, filename=u.path[:1], nocel=True)

    def ontology(self):
        if self.options.user is None:
            raise ValueError('need user')

        from pyontutils.core import OntResPath
        from interlex.load import BasicDBFactory, FileFromFileFactory
        from interlex.dump import Queries

        def make_reference_name(reference_host, group, path):
            # FIXME UGH complection from Endpoints.build_reference_name
            # not compositional enough in the thinking when I was originally working on this stuff
            # that thinking came later likely inspired by the issues here
            return os.path.join(f'https://{reference_host}', group, path)

        def load_path(filesystem_path, group, auth_user, session):
            #auth = Auth(session)
            bdb = BasicDBFactory(session)
            fff = FileFromFileFactory(session)
            q = Queries(session)

            #token = auth.decrypt(auth_user)  # lol
            token = auth_user
            db = bdb(group, auth_user, token)

            reference_name = make_reference_name(q.reference_host, group, path)
            loader = fff(group, db.user, reference_name)
            loader.check(filesystem_path)  # this configures the loader to actually load the path I think? ugh this was a dark period in my python style
            expected_bound_name = None
            breakpoint()
            setup_ok = loader(expected_bound_name)  # XXX parsing happens here which is why we switched to split metadata for ontres
            out = loader.load()
            return out

        from interlex.uri import run_uri
        app = run_uri()
        db = app.extensions['sqlalchemy']

        strpaths = self.options.ontology_filename
        paths = [Path(p).resolve() for p in strpaths]
        group = auth_user = self.options.user  # ingest requests are always pinned to a user
        # TODO need to figure out how to ensure that triples from unpublished ontologies
        # don't accidentally leak out, we probably need separate endpoints to distinguish
        # requests for ingest into the general pool vs in draft workspaces
        results = []
        with app.app_context():
            with db.session() as session, session.begin():
                for path in paths:
                    res = load_path(
                        path,
                        group,
                        auth_user,
                        session,
                    )
                    results.append(res)

        return

    def password(self):
        if self.options.user is None:
            raise ValueError('need user')

        from interlex.uri import run_uri
        from sqlalchemy.sql import text as sql_text
        app = run_uri(dbonly=True)
        db = app.extensions['sqlalchemy']
        session = db.session

        from interlex import auth
        from getpass import getpass
        group = self.options.user
        a = getpass()
        b = getpass()
        if a == b:
            argon2_string = auth.hash_password(a)
        else:
            raise ValueError('passwords do not match')

        sql = ('INSERT INTO user_passwords (user_id, argon2_string) '
               'VALUES ((SELECT groups.id FROM groups '
               'JOIN users ON groups.id = users.id WHERE groups.groupname = :groupname), :argon2_string) '
               'ON CONFLICT (user_id) DO UPDATE '
               'SET argon2_string = EXCLUDED.argon2_string '
               'WHERE user_passwords.user_id = EXCLUDED.user_id')
        params = dict(groupname=group, argon2_string=argon2_string)

        with app.app_context():
            session.execute(sql_text(sql), params)
            session.commit()

        breakpoint()

def main():
    from docopt import docopt, parse_defaults
    defaults = {o.name:o.value if o.argcount else None for o in parse_defaults(__doc__)}
    args = docopt(__doc__, version='interlex 0.0.0')
    options = Options(args, defaults)
    # run all database settings through the environment
    # just have to make sure to set it before config is imported
    if options.test:
        # FIXME I think this default for this is backwards, the test database
        # should be the default if no options are provided
        from interlex.config import auth
        os.environ['INTERLEX_DATABASE'] = auth.get('test-database')
        # FIXME this is super janky probably also need to update the host
        # it also destroys the provenance for the config setting
    elif options.database:
        #os.environ.update({'INTERLEX_DATABASE':args['<database>']})
        os.environ['INTERLEX_DATABASE'] = args['<database>']#.update({'INTERLEX_DATABASE':args['<database>']})

    main = Main(options)
    if main.options.debug:
        print(main.options)

    main()

if __name__ == '__main__':
    main()
