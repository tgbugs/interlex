import os
import json
import rdflib
from functools import wraps
from flask import Flask, request, redirect, url_for, abort
from flask_restplus import Api, Resource, Namespace, fields
from flask_sqlalchemy import SQLAlchemy
from protcur.server import table_style, details_style, render_table
from pyontutils.htmlfun import atag, htmldoc
from pyontutils.core import makePrefixes, makeGraph
from pyontutils.ttlser import CustomTurtleSerializer
from interlex.exc import LoadError, NotGroup
from interlex.core import printD
from interlex.core import dbUri, permissions_sql
from interlex.core import RegexConverter, make_paths, makeParamsValues
from interlex.load import FileFromIRI, FileFromPost, TripleLoader, BasicDB
from interlex.dump import TripleExporter, Queries
from IPython import embed

def uriStructure():
    ilx_pattern = 'ilx_<regex("[0-9]{7}"):id>'
    basic = [ilx_pattern, 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']
    compare = ['own', 'diff']
    version_compare = []  # TODO? probably best to deal with the recursion in make_paths
    versioned_ids = basic + ['curies', 'uris']
    intermediate_filename = ['<filename>.<extension>', '<filename>']
    parent_child = {
        '<user>':              basic + branches + compare + ['contributions', 'upload', 'prov'],
        '<other_user>':        branches,  # no reason to access /user/own/otheruser/ilx_ since identical to /user/ilx_
        '<other_user_diff>':   basic + branches, 
        'readable':            ['<word>'],
        'versions':            ['<epoch_verstr_id>'],  # FIXME version vs versions!?
        '<epoch_verstr_id>':   versioned_ids + version_compare,
        'ontologies':          [None, '<path:ont_path>'] + intermediate_filename,  # TODO /ontologies/external/<iri> ? how? where?
        # TODO distinguish between ontology _files_ and 'ontologies' which are the import closure?
        # ya, identified vs unidentified imports, owl only supports unidentified imports
        '<path:ont_path>':     intermediate_filename,  # FIXME this would seem to only allow a single extension?
        '<filename>':          [None, 'version'],
        'version':             ['<epoch_verstr_ont>'],
        '<epoch_verstr_ont>':  ['<filename_terminal>', '<filename_terminal>.<extension>'],
        'curies':              [None, '<prefix_iri_curie>'],  # external onts can be referenced from here...
        'uris':                ['<path:uri_path>'],  # TODO no ilx_ check here as well as in database
        'own':                 ['<other_user>'],
        'diff':                ['<other_user_diff>'],

        # TODO considerations here
        #'upload':              [None],  # smart endpoint that hunts down bound names or tracks unbound sets
        'contributions':       [None, 'interlex', 'external', 'curation'],  # None implies any direct to own
        'prov':                ['identities'],
        'identities':          ['<identity>'],
    }
    node_methods = {'curies_':['GET', 'POST'],
                    'upload':['POST'],
                    #'<prefix_iri_curie>':[],  only prefixes can be updated...?
                    ilx_pattern:['GET', 'PATCH'],
                    '<word>':['GET', 'PATCH'],
                    '<filename>':['GET', 'POST'],
                    '<filename>.<extension>':['GET', 'POST'],
                    '<filename_terminal>':['GET', 'POST'],
                    '<filename_terminal>.<extension>':['GET', 'POST'],
    }
    return ilx_pattern, parent_child, node_methods

def server_uri(db=None, structure=uriStructure, dburi=dbUri(), echo=False):
    app = Flask('InterLex uri server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    #db.reflect(app=app)
    database = db
    app.url_map.converters['regex'] = RegexConverter
    ilx_pattern, parent_child, node_methods = structure()
    api = Api(app,
              version='0.0.1',
              title='InterLex URI structure API',
              description='Resolution, update, and compare for ontologies and ontology identifiers.',
              default='URIs',
              default_label='User URIs',
              doc='/docs',)
    #ns_user = api.namespace('{user}')
    #ns = api.namespace('api')
    #blueprint = Blueprint(ns.name, 'uri_api', url_prefix=ns.path)
    #api.init_app(blueprint)
    #app.register_blueprint(blueprint)

    def basic(function):
        @wraps(function)
        def basic_checks(self, *args, **kwargs):
            # TODO auth goes here
            user = kwargs['user']
            db = self.getBasicInfo(user, user)
            if db is None:
                return abort(404)
            return function(self, *args, **kwargs, db=db)

        return basic_checks

    def basic2(function):
        @wraps(function)
        def basic2_checks(self, *args, **kwargs):
            # TODO auth goes here
            user = kwargs['user']
            if 'other_user' in kwargs:
                other_user = kwargs['other_user']
            elif 'other_user_diff' in kwargs:
                other_user = kwargs['other_user_diff']

            db = self.getBasicInfo(user, user)
            db2 = self.getBasicInfo(other_user, other_user)
            if db is None:
                return abort(404)
            if db2 is None:
                return abort(404)

            db.other = db2
            return function(self, *args, **kwargs, db=db)

        return basic2_checks

    class Endpoints:
        db = database
        reference_host = None
        def __init__(self):
            self.session = self.db.session
            effi = type('FileFromIRI', (FileFromIRI,), {})
            self.FileFromIRI = effi(self.session)  # FIXME need a way to pass ref host?
            ffp = type('FileFromPost', (FileFromPost,), {})
            self.FileFromPost = ffp(self.session)
            bdb = type('BasicDB', (BasicDB,), {})
            self.BasicDB = bdb(self.session)

            self.queries = Queries(self.session)

        def getBasicInfo(self, group, user):
            try:
                return self.BasicDB(group, user)
            except NotGroup:
                return None

        def getGroupCuries(self, group, epoch_verstr=None):
            PREFIXES = self.queries.getGroupCuries(group, epoch_verstr)
            currentHost = request.headers['Host']
            PREFIXES = {cp:ip.replace('uri.interlex.org', currentHost) if app.debug else ip
                        # TODO app.debug should probably be switched out for something configurable
                        for cp, ip in PREFIXES.items()}
            #printD(PREFIXES)
            g = makeGraph(group + '_curies_helper', prefixes=PREFIXES)
            return PREFIXES, g

        def reference_name(self, user, path):
            # need this for testing, in an ideal world we read from headers
            return os.path.join(f'https://{self.reference_host}', user, path) 
        @staticmethod
        def iriFromPrefix(prefix, *ordered_prefix_sets):
            for PREFIXES in ordered_prefix_sets:
                try:
                    return PREFIXES[prefix]  # redirect(iri, 302)
                except KeyError:
                    pass
            else:
                return f'Unknown prefix {prefix}', 404

        def get_func(self, nodes):
            mapping = {
                ilx_pattern:self.ilx,
                'readable':self.readable,
                'uris':self.uris,
                'curies_':self.curies_,
                'curies':self.curies,
                'ontologies_':self.ontologies_,
                'ontologies':self.ontologies,
                'version':self.ontologies_version,  # FIXME collision prone?
                'contributions_':self.contributions_,
                'contributions':self.contributions,
                'upload':self.upload,
                'prov':self.prov,
            }
            for node in nodes[::-1]:
                if node in mapping:
                    return mapping[node]
            else:
                raise KeyError(f'could not find any value for {nodes}')

        # TODO PATCH
        @basic
        def ilx(self, user, id, db=None):
            # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}
            # printD(tc.red('AAAAA'), user, id)

            if user != 'base' and user != 'latest':
                #args = dict(id=id, user=user)
                #sql = ('SELECT ou.username, t.id FROM interlex_ids as t, org_user_view as ou '
                       #'WHERE t.id = :id AND ou.username = :user')
                #sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       #'SELECT groups AS g JOIN users AS u ON g.id = u.id WHERE g.groupname = :user UNION '
                       #'SELECT groups AS g JOIN orgs AS o ON g.id = o.id WHERE g.groupname = :user')
                # TODO it seems WAY more efficient to add a 'verfied' column to groups
                #sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       # doesn't work because doesn't fail on no id
                       #"SELECT id::text FROM groups WHERE own_role < 'pending' AND groupname = :user")
                #sql = ('SELECT t.id, g.id FROM interlex_ids AS t, groups AS g '
                       #'WHERE t.id = :id AND g.validated = TRUE AND g.groupname = :user')

                #sql = ('SELECT t.id, g.id FROM interlex_ids AS t, groups AS g '
                       #"WHERE t.id = :id AND g.own_role < 'pending' AND g.groupname = :user")
                sql = 'SELECT id FROM interlex_ids WHERE id = :id'
                try:
                    res = next(self.session.execute(sql, dict(id=id)))
                    id = res.id
                    #printD(id, db.group_id)
                except StopIteration:
                    return abort(404)

            #printD(resp)
            PREFIXES, g = self.getGroupCuries(user)
            resp = self.queries.getById(id, user)
            te = TripleExporter()
            _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

            cts = CustomTurtleSerializer(g.g)
            gsortkey = cts._globalSortKey
            psortkey = lambda p: cts.predicate_rank[p]
            def sortkey(triple):
                s, p, o = triple
                return gsortkey(s), psortkey(p), gsortkey(o)

            trips = ((atag(e, g.qname(e))
                      if isinstance(e, rdflib.URIRef) and e.startswith('http')
                      else str(e)
                      for e in t)
                     for t in sorted(g.g, key=sortkey))

            # TODO list users with variants from base and/org curated
            # we need an 'uncurated not latest' or do we?
            return htmldoc(render_table(trips, 'subject', 'predicate', 'object'),
                           title=f'ilx.{user}:ilx_{id}',
                           styles=(table_style,))

        # TODO PATCH only admin can change the community readable mappings just like community curies
        @basic
        def readable(self, user, word, db=None):
            return request.path

        @basic
        def contributions_(self, user, db=None):
            # without at type lands at the additions and deletions page
            return 'TODO identity for user contribs directly to interlex'

        @basic
        def contributions(self, *args, **kwargs):
            return 'TODO slicing on contribs ? or use versions?'

        # TODO POST ?private if private PUT (to change mapping) PATCH like readable 
        @basic
        def uris(self, user, uri_path, db=None):
            # owl:Class, owl:*Property
            # owl:Ontology
            # /<user>/ontologies/obo/uberon.owl << this way
            # /<user>/uris/obo/uberon.owl << no mapping to ontologies here
            return request.path

        # TODO POST PUT PATCH
        @basic
        def curies_(self, user, db=None):
            # TODO auth
            PREFIXES, g = self.getGroupCuries(user)
            if request.method == 'POST':
                # TODO diff against existing
                if request.json is None:
                    return 'No curies were sent\n', 400
                values = tuple((cp, ip) for cp, ip in request.json.items())
                # FIXME impl in load pls
                values_template, params = makeParamsValues(values,
                                                           constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
                params['group'] = user
                sql = 'INSERT INTO curies (group_id, curie_prefix, iri_prefix) VALUES ' + values_template
                try:
                    resp = self.session.execute(sql, params)
                    self.session.commit()
                    return 'ok\n', 200
                except sa.exc.IntegrityError as e:
                    self.session.rollback()
                    return f'Curie exists\n{e.orig.pgerror}', 409  # conflict
                    return f'Curie exists\n{e.args[0]}', 409  # conflict


            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        # TODO POST PATCH PUT
        @basic
        def curies(self, user, prefix_iri_curie, db=None):
            PREFIXES, g = self.getGroupCuries(user)
            qname, expand = g.qname, g.expand
            if prefix_iri_curie.startswith('http') or prefix_iri_curie.startswith('file'):  # TODO decide about urlencoding
                iri = prefix_iri_curie
                curie = qname(iri)
                return curie
            elif ':' in prefix_iri_curie:
                curie = prefix_iri_curie
                try:
                    iri = expand(curie)
                except KeyError:
                    prefix, *_ = curie.split(':')
                    return f'Unknown prefix {prefix}', 404
                if 'local' in request.args and request.args['local'].lower() == 'true':
                    # FIXME super inefficient even with index?
                    sql = ('SELECT ilx_id FROM existing_iris AS e WHERE e.iri = :iri '
                           'AND (e.group_id = :group_id OR e.group_id = 1)')
                    try:
                        resp = next(self.session.execute(sql, dict(iri=iri, group_id=db.group_id)))
                        return redirect(url_for(f'Endpoints.ilx /<user>/{ilx_pattern}',
                                                user=user, id=resp.ilx_id), code=302)
                    except StopIteration:
                        return abort(404)
                        pass

                    #return redirect('https://curies.interlex.org/' + curie, code=302)  # TODO abstract
                return redirect(iri, code=302)
            else:
                prefix = prefix_iri_curie
                if prefix not in PREFIXES:
                    # TODO query for user failover preferences
                    bPREFIXES, g = self.getGroupCuries('base')  # FIXME vs curated
                    ordered_prefix_sets = bPREFIXES,
                else:
                    ordered_prefix_sets = PREFIXES,

                return self.iriFromPrefix(prefix, *ordered_prefix_sets)

        @basic
        def upload(self, user, db=None):
            """ Expects files """
            # only POST
            # TODO auth

            # TODO load stats etc
            try:
                loader = self.FileFromPost(user, user, self.reference_host)
            except NotGroup:
                return abort(404)

            header = request.headers
            create = request.form.get('create', False)
            if isinstance(create, str):
                create = create.lower()
                if create == 'true':
                    create = True
                else:
                    create = False
                
            names = []
            for name, file in request.files.items():
                setup_ok = loader(file, header, create)
                if setup_ok is not None:
                    return setup_ok
                names.append({'reference_name':loader.reference_name,
                              'bound_name':loader.Loader.bound_name})  # sigh json
                load_ok = loader.load()
                if load_ok is not None:
                    msg, code = load_ok
                    data = {'error':msg, 'names':names}
                    sigh = json.dumps(data)
                    return sigh, code, {'Content-Type':'application/json'}

            return json.dumps(names)

        # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
        # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
        # TODO HEAD -> return owl:Ontology section
        @basic
        def ontologies_(self, user, db=None):
            return json.dumps('your list sir')

        @basic
        def ontologies(self, user, filename, extension=None, ont_path='', db=None):
            # on POST for new file check to make sure that that the ontology iri matches the post endpoint
            # response needs to include warnings about any parts of the file that could not be lifted to interlex
            # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
            # we should be able to track file 'renames' without too much trouble
            printD(user, filename, extension, ont_path)
            group = user  #  FIXME
            user = 'tgbugs'  # FIXME from api token decryption
            extension = '.' + extension if extension else ''
            match_path = os.path.join(ont_path, filename + extension)
            path = os.path.join('ontologies', match_path)  # FIXME get middle from request?
            #request_reference_name = request.headers['']
            reference_name = self.reference_name(group, path)
            try:
                loader = self.FileFromIRI(group, user, reference_name, self.reference_host)
            except NotGroup:
                return abort(404)
            printD(request.headers)
            if request.method == 'HEAD':
                # TODO return bound_name + metadata
                return 'HEAD TODO\n'
            if request.method == 'POST':
                existing = False  # TODO check if the file already exists
                # check what is being posted
                #embed()
                #if requests.args:
                    #printD(request.args)
                #elif request.json is not None:  # jsonld u r no fun
                    #printD(request.json)
                    #{'iri':'http://purl.obolibrary.org/obo/uberon.owl'}
                #elif request.data:
                    #printD(request.data)

                if not existing:
                    if request.files:
                        # TODO retrieve and if existing-iri make sure stuff matches
                        printD(request.files)
                    if request.json is not None:  # jsonld u r no fun
                        printD(request.json)
                        if 'name' in request.json:
                            name = request.json['name']  # FIXME not quite right?
                            if 'bound-name' in request.json:
                                expected_bound_name = request.json['bound-name']
                            else:
                                expected_bound_name = None

                            # FIXME this should be handled elsewhere for user
                            if match_path not in name and match_path not in expected_bound_name:
                                return f'No common name between {expected_bound_name} and {reference_name}', 400

                            setup_ok = loader(name, expected_bound_name)
                            if setup_ok is not None:
                                return setup_ok

                            out = loader.load()

                            # TODO get actual user from the api key
                            # out = f(user, filepath, ontology_iri, new=True)
                            #embed()
                            printD('should be done running?')

                            # TODO return loading stats etc
                            return out

                    #if 'external-iri' in request.args:
                        # cron jobs and webhooks... for the future on existing iris
                        # frankly we can just peek
                        #external_iri = request.args['external-iri']
                    # elif 'crawl' in request.args['']


                return 'POST TODO\n'

            # much easier to implement this way than current attempts
            return request.path + '\n'

        @basic
        def ontologies_version(self, user, filename, epoch_verstr_ont,
                               filename_terminal, extension=None, ont_path='', db=None):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'

        @basic
        def prov(self, *args, **kwargs):
            """ Return all the identities that an org/user has uploaded 
                Show users their personal uploads and then their groups.
                Show groups all uploads with the user who did it
            """
            # in html
            # reference_name, bound_name, identity, date, triple_count, parts
            # if org: uploading_user
            # if user: contribs per group
            return 'TODO\n'


    class Versions(Endpoints):
        # TODO own/diff here could make it much easier to view changes
        @basic
        def ilx(self, user, epoch_verstr_id, id, db=None):
            # TODO epoch and reengineer how ilx is implemented
            # so that queries can be conducted at a point in time
            # sigh dataomic
            # or just give up on the reuseabilty of the query structure?
            return super().ilx(user, id)

        @basic
        def readable(self, user, epoch_verstr_id, word, db=None):
            return request.path

        @basic
        def uris(self, user, epoch_verstr_id, uri_path, db=None):
            return request.path

        @basic
        def curies_(self, user, epoch_verstr_id, db=None):
            PREFIXES, g = self.getGroupCuries(user, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        @basic
        def curies(self, user, epoch_verstr_id, prefix_iri_curie, db=None):
            return request.path


    class Own(Endpoints):
        @basic2
        def uris(self, user, other_user, uri_path, db=None):
            return request.path

        @basic2
        def curies_(self, user, other_user, db=None):
            PREFIXES, g = self.getGroupCuries(user)
            otherPREFIXES, g = self.getGroupCuries(other_user)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        @basic2
        def curies(self, user, other_user, prefix_iri_curie, db=None):
            return request.path

        @basic2
        def ontologies(self, user, other_user, filename, extension=None, ont_path='', db=None):
            return request.path

        @basic2
        def ontologies_version(self, user, other_user, filename, epoch_verstr_ont,
                               filename_terminal, extension=None, ont_path='', db=None):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'


    class OwnVersions(Own, Versions):
        @basic2
        def ilx(self, user, other_user, epoch_verstr_id, id, db=None):
            return request.path

        @basic2
        def readable(self, user, other_user, epoch_verstr_id, word, db=None):
            return request.path

        @basic2
        def uris(self, user, other_user, epoch_verstr_id, uri_path, db=None):
            return request.path

        @basic2
        def curies_(self, user, other_user, epoch_verstr_id, db=None):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        @basic2
        def curies(self, user, other_user, epoch_verstr_id, prefix_iri_curie, db=None):
            return request.path


    class Diff(Endpoints):
        @basic2
        def ilx(self, user, other_user_diff, id, db=None):
            return request.path
        @basic2
        def readable(self, user, other_user_diff, word, db=None):
            return request.path
        @basic2
        def uris(self, user, other_user_diff, uri_path, db=None):
            return request.path

        @basic2
        def curies_(self, user, other_user_diff, db=None):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user_diff)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        @basic2
        def curies(self, user, other_user_diff, prefix_iri_curie, db=None):
            return request.path
        @basic2
        def ontologies(self, user, other_user_diff, filename, extension=None, ont_path='', db=None):
            return request.path
        @basic2
        def ontologies_version(self, user, other_user_diff, filename,
                               epoch_verstr_ont, filename_terminal, extension=None, ont_path='', db=None):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'


    class DiffVersions(Diff, Versions):
        @basic2
        def ilx(self, user, other_user_diff, epoch_verstr_id, id):
            return request.path
        @basic2
        def readable(self, user, other_user_diff, epoch_verstr_id, word):
            return request.path
        @basic2
        def uris(self, user, other_user_diff, epoch_verstr_id, uri_path):
            return request.path

        @basic2
        def curies_(self, user, other_user_diff, epoch_verstr_id):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user_diff, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        @basic2
        def curies(self, user, other_user_diff, epoch_verstr_id, prefix_iri_curie):
            return request.path


    class VersionsOwn(Endpoints):
        pass  # TODO


    class VersionsDiff(Endpoints):
        pass  # TODO

    @app.before_first_request
    def runonce():
        # FIXME this is a reasonably safe way to make sure that we have a db connection
        Endpoints.reference_host = next(db.session.execute('SELECT reference_host()'))[0]
        db.engine.echo = echo
        printD(Endpoints.reference_host)

    endpoints = Endpoints()
    versions = Versions()
    own = Own()
    ownversions = OwnVersions()
    diff = Diff()
    diffversions = DiffVersions()

    doc_namespaces = {
        # NOTE creation order here translates to the swagger docs, it also affects sorts first
        'curies':api.namespace('Curies', 'User curies', '/'),
        'ontologies':api.namespace('Ontologies', 'URIs for serializations of subsets of InterLex, virtualized files', '/'),
        'contributions':api.namespace('Contributions', 'User contributions', '/'),
        'versions':api.namespace('Versions', 'View data associated with any ilx: URI at a given timepoint or version', '/'),
        'diff':api.namespace('Diff', 'Compare users', '/'),
        'own':api.namespace('Own', 'See one user\'s view of another user\'s personalized IRIs', '/'),
    }
    extra = {name + '_':ns for name, ns in doc_namespaces.items() if name in ('curies', 'contributions', 'ontologies')}
    doc_namespaces = {**extra, **doc_namespaces}  # make sure the extras come first for priority ordering

    routes = list(make_paths(parent_child))
    for route in routes:
        nodes = route.split('/')
        if 'diff' in nodes:
            if 'versions' in nodes:
                inst = diffversions
            else:
                inst = diff
        elif 'own' in nodes:
            if 'versions' in nodes:
                inst = ownversions
            else:
                inst = own
        elif 'versions' in nodes:
            inst = versions
        else:
            inst = endpoints

        if nodes[-1] == '':
            if 'curies' in nodes:
                nodes = tuple(nodes[:-2]) + ('curies_',)
                #printD('terminal nodes', nodes)
            if 'ontologies' in nodes:
                nodes = tuple(nodes[:-2]) + ('ontologies_',)
                #printD('terminal nodes', nodes)
            if 'contributions' in nodes:
                nodes = tuple(nodes[:-2]) + ('contributions_',)
                #printD('terminal nodes', nodes)

        function = inst.get_func(nodes)
        name = inst.__class__.__name__ + '.' + function.__name__ + ' ' + route
        if 'diff' not in nodes and 'version' not in nodes and 'versions' not in nodes and nodes[-1] in node_methods:
            methods = node_methods[nodes[-1]]
        else:
            methods = ['GET', 'HEAD']
        app.add_url_rule(route, name, function, methods=methods)
        cname = inst.__class__.__name__ + '_' + function.__name__
        #model = api.model('Model', {})#{'thing': fields.String})
        #print(function)
        def __init__(self, *args, **kwargs):
            super(self.__class__, self).__init__(*args, **kwargs)
            self.__class__.__bases__[-1].__init__(self)  # FIXME doubles instances...
            #embed()

        newclass = type(cname,
                        (
                            Resource,
                            #inst.__class__,
                        ),
                        {#'__init__': __init__,
                         #**{m.lower():api.route(ns.path + route, endpoint=ns.name + name)(getattr(inst.__class__, function.__name__))
                         #**{m.lower():ns.doc(params={'a':'b'})(getattr(inst.__class__, function.__name__))
                         **{m.lower():function
                            for m in methods
                            if m != 'HEAD'  # skip head since it is implied?
                           }})
        #print(newclass)
        #print(ns.name, route)
        for name, ns in list(doc_namespaces.items())[::-1]:  # reversted so versions diff etc get their endpoints  # also ICK :/
            if name in nodes:
                ns.route(route)(newclass)
                break
        else:
            api.route(route)(newclass)

        printD(route, methods)

    #for k, v in app.view_functions.items():
        #printD(k, v)

    return app

def run_uri(echo=False):
    return server_uri(db=SQLAlchemy(), echo=echo)
