from flask import Flask
from flask_restplus import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from interlex.exc import LoadError, NotGroup
from interlex.core import printD
from interlex.core import dbUri, diffCuries
from interlex.core import RegexConverter, make_paths, makeParamsValues
from interlex.load import BasicDBFactory
from interlex.config import ilx_pattern


def uriStructure():
    basic = [ilx_pattern, 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']  # 'prov'
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
        'ontologies':          [2, '<path:ont_path>'] + intermediate_filename,  # TODO /ontologies/external/<iri> ? how? where?
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
        # TODO get ontologies by qualifier and by data subgraph? also allow direct access via and identities endpoint since we have those?
        #'upload':              [None],  # smart endpoint that hunts down bound names or tracks unbound sets
        'contributions':       [None, 'interlex', 'external', 'curation'],  # None implies any direct to own
        'prov':                ['identities'],
        'identities':          ['<identity>'],
        'qualifiers':          ['<qualifier>'],
    }
    node_methods = {'curies_':['GET', 'POST'],
                    'upload':['HEAD', 'POST'],
                    #'<prefix_iri_curie>':[],  only prefixes can be updated...?
                    ilx_pattern:['GET', 'PATCH'],
                    '<word>':['GET', 'PATCH'],
                    '<filename>':['GET', 'POST'],
                    '<filename>.<extension>':['GET', 'POST'],
                    '<filename_terminal>':['GET', 'POST'],
                    '<filename_terminal>.<extension>':['GET', 'POST'],
    }
    return parent_child, node_methods


def server_uri(db=None, structure=uriStructure, dburi=dbUri(), echo=False):
    from interlex.endpoints import Endpoints, Versions, Own, OwnVersions, Diff, DiffVersions
    app = Flask('InterLex uri server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    #db.reflect(app=app)
    database = db
    app.url_map.converters['regex'] = RegexConverter
    parent_child, node_methods = structure()
    api = Api(app,  # NOTE if the docs fail to load, make sure X-Forwarded-Proto is set in nginx
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

    endpoints = Endpoints(db)
    versions = Versions(db)
    own = Own(db)
    ownversions = OwnVersions(db)
    diff = Diff(db)
    diffversions = DiffVersions(db)

    @app.before_first_request
    def runonce():
        # FIXME this is a reasonably safe way to make sure that we have a db connection
        Endpoints.reference_host = next(db.session.execute('SELECT reference_host()'))[0]
        db.engine.echo = echo
        printD(endpoints.reference_host)
        for group in endpoints.queries.getBuiltinGroups():  # FIXME inelegant way around own_role < 'pending'
            BasicDBFactory._cache_groups[group.groupname] = group.id, group.own_role

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
            #print(nodes)
            if 'curies' in nodes:
                nodes = tuple(nodes[:-2]) + ('curies_',)
                #printD('terminal nodes', nodes)
            if nodes == ['', '<user>', 'ontologies', '']:  # only at depth 2
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

        #printD()
        #print('\t', route)
        #print('\t', name)
        #print('\t', function)
        app.add_url_rule(route, name, function, methods=methods)
        cname = inst.__class__.__name__ + '_' + function.__name__
        #model = api.model('Model', {})#{'thing': fields.String})
        #print(function)
        #def __init__(self, *args, **kwargs):
            #super(self.__class__, self).__init__(*args, **kwargs)
            #self.__class__.__bases__[-1].__init__(self)  # FIXME doubles instances...

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

        #printD(route, methods)

    #for k, v in app.view_functions.items():
        #printD(k, v)

    return app

def run_uri(echo=False, database=None):
    if database:
        dburi = dbUri(database=database)
    else:
        dburi = dbUri()

    return server_uri(db=SQLAlchemy(), echo=echo, dburi=dburi)
