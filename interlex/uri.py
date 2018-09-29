from collections import OrderedDict as od
from flask import Flask
from flask_restplus import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from interlex import config
from interlex.core import dbUri, mqUri, diffCuries
from interlex.core import RegexConverter, make_paths, makeParamsValues
from interlex.utils import printD, makeSimpleLogger
from interlex.tasks import cel
from interlex.config import ilx_pattern

log = makeSimpleLogger('setup')


def uriStructure():
    basic = [ilx_pattern, 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']  # 'prov'
    compare = ['own', 'diff']
    version_compare = []  # TODO? probably best to deal with the recursion in make_paths
    versioned_ids = basic + ['curies', 'uris']
    intermediate_filename = ['<filename>.<extension>', '<filename>']
    parent_child = {
        '<user>':              basic + ['lexical'] + branches + compare + ['contributions', 'upload', 'prov'],
        '<other_user>':        branches,  # no reason to access /user/own/otheruser/ilx_ since identical to /user/ilx_
        '<other_user_diff>':   basic + ['lexical'] + branches,
        'lexical':             ['<label>'],
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


def add_leafbranches(nodes):
    if nodes[-1] == '':
        prefix = tuple(nodes[:-2])
        if 'curies' in nodes:
            nodes = prefix + ('curies_',)
        if nodes == ['', '<user>', 'ontologies', '']:  # only at depth 2
            nodes = prefix + ('ontologies_',)
        if 'contributions' in nodes:
            nodes = prefix + ('contributions_',)
        else:
            log.debug(f'unhandled leafbranch {nodes}')

    return nodes


def build_endpoints(db):
    from interlex.endpoints import Endpoints, Versions, Own, OwnVersions, Diff, DiffVersions

    endpoints = Endpoints(db)
    versions = Versions(db)
    own = Own(db)
    ownversions = OwnVersions(db)
    diff = Diff(db)
    diffversions = DiffVersions(db)

    # build the route -> endpoint mapping function

    dispatch = {'diff': {'versions': {'': diffversions},
                         '': diff},
                'own': {'versions': {'': ownversions},
                        '': own},
                'versions': {'': versions},
                '': endpoints}

    def route_endpoint_mapper(nodes, dispatch_dict=dispatch):
        for path_element, subdispatch in dispatch_dict.items():
            if path_element == '':
                return subdispatch
            elif path_element in nodes:
                return route_endpoint_mapper(nodes, subdispatch)

    return route_endpoint_mapper, endpoints


def route_methods(nodes, node_methods):
    if 'diff' not in nodes and 'version' not in nodes and 'versions' not in nodes and nodes[-1] in node_methods:
        methods = node_methods[nodes[-1]]
    else:
        methods = ['GET', 'HEAD']

    return methods


def build_api(app):
    # swagger dosc setup
    api = Api(app,  # NOTE if the docs fail to load, make sure X-Forwarded-Proto is set in nginx
              version='0.0.1',
              title='InterLex URI structure API',
              description='Resolution, update, and compare for ontologies and ontology identifiers.',
              default='URIs',
              default_label='User URIs',
              doc='/docs',)

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
    return api, doc_namespaces


def api_rule_maker(api, doc_namespaces):
    def add_api_rule(route, name, function, methods, nodes):
        # api docs class creation for introspection
        apiclass = type(name, (Resource,), {m.lower():function
                                            for m in methods
                                            if m != 'HEAD'})
        for name, ns in list(doc_namespaces.items())[::-1]:  # reversed so versions diff etc get their endpoints  # also ICK :/
            if name in nodes:
                ns.route(route)(apiclass)
                break
        else:
            api.route(route)(apiclass)

    return add_api_rule


def setup_runonce(app, endpoints, echo):
    from interlex.load import BasicDBFactory
    @app.before_first_request
    def runonce():
        # FIXME this is a reasonably safe way to make sure that we have a db connection
        endpoints.db.engine.echo = echo
        endpoints.__class__.reference_host = next(endpoints.session.execute('SELECT reference_host()'))[0]
        log.info(f'reference_host = {endpoints.reference_host}')
        for group in endpoints.queries.getBuiltinGroups():  # FIXME inelegant way around own_role < 'pending'
            BasicDBFactory._cache_groups[group.groupname] = group.id, group.own_role


def server_uri(db=None, mq=None, structure=uriStructure, echo=False):
    # app setup and database binding
    app = Flask('InterLex uri server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dbUri()  # use os.environ.update
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['CELERY_BROKER_URL'] = config.broker_url
    app.config['CELERY_RESULT_BACKEND'] = config.broker_backend
    app.config['CELERY_ACCEPT_CONTENT'] = config.accept_content
    app.url_map.converters['regex'] = RegexConverter

    db.init_app(app)
    mq.init_app(app)

    route_endpoint_mapper, endpoints = build_endpoints(db)   # endpoints
    setup_runonce(app, endpoints, echo)                      # runonce

    api, doc_namespaces = build_api(app)                     # api init
    add_api_rule = api_rule_maker(api, doc_namespaces)       # api binding

    parent_child, node_methods = structure()                 # uri path nodes
    routes = list(make_paths(parent_child))                  # routes

    @app.route('/api/job/<jobid>')
    def route_api_job(jobid):
        # FIXME prevent garbage?
        task = mq.AsyncResult(jobid)
        printD('s', task.status)
        printD('i', task.info)
        printD('r', task.result)
        return task.status

    for route in routes:
        nodes = route.split('/')
        nodes = add_leafbranches(nodes)
        endpoint_type = route_endpoint_mapper(nodes)
        function = endpoint_type.get_func(nodes)
        methods = route_methods(nodes, node_methods)

        # route -> endpoint function
        name = endpoint_type.__class__.__name__ + '.' + function.__name__ + ' ' + route
        app.add_url_rule(route, name, function, methods=methods)

        # route -> api
        apiname = endpoint_type.__class__.__name__ + '_' + function.__name__
        add_api_rule(route, apiname, function, methods, nodes)

    #for k, v in app.view_functions.items():
        #printD(k, v)

    return app

def run_uri(echo=False):
    return server_uri(db=SQLAlchemy(), mq=cel, echo=echo)
