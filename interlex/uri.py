from pathlib import Path
from collections import OrderedDict as od
from flask import Flask, url_for
from flask_restx import Api, Resource, apidoc
from flask_restx.api import SwaggerView
from flask_sqlalchemy import SQLAlchemy
from interlex import config
from interlex.core import dbUri, mqUri, diffCuries
from interlex.core import RegexConverter, make_paths, makeParamsValues
from interlex.utils import printD, makeSimpleLogger
from interlex.tasks import cel
from interlex.config import ilx_pattern

log = makeSimpleLogger('setup')


class DocsApi(Api):
    """ Customized restx Api to serve all swagger content from /docs/ """

    def _register_apidoc(self, app: Flask) -> None:
        conf = app.extensions.setdefault('restx', {})
        custom_apidoc = apidoc.Apidoc('restx_doc', 'flask_restx.apidoc',
                                        template_folder='templates',
                                        static_folder=(Path(apidoc.__file__).parent / 'static').as_posix(),
                                        static_url_path='/docs/swaggerui')

        @custom_apidoc.add_app_template_global
        def swagger_static(filename: str) -> str:
            return url_for('restx_doc.static', filename=filename)

        if not conf.get('apidoc_registered', False):
            app.register_blueprint(custom_apidoc)
        conf['apidoc_registered'] = True

    def _register_specs(self, app: Flask) -> None:
        if self._add_specs:
            endpoint = str('specs')
            self._register_view(
                app,
                SwaggerView,
                self.default_namespace,
                '/docs/swagger.json',
                endpoint=endpoint,
                resource_class_args=(self, )
            )
            self.endpoints.add(endpoint)


def uriStructure():
    ilx_get = ilx_pattern + '.<extension>'
    path_names = {
        # dissociate the node names which must be unique
        # from the name the will have in the resolver structure
        '*uris_ont': 'uris',
        '*uris_version': 'version',
        '*<uris_filename>': '<filename>',
        '*<path:uris_ont_p>': '<path:ont_path>',
        '*ont_ilx_get': ilx_get,
        '*contributions_ont': 'contributions',
        '*external': 'external',  # FIXME TEMP
        #'*<other_group_diff>': '<other_group>',  # FIXME consider whether this is a good idea ...
    }

    def path_to_route(node):
        return path_names[node] if node in path_names else node

    basic = [ilx_pattern, 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']  # 'prov'
    compare = ['own', 'diff']
    version_compare = []  # TODO? probably best to deal with the recursion in make_paths
    versioned_ids = basic + ['curies', 'uris']
    intermediate_filename = ['<filename>.<extension>', '<filename>']
    uris_intermediate_filename = ['<filename>.<extension>', '*<uris_filename>']
    parent_child = {
        '<group>':             basic + [ilx_get, 'lexical'] + branches + compare + ['contributions', 'upload', 'prov', 'external'],
        '<other_group>':       branches,  # no reason to access /group/own/othergroup/ilx_ since identical to /group/ilx_
        '<other_group_diff>':  basic + ['lexical'] + branches,
        'lexical':             ['<label>'],
        'readable':            ['<word>'],
        'versions':            ['<epoch_verstr_id>'],  # FIXME version vs versions!?
        '<epoch_verstr_id>':   versioned_ids + version_compare,
        #'ontologies':          [2, ilx_get, '*uris_ont'] + intermediate_filename + ['<path:ont_path>'],  # TODO /ontologies/external/<iri> ? how? where?
        'ontologies':          ['*ont_ilx_get', '*uris_ont', '*contributions_ont'] + intermediate_filename + ['<path:ont_path>'],  # TODO /ontologies/external/<iri> ? how? where?
        #'collections':         [2, '<path:ont_path>'] + intermediate_filename,  # TODO more general than files, ontologies, or resources
        # TODO distinguish between ontology _files_ and 'ontologies' which are the import closure?
        # ya, identified vs unidentified imports, owl only supports unidentified imports
        '<path:ont_path>':     intermediate_filename,  # FIXME this would seem to only allow a single extension?
        '*<path:uris_ont_p>':  uris_intermediate_filename,  # FIXME this would seem to only allow a single extension?
        '*uris_ont':           uris_intermediate_filename + ['*<path:uris_ont_p>'],  # FIXME need the ability to dissociate node name from render name
        '*<uris_filename>':    [None, '*uris_version'],
        '*uris_version':       ['<epoch_verstr_ont>'],

        '<filename>':          [None, 'version'],
        'version':             ['<epoch_verstr_ont>'],
        '<epoch_verstr_ont>':  ['<filename_terminal>', '<filename_terminal>.<extension>'],
        'curies':              [None, '<prefix_iri_curie>'],  # external onts can be referenced from here...
        'uris':                ['<path:uri_path>'],  # TODO no ilx_ check here as well as in database
        'own':                 ['<other_group>'],
        'diff':                ['<other_group_diff>'],
        # TODO considerations here
        # TODO get ontologies by qualifier and by data subgraph? also allow direct access via and identities endpoint since we have those?
        #'upload':              [None],  # smart endpoint that hunts down bound names or tracks unbound sets
        'contributions':       [None, 'interlex', '*external', 'curation'],  # None implies any direct to own
        'prov':                ['identities'],
        'external':            ['mapped'],
        'identities':          ['<identity>'],  # current cypher (initally sha256)
        'qualifiers':          ['<qualifier>'],  # integer
        'triples':             ['<triple>'],  # integer
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
                    'mapped':['GET', 'POST'],
    }
    return parent_child, node_methods, path_to_route


def add_leafbranches(nodes):
    if nodes[-1] == '':
        prefix = tuple(nodes[:-2])
        if 'curies' in nodes:
            nodes = prefix + ('curies_',)
        if nodes == ['', '<group>', 'ontologies', '']:  # only at depth 2
            nodes = prefix + ('ontologies_',)
        if 'contributions' in nodes:
            nodes = prefix + ('contributions_',)
        else:
            log.debug(f'possibly unhandled leafbranch {nodes}')

    return nodes


def build_endpoints(db):
    from interlex.endpoints import Endpoints, Versions, Own, OwnVersions, Diff, DiffVersions
    from interlex.endpoints import Ontologies

    endpoints = Endpoints(db)
    ontologies = Ontologies(db)
    versions = Versions(db)
    own = Own(db)
    ownversions = OwnVersions(db)
    diff = Diff(db)
    diffversions = DiffVersions(db)

    # build the route -> endpoint mapping function

    dispatch = {'diff': {'versions': {'': diffversions},
                         '': diff},
                #'ontologies': {'': ontologies},
                'own': {'versions': {'': ownversions},
                        '': own},
                'versions': {'': versions},
                'ontologies': {'': ontologies},
                '': endpoints,
                #'': {'ontologies': {'': ontologies}, '': endpoints}
    }

    def route_endpoint_mapper(nodes, dispatch_dict=dispatch):
        for path_element, subdispatch in dispatch_dict.items():
            if path_element == '':
                return subdispatch
                #if isinstance(subdispatch, dict):
                    #return route_endpoint_mapper(nodes, subdispatch)
                #else:
                    #return subdispatch

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
    # FIXME we probably want to exclude explicit endpoints for ontologies/uris
    # since we are really just using the router to enforce regularity of naming
    # and we can handle all of it with one function
    api = DocsApi(app,  # NOTE if the docs fail to load, make sure X-Forwarded-Proto is set in nginx
                  version='0.0.1',
                  title='InterLex URI structure API',
                  description='Resolution, update, and compare for ontologies and ontology identifiers.',
                  default='URIs',
                  default_label='Group URIs',
                  doc='/docs',)

    doc_namespaces = {
        # NOTE creation order here translates to the swagger docs, it also affects sorts first
        'curies':api.namespace('Curies', 'Group curies', '/'),
        'ontologies':api.namespace('Ontologies', 'URIs for serializations of subsets of InterLex, virtualized files', '/'),
        'contributions':api.namespace('Contributions', 'User contributions', '/'),
        'versions':api.namespace('Versions', 'View data associated with any ilx: URI at a given timepoint or version', '/'),
        'diff':api.namespace('Diff', 'Compare groups', '/'),
        'own':api.namespace('Own', 'See one group\'s view of another group\'s personalized IRIs', '/'),
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
        log.info(f'reference_host = {endpoints.reference_host}')
        for group in endpoints.queries.getBuiltinGroups():  # FIXME inelegant way around own_role < 'pending'
            BasicDBFactory._cache_groups[group.groupname] = group.id, group.own_role


def server_uri(db=None, mq=None, structure=uriStructure, echo=False):
    # app setup and database binding
    app = Flask('InterLex uri server')
    kwargs = {k:config.auth.get(f'db-{k}')  # TODO integrate with cli options
              for k in ('user', 'host', 'port', 'database')}
    kwargs['dbuser'] = kwargs.pop('user')
    if kwargs['database'] is None:
        raise ValueError('db-database is None, did you remember to set one?')

    app.config['SQLALCHEMY_DATABASE_URI'] = dbUri(**kwargs)  # use os.environ.update
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

    parent_child, node_methods, path_to_route = structure() # uri path nodes
    paths = list(make_paths(parent_child))                  # paths
    routes = ['/'.join(path_to_route(node) for node in path) for path in paths]

    @app.route('/api/job/<jobid>')
    def route_api_job(jobid):
        # FIXME prevent garbage?
        task = mq.AsyncResult(jobid)
        printD('s', task.status)
        printD('i', task.info)
        printD('r', task.result)
        return task.status

    for route, nodes in zip(routes, paths):
        nodes = add_leafbranches(nodes)
        endpoint_type = route_endpoint_mapper(nodes)
        function = endpoint_type.get_func(nodes)
        methods = route_methods(nodes, node_methods)

        #log.info(nodes)
        #log.info(endpoint_type)

        # route -> endpoint function
        name = endpoint_type.__class__.__name__ + '.' + function.__name__ + ' ' + route
        app.add_url_rule(route, name, function, methods=methods)

        # route -> api
        apiname = endpoint_type.__class__.__name__ + '_' + function.__name__
        add_api_rule(route, apiname, function, methods, nodes)

    for k, v in app.view_functions.items():
        if ' ' in k:
            name, path = str(k).split(' ', 1)
        else:
            name, path = k, ''

        if path:
            log.debug(f'{name:<40}{path:<130}{v}')
        #printD(k, v)

    return app

def run_uri(echo=False):
    return server_uri(db=SQLAlchemy(), mq=cel, echo=echo)
