from pathlib import Path
from datetime import timedelta
from collections import OrderedDict as od
from flask import Flask, url_for, abort
from flask_restx import Api, Resource, apidoc
from flask_restx.api import SwaggerView
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from interlex import config
from interlex.core import dbUri, mqUri, diffCuries, remove_terminals, TERMINAL
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

    def make_response(self, data, *args, **kwargs):
        # this only affects /docs/swagger.json right now
        resp = super().make_response(data, *args, **kwargs)
        resp.headers['Access-Control-Allow-Origin'] = '*'  # FIXME TODO need on ALL endpoints not just docs
        # https://stackoverflow.com/questions/26980713/solve-cross-origin-resource-sharing-with-flask
        return resp


def uriStructure():
    ilx_get = ilx_pattern + '.<extension>'
    path_names = {
        # dissociate the node names which must be unique
        # from the name the will have in the resolver structure
        '*priv': 'priv',
        '*email-verify': 'email-verify',
        '*ops-pull': 'ops',
        '*uris_ont': 'uris',
        '*uris_version': 'version',
        '*<uris_filename>': '<filename>',
        '*<path:uris_ont_p>': '<path:ont_path>',
        '*ilx_pattern': ilx_pattern,
        '*ilx_get': ilx_get,
        '*ont_ilx_get': ilx_get,
        '*contributions_ont': 'contributions',
        '*external': 'external',  # FIXME TEMP
        '*versions': 'versions',
        #'*<other_group_diff>': '<other_group>',  # FIXME consider whether this is a good idea ... XXX i think it is, because we normalize them to the same value in request processing, and it simplifies auth processing, and Own/Diff/Other do not overlap so there is never a 3 way rule? but i could see maybe trying to view the diff between two other groups via you own context so yeah we could have 3 sort of "explain the argument between groups a and b using the language of perspective c"
    }

    def path_to_route(node):
        return path_names[node] if node in path_names else node

    basic = ['*ilx_pattern', 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']  # 'prov'
    compare = ['own', 'diff']
    version_compare = []  # TODO? probably best to deal with the recursion in make_paths
    versioned_ids = basic + ['curies', 'uris']
    intermediate_filename = ['<filename>.<extension>', '<filename>']
    uris_intermediate_filename = ['<filename>.<extension>', '*<uris_filename>']
    spec_ext = ['spec', 'spec.<extension>']
    # reminder: None is used to mark branches that are also terminals
    parent_child = {
        '<group>':             basic + ['*ilx_get', 'lexical'] + branches + compare + [
            'priv', 'pulls', 'contributions', 'prov', 'external',],
        'u':                   ['ops', '*priv'],
        'ops':                 ['login',
                                'user-new',
                                'user-login',
                                'user-recover',
                                'email-verify', 'ever',
                                'orcid-new',
                                'orcid-login',
                                'orcid-land-new',
                                'orcid-land-login',
                                ],
        '*priv':               ['user-new',
                                'orcid-land-assoc',  # currently null case
                                'orcid-land-change',  # currently not null case
                                ],
        'priv':                ['role',  # note that priv -> privileged NOT private!
                                'upload',
                                'request-ingest',
                                #'ontology-new',  # not clear whether we actually need new-ontology on the api because all new ontologies should be POSTed to their desired uri, the frontend probably needs that though?

                                'pull-new',

                                #'ont-new',  # FIXME TODO still figuring out what to do about this one ...

                                'entity-new',
                                'modify-a-b',
                                'modify-add-rem',

                                'org-new',
                                #'reviewer-new',  # generate url to send to reviewer i think, obvs reviewers is a role so you can't just create a new one
                                'committee-new',

                                'curation',  # XXX pulls ? or everything in here at once?
                                # FIXME TODO
                                # pulls and pull actions need to be protected as well
                                #'pull-create',

                                # XXX TODO see if we really need this also probably want /<group>/priv/settings/<sub>
                                'settings',
                                'password-change',
                                'user-deactivate',

                                'orcid-assoc',
                                'orcid-change',
                                'orcid-dissoc',

                                'email-add',
                                'email-del',
                                '*email-verify',
                                'email-primary',

                                'api-tokens',
                                'api-token-new',
                                'api-token-revoke',
                                ],
        'role':                ['<user>'],
        'pulls':               [None, '<pull>'],
        '<pull>':              [None, '*ops-pull', 'review'],
        'reviews':             ['<review>'],
        '<review>':            [None, 'vote'],
        '*ops-pull':           ['merge', 'close', 'reopen', 'lock'],
        '*ilx_pattern':        [None, 'other', '*versions'],  # FIXME this is now doing a stupid redirect to ilx_pattern/ >_<
        '<other_group>':       branches,  # no reason to access /group/own/othergroup/ilx_ since identical to /group/ilx_
        '<other_group_diff>':  basic + ['lexical'] + branches,
        'lexical':             ['<label>'],
        'readable':            ['<word>'],  # FIXME no path here? i mean i guess?
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

        '<filename>':          [None, 'version'] + spec_ext,
        'version':             ['<epoch_verstr_ont>'],
        '<epoch_verstr_ont>':  ['<filename_terminal>', '<filename_terminal>.<extension>'],
        '<filename_terminal>': [None,] + spec_ext,
        'curies':              [None, '<prefix_iri_curie>', '<prefix_iri_curie>.<extension>'],  # external onts can be referenced from here...
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
                    'ontologies_':['GET'],
                    #'versions':['GET'],
                    'spec':['GET', 'POST', 'PATCH'],  # post to create a new ontology with that name i think
                    'spec.<extension>':['GET', 'POST', 'PATCH'],
                    #'<prefix_iri_curie>':[],  only prefixes can be updated...?
                    'ilx':['GET', 'PATCH'],  # FIXME why is this complaining?
                    #'*ilx_pattern':['GET', 'PATCH'],
                    '<word>':['GET', 'PATCH'],
                    '<filename>':['GET', 'POST'],
                    '<filename>.<extension>':['GET', 'POST'],  # TODO probably should only be get and use /spec for post ... that's not strictly true ?
                    '<filename_terminal>':['GET', 'POST'],
                    '<filename_terminal>.<extension>':['GET', 'POST'],
                    'mapped':['GET', 'POST'],

                    # pulls
                    'pulls': ['GET'],
                    '<pull>': ['GET'],  # I don't think we need to post to that?
                    # pull ops all post only for now
                    'merge': ['POST'],  # FIXME TODO how to implement the various review approval workflows e.g. multi voting
                    'close': ['POST'],
                    'reopen': ['POST'],
                    'lock': ['POST'],
                    # reviews
                    'reviews': ['GET'],
                    '<review>': ['GET'],
                    'vote': ['POST'],  # approve deny present (possibly implicit present)

                    # ops
                    'login': ['GET', 'POST'],
                    'user-new': ['GET', 'POST'],  # FIXME why are tests trying head?
                    'user-login': ['GET', 'POST'],
                    'user-recover': ['GET', 'POST'],
                    'orcid-new': ['GET'],
                    'orcid-login': ['GET'],

                    # priv
                    '<user>': ['GET', 'PUT', 'DELETE'],  # for user roles
                    'upload':['HEAD', 'POST'],  # FIXME why did this need head?
                    'request-ingest': ['POST'],

                    'entity-new': ['POST'],
                    'modify-a-b': ['PATCH'],  # accepts add remove ban requires both add and remove but can be empty for either only for bulk
                    'modify-add-rem': ['PATCH'],  # takes a before and after so that the backend can generate the add and remove subset

                    'org-new': ['POST'],

                    #'settings': ['GET'],  # TODO might allow PUT ?
                    'password-change': ['POST'],
                    'user-deactivate': ['POST'],

                    'orcid-assoc': ['GET'],
                    'orcid-change': ['POST'],
                    'orcid-dissoc': ['POST'],
                    'email-add': ['POST'],
                    'email-del': ['POST'],
                    '*email-verify': ['GET'],  # use query parameters
                    'email-primary': ['POST'],

                    'api-tokens': ['GET'],
                    'api-token-new': ['GET', 'POST'],
                    'api-token-revoke': ['GET', 'PUT'],  # can revoke as many times as you want only the first will do anything
    }
    return parent_child, node_methods, path_to_route, path_names


_known_default = (
    #'other',
    #'*ilx_get'
    #'',  # unhandled terminal case
    #TERMINAL,  # unhandled terminal case FIXME these aren't unhandled ... it is a path/route mismatch
    'other',
    '*ilx_get',
    '<label>',
    '<path:uri_path>',
    '<prefix_iri_curie>',  # FIXME maybe allow patch to change individual curie and post to create?
    '<prefix_iri_curie>.<extension>',
    '*ont_ilx_get',
    '<filename_terminal>',
    '<filename_terminal>.<extension>',
    '<word>',
    'contributions',

    'settings',

    'ever',
    'email-verify',
    'orcid-land-new',
    'orcid-land-login',
    'orcid-land-assoc',
    'orcid-land-change',

)


def add_leafbranches(nodes):
    if nodes[-1] == TERMINAL:
        prefix = tuple(nodes[:-2])
        if 'curies' in nodes:
            nodes = prefix + ('curies_',)
        elif nodes == ['', '<group>', 'ontologies', TERMINAL]:  # only at depth 2
            nodes = prefix + ('ontologies_',)
        elif 'contributions' in nodes:
            nodes = prefix + ('contributions_',)
        elif '*ilx_pattern' in nodes:
            nodes = prefix + ('ilx',)
        else:
            if not nodes[-2].startswith('<') and not nodes[-2].startswith('*<'):
                log.debug(f'possibly unhandled leafbranch {nodes}')

    return nodes


def build_endpoints(db, rules_req_auth):
    from interlex.endpoints import Endpoints, Versions, Own, OwnVersions, Diff, DiffVersions
    from interlex.endpoints import Ontologies, Ops, Privu, Priv, Pulls

    endpoints = Endpoints(db, rules_req_auth)
    ontologies = Ontologies(db, rules_req_auth)
    versions = Versions(db, rules_req_auth)
    own = Own(db, rules_req_auth)
    ownversions = OwnVersions(db, rules_req_auth)
    diff = Diff(db, rules_req_auth)
    diffversions = DiffVersions(db, rules_req_auth)
    ops = Ops(db, rules_req_auth)
    privu = Privu(db, rules_req_auth)
    priv = Priv(db, rules_req_auth)
    pulls = Pulls(db, rules_req_auth)

    # build the route -> endpoint mapping function

    dispatch = {'diff': {'versions': {'': diffversions},
                         '': diff},
                #'ontologies': {'': ontologies},
                'own': {'versions': {'': ownversions},
                        '': own},
                'versions': {'': versions},
                'ontologies': {'': ontologies},
                'pulls': {'': pulls},
                'priv': {'': priv},
                '*priv': {'': privu},
                'ops': {'': ops},
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


def route_methods(nodes, node_methods, path_names):
    default_methods = ['GET', 'HEAD']
    if nodes[-1] == TERMINAL:
        idx = -2
    else:
        idx = -1

    def erms(extra=''):
        if (nodes[idx] not in _known_default and
            (nodes[idx] not in path_names or
             (nodes[idx] in path_names and path_names[nodes[idx]] not in _known_default))):
            if extra:
                extra = (' ' * (24 - len(nodes[idx]))) + extra
            msg = f'using default methods GET HEAD for {nodes[idx]}{extra}'
            log.warning(msg)


    if 'diff' not in nodes and 'version' not in nodes and 'versions' not in nodes:
        if nodes[idx] in node_methods:
            methods = node_methods[nodes[idx]]
        elif nodes[idx] in path_names and path_names[nodes[idx]] in node_methods:
            methods = node_methods[path_names[nodes[idx]]]
        else:
            erms()
            methods = default_methods
    else:
        erms(' but was diff or version')
        methods = default_methods

    if 'GET' in methods and 'HEAD' not in methods:
        methods += ['HEAD']

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
                  default='URIs',  # FIXME warn when other stuff sneeks in to the default
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
        'ops':api.namespace('Operations', 'Stateful operations.', '/'),
        '*priv':api.namespace('Privileged*', 'Resources and operations that always require auth but no group', '/'),
        'priv':api.namespace('Privileged', 'Resources and operations that always require auth', '/'),
        'pulls':api.namespace('Pulls', 'Pull requests and reviews', '/'),
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
                if ' ' in ns.name:
                    # causes api namespaces to print in debug below obviously
                    # we could be smarter than checking whether there is a
                    # space in the name, but for now, nospace
                    msg = f'namespace names should not contain spaces! {ns.name!r}'
                    raise ValueError(msg)

                ns.route(route)(apiclass)
                break
        else:
            api.route(route)(apiclass)

    return add_api_rule


def setup_runonce(app, endpoints, echo):
    from interlex.load import BasicDBFactory

    def runonce():
        # FIXME this is a reasonably safe way to make sure that we have a db connection
        with app.app_context():
            endpoints.db.engine.echo = echo
            log.info(f'reference_host = {endpoints.reference_host}')
            for group in endpoints.queries.getBuiltinGroups():  # FIXME inelegant way around own_role < 'pending'
                BasicDBFactory._cache_groups[group.groupname] = group.id, group.own_role

    return runonce


def server_uri(db=None, mq=None, lm=None, structure=uriStructure, echo=False, dbonly=False, db_kwargs=None):
    # app setup and database binding
    app = Flask('InterLex uri server')

    if db_kwargs is None:
        db_kwargs = {k:config.auth.get(f'db-{k}')  # TODO integrate with cli options
                for k in ('user', 'host', 'port', 'database')}
        db_kwargs['dbuser'] = db_kwargs.pop('user')
        if db_kwargs['database'] is None:
            raise ValueError('db-database is None, did you remember to set one?')

    app.config['SECRET_KEY'] = config.auth.get('fl-session-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = dbUri(**db_kwargs)  # use os.environ.update
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['CELERY_BROKER_URL'] = config.broker_url
    app.config['CELERY_RESULT_BACKEND'] = config.broker_backend
    app.config['CELERY_ACCEPT_CONTENT'] = config.accept_content
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=180)
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True  # XXX see how this interacts with the frontend
    app.url_map.converters['regex'] = RegexConverter

    db.init_app(app)
    mq.init_app(app)
    lm.init_app(app)

    if dbonly:  # FIXME consider putting this before mq or lm are inited or rename dbonly to setup only or something?
        return app

    rules_req_auth = set()
    route_endpoint_mapper, endpoints = build_endpoints(db, rules_req_auth)  # endpoints
    runonce = setup_runonce(app, endpoints, echo)                           # runonce

    lm.user_loader(endpoints.auth.load_user)                 # give login manager access to db
    lm.needs_refresh_handler(endpoints.auth.refresh_login)   # tell login manager what to use to handle refresh

    api, doc_namespaces = build_api(app)                     # api init
    add_api_rule = api_rule_maker(api, doc_namespaces)       # api binding

    parent_child, node_methods, path_to_route, path_names = structure()  # uri path nodes
    paths = list(make_paths(parent_child))                               # paths
    routes = ['/'.join(remove_terminals([path_to_route(node) for node in path])) for path in paths]

    @app.route('/favicon.ico')
    def route_fav():
        return b'GO AWAY'

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
        methods = route_methods(nodes, node_methods, path_names)

        if 'uris' in nodes or '*uris_ont' in nodes or 'priv' in nodes or '*priv' in nodes:
            # FIXME TODO there are others
            rules_req_auth.add(route)

        #log.info(nodes)
        #log.info(endpoint_type)

        # route -> endpoint function
        name = endpoint_type.__class__.__name__ + '.' + function.__name__ + ' ' + route
        app.add_url_rule(route, name, function, methods=methods)

        # route -> api
        apiname = endpoint_type.__class__.__name__ + '_' + function.__name__
        add_api_rule(route, apiname, function, methods, nodes)

    for k, v in app.view_functions.items():
        if ' ' in k:  # FIXME this is a dumb way to detect api vs real
            name, path = str(k).split(' ', 1)
        else:
            name, path = k, ''

        if path:
            log.debug(f'{name:<40}{path:<140}{v}')

        #printD(k, v)

    runonce()
    return app

def run_uri(echo=False, dbonly=False, db_kwargs=None):
    return server_uri(db=SQLAlchemy(), mq=cel, lm=LoginManager(), echo=echo, dbonly=dbonly, db_kwargs=db_kwargs)
