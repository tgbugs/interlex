import socket
from pathlib import PurePath
import rdflib  # FIXME FIXME FIXME BAD DESIGN DETECTED
from flask import Flask, request, abort, redirect
from flask_sqlalchemy import SQLAlchemy
import ontquery as oq
from pyontutils import sneechenator as snch  # FIXME why do we need to import this here this is an issue :/
from pyontutils.utils import mysql_conn_helper, TermColors as tc
from pyontutils.core import OntGraph
from pyontutils.namespaces import PREFIXES as uPREFIXES, rdf, rdfs  # FIXME should not need these here :/
from interlex import exceptions as exc
from interlex import config
from interlex import render
from interlex.dump import MysqlExport
from interlex.render import TripleRender  # FIXME need to move the location of this


def dbUri(user='nif_eelg_secure', host='nif-mysql.crbs.ucsd.edu', port=3306, database='nif_eelg'):
    # NOTE we MUST use pymysql here because mysqlconnector cannot convert tuples like in :ids
    DB_URI = 'mysql+pymysql://{user}:{password}@{host}:{port}/{db}'  # FIXME db => pyontutils refactor
    db_cfg_kwargs = mysql_conn_helper(host, database, user, port)
    return DB_URI.format(**db_cfg_kwargs)


def server_alt(db=None, dburi=dbUri()):
    app = Flask('InterLex alt server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    database = db
    session = db.session
    ilxexp = MysqlExport(session)

    tripleRender = TripleRender()
    object_to_existing = {}

    group_render = None

    @app.route('/<group>/<frag_pref>_<id>')
    def ilx(group, frag_pref, id, redirect=True, ontology=True):
        # XXX FIXME termsets should render like regular terms on the /base/ilx_ endpoint
        # and like ontologies on the /base/ontologies/ilx_ endpoint
        if group not in ('base', 'sparc', 'interlex'):  # XXX HACK the db has no groups
            # the interlex group is used to serialize using only interlex internal ids
            # this is where conflating groups and perspectives is a problem
            # really perspectives are render preferences which do not map 1:1
            # on to groups, and might need to be passed as parameter instead of
            # part of the tree structure to keep all the endpoints from multiplying
            # nope, perspectives HAVE to be part of the url path :/ see comment
            # on stubs below, alternately we have to have some other way to
            # track perspectives independent of the url e.g. in the metadata
            return abort(404)

        try:
            prefix = {
                'ilx': 'ILX',
                'cde': 'ILX.CDE',
                'pde': 'PDE',
                'fde': 'FDE',
            }[frag_pref]
        except KeyError:
            return abort(404)

        if group == 'base':
            title = f'{prefix}:{id}'
        else:
            title = f'ilx.{group}:{frag_pref}_{id}'

        try:
            tripleRender.check(request)
        except exc.UnsupportedType as e:
            return e.message, e.code

        graph = OntGraph()
        oq.OntCuries.populate(graph)
        [graph.add(t) for t in ilxexp(frag_pref, id, ontology)]

        kwargs = {}
        group_rend = group if group_render is None else group_render
        if group_rend == 'sparc':  # TODO real support for render preferences
            # XXX HACK
            _pr = ['FMA'] + [p for p in tripleRender.default_prefix_ranking if p != 'FMA']
            kwargs['ranking'] = _pr
        elif group_rend == 'interlex':
            _pr = ['CDE', 'PDE', 'FDE', 'ILX.CDE', 'ILX']
            kwargs['ranking'] = _pr

        # XXX HACK stubs, needs design review
        # XXX FIXME THIS CANNOT BE USED FOR REAL PURPOSES
        # the issue is that the parameter then becomes part
        # of the uri and we absolutely do not want to allow that
        # so going to set it as default behavior for now, when
        # we get to perspectives they WILL
        #if 'stubs' in request.args and request.args['stubs'].lower() == 'true':
            #kwargs['ilx_stubs'] = True
        #kwargs['ilx_stubs'] = True  # XXX aaahhhh not clear the use case, so not now

        try:
            return tripleRender(
                request, graph, group_rend, frag_pref, id, object_to_existing, title,
                redirect=redirect, **kwargs)
        except BaseException as e:
            print(tc.red('ERROR'), e)
            raise e
            return abort(404)

    @app.route('/<group>/<frag_pref>_<id>.<extension>')
    def ilx_get(group, frag_pref, id, extension):
        return ilx(group, frag_pref, id, redirect=False)

    @app.route('/base/curies')
    def curies_():
        return ilxexp.getGroupCuries('base')

    @app.route('/base/curies/<prefix_iri_curie>')
    def curies(prefix_iri_curie):
        # FIXME it looks like it is not actually possible to pass the iri here for some reason :/
        # TODO args to match ?local=true
        iri_ilx = ilxexp.expandPrefixIriCurie('base', prefix_iri_curie)
        if iri_ilx is None:
            return abort(404)
        elif len(iri_ilx) == 1:  # FIXME so dumb
            return iri_ilx  # expanded prefix case
        else:
            iri, ilx = iri_ilx

        if iri.u == prefix_iri_curie:
            return iri.curie

        elif 'local' in request.args and request.args['local'].lower() == 'true':
            if ilx is None:  # never happens in the mysql version
                return abort(501)
            return redirect(ilx, code=302)
        else:
            return redirect(iri, code=302)

        return
        g = OntGraph()
        g.namespace_manager.populate_from(prefixes)
        try:
            iri = g.namespace_manager.expand(prefix_iri_curie)
        except ValueError:
            iri = prefix_iri_curie

    @app.route('/<group>/ontologies/<frag_pref>_<id>')
    def ontologies_ilx(group, frag_pref, id):
        return ilx(group, frag_pref, id, ontology=True)

    @app.route('/<group>/ontologies/<frag_pref>_<id>.<extension>')
    def ontologies_ilx_get(group, frag_pref, id, extension):
        return ilx(group, frag_pref, id, redirect=False, ontology=True)

    @app.route('/<group>/ontologies/community-terms')
    def group_ontologies_terms(group):
        if group not in ilxexp._group_community:
            return 'no such group', 404

        if group == 'base':
            return 'base has too many terms', abort(404)  # too many terms
        else:
            title = f'Terms for {group}'

        try:
            tripleRender.check(request)
        except exc.UnsupportedType as e:
            return e.message, e.code

        graph = OntGraph()
        graph.namespace_manager.populate_from(uPREFIXES)
        [graph.add(t) for t in ilxexp._call_group(group)]
        #ontid = f'http://uri.interlex.org/{group}/ontologies/community-terms'  # FIXME
        _host = 'uri.interlex.org'
        _scheme = 'http'
        ontid = _scheme + '://' + _host + PurePath(request.path).with_suffix('').as_posix()
        kwargs = {}  # FIXME indicates a design flaw ...
        group_rend = group if group_render is None else group_render
        if group_rend == 'sparc':  # FIXME should not be hardcoded should be a function -> database
            _pr = ['FMA'] + [p for p in tripleRender.default_prefix_ranking if p != 'FMA']
            kwargs['ranking'] = _pr
        elif group_rend == 'interlex':
            _pr = ['CDE', 'PDE', 'FDE', 'ILX.CDE', 'ILX']
            kwargs['ranking'] = _pr

        try:
            # FIXME TODO
            return tripleRender(request, graph, group_rend, 'ilx', None, object_to_existing,
                                title, ontid=ontid, **kwargs, redirect=False)
        except BaseException as e:
            print(tc.red('ERROR'), e)
            raise e
            return abort(404)

    @app.route('/<group>/ontologies/community-terms.<extension>')
    def group_ontologies_terms_get(group, extension):
        return group_ontologies_terms(group)

    @app.route('/<group>/external/mapped', methods=['GET', 'POST'])
    def group_external_mapped(group):
        # semantics here need a review, but I think the sensible thing to do
        # would just be to match the longest matching namespace and return
        # everything that fits the pattern ... seems reasonable and already implemented

        # FIXME supporting file extensions on a parameterized endpoint makes this pattern
        # quite awkward, as is naming/retrieving the output ... naming of mappings to exernal
        # systems almost certainly requires that we maintain a set of static unchanging curies
        # that are used to deterministically make external namespaces url safe and invertible
        # I think this means that these operations always need to map against base where no
        # transformations will be made during rendering, and probably implementations like this
        # one should be moved to those endpoints and then we can redirect ...
        iri = request.args.get('iri', None)
        curie = request.args.get('curie', None)
        prefix = request.args.get('prefix', None)
        vals = set(i for i in (iri, curie, prefix) if i)
        if len(vals) > 1:
            conflicting = [a for a, b in
                           zip(('iri', 'curie', 'prefix'), (iri, curie, prefix))
                           if b]
            return abort(400, {'message':
                               f'conflicting query params {conflicting}'})
        elif vals:
            # ilxexp.getGroupCuries(group)  # TODO
            thing = next(iter(vals))
            nses = oq.OntCuries.identifier_namespaces(thing)
            if nses:
                ns = nses[-1]
            else:
                return abort(400, {'message': f'Unknown prefix {next(iter(vals))}'})

            # TODO handle unknown namespace case
            # FIXME this needs to always expand in a consistent unchanging way
            prefix = oq.OntCuries.identifier_prefixes(ns)[-1]
            mprefix = f'/{prefix}'
            tprefix = f' uri.interlex.org {prefix}'  # FIXME remove hardcoding of ref host
        else:
            ns = None
            mprefix = ''
            tprefix = f' uri.interlex.org'  # FIXME remove hardcoding of ref host

        graph = OntGraph()
        oq.OntCuries.populate(graph)

        base = 'http://uri.interlex.org/base/resources'
        if request.method == 'POST':
            """ Accepts a newline separated list of uris """
            uris = request.data.decode().split('\n')
            graph.bind('snchn', str(snch.snchn))
            graph.populate_from_triples(ilxexp.alreadyMapped(uris, ns))
            # FIXME fragment id breaks version iri generation
            ontid = rdflib.URIRef(f'{base}/index{mprefix}#ArbitrarySubset')
            title = f'Subset of Mapped IRIs for {tprefix}'
            tmet = ((ontid, p, o) for p, o in
                    ((rdf.type, snch.snchn.PartialIndexGraph),
                     (rdfs.label, rdflib.Literal(title))))

        elif request.method == 'GET':
            # TODO metadata section should match sneech index graph
            graph.populate_from_triples(ilxexp.index_triples(ns))
            # FIXME in theory prefix could change make sure it wont ...
            ontid = rdflib.URIRef(f'{base}/index{mprefix}')
            title = f'Mapped IRIs for {tprefix}'
            tmet = ((ontid, p, o) for p, o in
                    ((rdf.type, snch.snchn.IndexGraph),
                     (rdfs.label, rdflib.Literal(title))))

        else:
            return abort(501)

        # FIXME triple render is actually not what we want here
        # we just want the asTtl, asRdfXml, asOwlXml, asManchester, asOwlFunctional, asTtlHtml, etc.
        # all keyed off of mimetype ...
        # so we can untangle triple render from the transforms, the format, etc.

        # FIXME probably not an ontid at this point ... so distinguish resources and ontologies ??! *think think think*
        # or if we should leave already mapped clean from the database
        # and add a partialIndexGraph generator as well ...
        #, graph, group, None, object_to_existing, title, ontid=ontid, redirect=False)
        extension, mimetype, func = tripleRender.check(request)
        graph.populate_from_triples(tmet)  # FIXME I think the way to solve the neededing namespaces here is to move this inside the branches
        # and the we move it into render and let render mediate the additional stream types beyond owl, interlex, neurdf etc
        return graph.asMimetype(mimetype)

    @app.route('/<group>/own/<group_data>/<path:path>', methods=['GET'], defaults={'extension': None})
    @app.route('/<group>/own/<group_data>/<path:path>.<extension>', methods=['GET'])
    def group_own(group, group_data, path, extension):
        host = request.host
        adapter = app.url_map.bind(request.host)
        ext = '' if extension is None else f'.{extension}'
        fname, kwargs = adapter.match(f'/{group_data}/{path}{ext}', method='GET')
        f = app.view_functions[fname]
        # XXX watch out with nonlocal, if the gil ever gets turned off
        # this isn't going to be thread safe like lisp dynamic variables
        nonlocal group_render
        group_render = group
        try:
            return f(**kwargs)
        finally:
            group_render = None

    return app


def run_alt():
    kwargs = {k:config.auth.get(f'alt-db-{k}')  # TODO integrate with cli options
              for k in ('user', 'host', 'port', 'database')}
    return server_alt(db=SQLAlchemy(), dburi=dbUri(**kwargs))


def main():
    from sqlalchemy import create_engine
    from sqlalchemy.orm.session import sessionmaker
    kwargs = {k:config.auth.get(f'alt-db-{k}')
              for k in ('user', 'host', 'port', 'database')}
    if kwargs['database'] is None:
        raise ValueError('alt-db-database is None, did you remember to set one?')

    engine = create_engine(dbUri(**kwargs), echo=True)
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()

    ilxexp = MysqlExport(session)
    frag_pref = 'ilx'
    ilx_id = '0101431'
    ilx_fragment = frag_pref + '_' + ilx_id
    term = ilxexp.term(ilx_fragment)
    trips = list(ilxexp(frag_pref, ilx_id))


if __name__ == '__main__':
    main()
