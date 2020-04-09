import socket
import rdflib  # FIXME FIXME FIXME BAD DESIGN DETECTED
from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy
import ontquery as oq
from pyontutils import sneechenator as snch  # FIXME why do we need to import this here this is an issue :/
from pyontutils.utils import mysql_conn_helper, TermColors as tc
from pyontutils.core import makeGraph, OntGraph
from pyontutils.namespaces import PREFIXES as uPREFIXES, rdf, rdfs  # FIXME should not need these here :/
from interlex import exc
from interlex import config
from interlex import render
from interlex.dump import MysqlExport
from interlex.render import TripleRender  # FIXME need to move the location of this


def dbUri(user='nif_eelg_secure', host='nif-mysql.crbs.ucsd.edu', port=3306, database='nif_eelg'):
    DB_URI = 'mysql+pymysql://{user}:{password}@{host}:{port}/{db}'  # FIXME db => pyontutils refactor
    if socket.gethostname() in config.dev_remote_hosts:
        db_cfg_kwargs = mysql_conn_helper('localhost', database, user, 33060)  # see .ssh/config
    else:
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

    @app.route('/base/ilx_<id>')
    def ilx(id, redirect=True):
        user = 'base'  # TODO
        if user == 'base':
            title = f'ILX:{id}'
        else:
            title = f'ilx.{user}:ilx_{id}'

        try:
            tripleRender.check(request)
        except exc.UnsupportedType as e:
            return e.message, e.code

        graph = OntGraph()
        oq.OntCuries.populate(graph)
        [graph.add(t) for t in ilxexp(id)]
        try:
            return tripleRender(request, graph, user, id, object_to_existing, title, redirect=redirect)
        except BaseException as e:
            print(tc.red('ERROR'), e)
            raise e
            return abort(404)

    @app.route('/base/ilx_<id>.<extension>')
    def ilx_get(id, extension):
        return ilx(id, redirect=False)

    @app.route('/base/ontologies/ilx_<id>')
    def ontologies_ilx(id):
        return ilx(id)

    @app.route('/base/ontologies/ilx_<id>.<extension>')
    def ontologies_ilx_get(id, extension):
        return ilx(id, redirect=False)

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

        graph = makeGraph(group + '_export_helper', prefixes=uPREFIXES).g
        [graph.add(t) for t in ilxexp._call_group(group)]
        ontid = f'http://uri.interlex.org/{group}/ontologies/community-terms'  # FIXME
        kwargs = {}  # FIXME indicates a design flaw ...
        if group == 'sparc':  # FIXME should not be hardcoded should be a function -> database
            _pr = ['FMA'] + [p for p in tripleRender.default_prefix_ranking if p != 'FMA']
            kwargs['ranking'] = _pr
        try:
            # FIXME TODO
            return tripleRender(request, graph, group, None, object_to_existing,
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


    return app


def run_alt():
    return server_alt(db=SQLAlchemy())


def main():
    from sqlalchemy import create_engine
    from sqlalchemy.orm.session import sessionmaker
    engine = create_engine(dbUri(), echo=True)
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()

    ilxexp = MysqlExport(session)
    ilx_id = '0101431'
    ilx_fragment = 'ilx_' + ilx_id
    term = ilxexp.term(ilx_fragment)
    trips = list(ilxexp(ilx_id))


if __name__ == '__main__':
    main()
