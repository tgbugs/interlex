import os
import unittest
from unittest.mock import MagicMock
import pytest
from pathlib import Path
import rdflib
from sqlalchemy.sql import text as sql_text
from pyontutils.core import OntGraph
from interlex import exceptions as exc
from interlex.core import FakeSession as FakeSessionBase
from interlex.load import FileFromFileFactory, FileFromIRIFactory, TripleLoaderFactory
from interlex.dump import Queries, TripleExporter
from interlex.config import auth
from .setup_testing_db import getSession


class FakeSession(FakeSessionBase):

    def execute(self, sql, params):
        if 'expected_bound_name' in sql.text:
            return (_ for _ in range(0))
        else:
            self.current_return_value = (FakeResultProxy for _ in range(1))
            return super().execute(sql, params)


class FakeResultProxy:
    name = 'no one actually checks this value'
    expected_bound_name = None
    _deadbeef = b'\xde\xad\xbe\xef'
    identity = _deadbeef + (b'\xff' * (32 - len(_deadbeef)))
    id = 'this isnt actually an i'
    own_role = 'not actually a role'
    reference_host = 'uri.interlex.org'


def ident_exists(*args, **kwargs):
    return False


class TestLoader(unittest.TestCase):

    def setUp(self):  # NOTE this runs multiple times
        self.session = FakeSession()
        FileFromFileFactory.refresh()  # clear cached anything
        self.FileFromFile = FileFromFileFactory(self.session)
        self.nasty = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/nasty.ttl'
        self.nastyebn = rdflib.URIRef('http://testurl.org/filename.ttl')
        #self.results = (FakeResultProxy for _ in range(999))
        #self.session.execute = MagicMock(return_value=self.results)
        self.FileFromFile.ident_exists = ident_exists

    def test_loader(self):
        ttl = auth.get_path('ontology-local-repo') / 'ttl'
        paths =  ('NIF-GrossAnatomy.ttl',
                  #'NIF-Chemical.ttl',
                  #'external/uberon.owl',  # FIXME to big for testing w/o pypy3
                  #'external/uberon.ttl',
                  #'generated/parcellation'/
                  'generated/parcellation-artifacts.ttl',
                  'nif.ttl',)
        names = [ttl/p for p in paths]
        # TODO the ontology should define the iri path mapping in its own metadata?
        # and/or infer it using the augpathlib logic that I implemented somewhere already?
        ebns = [rdflib.URIRef(os.path.join('http://ontology.neuinfo.org/NIF/ttl', p)) for p in paths]
        for name, ebn in list(zip(names, ebns))[::-1]:
            #self.FileFromFile.session.return_value = results
            fff = self.FileFromFile(user='tgbugs', group='tgbugs')  # FIXME get a real test user
            check_failed = fff.check(name)
            if check_failed:
                raise exc.LoadError(check_failed)

            setup_failed = fff(ebn)
            if setup_failed:
                raise exc.LoadError(setup_failed)
            #fff.process_graph()  # load calls this, but this is what is needed if you want the graph loaded but not sent to interlex
            #fff.subgraph_identities  # after calling process_graph this will work
            out = fff.load(commit=False)  # TODO raise error on this one

    def test_nasty(self, first=True):
        from pyontutils.core import rdf, owl
        fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME
        graph = rdflib.Graph().parse(self.nasty.as_posix(), format='ttl')
        for s in graph[:rdf.type:owl.Ontology]:
            if s != self.nastyebn:
                graph.remove((s, rdf.type, owl.Ontology))

        fff._serialization = graph.serialize(format='nifttl')
        fff._extension = 'ttl'

        check_failed = fff.check(self.nasty)
        if check_failed:
            raise exc.LoadError(check_failed)

        setup_failed = fff(self.nastyebn)
        if setup_failed is not None:
            breakpoint()
            raise exc.LoadError(setup_failed)

        out = fff.load()

        if first:
            self.test_nasty(False)  # test double loading file

    def test_no_bound_name(self):
        # TODO
        pass

    def test_negative(self):
        # TODO test to make sure things fail as expected
        # 0) multiple owl:Ontology sections
        fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME
        check_failed = fff.check(self.nasty)
        if check_failed:
            raise exc.LoadError(check_failed)

        setup_failed = fff(self.nastyebn)
        assert setup_failed is not None, 'by default nasty has multiple bound names this should have failed'
        # 1) names do not match
        # 2) value already inserted

    def test_roundtrip(self):
        # FIXME TODO one issue this reveals is that we do not correctly handle load failure cases
        # so right now when we try to load uberon, fma, etc. because they failed to load before and
        # we did not confirm that ingest happened successfully but we did insert into the identities
        # table, the issue is that we can't correct the data because we only computed on the python
        # side and never closed the loop coming back, so we need to close the loop before coming back
        # doing that should also make it possible to create restartable ingest at some point
        import uuid
        from pyontutils.namespaces import rdf, rdfs, owl, ilxtr
        from pyontutils.identity_bnode import IdentityBNode
        graph = OntGraph(idbn_class=IdentityBNode)
        bnm = rdflib.BNode()
        bn0 = rdflib.BNode()
        bn1 = rdflib.BNode()
        bnh = rdflib.BNode()
        bn2 = rdflib.BNode()
        bnh2 = rdflib.BNode()
        bn3 = rdflib.BNode()
        differ = uuid.uuid4().hex
        ontid = rdflib.URIRef(f'http://uri.interlex.org/tgbugs/ontologies/uris/test-roundtrip/{differ}')
        thingid = ilxtr[f'thing-{differ}']

        evilid = ilxtr[f'evil-{differ}']
        evilid2 = ilxtr[f'evil2-{differ}']
        ebn1 = rdflib.BNode()
        ebn2 = rdflib.BNode()
        ebn3 = rdflib.BNode()
        ebn4 = rdflib.BNode()
        ebn5 = rdflib.BNode()
        # FIXME TODO I can do something EVEN MORE EVIL which is to have an explicit bnode that is referenced by both the metadata and data
        # sections !!!! what do we do in that case ??? include the subgraph in both when computing the id! have impl though :/
        sebn0 = rdflib.BNode()

        # TODO need to test the the case where a list is
        # a subgraph of two different graphs
        bnl0 = rdflib.BNode()
        bnl1 = rdflib.BNode()
        bnl2 = rdflib.BNode()
        bnl3 = rdflib.BNode()
        bnl4 = rdflib.BNode()
        bnl5 = rdflib.BNode()

        ban0 = rdflib.BNode()
        ban1 = rdflib.BNode()
        ban2 = rdflib.BNode()
        ban3 = rdflib.BNode()
        ban4 = rdflib.BNode()
        ban5 = rdflib.BNode()
        ban6 = rdflib.BNode()

        ban3_1 = rdflib.BNode()
        ban4_1 = rdflib.BNode()
        ban5_1 = rdflib.BNode()
        ban6_1 = rdflib.BNode()

        trips = (
            (ontid, rdf.type, owl.Ontology),  # FIXME using a /uris/ iri instead of an /ontologies/ uri for owl:Ontology should be an error
            (ontid, ilxtr.load_it_anyway, rdflib.Literal(differ)),
            (ontid, ilxtr.mpred0, bnm),
            (bnm, ilxtr.mpred1, rdflib.Literal('mlit1')),
            (ontid, ilxtr.mpred2, sebn0),

            # if someone actually does this then in practice it is very likely that
            # we will wind up with a dangling bnode because we cut the serialization
            # at the end of the metadata entity no matter what
            # XXX hilariously though the ingestion process already successfully
            # roundtrips this likely because we use subject_triples
            (sebn0, ilxtr.EVIL, rdflib.Literal('EXTREMELY EVIL')),

            (thingid, rdf.type, owl.Class),
            (thingid, ilxtr.pred0, sebn0),
            (thingid, ilxtr.pred1, bn0),
            (bn0, ilxtr.pred2, rdflib.Literal('lit1')),
            (bn0, ilxtr.pred3, ilxtr.obj1),
            (bn0, ilxtr.pred14, rdflib.Literal('lit4')),
            (bn0, ilxtr.pred4, bn1),
            (bn1, ilxtr.pred5, rdflib.Literal('lit2')),
            (bn1, ilxtr.pred6, ilxtr.obj2),
            # list issues
            (thingid, ilxtr.pred15, bnl0),
            (bnl0, rdf.first, ilxtr.obj4),
            (bnl0, rdf.rest, bnl1),
            (bnl1, rdf.first, ilxtr.obj5),
            (bnl1, rdf.rest, rdf.nil),
            (thingid, ilxtr.pred15, bnl2),
            (bnl2, rdf.first, ilxtr.obj5),
            (bnl2, rdf.rest, bnl3),
            (bnl3, rdf.first, ilxtr.obj4),
            (bnl3, rdf.rest, rdf.nil),

            (bnh, ilxtr.pred7, ilxtr.obj3),
            (bnh, ilxtr.pred8, bn2),
            (bn2, ilxtr.pred9, rdflib.Literal('lit3')),
            (bnh, ilxtr.pred14, rdflib.Literal('lit4')),

            # TODO
            # need to figure out the preferred way to handle cases where
            # free subgraphs are duplicated, ideally of course they would not be
            # but sometimes we may have to ingest a serialized form that does
            # have this, and we won't be able to roundtrip
            (bnh2, ilxtr.pred7, ilxtr.obj3),
            (bnh2, ilxtr.pred8, bn3),
            (bn3, ilxtr.pred9, rdflib.Literal('lit3')),
            (bnh2, ilxtr.pred14, rdflib.Literal('lit4')),

            # for maximum evil, observe the following super duper non-injective cases
            (evilid, rdf.type, owl.Class),
            (evilid, ilxtr.pred10, ebn1),
            (ebn1, ilxtr.pred, ilxtr.obj),
            (evilid, ilxtr.pred11, ebn2),
            (ebn2, ilxtr.pred, ilxtr.obj),
            (evilid2, ilxtr.pred12, ebn2),
            (evilid2, ilxtr.pred13, ebn5),
            (ebn5, ilxtr.pred, ilxtr.obj),
            (evilid, rdf.type, owl.Class),
            (ebn3, ilxtr.pred, ilxtr.obj),
            (ebn4, ilxtr.pred, ilxtr.obj),

            # TODO missing example where an explicit bnode appears inside another subgraph >_<

            # or is it banannos >_<
            # FIXME somehow ingest is working without actually deduplicating the results here, did i fail to materialize the subgraph
            # and it still works due to dedupe ??? and the join on the dedupe table ???
            (ban0, ilxtr.ban_p0, ban5),
            (ban1, ilxtr.ban_p1, ban5),
            (ban2, ilxtr.ban_p2, ban5),

            (ban0, ilxtr.ban_p0o, rdflib.Literal('other 0')),
            (ban1, ilxtr.ban_p1o, rdflib.Literal('other 1')),
            (ban2, ilxtr.ban_p2o, rdflib.Literal('other 2')),

            # ban5 must come after ban3 so that its replica number
            # will not match, which breaks our python roundtrip, the db roundtrip
            # has its own issues with secondary in general not being implemented yet
            (ban3, ilxtr.ban_p3, ban3_1),
            (ban4, ilxtr.ban_p3, ban4_1),  # yep, it's evil!
            (ban5, ilxtr.ban_p3, ban5_1),
            (ban6, ilxtr.ban_p3, ban6_1),

            (ban3_1, ilxtr.ban_p4, rdflib.Literal("really?")),
            (ban4_1, ilxtr.ban_p4, rdflib.Literal("really?")),  # yep, it's evil!
            (ban5_1, ilxtr.ban_p4, rdflib.Literal("really?")),
            (ban6_1, ilxtr.ban_p4, rdflib.Literal("really?")),

        )
        for t in trips:
            graph.add(t)

        def load_graph(session, graph):
            TripleLoader = TripleLoaderFactory(session)
            user = 'tgbugs'
            # FIXME TODO need a better way to deal with reference names :/
            # XXX and here we can also see why requiring ebn is dumb
            bound_name = graph.boundIdentifier
            loader = TripleLoader(user=user, group=user, reference_name=bound_name)
            # FIXME reference name should not be required, should come
            # from bound name, and if there is no bound name then that is
            # a separate issue ...
            loader._serialization = graph.serialize(format='nifttl')  # XXX FIXME load_event expects a serialization id even if some graphs may not have one
            loader._graph = graph
            check_failed = loader.check(bound_name)
            if check_failed:
                raise exc.LoadError(check_failed)
            setup_failed = loader(expected_bound_name=bound_name)  # XXX FIXME rdflib.URIRef vs str types ... SIGH SIGH SIGH
            if setup_failed:
                raise exc.LoadError(setup_failed)
            http_resp = loader.load(commit=False)  # XXX FIXME really should not be returning an http response here, so incredibly complected
            return loader

        session = getSession()
        loader = load_graph(session, graph)
        q = Queries(session)
        rows = q.getGraphByBoundName(ontid)
        #_ = [print(((*r[:-2], (r[-2].hex() if r[-2] else r[-2]), r[-1]))) for r in rows]
        #res = list(q.session_execute('select * from triples'))
        #hrm = [(*r[:-1], (r[-1].hex() if r[-1] else r[-1])) for r in res]
        #_ = [print(_) for _ in hrm]
        if False:
            o_rows = q.getBySubject(ontid, None)
            t_rows = q.getBySubject(thingid, None)
            e_rows = q.getBySubject(evilid, None)
            e2_rows = q.getBySubject(evilid2, None)
            # FIXME yeah missing the free subgraphs, which is not at all surprising
            # because it is not clear how we would retrieve them anyway
            rows = o_rows + t_rows + e_rows + e2_rows

        te = TripleExporter()
        out_graph = OntGraph(idbn_class=IdentityBNode)
        # FIXME TODO curies etc.
        _ = [out_graph.add(te.triple(*r)) for r in rows]
        # FIXME TODO really need the single query to reconstruct a specific loaded ontology

        from ttlser.serializers import CustomTurtleSerializer
        class AllPredicates:
            def __contains__(self, other):
                return True

        CustomTurtleSerializer.no_reorder_list = AllPredicates()
        try:
            # some simple checks first
            graph.debug()
            out_graph.debug()
            assert len(graph) == len(out_graph), f'graph lengths do not match {len(graph)} != {len(out_graph)}'
            gi, ogi = graph.identity(), out_graph.identity()  # FIXME identity always uses the latest
            assert gi == ogi
            IdentityBNode._if_cache = {}
            i = IdentityBNode(graph, debug=True)
            IdentityBNode._if_cache = {}
            oi = IdentityBNode(out_graph, debug=True)
            #breakpoint()

            if False:
                sql = 'select * from triples where s = :ontid or s = :tid'
                res = session.execute(sql_text(sql), params=dict(ontid=ontid, tid=ilxtr.thing))
                rows = list(res)
        finally:
            session.rollback()

    @staticmethod
    def do_loader(loader, n, ebn):
        check_failed = loader.check(n)
        if check_failed:
            raise exc.LoadError(check_failed)

        setup_failed = loader(ebn)
        if setup_failed:
            raise exc.LoadError(setup_failed)

        out = loader.load(commit=False)
        return out

    def _do_test_uri(self, uri_string):
        #from interlex.endpoints import Endpoints  # FIXME
        from urllib.parse import urlparse
        session = getSession(echo=True)
        q = Queries(session)
        #class db:
            #session = s
        #endpoints = Endpoints(db)
        #FileFromIRI = FileFromIRIFactory(db.session)
        FileFromIRI = FileFromIRIFactory(session)
        #rh = 'uri.interlex.org'  #FIXME
        user = 'tgbugs'
        iri = rdflib.URIRef(uri_string)
        url = urlparse(iri)
        # FIXME need to populate reference names
        reference_name = rdflib.URIRef(f'http://uri.interlex.org/base/ontologies/{url.netloc}{url.path}')
        loader = FileFromIRI(user, user, reference_name)
        try:
            out = self.do_loader(loader, iri, iri)
            rows = q.getGraphByBoundName(iri)
            te = TripleExporter()
            out_graph = OntGraph()
            out_graph.namespace_manager.populate_from(loader.graph)
            _ = [out_graph.add(te.triple(*r)) for r in rows]
            #loader.graph.write(Path('/tmp') / (Path(url.path).name + '.ttl'))
            #out_graph.write(Path('/tmp') / (Path(url.path).name + '-out.ttl'))
            assert loader.graph.identity() == out_graph.identity()
        finally:
            session.rollback()
            session.close()

    @pytest.mark.skip('manual test')
    def test_small_resource(self):
        res = (
            'http://purl.obolibrary.org/obo/ro.owl',  # looks like we are somehow winding up with two rdf:first values in the same node of an rdf:List
            'http://purl.obolibrary.org/obo/bfo.owl',  # this one works but now ro is broken
        )
        for uri_string in res:
            self._do_test_uri(uri_string)

    @pytest.mark.skip('manual test')
    def test_small_file(self):
        session = getSession()
        FileFromFile = FileFromFileFactory(session)
        loader = FileFromFile('tgbugs', 'tgbugs')
        try:
            out = self.do_loader(loader, self.nasty, self.nastyebn)
        finally:
            session.close()
