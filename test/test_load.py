import os
import unittest
from unittest.mock import MagicMock
import pytest
from pathlib import Path
from sqlalchemy.sql import text as sql_text
from interlex import exceptions as exc
from interlex.core import FakeSession
from interlex.load import FileFromFileFactory, FileFromIRIFactory, TripleLoaderFactory
from interlex.dump import Queries, TripleExporter
from interlex.config import auth
from .setup_testing_db import getSession


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
    session = FakeSession()
    FileFromFile = FileFromFileFactory(session)
    def setUp(self):  # NOTE this runs multiple times
        self.FileFromFile.refresh()  # clear cached anything
        self.nasty = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/nasty.ttl'
        self.nastyebn = 'http://testurl.org/filename.ttl'
        self.results = (FakeResultProxy for _ in range(999))
        self.session.execute = MagicMock(return_value=self.results)
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
        ebns = [os.path.join('http://ontology.neuinfo.org/NIF/ttl', p) for p in paths]
        for name, ebn in list(zip(names, ebns))[::-1]:
            #self.FileFromFile.session.return_value = results
            fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME get a real test user
            check_not_ok = fff.check(name)
            setup_ok = fff(ebn)
            if setup_ok is not None:
                raise exc.LoadError(setup_ok)
            #fff.process_graph()  # load calls this, but this is what is needed if you want the graph loaded but not sent to interlex
            #fff.subgraph_identities  # after calling process_graph this will work
            out = fff.load()  # TODO raise error on this one

    def test_nasty(self, first=True):
        import rdflib
        from pyontutils.core import rdf, owl
        fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME
        graph = rdflib.Graph().parse(self.nasty.as_posix(), format='ttl')
        for s in graph[:rdf.type:owl.Ontology]:
            if s.toPython() != self.nastyebn:
                graph.remove((s, rdf.type, owl.Ontology))

        fff._serialization = graph.serialize(format='nifttl')
        fff._extension = 'ttl'

        check_not_ok = fff.check(self.nasty)
        setup_ok = fff(self.nastyebn)
        if setup_ok is not None:
            raise exc.LoadError(setup_ok)

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
        check_not_ok = fff.check(self.nasty)
        setup_ok = fff(self.nastyebn)
        assert setup_ok is not None, 'by default nasty has multiple bound names this should have failed'
        # 1) names do not match
        # 2) value already inserted

    def test_roundtrip(self):
        import rdflib
        import uuid
        from pyontutils.namespaces import rdf, rdfs, owl, ilxtr
        from pyontutils.core import OntGraph
        graph = OntGraph()
        bn0 = rdflib.BNode()
        bn1 = rdflib.BNode()
        ontid = rdflib.URIRef('http://uri.interlex.org/tgbugs/ontologies/uris/test-roundtrip')
        trips = (
            (ontid, rdf.type, owl.Ontology),  # FIXME using a /uris/ iri instead of an /ontologies/ uri for owl:Ontology should be an error
            (ontid, ilxtr.load_it_anyway, rdflib.Literal(uuid.uuid4().hex)),
            (ilxtr.thing, rdf.type, owl.Class),
            (ilxtr.thing, ilxtr.pred1, bn0),
            (bn0, ilxtr.pred2, rdflib.Literal('lit1')),
            (bn0, ilxtr.pred3, ilxtr.obj1),
            (bn0, ilxtr.pred4, bn1),
            (bn1, ilxtr.pred5, rdflib.Literal('lit2')),
            (bn1, ilxtr.pred6, ilxtr.obj2),
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

        session = getSession()
        load_graph(session, graph)
        q = Queries(session)
        o_rows = q.getBySubject(ontid, None)
        t_rows = q.getBySubject(ilxtr.thing, None)
        rows = o_rows + t_rows
        te = TripleExporter()
        out_graph = OntGraph()
        # FIXME TODO curies etc.
        _ = [out_graph.add(te.triple(*r)) for r in rows]
        # FIXME TODO really need the single query to reconstruct a specific loaded ontology

        try:
            # some simple checks first
            assert len(graph) == len(out_graph), (graph.debug(), out_graph.debug(), f'graph lengths do not match {len(graph)} != {len(out_graph)}')[-1]
            breakpoint()

            if False:
                sql = 'select * from triples where s = :ontid or s = :tid'
                res = session.execute(sql_text(sql), params=dict(ontid=ontid, tid=ilxtr.thing))
                rows = list(res)
        finally:
            session.rollback()

    @staticmethod
    def do_loader(loader, n, ebn):
        check_failed = loader.check(n)
        setup_failed = loader(ebn)
        out = loader.load()
        return out

    @pytest.mark.skip('manual test')
    def test_small_resource(self):
        from interlex.endpoints import Endpoints  # FIXME
        s = getSession()
        class db:
            session = s
        endpoints = Endpoints(db)
        FileFromIRI = FileFromIRIFactory(db.session)
        rh = 'uri.interlex.org'  #FIXME
        loader = FileFromIRI('tgbugs', 'tgbugs', '', rh)
        iri = 'http://purl.obolibrary.org/obo/ro.owl'
        try:
            out = self.do_loader(loader, iri, iri)
        finally:
            s.close()

    @pytest.mark.skip('manual test')
    def test_small_file(self):
        session = getSession()
        FileFromFile = FileFromFileFactory(session)
        loader = FileFromFile('tgbugs', 'tgbugs')
        try:
            out = self.do_loader(loader, self.nasty, self.nastyebn)
        finally:
            session.close()
