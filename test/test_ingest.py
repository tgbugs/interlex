import unittest
import rdflib
from pyontutils.core import OntGraph
from pyontutils.namespaces import ilxtr, rdf, owl
from pyontutils.identity_bnode import IdentityBNode, idf, it as ibn_it

from interlex.config import auth
from interlex.ingest import process_triple_seq, ingest_path, ingest_ontspec
from .common import working_dir
from .setup_testing_db import getSession

class TestIngestIdentityFunction(unittest.TestCase):
    """ make sure that ingest and ibnode produce the same results """

    def _doit(self, trips):
        dout = {}
        IdentityBNode._if_cache = {}
        pts = list(process_triple_seq(trips, dout=dout))

        g = OntGraph().populate_from_triples(trips)
        # XXX watch out for the default namespace 
        #g.namespace_manager.store._Memory__namespace.clear()
        #g.namespace_manager.store._Memory__prefix.clear()

        IdentityBNode._if_cache = {}
        gid = IdentityBNode(
            g,
            as_type=ibn_it['triple-seq'],
            id_method=idf['graph-combined'],
            #id_method=idf['graph-combined-and-local-conventions'],
        )

        if dout['graph_combined_identity'] != gid.identity:
            breakpoint()

        assert dout['graph_combined_identity'] == gid.identity

    def test_no_link(self):
        bn0 = rdflib.BNode()
        trips = (
            (ilxtr.s0, ilxtr.p0, bn0),
            (bn0, ilxtr.p1, ilxtr.o0),
        )
        self._doit(trips)

    def test_bnode_all(self):
        bn0 = rdflib.BNode()
        bn1 = rdflib.BNode()
        trips = (
            (ilxtr.s0, ilxtr.p0, bn0),
            (bn0, ilxtr.p1, bn1),
            (bn1, ilxtr.p2, ilxtr.o0),
        )
        self._doit(trips)

    def test_named(self):
        trips = (
            (ilxtr.s, ilxtr.p, ilxtr.o),
        )
        self._doit(trips)

    def test_all(self):
        bn0 = rdflib.BNode()
        bn1 = rdflib.BNode()
        trips = (
            (ilxtr.s, ilxtr.p, ilxtr.o),
            (ilxtr.s0, ilxtr.p0, bn0),
            (bn0, ilxtr.p1, bn1),
            (bn1, ilxtr.p2, ilxtr.o0),
        )
        self._doit(trips)

    def test_nometa(self):
        if working_dir is None:
            # FIXME hardcoded to docker install path
            path = '/usr/share/interlex/test/data/nometa.ttl'
        else:
            path = working_dir / 'test/data/nometa.ttl'

        session = getSession()
        ingest_path(path, 'tgbugs', debug=True, session=session)

    def test_nasty(self):
        path = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/nasty.ttl'
        session = getSession()
        ingest_path(path, 'tgbugs', debug=True, session=session)

    def test_evil(self):
        # evil violations many assumptions
        path = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/evil.ttl'
        session = getSession()
        try:
            ingest_path(path, 'tgbugs', session=session)
            raise AssertionError('should have failed')
        except AssertionError as e:
            raise
        except Exception as e:
            # we expect this to fail at the moment because we have not
            # implemented ingest for graphs with cycles (among others)
            pass


class TestIngestVersions(unittest.TestCase):

    def test_ingest_versions(self):
        session = getSession()
        g0 = OntGraph()
        g1 = OntGraph()

        b0 = rdflib.BNode()
        #b1 = rdflib.BNode()
        #b2 = rdflib.BNode()
        s0 = ilxtr.s0
        p0 = ilxtr.p0
        p1 = ilxtr.p1
        trips_c = (
            (ilxtr['test-ont-v'], rdf.type, owl.Ontology),
            (s0, rdf.type, owl.Class),
            (b0, rdf.type, owl.Restriction),
            (b0, owl.onProperty, ilxtr.prop0),
            (b0, owl.someValuesFrom, ilxtr.value0),
        )
        [[g.add(t) for t in trips_c] for g in (g0, g1)]
        g0.add((s0, p0, b0))
        g1.add((s0, p1, b0))

        d0 = ingest_ontspec(g0, session)
        d1 = ingest_ontspec(g1, session)
        session.commit()
        breakpoint()
