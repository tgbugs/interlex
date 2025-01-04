import unittest
import rdflib
from pyontutils.core import OntGraph
from pyontutils.namespaces import ilxtr
from pyontutils.identity_bnode import IdentityBNode, idf, it as ibn_it

from interlex.ingest import process_triple_seq, ingest_path


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

    def test_path(self):
        path = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/nasty.ttl'
        ingest_path(path, 'tgbugs', debug=True)

    def test_evil(self):
        # evil violations many assumptions
        path = auth.get_path('git-local-base') / 'pyontutils/ttlser/test/evil.ttl'
        ingest_path(path, 'tgbugs')
