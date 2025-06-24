import unittest
from interlex.dump import Queries
from interlex.vervar import process_vervar
from .setup_testing_db import getSession


class TestQueries(unittest.TestCase):

    def test_vervar(self):
        session = getSession()
        queries = Queries(session)
        ss = (
            'http://uri.interlex.org/base/ilx_0101431',
            'http://purl.obolibrary.org/obo/UBERON_0000955',
            'http://purl.obolibrary.org/obo/UBERON_0004829',
            'http://purl.obolibrary.org/obo/RO_0002131',  # XXX broken reconstruction of lists for property chain axiom
            'http://purl.obolibrary.org/obo/HP_0003001',
            'http://purl.obolibrary.org/obo/HP_0002001',
            'http://uri.interlex.org/tgbugs/ontologies/uris/test-6bfbce3594c2/spec',
              )
        res = []
        for s in ss:
            asdf = snr, ttsr, tsr, trr = queries.getVerVarBySubject(s)
            vv, uniques, metagraphs, ugraph, vvgraphs, resp = process_vervar(s, snr, ttsr, tsr, trr)
            res.append((asdf, vv, uniques, metagraphs, ugraph, vvgraphs, resp))

        breakpoint()

    def test_transitive(self):
        session = getSession()
        queries = Queries(session)
        #'http://purl.obolibrary.org/obo/UBERON_0000955',
        hrm = queries.getTransitive(
            ['http://uri.interlex.org/base/ilx_0101431'],
            ['http://uri.interlex.org/base/ilx_0112785'],
            True,)
        from pyontutils.core import OntGraph
        from interlex.dump import TripleExporter
        te = TripleExporter()

        g = OntGraph()
        for r in hrm:
            t = te.triple(r.s, None, r.p, r.o, r.o_lit, r.datatype, r.language)
            g.add(t)
        breakpoint()
