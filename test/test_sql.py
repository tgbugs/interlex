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
