"""Tests to compare ensure that the database routines and
the python routines compute the same identities """

import unittest
from interlex.dump import Queries, TripleExporter
from test.test_stress import nottest  # FIXME put nottest in test utils
from test.setup_testing_db import getSession
from IPython import embed


class endpoints:
    reference_host = 'uri.interlex.org'


class TestHash(unittest.TestCase):
    @nottest
    def test_db_tripleIdentity(self):
        session = getSession()
        queries = Queries(session)
        idents = list(queries.tripleIdentity(10, 11))
        raw_trips = list(queries.getTriplesById(10, 11))
        te = TripleExporter()
        trips = [te.star_triple(t) for t in raw_trips]
        embed()
