"""Tests to compare ensure that the database routines and
the python routines compute the same identities """

import unittest
import pytest
from interlex.dump import Queries, TripleExporter
from .setup_testing_db import getSession


class endpoints:
    reference_host = 'uri.interlex.org'


class TestHash(unittest.TestCase):
    @pytest.mark.skip('manual test')
    def test_db_tripleIdentity(self):
        session = getSession()
        queries = Queries(session)
        idents = list(queries.tripleIdentity(10, 11))
        raw_trips = list(queries.getTriplesById(10, 11))
        te = TripleExporter()
        trips = [te.star_triple(t) for t in raw_trips]
        breakpoint()
