import os
import unittest
from unittest.mock import MagicMock
import pytest
from pathlib import Path
import rdflib
from sqlalchemy.sql import text as sql_text
from pyontutils.core import OntGraph
from pyontutils.namespaces import ilxtr
from interlex import exceptions as exc
from interlex.core import FakeSession as FakeSessionBase
from interlex.load import FileFromFileFactory, FileFromIRIFactory, TripleLoaderFactory
from interlex.dump import Queries, TripleExporter
from interlex.config import auth
from .setup_testing_db import getSession

from interlex.ingest import process_triple_seq

class TestIngest(unittest.TestCase):
    def test_idf(self):
        bn0 = rdflib.BNode()
        trips = (
            (ilxtr.s0, ilxtr.p0, bn0),
            (bn0, ilxtr.p1, ilxtr.o0),
        )
        dout = {}
        pts = list(process_triple_seq(trips, dout=dout))

        g = OntGraph().populate_from_triples(trips)
        gid = g.identity()

        breakpoint()
