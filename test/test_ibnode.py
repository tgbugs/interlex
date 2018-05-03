import unittest
from pathlib import Path
from rdflib import Graph
from pyontutils.config import devconfig
from interlex.core import IdentityBNode

class TestIBNode(unittest.TestCase):
    def setUp(self):
        self.graph = Graph()
        file = Path(devconfig.ontology_local_repo) / 'ttl/BIRNLex_annotation_properties.ttl'
        self.graph.parse(file.as_posix(), format='turtle')
    def test_ibnode(self):
        identity = IdentityBNode(self.graph)


