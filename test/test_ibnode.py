import unittest
from pathlib import Path
from rdflib import Graph
from pyontutils.config import devconfig
from interlex.core import bnodes, IdentityBNode

class TestIBNode(unittest.TestCase):
    def setUp(self):
        self.graph1 = Graph()
        file = Path(devconfig.ontology_local_repo) / 'ttl/BIRNLex_annotation_properties.ttl'
        with open(file.as_posix(), 'rb') as f:
            self.ser1 = f.read()
        self.graph1.parse(data=self.ser1, format='turtle')

        g2format = 'xml'
        self.ser2 = self.graph1.serialize(format=g2format)

        self.graph2 = Graph()
        self.graph2.parse(data=self.ser2, format=g2format)

    def test_ser(self):
        assert IdentityBNode(self.ser1) != IdentityBNode(self.ser2), 'serialization matches!'

    def test_bnodes(self):
        assert sorted(bnodes(self.graph1)) != sorted(bnodes(self.graph2)), 'bnodes match!'

    def test_ibnode(self):
        identity1 = IdentityBNode(self.graph1)
        identity2 = IdentityBNode(self.graph2)
        assert identity1 == identity2, 'identities do not match!'


