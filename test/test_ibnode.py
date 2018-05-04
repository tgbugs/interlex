import unittest
from pathlib import Path
from rdflib import Graph
from pyontutils.config import devconfig
from interlex.core import bnodes, IdentityBNode
from IPython import embed

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
        def sbs(l1, l2):
            for a, b in zip(l1, l2):
                print('', a[:5], a[-5:], '\n', b[:5], b[-5:], '\n\n')

        def ds(d1, d2):
            for (k1, v1), (k2, v2) in zip(sorted(d1.items()), sorted(d2.items())):
                if k1 != k2:
                    # TODO len t1 != len t2
                    for t1, t2 in sorted(zip(sorted(v1), sorted(v2))):
                        print(tuple(e[:5] if type(e) == bytes else e for e in t1))
                        print(tuple(e[:5] if type(e) == bytes else e for e in t2))
                        print()
            

        id1 = IdentityBNode(self.graph1, True)
        id2 = IdentityBNode(self.graph2, True)

        idni1 = sorted(id1.named_identities) 
        idni2 = sorted(id2.named_identities) 
        assert idni1 == idni2, 'named identities do not match'

        idli1 = sorted(id1.linked_identities) 
        idli2 = sorted(id2.linked_identities) 
        assert idli1 == idli2, 'linked identities do not match'

        idfi1 = sorted(id1.free_identities) 
        idfi2 = sorted(id2.free_identities) 
        assert idfi1 == idfi2, 'free identities do not match'

        assert id1.identity == id2.identity, 'identities do not match'

