import unittest
from pathlib import Path
import rdflib
from pyontutils.config import devconfig
from interlex.core import bnodes, IdentityBNode
from IPython import embed

class TestIBNode(unittest.TestCase):
    def setUp(self):
        self.graph1 = rdflib.Graph()
        file = Path(devconfig.ontology_local_repo) / 'ttl/BIRNLex_annotation_properties.ttl'
        with open(file.as_posix(), 'rb') as f:
            self.ser1 = f.read()
        self.graph1.parse(data=self.ser1, format='turtle')

        g2format = 'xml'
        self.ser2 = self.graph1.serialize(format=g2format)

        self.graph2 = rdflib.Graph()
        self.graph2.parse(data=self.ser2, format=g2format)

    def test_ser(self):
        assert IdentityBNode(self.ser1) != IdentityBNode(self.ser2), 'serialization matches!'

    def test_nodes(self):
        assert IdentityBNode('hello there') == IdentityBNode('hello there')
        assert IdentityBNode(b'hello there') == IdentityBNode(b'hello there')
        try:
            assert IdentityBNode(rdflib.BNode()) != IdentityBNode(rdflib.BNode())
            # TODO consider returning the bnode itself?
            raise AssertionError('identity bnode returned identity for bnode')
        except ValueError as e:
            pass
            
        try:
            bnode = rdflib.BNode()
            assert IdentityBNode(bnode) == IdentityBNode(bnode)
            raise AssertionError('identity bnode returned identity for bnode')
        except ValueError as e:
            pass
        
        lit1 = rdflib.Literal('hello there')
        lit2 = rdflib.Literal('hello there', datatype=rdflib.XSD.string)
        lit3 = rdflib.Literal('hello there', lang='klingon')
        
        assert IdentityBNode(lit1) == IdentityBNode(lit1)
        assert IdentityBNode(lit2) == IdentityBNode(lit2)
        assert IdentityBNode(lit3) == IdentityBNode(lit3)

        assert IdentityBNode(lit1) != IdentityBNode(lit2)
        assert IdentityBNode(lit1) != IdentityBNode(lit3)
        assert IdentityBNode(lit2) != IdentityBNode(lit3)

        uri1 = rdflib.URIRef('http://example.org/1')
        uri2 = rdflib.URIRef('http://example.org/2')

        assert IdentityBNode(uri1) == IdentityBNode(uri1)
        assert IdentityBNode(uri2) == IdentityBNode(uri2)

        assert IdentityBNode(uri1) != IdentityBNode(uri2)

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

    def test_check(self):
        id1 = IdentityBNode(self.graph1)
        assert id1.check(self.graph2), 'check failed!'
