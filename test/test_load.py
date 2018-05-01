import os
import unittest
from unittest.mock import MagicMock
from pathlib import Path
from pyontutils.config import devconfig  # FIXME this will cause issues down the line
from interlex.exc import LoadError
from interlex.core import FakeSession
from interlex.load import FileFromFile
from IPython import embed

class FakeResultProxy:
    name = 'no one actually checks this value'
    expected_bound_name = None

def ident_exists(*args, **kwargs):
    return False

class TestLoader(unittest.TestCase):
    def test_loader(self):
        session = FakeSession()
        myFileFromFile = FileFromFile(session)  # be careful, you only get to call this once
        myFileFromFile.ident_exists = ident_exists
        results = (FakeResultProxy for _ in range(999))
        #FFF.reference_host = 'uri.interlex.org'
        #embed()
        ttl = Path(devconfig.ontology_local_repo) / 'ttl'
        paths =  ('NIF-GrossAnatomy.ttl',
                  #'NIF-Chemical.ttl',
                  #'external/uberon.owl',  # FIXME to big for testing w/o pypy3
                  #'external/uberon.ttl',
                  #'generated/parcellation'/
                  'generated/parcellation-artifacts.ttl',
                  'nif.ttl',)
        names = [ttl/p for p in paths]
        # TODO devconfig needs the remove ontology uri base
        ebns = [os.path.join('http://ontology.neuinfo.org/NIF/ttl', p) for p in paths]
        name = names[0]
        for name, ebn in list(zip(names, ebns))[::-1]:
            session.execute = MagicMock(return_value=results)
            #myFileFromFile.session.return_value = results
            fff = myFileFromFile()
            setup_ok = fff(name, ebn)
            if setup_ok is not None:
                raise LoadError(setup_ok)
            #fff.process_graph()  # load calls this, but this is what is needed if you want the graph loaded but not sent to interlex
            #fff.subgraph_identities  # after calling process_graph this will work
            out = fff.load()  # TODO raise error on this one
