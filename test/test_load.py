import os
import unittest
from pathlib import Path
from pyontutils.config import devconfig  # FIXME this will cause issues down the line
from interlex.exc import LoadError
from interlex.core import FakeSession
from interlex.load import FileFromFile
from IPython import embed

class FakeResultProxy:
    name = 'no one actually checks this value'
    expected_bound_name = None

class TestLoader(unittest.TestCase):
    def test_loader(self):
        session = FakeSession()
        FFF = FileFromFile(session)
        FFF.session._return_value = (FakeResultProxy for _ in range(1))
        #FFF.reference_host = 'uri.interlex.org'
        #embed()
        fff = FFF()
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
            with fff as f:
                setup_ok = f(name.as_posix(), ebn)
                if setup_ok is not None:
                    raise LoadError(setup_ok)
                
                out = f.load()  # TODO raise error on this one
