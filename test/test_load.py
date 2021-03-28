import os
import unittest
from unittest.mock import MagicMock
import pytest
from pathlib import Path
from pyontutils.config import devconfig  # FIXME this will cause issues down the line
from interlex import exceptions as exc
from interlex.core import FakeSession
from interlex.load import FileFromFileFactory, FileFromIRIFactory
from test.setup_testing_db import getSession
from IPython import embed


class FakeResultProxy:
    name = 'no one actually checks this value'
    expected_bound_name = None
    _deadbeef = b'\xde\xad\xbe\xef'
    identity = _deadbeef + (b'\xff' * (32 - len(_deadbeef)))
    id = 'this isnt actually an i'
    own_role = 'not actually a role'
    reference_host = 'uri.interlex.org'


def ident_exists(*args, **kwargs):
    return False


class TestLoader(unittest.TestCase):
    session = FakeSession()
    FileFromFile = FileFromFileFactory(session)
    def setUp(self):  # NOTE this runs multiple times
        self.FileFromFile.refresh()  # clear cached anything
        self.nasty = Path(devconfig.git_local_base, 'pyontutils/ttlser/test/nasty.ttl')
        self.nastyebn = 'http://testurl.org/filename.ttl'
        self.results = (FakeResultProxy for _ in range(999))
        self.session.execute = MagicMock(return_value=self.results)
        self.FileFromFile.ident_exists = ident_exists

    def test_loader(self):
        ttl = Path(devconfig.ontology_local_repo) / 'ttl'
        paths =  ('NIF-GrossAnatomy.ttl',
                  #'NIF-Chemical.ttl',
                  #'external/uberon.owl',  # FIXME to big for testing w/o pypy3
                  #'external/uberon.ttl',
                  #'generated/parcellation'/
                  'generated/parcellation-artifacts.ttl',
                  'nif.ttl',)
        names = [ttl/p for p in paths]
        # TODO devconfig needs the remote ontology uri base
        ebns = [os.path.join('http://ontology.neuinfo.org/NIF/ttl', p) for p in paths]
        for name, ebn in list(zip(names, ebns))[::-1]:
            #self.FileFromFile.session.return_value = results
            fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME get a real test user
            check_not_ok = fff.check(name)
            setup_ok = fff(ebn)
            if setup_ok is not None:
                raise exc.LoadError(setup_ok)
            #fff.process_graph()  # load calls this, but this is what is needed if you want the graph loaded but not sent to interlex
            #fff.subgraph_identities  # after calling process_graph this will work
            out = fff.load()  # TODO raise error on this one

    def test_nasty(self, first=True):
        import rdflib
        from pyontutils.core import rdf, owl
        fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME
        graph = rdflib.Graph().parse(self.nasty.as_posix(), format='ttl')
        for s in graph[:rdf.type:owl.Ontology]:
            if s.toPython() != self.nastyebn:
                graph.remove((s, rdf.type, owl.Ontology))

        fff._serialization = graph.serialize(format='nifttl')
        fff._extension = 'ttl'

        check_not_ok = fff.check(self.nasty)
        setup_ok = fff(self.nastyebn)
        if setup_ok is not None:
            raise exc.LoadError(setup_ok)

        out = fff.load()

        if first:
            self.test_nasty(False)  # test double loading file

    def test_no_bound_name(self):
        # TODO
        pass

    def test_negative(self):
        # TODO test to make sure things fail as expected
        # 0) multiple owl:Ontology sections
        fff = self.FileFromFile('tgbugs', 'tgbugs')  # FIXME
        check_not_ok = fff.check(self.nasty)
        setup_ok = fff(self.nastyebn)
        assert setup_ok is not None, 'by default nasty has multiple bound names this should have failed'
        # 1) names do not match
        # 2) value already inserted

    @staticmethod
    def do_loader(loader, n, ebn):
        check_failed = loader.check(n)
        setup_failed = loader(ebn)
        out = loader.load()
        return out

    @pytest.mark.skip('manual test')
    def test_small_resource(self):
        from interlex.endpoints import Endpoints  # FIXME
        s = getSession()
        class db:
            session = s
        endpoints = Endpoints(db)
        FileFromIRI = FileFromIRIFactory(db.session)
        rh = 'uri.interlex.org'  #FIXME
        loader = FileFromIRI('tgbugs', 'tgbugs', '', rh)
        iri = 'http://purl.obolibrary.org/obo/ro.owl'
        try:
            out = self.do_loader(loader, iri, iri)
        finally:
            s.close()

    @pytest.mark.skip('manual test')
    def test_small_file(self):
        session = getSession()
        FileFromFile = FileFromFileFactory(session)
        loader = FileFromFile('tgbugs', 'tgbugs')
        try:
            out = self.do_loader(loader, self.nasty, self.nastyebn)
        finally:
            session.close()
