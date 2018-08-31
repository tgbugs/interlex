import unittest
from pyontutils.utils import injective_dict
from interlex.core import diffCuries

class TestDiffCuries(unittest.TestCase):
    def test_value_bound(self):
        old = {}
        new = {'a':'a',
               'b':'a'}
        expect = False, None, None, '??'
        self.do_test(old, new, expect)

    def test_key_bound(self):
        old = {'a':'a'}
        new = {'a':'b'}
        expect = False, None, None, '??'
        self.do_test(old, new, expect)

    def test_old(self):
        old = {'a':'b'}
        new = {}
        expect = True, {}, {}, '??'
        self.do_test(old, new, expect)

    def test_new(self):
        old = {}
        new = {'a':'b'}
        expect = True, new, {}, '??'
        self.do_test(old, new, expect)

    def test_old_new(self):
        old = {'a':'b'}
        new = {'c':'d'}
        expect = True, new, {}, '??'
        self.do_test(old, new, expect)

    def test_old_old(self):
        old = {'a':'b'}
        new = {'a':'b'}
        expect = True, {}, old, '??'
        self.do_test(old, new, expect)

    def test_old_oldnew(self):
        old = {'a':'b'}
        new = {'a':'b', 'c':'d'}
        expect = True, {'c':'d'}, old, '??'
        self.do_test(old, new, expect)

    def test_oldold_new(self):
        old = {'a':'b', 'c':'d'}
        new = {'a':'b'}
        expect = True, {}, new, '??'
        self.do_test(old, new, expect)

    def do_test(self, old, new, expect):
        out = diffCuries(old, new)
        print(out)
        ok, toAdd, existing, message = out
        assert out[:-1] == expect[:-1], f'\n{out}\n{expect}'
