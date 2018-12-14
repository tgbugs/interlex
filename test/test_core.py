import unittest
from pyontutils.utils import injective_dict
from interlex.core import diffCuries, makeParamsValues

class TestDiffCuries(unittest.TestCase):
    def test_value_bound(self):
        old = {}
        new = {'a':'a',
               'b':'a'}
        expect = False, None, None, '??'
        self.run_diff(old, new, expect)

    def test_key_bound(self):
        old = {'a':'a'}
        new = {'a':'b'}
        expect = False, None, None, '??'
        self.run_diff(old, new, expect)

    def test_old(self):
        old = {'a':'b'}
        new = {}
        expect = True, {}, {}, '??'
        self.run_diff(old, new, expect)

    def test_new(self):
        old = {}
        new = {'a':'b'}
        expect = True, new, {}, '??'
        self.run_diff(old, new, expect)

    def test_old_new(self):
        old = {'a':'b'}
        new = {'c':'d'}
        expect = True, new, {}, '??'
        self.run_diff(old, new, expect)

    def test_old_old(self):
        old = {'a':'b'}
        new = {'a':'b'}
        expect = True, {}, old, '??'
        self.run_diff(old, new, expect)

    def test_old_oldnew(self):
        old = {'a':'b'}
        new = {'a':'b', 'c':'d'}
        expect = True, {'c':'d'}, old, '??'
        self.run_diff(old, new, expect)

    def test_oldold_new(self):
        old = {'a':'b', 'c':'d'}
        new = {'a':'b'}
        expect = True, {}, new, '??'
        self.run_diff(old, new, expect)

    def run_diff(self, old, new, expect):
        out = diffCuries(old, new)
        print(out)
        ok, toAdd, existing, message = out
        assert out[:-1] == expect[:-1], f'\n{out}\n{expect}'


class TestMakeParamsValues(unittest.TestCase):
    def test_dict(self):
        list(makeParamsValues(({'hello':'world'}, ('hello',))))  # FIXME seems ... not quite right

    def test_list(self):
        list(makeParamsValues((['hello', 'world'],)))

    def test_dl(self):
        list(makeParamsValues(({'hello':['world']},)))  # FIXME only parameterizes hello ...

    def test_ld(self):
        list(makeParamsValues(([{'hello':'world'}],)))

    def test_dd(self):
        list(makeParamsValues(({'hello':{'hello':'world'}},)))  # FIXME

    def test_ll(self):
        list(makeParamsValues((['hello', ['world']],)))  # FIXME this only sort of works?

    def test_True_1(self):
        list(makeParamsValues(((1,), (True,))))

    def test_False_0(self):
        list(makeParamsValues(((0, False),)))
