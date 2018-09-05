import unittest
from pyontutils.ontutils import url_blaster
from joblib import Parallel, delayed

try:
    from nose.tools import nottest
except:
    def nottest(function):
        return function


def blast(scheme, host, start, stop):
    urls = [f"{scheme}://{host}/base/ilx_{id:0>7}"
            for id in range(start, stop)]
    # oh url_blaster you are so ... not fast
    url_blaster(urls, 0, method='head', fail=True)


class TestStress(unittest.TestCase):
    host='localhost:8606'  # FIXME
    scheme = 'http'
    @nottest
    def test_stress(self):
        n_jobs = 9
        start = 100000
        stop =  110000
        step = (stop - start) // (n_jobs - 1)
        Parallel(n_jobs=n_jobs,
                 backend='multiprocessing')(delayed(blast)(self.scheme, self.host, start, stop)
                                            for start, stop in
                                            ((start, start + step)
                                             for start in range(start, stop, step) if not print(start)))
