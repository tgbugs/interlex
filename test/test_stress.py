import unittest
import pytest
from joblib import Parallel, delayed
from pyontutils.ontutils import url_blaster
from interlex.config import test_host, test_stress_port


def blast(scheme, host, port, start, stop):
    urls = [f"{scheme}://{host}:{port}/base/ilx_{id:0>7}"
            for id in range(start, stop)]
    # oh url_blaster you are so ... not fast
    url_blaster(urls, 0, method='head', fail=True)


class TestStress(unittest.TestCase):
    host = test_host
    port = test_stress_port
    scheme = 'http'

    @pytest.mark.skip('only run manually')
    def test_stress(self):
        n_jobs = 9
        start = 100000
        stop =  110000
        step = (stop - start) // (n_jobs - 1)
        Parallel(n_jobs=n_jobs,
                 backend='multiprocessing')(delayed(blast)(self.scheme,
                                                           self.host, self.port,
                                                           start, stop)
                                            for start, stop in
                                            ((start, start + step)
                                             for start in range(start, stop, step)
                                             if not print(start)))
