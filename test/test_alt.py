import unittest
import requests
from interlex.render import TripleRender

tr = TripleRender()


class TestRoutes(unittest.TestCase):
    host = '127.0.0.1'
    port = '80'
    scheme = 'http'
    hostname = 'uri.interlex.org'
    def test_no_user(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/ilx_0101431',
        ]
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname})
            assert out.ok

    def test_content_type(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431',
        ]
        for url in urls:
            for ct in tr.mimetypes:
                out = requests.get(url, headers={'host': self.hostname, 'Content-Type': ct})
                assert out.ok
                oct = out.headers['Content-Type']
                # charset may be added so use startswith
                assert oct.startswith(ct), f'{out.status_code} {oct} != {ct}'

    def test_extension(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431.html',
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431.ttl',
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431.xml',
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431.nt',
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431.n3',
        ]
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname})
            assert out.ok
