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
            f'{self.scheme}://{self.host}:{self.port}/ilx_0101431.ttl',
        ]
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname})
            msg = out.url + '\n' + out.content.decode()
            assert out.ok, msg

    def test_no_user_content_type(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/ilx_0101431',
        ]
        ct = 'text/turtle'
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname, 'Accept':ct})
            msg = out.url + '\n' + out.content.decode()
            assert out.ok, msg

    def test_content_type(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431',
        ]
        for url in urls:
            for ct in tr.mimetypes:
                out = requests.get(url, headers={'host': self.hostname, 'Accept': ct})
                assert out.ok
                oct = out.headers['Content-Type']
                # charset may be added so use startswith
                assert oct.startswith(ct), f'{out.status_code} {oct} != {ct}'

    def test_extension(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431',
        ]
        for base_url in urls:
            for ex in tr.extensions:
                url = base_url + '.' + ex
                out = requests.get(url, headers={'host': self.hostname})
                #if ex == 'jsonld':
                    #print(out.json())
                assert out.ok, out.url + '\n' + out.content.decode()

    def test_ilx_types(self):
        ids = dict(fde='0381413',
                   cde='0301431',
                   term='0101431',
                   annotation='0381355',
                   relation='0381385')

        for type, id in ids.items():
            url = f'{self.scheme}://{self.host}:{self.port}/base/ilx_{id}'
            ct = 'text/turtle'
            out = requests.get(url, headers={'host': self.hostname, 'Accept':ct})
            msg = out.url + '\n' + out.content.decode()
            oct = out.headers['Content-Type']
            assert out.ok, msg
            assert oct.startswith(ct), f'{out.status_code} {oct} != {ct}'
            #print(url, msg, ct, oct)
