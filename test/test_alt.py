import pytest
import unittest
import requests
from interlex.render import TripleRender

tr = TripleRender()


class TestRoutes(unittest.TestCase):
    host = '127.0.0.1'
    port = '80'
    scheme = 'http'
    hostname = 'uri.interlex.org'

    @pytest.mark.skipif(port != '80', reason='no nginx redirects')
    def test_no_user(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/ilx_0101431.ttl',
        ]
        bads = []
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname})
            msg = out.url + '\n' + out.content.decode()
            if not out.ok:
                bads.append(msg)

        assert not bads, '\n'.join(bads)

    @pytest.mark.skipif(port != '80', reason='no nginx redirects')
    def test_no_user_content_type(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/ilx_0101431',
        ]
        ct = 'text/turtle'
        bads = []
        for url in urls:
            out = requests.get(url, headers={'host': self.hostname, 'Accept':ct})
            msg = out.url + '\n' + out.content.decode()
            if not out.ok:
                bads.append(msg)

        assert not bads, '\n'.join(bads)

    def test_content_type(self):
        urls = [
            f'{self.scheme}://{self.host}:{self.port}/base/ilx_0101431',
        ]
        bads = []
        doskip = False
        for url in urls:
            for ct in tr.mimetypes:
                if ct is None:
                    # can't deal with testing */* in here
                    # and there is a legitimate use case for the None mimetype
                    # though type nullability does indeed suck
                    continue

                if ct == 'text/turtle+html':
                    expect = 'text/html'
                else:
                    expect = ct

                try:
                    out = requests.get(url, headers={'host': self.hostname, 'Accept': ct})
                except requests.exceptions.SSLError as e:
                    doskip = 'There was an SSL failure.'
                    continue

                if not out.ok:
                    msg = f'{url} {ct} failed'
                    bads.append(msg)
                    continue  # don't try to check content type on failed requests

                oct = out.headers['Content-Type']
                if not oct.startswith(expect):
                    # charset may be added so use startswith
                    bads.append(f'{url} {out.status_code} {oct} != {expect}')

        assert not bads, '\n'.join(bads)
        if doskip:
            pytest.skip(doskip)

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
        ids = dict(fde=['ilx_0381413'],  # XXX currently none of these are using the fde_ prefix?
                   cde=['ilx_0301431',
                        'cde_0288556'],
                   pde=['ilx_0738259',
                        'pde_01000045'],
                   term=['ilx_0101431',
                         'ilx_0728778',  # multi ilx case
                         ],
                   annotation=['ilx_0381355'],
                   relation=['ilx_0381385'],
                   termset=['ilx_0770272',
                            'ilx_0774501',  # gnarly multiply nested case
                            ],
                   )

        bads = []
        for type, frags in ids.items():
            for frag in frags:
                url = f'{self.scheme}://{self.host}:{self.port}/base/{frag}'
                ct = 'text/turtle'
                out = requests.get(url, headers={'host': self.hostname, 'Accept':ct})
                msg = out.url + '\n' + out.content.decode()
                oct = out.headers['Content-Type']
                if not out.ok:
                    bads.append(msg)
                if not oct.startswith(ct):
                    bads.append(f'{out.status_code} {oct} != {ct}')

                #print(url, msg, ct, oct)

        assert not bads, '\n'.join(bads)
