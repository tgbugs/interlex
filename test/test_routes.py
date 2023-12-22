import unittest
import requests
from pyontutils.ontutils import url_blaster
from interlex.uri import uriStructure, run_uri
from interlex.core import make_paths
from interlex.config import ilx_pattern
from interlex.config import test_host, test_port
from interlex.utils import log


def makeTestRoutes(limit=1):
    parent_child, node_methods, path_to_route = uriStructure()
    groups = 'base', 'origin', 'tgbugs'  # base redirects to default/curated ...
    other_groups = 'latest', 'curated', 'bob'
    ilx_patterns = 'ilx_0123456', 'ilx_0090000'
    words = 'isReadablePredicate', 'cookies'
    labels = 'brain', 'mus musculus'
    versions = '1524344335', '2018-04-01'  # FIXME should version alone 404 or return the qualifier?
    filenames = 'brain', 'myOntology', 'your-ontology-123', '_yes_this_works'
    extensions = 'ttl', 'owl', 'n3', 'xml', 'json'
    filenames_extensions = tuple(f + '.' + e for f in filenames for e in extensions)
    ilx_patterns_extensions = tuple(f + '.' + e for f in ilx_patterns for e in extensions)
    pics = 'GO', 'GO:', 'GO:123', 'http://purl.obolibrary.org/obo/GO_'
    identities = 'i am a tea pot short and stout this is my hash and i am out!',
    ont_paths = 'anatomy', 'anatomy/brain', 'anatomy/stomach', 'methods-core/versions/100'
    uri_paths = ('mouse/labels', 'mouse/labels/', 'mouse/labels/1',
                 'mouse/versions/1',
                 'mouse/versions/1/',
                 'mouse/versions/1/labels')
    options = {
        ilx_pattern: ilx_patterns,
        ilx_pattern + '.<extension>': ilx_patterns_extensions,
        '<group>': groups,
        '<other_group>': other_groups,
        '<other_group_diff>': other_groups,
        '<word>': words,
        '<label>': labels,
        '<epoch_verstr_id>': versions,
        '<epoch_verstr_ont>': versions,
        '<filename>': filenames,
        '<filename_terminal>': filenames,
        '<filename>.<extension>': filenames_extensions,
        '<filename_terminal>.<extension>': filenames_extensions,
        '<prefix_iri_curie>': pics,
        '<path:uri_path>': uri_paths,
        '<path:ont_path>': ont_paths,
        '<identity>': identities,

        '*ont_ilx_get': ilx_patterns_extensions,
        '*<uris_filename>': filenames,
        '*<path:uris_ont_path>': ont_paths,
    }
    # make cartesian product of combinations
    paths = make_paths(parent_child, options=options, limit=limit)
    routes = ['/'.join(path_to_route(node) for node in path) for path in paths]
    return routes


class RouteTester:
    host = test_host
    port = test_port
    scheme = 'http'
    with_server = False

    @property
    def prefix(self):
        port = f':{self.port}' if self.port else ''
        return f'{self.scheme}://{self.host}{port}'

    @classmethod
    def setUpClass(cls):
        cls.app = run_uri()
        cls.client = cls.app.test_client()
        cls.runner = cls.app.test_cli_runner()

    def setUp(self):
        if self.with_server:
            self.url_blaster = staticmethod(url_blaster)
            self.get = staticmethod(requests.get)
        else:
            self.url_blaster = self._url_blaster
            self.get = self._get

    def _url_blaster(
            self, urls, rate, timeout=5, verbose=False, debug=False,
            method='head', fail=False, negative=False, ok_test=lambda r: r.ok):
        meth = getattr(self.client, method)
        fails = []
        all_ = [self._fix_resp(meth(url)) for url in urls]
        not_ok = [_.url for _ in all_ if not ok_test(_)]
        print('Failed:')
        if not_ok:
            for nok in not_ok:
                print(nok)
            ln = len(not_ok)
            lt = len(urls)
            lo = lt - ln
            msg = f'{ln} urls out of {lt} ({ln / lt * 100:2.2f}%) are not ok. D:'
            print(msg)  # always print to get around joblib issues
            if negative and fail:
                if len(not_ok) == len(all_):
                    raise AssertionError('Everything failed!')
            elif fail:
                raise AssertionError(f'{msg}\n' + '\n'.join(sorted(not_ok)))

        else:
            print(f'OK. All {len(urls)} urls passed! :D')

    def _fix_resp(self, resp):
        resp.ok = resp.status_code < 400
        resp.url = resp.request.url
        resp.content = resp.data
        return resp

    def _get(self, url, headers={}):
        resp = self.client.get(url, headers=headers)
        self._fix_resp(resp)
        return resp


class TestRoutes(RouteTester, unittest.TestCase):

    def test_routes(self):
        routes = makeTestRoutes()  # up limite here for more tests, 2 is about max reasonable
        # TODO a way to mark expected failures
        urls = [
            # NOTE: have to use lists here because url_blaster needs to call shuffle
            # which doesn't work on tuples
            f'{self.prefix}/tgbugs/curies/BIRNLEX:796?local=true',
            f'{self.prefix}/tgbugs/curies/BIRNLEX:796',
            ]
        urls = [f'{self.prefix}{r}' for r in routes] + urls
        [print(u) for u in urls]

        def ok_test(r):
            if r.status_code == 501:
                path = r.request.path_url if self.with_server else r.request.path
                log.info(f'TODO: {path}')

            return r.ok or r.status_code == 501

        self.url_blaster(urls, 0, fail=True, ok_test=ok_test)

    def test_negative(self):
        urls = [
            f'{self.prefix}/tgbugs/curies/BIRNLEEX:796?local=true',
            f'{self.prefix}/tgbugs/curies/BIRNLEEX:796',
        ]
        [print(u) for u in urls]
        try:
            try:
                self.url_blaster(urls, 0, fail=True, negative=True)
                raise ValueError('All urls should have failed.')
            except AssertionError:
                pass
        except ValueError as e:
            raise AssertionError from e

    def test_lexical_no_external_redirect(self):
        url = f'{self.prefix}/base/lexical/liver'
        resp = self.get(url)
        assert self.host in resp.url


class TestApiDocs(RouteTester, unittest.TestCase):
    def test_docs(self):
        urls = [f'{self.prefix}/docs']  # NOTE /docs/ should fail?
        self.url_blaster(urls, 0, fail=True)

    def test_swagger_json(self):
        urls = [f'{self.prefix}/docs/swagger.json']
        self.url_blaster(urls, 0, fail=True)

    def test_swaggerui_content(self):
        urls = [f'{self.prefix}/docs/swaggerui/favicon-16x16.png']
        self.url_blaster(urls, 0, fail=True)

    def test_swagger_not_at_root(self):
        urls = [f'{self.prefix}/swagger.json', f'{self.prefix}/swaggerui/favicon-16x16.png']
        try:
            try:
                self.url_blaster(urls, 0, fail=True, negative=True)
                raise ValueError('All urls should have failed.')
            except AssertionError:
                pass
        except ValueError as e:
            raise AssertionError from e
