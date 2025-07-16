import unittest
import pytest
import requests
import secrets
from pyontutils.ontutils import url_blaster
from interlex import endpoints
from interlex.uri import uriStructure, run_uri
from interlex.core import make_paths, remove_terminals
from interlex.dump import Queries
from interlex.config import ilx_pattern, auth
from interlex.config import test_host, test_port
from interlex.ingest import reingest_gclc
from interlex.utils import log


def makeTestRoutes(limit=1):
    parent_child, node_methods, path_to_route, path_names = uriStructure()
    groups = 'base', 'tgbugs'  # , 'origin'  # base redirects to default/curated ...
    other_groups = 'latest', 'curated'  # , 'bob'  # FIXME apparently NoGroup is insanely slow on error???
    ilx_patterns = 'ilx_0123456', 'tmp_000000001', 'ilx_0090000', 'cde_1000000'
    words = 'isReadablePredicate', 'cookies'
    labels = 'brain', 'mus musculus'
    versions = '1524344335', '2018-04-01'  # FIXME should version alone 404 or return the qualifier?
    filenames = 'brain', 'myOntology', 'your-ontology-123', '_yes_this_works'
    extensions = 'ttl', 'owl', 'n3', 'xml', 'json'
    filenames_extensions = tuple(f + '.' + e for f in filenames for e in extensions)
    ilx_patterns_extensions = tuple(f + '.' + e for f in ilx_patterns for e in extensions)
    spec_extensions = tuple('spec.' + e for e in extensions)
    pics = 'GO', 'GO:', 'GO:123', 'http://purl.obolibrary.org/obo/GO_'
    pics_ext = 'UBERON:0000955', 'ILX:0101431'
    identities = 'i am a tea pot short and stout this is my hash and i am out!',
    ont_paths = 'anatomy', 'anatomy/brain', 'anatomy/stomach', 'methods-core/versions/100'
    uri_paths = ('mouse/labels', 'mouse/labels/', 'mouse/labels/1',
                 'mouse/versions/1',
                 'mouse/versions/1/',
                 'mouse/versions/1/labels')
    #operations = ('user-new', 'login')
    #pages = 'email-verify', 'orcid-verify', 'api-tokens', 'org-new', 'logout', 'settings'
    users_role = 'tgbugs',
    pulls = '1', '3129', '2',
    qt_starts = 'ILX:0101431',
    qt_preds = 'rdfs:subClassOf', 'ilx.partOf:',
    dns_hosts = 'purl.obolibrary.org',
    dns_paths = 'obo/UBERON_0000955',
    dns_path_exts = tuple(f'{p}.{e}' for p in dns_paths for e in extensions)

    options = {
        '*ilx_pattern': ilx_patterns,
        '*ilx_get': ilx_patterns_extensions,
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
        '<prefix_iri_curie>.<extension>': pics_ext,
        '<path:uri_path>': uri_paths,
        '<path:ont_path>': ont_paths,
        '*<path:uris_ont_p>': ont_paths,
        '<identity>': identities,

        'spec.<extension>': spec_extensions,

        #'<operation>': operations,
        #'<page>': pages,
        '<user>': users_role,

        '*ont_ilx_get': ilx_patterns_extensions,
        '*<uris_filename>': filenames,
        '*<path:uris_ont_path>': ont_paths,

        '<dns_host>': dns_hosts,
        '*<path:dns_path>': dns_paths,
        '*<path:dns_path>.<extension>': dns_path_exts,

        '<pull>': pulls,

        '<qt_start>': qt_starts,
        '<qt_predicate>': qt_preds,
        # TODO
        # '<record_combined_identity>': record_combined_identities,
    }
    # make cartesian product of combinations
    paths = make_paths(parent_child, options=options, limit=limit)
    routes = ['/'.join(remove_terminals([path_to_route(node) for node in path])) for path in paths]
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
        cls.app = run_uri(echo=True, test=True)
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
        routes = makeTestRoutes()  # up limit here for more tests, 2 is about max reasonable
        # TODO a way to mark expected failures
        urls = [
            # NOTE: have to use lists here because url_blaster needs to call shuffle
            # which doesn't work on tuples
            f'{self.prefix}/tgbugs/curies/BIRNLEX:796?local=true',
            f'{self.prefix}/tgbugs/curies/BIRNLEX:796',
            ]
        urls = [f'{self.prefix}{r}' for r in routes] + urls
        if len(urls) < 1000:
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

    def test_post_entity_check(self):
        data, (_, _) = self.test_post_entity_new()
        # should fail
        _, (r1, r2) = self.test_post_entity_new(endpoint='entity-check', data=data)
        assert r2.status_code == 409, r2.status_code
        assert r2.json['existing'], r2.json['existing']

        # should succeed
        data2, (r3, r4) = self.test_post_entity_new(endpoint='entity-check')
        assert r4.status_code == 200, r4.status_code
        assert not r4.json['existing'], r4.json['existing']
        #breakpoint()

    def test_post_entity_new(self, endpoint='entity-new', data=None):
        self.app.debug = True
        client = self.app.test_client()
        tuser = auth.get('test-api-user')
        token = auth.get('interlex-test-api-key')
        headers = {'Authorization': f'Bearer {token}'}
        diff = secrets.token_hex(6)
        if data is None:
            data = {
                'rdf-type': 'owl:Class',
                'label': f'test term 1 {diff}',
                'exact': [f'test term one {diff}', f'first test term {diff}'],
            }

        url = f'{self.prefix}/{tuser}/priv/{endpoint}'
        resp = client.get(url, headers=headers)
        resp1 = client.post(url, json=data, headers=headers)
        if resp1.status_code == 303:
            headers = {'Accept': 'text/turtle'}
            resp2 = client.get(resp1.location, headers=headers)
            if resp2.status_code != 200:
                breakpoint()
                ''

            print(resp2.data.decode())

        return data, (resp, resp1,)

    def test_patch_entity(self):
        self.app.debug = True
        client = self.app.test_client()
        tuser = auth.get('test-api-user')
        token = auth.get('interlex-test-api-key')
        headers = {'Authorization': f'Bearer {token}'}
        headers_get = {**headers, 'Accept': 'application/ld+json'}
        headers_patch = {**headers, 'Content-Type': 'application/ld+json'}
        diff = secrets.token_hex(6)

        url = f'{self.prefix}/{tuser}/ilx_0101431'
        resp = client.get(url, headers=headers_get)
        jld = resp.json
        ont = [o for o in jld['@graph'] if o['@type'] == 'owl:Ontology'][0]
        pred = 'isAbout' if 'isAbout' in ont else 'http://purl.obolibrary.org/obo/IAO_0000136'
        frag_pref_id = ont[pred]['@id'].rsplit('/')[-1]
        # FIXME isAbout also may fail to expand if {group} does not
        # use that curie since we aren't yet merging with base curies
        # XXX this happens if the test user doesn't have curies loaded during config

        # FIXME isAbout iri mismatch somehow base vs group, not unexpected
        # but is a rendering bug because we don't currently require the group
        # because we are still using queries.getById instead of
        # getPerspectiveHeadForId or however it will be named
        ent = [o for o in jld['@graph'] if o['@id'].endswith(frag_pref_id)][0]
        spred = 'ilxr:synonym' if 'ilxr:synonym' in ent else 'http://uri.interlex.org/base/readable/synonym'
        ent[spred].append(f'lol test brain {diff}')

        resp_patch = client.patch(url, headers=headers_patch, json=jld)
        #breakpoint()

    def test_00_post_ontspec(self):
        self.app.debug = True
        client = self.app.test_client()
        tuser = auth.get('test-api-user')
        token = auth.get('interlex-test-api-key')
        headers = {'Authorization': f'Bearer {token}'}
        data = {'title': 'test ontology',
                'subjects': [
                    # FIXME not in test db by default
                    'http://uri.interlex.org/base/ilx_0101431',
                    'http://uri.interlex.org/base/ilx_0101432',
                    #'http://uri.interlex.org/base/ilx_0101433',
                    #'http://purl.obolibrary.org/obo/UBERON_0000955',
                    #'http://purl.obolibrary.org/obo/BFO_0000001',
                    #'http://purl.obolibrary.org/obo/IAO_0000001',
                ]}
        # FIXME TODO somehow looking at this I'm seeing that if we don't already have it we need
        # to ensure that we don't wind up with duplicate ontologies all having a single subject in them
        fname = 'test-' + secrets.token_hex(6)
        ont_url = f'{self.prefix}/{tuser}/ontologies/uris/{fname}'
        url = ont_url + '/spec'
        resp = client.post(url, json=data, headers=headers)
        if resp.location is not None:
            client2 = self.app.test_client()
            resp2 = client2.get(resp.location)
            client3 = self.app.test_client()
            #resp3 = client3.get(url + '.html')  # FIXME .html breaks url matcher TODO
            resp3 = client3.get(url, headers={'Accept': 'text/html'})

        else:
            with self.app.app_context():
                breakpoint()
                ''
            assert False, 'oops'

        with self.app.app_context():
            session = self.app.extensions['sqlalchemy'].session
            q = Queries(session)
            s = url.replace(self.prefix, 'http://' + q.reference_host)
            gclc_id = q.getLatestIdentityByName(s)
            dout = reingest_gclc(gclc_id, session=session)
            assert dout['graph_combined_local_conventions_identity'] == gclc_id
            ''

    def test_01_patch_ontspec(self):
        self.app.debug = True
        client = self.app.test_client()
        tuser = auth.get('test-api-user')
        token = auth.get('interlex-test-api-key')
        headers = {'Authorization': f'Bearer {token}'}
        onts_url = f'{self.prefix}/{tuser}/ontologies'
        resp1 = client.get(onts_url)

        data = {
            'title': 'test ontology updated',
                'add': [
                    #'http://uri.interlex.org/base/ilx_0101431',
                    #'http://uri.interlex.org/base/ilx_0101432',
                    'http://uri.interlex.org/base/ilx_0101433',
                    #'http://purl.obolibrary.org/obo/UBERON_0000955',
                    #'http://purl.obolibrary.org/obo/BFO_0000002',
                    #'http://purl.obolibrary.org/obo/IAO_0000001',
                ],
                'del': [
                    'http://uri.interlex.org/base/ilx_0101432',
                    #'http://purl.obolibrary.org/obo/BFO_0000001',
                ],
        }

        # FIXME TODO somehow looking at this I'm seeing that if we don't already have it we need
        # to ensure that we don't wind up with duplicate ontologies all having a single subject in them
        url = resp1.json[-1]['uri']
        resp2 = client.get(url, headers={'Accept': 'text/turtle'})
        resp3 = client.patch(url, json=data, headers=headers)
        if resp3.location is not None:
            client2 = self.app.test_client()
            resp2_1 = client2.get(resp3.location)
            client3 = self.app.test_client()
            #resp3 = client3.get(url + '.html')  # FIXME .html breaks url matcher TODO
            resp3_1 = client3.get(url, headers={'Accept': 'text/turtle'})
        else:
            with self.app.app_context():
                breakpoint()
                ''
            assert False, 'oops'

        assert resp2.data != resp3_1.data, 'no change?'
        with self.app.app_context():
            #breakpoint()
            ''

    def test_post_user_new(self):
        self.app.debug = True
        client = self.app.test_client()
        url = f'{self.prefix}/u/ops/user-new'
        diff = secrets.token_hex(6)
        username = f'some-user-{diff}'
        data = {
            'username': username,
            'password': 'passwordpassword',
            'email': f'email-{diff}@example.org',}
        resp = client.post(url, data=data)
        #if resp.status_code == 303:  # don't do this because it goes to orcid reg step
            #resp2 = client.get(resp.location)# url_settings)

        url_settings = f'{self.prefix}/{username}/priv/settings'
        resp2 = client.get(url_settings)

        if resp2.status_code != 200:
            with self.app.app_context():
                breakpoint()
                ''

    def test_post_user_recover(self):
        try:
            endpoints._reset_mock = True
            self.app.debug = True
            client = self.app.test_client()
            url = f'{self.prefix}/u/ops/user-recover'
            bads = []
            for test_user, exists in (('tgbugs', True), ('not-registered-username', False)):
                data = {'username': test_user}
                resp = client.post(url, data=data)
                if exists and test_user not in endpoints._reset_mock_tokens:
                    bads.append(data)
                elif not exists and test_user in endpoints._reset_mock_tokens:
                    bads.append(data)

            if bads:
                breakpoint()

        finally:
            endpoints._reset_mock = False


    def test_query_transitive(self):
        sps = (
            #(False, 'UBERON:0000955', 'BFO:0000050'),
            (False, 'ILX:0100612', 'rdfs:subClassOf'),
            (False, 'ILX:0101431', 'ILX:0112785'),
            (True, 'ILXdne:0101431', 'ILX:0112785'),
            (True, 'ILX:0101431', 'ILXdne:0112785'),
        )
        test_acc = (
            'text/html',
            'text/turtle',
            'application/json',
            'application/ld+json',
        )
        try:
            endpoints._reset_mock = True
            self.app.debug = True
            client = self.app.test_client()
            bads = []
            for xfail, start, predicate in sps:  # oof this takes a long time to run even with the mostly optimized queries
                for depth in (0, 1, 2, -1):
                    for obj_to_sub in (True, False):
                        params = '?'
                        if obj_to_sub:
                            params += 'obj-to-sub=true&'
                        if depth >= 0:
                            params += f'depth={depth}'

                        url = f'{self.prefix}/base/query/transitive/{start}/{predicate}{params}'
                        for acc in test_acc:
                            headers = {'Accept': acc}
                            resp = client.get(url, headers=headers)
                            if xfail:
                                if resp.status_code == 200:
                                    bads.append(resp)
                            else:
                                if resp.status_code != 200:
                                    bads.append(resp)

            if bads:
                breakpoint()

            assert not bads, bads

        finally:
            endpoints._reset_mock = False

    def test_dns(self):
        url = f'{self.prefix}/base/dns/purl.obolibrary.org/obo/GO_0007275.html?links=internal'
        resp = self.client.get(url)
        return

        url = f'{self.prefix}/base/dns/purl.obolibrary.org/obo/RO_0002492.html?links=internal'
        resp = self.client.get(url)

        url = f'{self.prefix}/base/dns/purl.obolibrary.org/obo/RO_0002492'
        resp = self.client.get(url)


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
