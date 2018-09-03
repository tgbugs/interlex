import unittest
from pyontutils.ontutils import url_blaster
from interlex.uri import uriStructure
from interlex.core import make_paths

def makeTestRoutes(limit=1):
    ilx_pattern, parent_child, node_methods = uriStructure()
    users = 'base', 'origin', 'tgbugs'  # base redirects to default/curated ...
    other_users = 'latest', 'curated', 'bob'
    ilx_patterns = 'ilx_0123456', 'ilx_0090000'
    words = 'isReadablePredicate', 'cookies'
    versions = '1524344335', '2018-04-01'
    filenames = 'brain', 'myOntology', 'your-ontology-123', '_yes_this_works'
    extensions = 'ttl', 'owl', 'n3', 'xml', 'json'
    filenames_extensions = tuple(f + '.' + e for f in filenames for e in extensions)
    pics = 'GO', 'GO:', 'GO:123', 'http://purl.obolibrary.org/obo/GO_'
    ont_paths = 'anatomy', 'anatomy/brain', 'anatomy/stomach', 'methods-core/versions/100'
    uri_paths = ('mouse/labels', 'mouse/labels/', 'mouse/labels/1',
                 'mouse/versions/1',
                 'mouse/versions/1/',
                 'mouse/versions/1/labels')
    options = {
        ilx_pattern:ilx_patterns,
        '<user>':users,
        '<other_user>':other_users,
        '<other_user_diff>':other_users,
        '<word>':words,
        '<epoch_verstr_id>':versions,
        '<epoch_verstr_ont>':versions,
        '<filename>':filenames,
        '<filename_terminal>':filenames,
        '<filename>.<extension>':filenames_extensions,
        '<filename_terminal>.<extension>':filenames_extensions,
        '<prefix_iri_curie>':pics,
        '<path:uri_path>':uri_paths,
        '<path:ont_path>':ont_paths,
    }
    # make cartesian product of combinations
    routes = make_paths(parent_child, options=options, limit=limit)
    return routes

class TestRoutes(unittest.TestCase):
    host='localhost:8505'  # FIXME
    scheme = 'http'
    def test_routes(self):
        routes = makeTestRoutes()
        # TODO a way to mark expected failures
        urls = [
            'http://localhost:8505/tgbugs/curies/BIRNLEX:796?local=true',
            'http://localhost:8505/tgbugs/curies/BIRNLEX:796',
            ]
        urls = [f'http://{self.host}{r}' for r in routes] + urls
        [print(u) for u in urls]
        url_blaster(urls, 0, fail=True)

    def test_negative(self):
        urls = [
            'http://localhost:8505/tgbugs/curies/BIRNLEEX:796?local=true',
            'http://localhost:8505/tgbugs/curies/BIRNLEEX:796',
        ]
        [print(u) for u in urls]
        try:
            try:
                url_blaster(urls, 0, fail=True, negative=True)
                raise ValueError('All urls should have failed.')
            except AssertionError:
                pass
        except ValueError as e:
            raise AssertionError from e

    def notest_stress(self):
        urls = [f"{self.scheme}://{self.host}/base/ilx_{id:0>7}" for id in range(100000,105000)]
        url_blaster(urls, 0, method='get', fail=True)
