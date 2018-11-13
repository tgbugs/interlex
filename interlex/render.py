import json
from datetime import datetime
from itertools import chain
import rdflib
from flask import abort  # FIXME decouple this??
from pyontutils.core import OntId
from pyontutils.ttlser import CustomTurtleSerializer
from pyontutils.htmlfun import atag, htmldoc
from pyontutils.htmlfun import table_style, render_table, ttl_html_style
from pyontutils.qnamefix import cull_prefixes
from pyontutils.namespaces import isAbout, ilxtr
from pyontutils.closed_namespaces import rdf, rdfs, owl
from interlex import exc

class TripleRender:
    def __init__(self):
        self.mimetypes = {None:self.html,
                          'text/html':self.ttl_html,
                          'application/json':self.json,
                          'application/ld+json':self.jsonld,
                          'text/turtle':self.ttl,
                          'application/rdf+xml':self.rdf_ser,
                          'application/n-triples':self.rdf_ser,
                          'text/n3':self.rdf_ser,
                          #'application/n-quads':self.rdf_ser  # TODO need qualifier context store
        }
        self.extensions = {'html': 'text/html',
                           'json': 'application/json',
                           'jsonld': 'application/ld+json',
                           'ttl': 'text/turtle',  # InterLex rdf?
                           'xml': 'application/rdf+xml',
                           'owl': 'application/rdf+xml',  # FIXME conversion rules for owl?
                           'nt': 'application/n-triples',
                           'n3': 'text/n3',
                           #'nq': 'application/n-quads',  # TODO need qualifier context store
        }

    def check(self, request):
        mimetype = (request.accept_mimetypes.best if
                    request.accept_mimetypes.best != '*/*' else
                    'text/html')
        extension = (request.view_args['extension'] if
                     'extension' in request.view_args else
                     None)

        if extension:
            try:
                mimetype = self.extensions[extension]
            except KeyError as e:
                raise exc.UnsupportedType(f"don't know what to do with {extension}", 415) from e
        elif (extension is None and
              'text/html' in request.accept_mimetypes and
              '*/*' in request.accept_mimetypes):
            # if we get a browser request without an extension
            # then return the usual crappy page as if it were
            # a redirect or the page itself
            # TODO actual browser detection
            return extension, mimetype, self.mimetypes[None]

        try:
            func = self.mimetypes[mimetype]
        except KeyError as e:
            raise exc.UnsupportedType(f"don't know what to do with {mimetype}", 415) from e

        return extension, mimetype, func

    def __call__(self, request, mgraph, user, id, object_to_existing,
                 title=None, labels=None):
        extension, mimetype, func = self.check(request)

        if not mgraph.g:
            if mimetype == 'text/html':
                return abort(404)
            else:
                return '', 404

        out = func(request, mgraph, user, id,
                   object_to_existing, title, mimetype, labels)
        code = 303 if mimetype == 'text/html' and extension != 'html' else 200  # cool uris
        to_plain = 'ttl', 'nt', 'n3', 'nq'
        headers = {'Content-Type': ('text/plain; charset=utf-8'
                                    if extension in to_plain
                                    else mimetype)}
        return out, code, headers

    def iri_selection_logic(self):  # TODO
        """ For a given set of conversion rules (i.e. from a user)
            when given an iri, convert it to the preferred form.
            Use a precedence list base on
            1. users
            2. orgs
            3. curie prefixes
            4. iri prefixes (?)
            5. etc ...
            See the ilx spec doc for this. We want this in its own class
            and will just be calling it from here. """

    def curie_selection_logic(self):
        """ Same as iri selection but for curies """

    def html(self, request, mgraph, user, id, object_to_existing,
             title, mimetype, labels):
        graph = mgraph.g
        cts = CustomTurtleSerializer(graph)
        gsortkey = cts._globalSortKey
        psortkey = lambda p: cts.predicate_rank[p]
        def sortkey(triple):
            s, p, o = triple
            return gsortkey(s), psortkey(p), gsortkey(o)

        trips = (tuple(atag(e, mgraph.qname(e))
                       if isinstance(e, rdflib.URIRef) and e.startswith('http')
                       else str(e)
                       for e in t)
                 for t in sorted(graph, key=sortkey))

        return htmldoc(render_table(trips, 'subject', 'predicate', 'object'),
                       title=title,
                       styles=(table_style,))

    def renderPreferences(self, user, graph, id):
        uri = rdflib.URIRef(f'http://uri.interlex.org/{user}/ilx_{id}')  # FIXME reference_host from db ...
        new_graph = rdflib.Graph()
        [new_graph.bind(p, n) for p, n in graph.namespaces()]
        ranking = ('UBERON', 'CHEBI', 'GO', 'PR', 'NCBITaxon', 'IAO', 'BIRNLEX', 'NLX',
                   # FIXME TODO much more complex than this and source user rankings from db ...
                   'NDA.CDE', 'ILX')
        not_in_rank = len(ranking) + 1
        def by_rank(oid):
            # FIXME preferring lower sorting identifiers seems
            # like a bad hack
            try:
                #print('AAAAAAAAA', oid, oid.prefix)
                return ranking.index(oid.prefix), '', oid.suffix
            except ValueError:
                # fail over to ilx, but alpha in even of weirdness
                return not_in_rank, oid.prefix, oid.suffix

        existing = sorted((OntId(o)
                           for _, o in chain(graph[:ilxtr.hasExistingId:],
                                             ((None, uri),))),  # uri backstops unmapped prefixes
                          key=by_rank)  # can use [uri::] for now because of the mysql logic
        preferred_iri = existing[0].u
        if preferred_iri != uri:
            new_graph.add((preferred_iri, ilxtr.hasIlxId, uri))
        #print(repr(uri), repr(preferred_iri))
        for s, p, o in graph:
            if o == preferred_iri and p == ilxtr.hasExistingId and preferred_iri != uri:
                # prevent the preferred iri from being listed as an existing iri of itself
                continue
            elif preferred_iri == uri == o and p == ilxtr.hasIlxId:
                # prevent ilx ids from being listed as ilx ids of themselves
                # mysql case
                continue

            if s == uri:
                ns = preferred_iri
            else:
                ns = s
            np = p  # TODO
            no = o  # TODO
            t = (ns, np, no)
            #print(repr(s), repr(uri), repr(ns))  # TODO user iri vs base iri issues
            new_graph.add(t)
        return preferred_iri, new_graph

    def graph(self, request, mgraph, user, id, object_to_existing,
              title, mimetype):
        preferred_iri, graph = self.renderPreferences(user, mgraph.g, id)
        nowish = datetime.utcnow()  # request doesn't have this
        epoch = nowish.timestamp()
        iso = nowish.isoformat()
        ontid = rdflib.URIRef(f'http://uri.interlex.org/{user}'
                              f'/ontologies/ilx_{id}')
        ver_ontid = rdflib.URIRef(ontid + f'/version/{epoch}/ilx_{id}')
        # FIXME this should be the preferred it ...
        graph.add((ontid, rdf.type, owl.Ontology))
        graph.add((ontid, owl.versionIRI, ver_ontid))
        graph.add((ontid, owl.versionInfo, rdflib.Literal(iso)))
        graph.add((ontid, isAbout, preferred_iri))
        graph.add((ontid, rdfs.comment, rdflib.Literal('InterLex single term result for '
                                                       f'{user}/ilx_{id} at {iso}')))
        # TODO consider data identity?
        ng = cull_prefixes(graph, {k:v for k, v in graph.namespaces()})  # ICK as usual
        return ng

    def ttl(self, request, mgraph, user, id, object_to_existing,
            title, mimetype, labels):
        ng = self.graph(request, mgraph, user, id,
                        object_to_existing, title, mimetype)
        return ng.g.serialize(format='nifttl')

    def ttl_html(self, request, mgraph, user, id, object_to_existing,
                 title, mimetype, labels):
        ng = self.graph(request, mgraph, user, id,
                        object_to_existing, title, mimetype)
        body = ng.g.serialize(format='htmlttl', labels=labels).decode()
        # TODO owl:Ontology -> <head><meta> prov see if there is a spec ...
        return htmldoc(body,
                       title=title,
                       styles=(table_style, ttl_html_style))

    def rdf_ser(self, request, mgraph, user, id, object_to_existing,
                title, mimetype, labels, **kwargs):
        ng = self.graph(request, mgraph, user, id,
                        object_to_existing, title, mimetype)
        return ng.g.serialize(format=mimetype, **kwargs)

    def jsonld(self, request, mgraph, user, id, object_to_existing,
               title, mimetype, labels):
        return self.rdf_ser(request, mgraph, user, id,
                            object_to_existing, title, mimetype, auto_compact=True)

    def json(self, request, mgraph, user, id, object_to_existing,
             title, mimetype):
        # lol
        graph = mgraph.g
        ng = cull_prefixes(graph, {k:v for k, v in graph.namespaces()})  # ICK as usual
        out = {'prefixes': {k:v for k, v in ng.g.namespaces()},
               'triples': [[mgraph.qname(e)
                            if isinstance(e, rdflib.URIRef) and e.startswith('http')
                            else str(e)
                            for e in t ]
                           for t in graph]}
        return json.dumps(out)
