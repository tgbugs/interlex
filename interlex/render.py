import json
from datetime import datetime
import rdflib
from flask import abort  # FIXME decouple this??
from pyontutils.ttlser import CustomTurtleSerializer
from pyontutils.htmlfun import atag, htmldoc
from pyontutils.htmlfun import table_style, render_table
from pyontutils.qnamefix import cull_prefixes
from pyontutils.closed_namespaces import rdf, rdfs, owl

class TripleRender:
    def __init__(self):
        self.mimetypes = {'text/html':self.html,
                          'application/json':self.json,
                          'text/ttl':self.ttl,  # not real
                          'text/turtle':self.ttl,}

    def __call__(self, request, mgraph, user, id, object_to_existing, title=None):
        mimetype = request.mimetype if request.mimetype else 'text/html'
        if not mgraph.g:
            if mimetype == 'text/html':
                return abort(404)
            else:
                return '', 404
        try:
            out = self.mimetypes[mimetype](request, mgraph, user, id, object_to_existing, title)
            code = 303 if mimetype == 'text/html' else 200  # cool uris
            return out, 200, {'Content-Type': mimetype}
        except KeyError:
            print(mimetype)
            return abort(415)

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

    def html(self, request, mgraph, user, id, object_to_existing, title):
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

    def ttl(self, request, mgraph, user, id, object_to_existing, title):
        graph = mgraph.g
        nowish = datetime.utcnow()  # request doesn't have this
        epoch = nowish.timestamp()
        iso = nowish.isoformat()
        ontid = rdflib.URIRef(f'http://uri.interlex.org/{user}'
                              f'/ontologies/ilx_{id}')
        ver_ontid = rdflib.URIRef(ontid + f'/version/{epoch}/ilx_{id}')
        graph.add((ontid, rdf.type, owl.Ontology))
        graph.add((ontid, owl.versionIRI, ver_ontid))
        graph.add((ontid, owl.versionInfo, rdflib.Literal(iso)))
        graph.add((ontid, rdfs.comment, rdflib.Literal('InterLex single term result for '
                                                       f'{user}/ilx_{id} at {iso}')))
        # TODO consider data identity?
        ng = cull_prefixes(graph, {k:v for k, v in graph.namespaces()})  # ICK as usual
        return ng.g.serialize(format='nifttl')

    def json(self, request, mgraph, user, id, object_to_existing, title):
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
