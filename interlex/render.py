import io
import csv
import json
from pathlib import PurePosixPath
from datetime import datetime
from itertools import chain
import rdflib
from flask import abort, Response  # FIXME decouple this??
from htmlfn import atag, htmldoc
from htmlfn import table_style, render_table, ttl_html_style
from ttlser import CustomTurtleSerializer
from pyontutils.core import OntId, OntGraph
from pyontutils.utils import isoformat, utcnowtz
from pyontutils.qnamefix import cull_prefixes
from pyontutils.namespaces import isAbout, ilxtr, ILX, definition, NIFRID
from pyontutils.closed_namespaces import rdf, rdfs, owl
from interlex import exceptions as exc
from interlex.utils import log
from interlex.namespaces import ilxr

class TripleRender:

    default_prefix_ranking = ('BFO',
                              'RO',
                              'PATO',
                              'UBERON',
                              'CHEBI',
                              'GO',
                              'PR',
                              'NCBITaxon',
                              'IAO',
                              'FMA',
                              'EMAPA',
                              'PAXRAT',
                              'PAXMUS',
                              'PAXSPN',
                              'npokb',
                              'BIRNLEX',
                              'SCR',
                              'RRID',
                              'NLX',
                              # FIXME TODO much more complex than this and source group rankings from db ...
                              'NDA.CDE',
                              'ILX',
                              'TMP')
    def __init__(self):
        self.mimetypes = {None:self.html,
                          'text/html':self.ttl_html,
                          'text/turtle+html': self.ttl_html,
                          'application/json':self.json,
                          'application/ld+json':self.jsonld,
                          'text/turtle':self.ttl,
                          'application/rdf+xml':self.rdf_ser,
                          'application/n-triples':self.rdf_ser,
                          'text/n3':self.rdf_ser,
                          'application/vnd.scicrunch.interlex+json': self.jsonilx,
                          'text/csv': self.tabular,
                          'text/tsv': self.tabular,
                          #'application/n-quads':self.rdf_ser  # TODO need qualifier context store
        }
        self.extensions = {'html': 'text/turtle+html',
                           'json': 'application/json',
                           'jsonilx': 'application/vnd.scicrunch.interlex+json',
                           'jsonld': 'application/ld+json',
                           'ttl': 'text/turtle',  # InterLex rdf?
                           'xml': 'application/rdf+xml',
                           'owl': 'application/rdf+xml',  # FIXME conversion rules for owl?
                           'nt': 'application/n-triples',
                           'n3': 'text/n3',
                           #'nq': 'application/n-quads',  # TODO need qualifier context store
                           'csv': 'text/csv',
                           'tsv': 'text/tsv',
        }

    def check(self, request):
        best = request.accept_mimetypes.best
        mimetype = (best if best and  # sometimes best can be None
                    best != '*/*' and
                    'application/signed-exchange' not in best
                    else 'text/html')
        extension = (request.view_args['extension'] if
                     'extension' in request.view_args else
                     None)

        mimetypes = [mimetype for mimetype, number in request.accept_mimetypes]
        if extension:
            try:
                mimetype = self.extensions[extension]
            except KeyError as e:
                raise exc.UnsupportedType(f"don't know what to do with {extension}", 415) from e
        elif (extension is None and
              'text/turtle+html' not in mimetypes and
              'text/html' in request.accept_mimetypes and
              '*/*' in mimetypes):
            # */* is 'in' but not really for text/html requests ...
            # if we get a browser request without an extension
            # then return the usual crappy page as if it were
            # a redirect or the page itself
            # TODO actual browser detection
            return extension, mimetype, self.mimetypes[None]

        try:
            func = self.mimetypes[mimetype]
        except KeyError as e:
            raise exc.UnsupportedType(f"don't know what to do with {mimetype}", 415) from e

        if mimetype == 'text/turtle+html':
            mimetype = 'text/html; charset=utf-8'

        return extension, mimetype, func

    def __call__(self, request, graph, group, frag_pref, id, object_to_existing,
                 title=None, labels=None, ontid=None, ranking=default_prefix_ranking,
                 ilx_stubs=False, redirect=True, for_alt=False, simple=False, internal_links=False):
        extension, mimetype, func = self.check(request)

        if not graph:
            if mimetype == 'text/html':
                return abort(404)
            else:
                return '', 404

        if labels is None:
            labels = {}

        out = func(request, graph, group, frag_pref, id, object_to_existing,
                   title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links)

        isont = '/ontologies/' in request.url  # FIXME this seems like it is not the right place to deal with this also FIXME bad way to do this
        code = (303
                if redirect and mimetype == 'text/html' and
                extension != 'html' and not isont
                else 200)  # cool uris
        to_plain = 'ttl', 'nt', 'n3', 'nq'
        headers = {'Content-Type': ('text/plain; charset=utf-8'
                                    if extension in to_plain
                                    else mimetype)}
        return out, code, headers

    def iri_selection_logic(self):  # TODO
        """ For a given set of conversion rules (i.e. from a group)
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

    def html(self, request, graph, group, frag_pref, id, object_to_existing,
             title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        cts = CustomTurtleSerializer(graph)
        gsortkey = cts._globalSortKey
        psortkey = lambda p: cts.predicate_rank[p]
        def sortkey(triple):
            s, p, o = triple
            return gsortkey(s), psortkey(p), gsortkey(o)

        trips = (tuple(atag(e, e.n3(graph.namespace_manager))
                       if isinstance(e, rdflib.URIRef) and e.startswith('http')
                       else str(e)
                       for e in t)
                 for t in sorted(graph, key=sortkey))

        return htmldoc(render_table(trips, 'subject', 'predicate', 'object'),
                       title=title,
                       styles=(table_style,))

    def renderPreferencesAlt(self, group, graph, frag_pref, id, ranking=default_prefix_ranking, ilx_stubs=False):
        # list of predicates where objects should not be rewritten
        # TODO maybe make it possible to add to this?
        # and/or make it possible to get the raw unrendered form more easily
        p_no_rewrite=(
            ilxtr.hasExistingId,  # don't change existing ids
            #ilxtr.hasIlxId,      # handled independently for now # TODO simplify the impl
        )

        new_graph = OntGraph()
        graph.namespace_manager.populate(new_graph)

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

        def getPreferred(graph):
            out = {}
            for s, o in sorted(graph[:ilxtr.hasExistingId:], key=lambda so: by_rank(OntId(so[1]))):
                if s not in out:
                    out[s] = o

            return out

        preferred_all = getPreferred(graph)

        hasIlxId = {}
        hasLabel = {}
        for s, p, o in graph:
            if s in preferred_all:
                # XXX FIXME this can result in multiple labels
                # if deprecated terms have had their label changed
                # or if the terms had distinct labels to start with
                ns = preferred_all[s]
            else:
                ns = s

            if ns not in hasIlxId:
                hasIlxId[ns] = False

            if p == ilxtr.hasIlxId:
                #log.debug((s, p, o))
                new_graph.add((ns, p, o))
                hasIlxId[ns] = True
                continue
            elif p == rdfs.label:
                __argh = False
                if ns not in hasLabel:
                    hasLabel[ns] = [(s, o)]
                else:
                    if o not in hasLabel[ns]:
                        __argh = True

                    hasLabel[ns].append((s, o))

                if __argh:
                    log.warning(f'MULTIPLE LABELS FOR {ns}\n{hasLabel[ns]}')

                continue

            if p in preferred_all:
                np = preferred_all[p]
            else:
                np = p

            if o in preferred_all and p not in p_no_rewrite:
                no = preferred_all[o]
            else:
                no = o

            t = (ns, np, no)
            new_graph.add(t)

        for ns, sobjs in hasLabel.items():
            objs = [o for s, o in sorted(sobjs)]
            for o in objs[:1]:
                new_graph.add((ns, rdfs.label, o))

            if len(objs) > 1:
                for o in objs[1:]:
                    new_graph.add((ns, ilxtr.deprecatedLabel, o))

        if not [k for k, v in hasIlxId.items() if v]:
            # handle old case where pref and ilx were not present
            cands = list(graph.subjects(rdf.type, owl.Class))
            if len(cands) == 1:
                s = OntId(cands[0])
                su = s.u
                if s.prefix == 'ILX':
                    new_graph.add((su, ilxtr.hasIlxId, su))
                    new_graph.add((su, ilxtr.hasIlxPreferredId, su))
                    hasIlxId[su] = True
                    preferred_all[su] = su

        for k, v in hasIlxId.items():
            if not v and not isinstance(k, rdflib.BNode):
                new_graph.add((k, ilxtr.MISSING_ILX_ID, rdflib.Literal(True)))

        if ilx_stubs:
            for ilx, pref in preferred_all.items():
                if ilx != pref:
                    new_graph.add((ilx, rdfs.label, next(graph[ilx:rdfs.label:])))

        if id is not None:
            # FIXME is_termset horribly inefficient and brittle
            termsets = list(graph[:rdf.type:ilxr.TermSet])
            is_termset = termsets and [t for t in termsets if t.endswith(id)]
            if not is_termset:
                _uri = f'http://uri.interlex.org/{group}/{frag_pref}_{id}'
                uri = rdflib.URIRef(_uri)  # FIXME reference_host from db ...
                try:
                    preferred_iri = preferred_all[uri]
                except KeyError as e:
                    log.debug('printing graph one line below this')
                    graph.debug()
                    log.debug('printing graph one line above this')
                    log.exception(e)
                    log.error('the input graph probably has a bad structure '
                            'probably need to sync from interlex again or write a lifting rule')
                    preferred_iri = None
            else:
                preferred_iri = None
        else:
            preferred_iri = None

        return preferred_iri, new_graph

    def graph(self, request, graph, group, frag_pref, id, object_to_existing,
              title, mimetype, ontid, ranking=default_prefix_ranking, ilx_stubs=False, for_alt=False,
              simple=False,):
        # FIXME abstract to replace id with ontology name ... local ids are hard ...
        if simple:
            return graph
        elif for_alt:
            preferred_iri, rgraph = self.renderPreferencesAlt(group, graph, frag_pref, id, ranking, ilx_stubs)
        else:
            # FIXME TODO
            preferred_iri, rgraph = rdflib.URIRef(f'http://uri.interlex.org/{group}/{frag_pref}_{id}'), graph

        # FIXME nowish should come from the last change or the last transitive change
        nowish = utcnowtz()  # request doesn't have this
        epoch = int(nowish.timestamp())  # truncate to second to match iso
        iso = isoformat(nowish)
        if ontid is None:
            ontid = rdflib.URIRef(f'http://uri.interlex.org/{group}'
                                  f'/ontologies/{frag_pref}_{id}')
            ver_ontid = rdflib.URIRef(ontid + f'/version/{epoch}/{frag_pref}_{id}')
        else:
            po = PurePosixPath(ontid)
            base, rest = ontid.rsplit('/', 1)
            ontid = rdflib.URIRef(ontid)
            ver_ontid = rdflib.URIRef(f'{base}/{po.stem}/version/{epoch}/{po.name}')

        # FIXME this should be the preferred it ...
        rgraph.add((ontid, rdf.type, owl.Ontology))
        rgraph.add((ontid, owl.versionIRI, ver_ontid))
        rgraph.add((ontid, owl.versionInfo, rdflib.Literal(iso)))
        if preferred_iri is not None:
            rgraph.add((ontid, isAbout, preferred_iri))
            rgraph.add((ontid, rdfs.comment, rdflib.Literal('InterLex single term result for '
                                                            f'{group}/{frag_pref}_{id} at {iso}')))

        # TODO consider data identity?
        return cull_prefixes(rgraph, {k:v for k, v in rgraph.namespaces()}).g  # ICK as usual

    def ttl(self, request, graph, group, frag_pref, id, object_to_existing,
            title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        rgraph = self.graph(request, graph, group, frag_pref, id,
                            object_to_existing, title, mimetype, ontid, ranking,
                            ilx_stubs, for_alt=for_alt, simple=simple)
        return rgraph.serialize(format='nifttl')

    def ttl_html(self, request, graph, group, frag_pref, id, object_to_existing,
                 title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        rgraph = self.graph(request, graph, group, frag_pref, id,
                            object_to_existing, title, mimetype, ontid, ranking,
                            ilx_stubs, for_alt=for_alt, simple=simple)
        body = rgraph.serialize(format='htmlttl', labels=labels, internal_links=internal_links).decode()
        # TODO owl:Ontology -> <head><meta> prov see if there is a spec ...
        return htmldoc(body,
                       title=title,
                       styles=(table_style, ttl_html_style))

    def rdf_ser(self, request, graph, group, frag_pref, id, object_to_existing,
                title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links, **kwargs):
        rgraph = self.graph(request, graph, group, frag_pref, id,
                            object_to_existing, title, mimetype, ontid, ranking,
                            ilx_stubs, for_alt, simple)
        return rgraph.serialize(format=mimetype, **kwargs)

    def jsonld(self, request, graph, group, frag_pref, id, object_to_existing,
               title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        return self.rdf_ser(request, graph, group, frag_pref, id,
                            object_to_existing, title, mimetype, labels, ontid, ranking,
                            ilx_stubs, for_alt, simple, internal_links, auto_compact=True)

    def json(self, request, graph, group, frag_pref, id, object_to_existing,
             title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        # lol
        rgraph = cull_prefixes(graph, {k:v for k, v in graph.namespaces()}).g  # ICK as usual
        out = {'prefixes': {k:v for k, v in rgraph.namespaces()},
               'triples': [[e.n3(rgraph.namespace_manager)
                            if isinstance(e, rdflib.URIRef) and e.startswith('http')
                            else str(e)
                            for e in t]
                           for t in graph]}
        return json.dumps(out)

    def jsonilx(self, request, graph, group, frag_pref, id, object_to_existing,
                title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        # TODO
        return {}

    def tabular(self, request, graph, group, frag_pref, id, object_to_existing,
                title, mimetype, labels, ontid, ranking, ilx_stubs, for_alt, simple, internal_links):
        # spec is currently
        # ILX ID, label, synonyms, description, comment, Preferred ID, Other IDs.
        # Interlex URL (community specific so that it goes to REVA, eg) (no way do this one right now)

        synpreds = (
            #fma.synonym,
            NIFRID.synonym,
            rdflib.URIRef('http://purl.org/sig/ont/fma/synonym'),
            ILX['0737161'],  # exact
            ILX['0737162'],  # related
            ILX['0737163'],  # narrow
            ILX['0737164'],  # broad
        )
        col_preds = {
            'label': [rdfs.label],
            'synonyms': synpreds,
            'definition': [definition],
            'subClassOf': [rdfs.subClassOf],
            'iri-preferred': [ilxtr.hasIlxPreferredId],
            'iri-existing': [ilxtr.hasExistingId],
            'type': [rdf.type,],
        }
        sep = ',' if mimetype == 'text/csv' else '\t'
        unit_sep = b'\x1f'.decode()  # ascii unit sep, joins multiple values in a single cell
        # ironically/annoyingly even if we used the ascii control chars for this there is
        # still the need for a non-printing charachter for when we have to flatten a bunch of
        # separate values into a single cell
        def genrows():
            yield sep.join(['iri'] + list(col_preds)) + '\n'
            out = io.StringIO()
            writer = csv.writer(out, delimiter=sep, lineterminator='\n')
            for s in sorted(set(graph.subjects())):
                if isinstance(s, rdflib.BNode):
                    continue
                cells = [s]
                for header, preds in col_preds.items():
                    raw = unit_sep.join(str(o) for p in preds for o in graph[s:p])
                    cells.append(raw)
                writer.writerow(cells)
                yield out.getvalue()
                out.seek(0)
                out.truncate()

        # FIXME decouple use of Response ???
        return Response(genrows(), mimetype=mimetype)
