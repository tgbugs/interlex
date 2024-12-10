import gc
import os
import time
import subprocess
from pathlib import Path, PurePath
from collections import defaultdict
from urllib.parse import urlparse
import rdflib
import hashlib
import requests
import sqlalchemy as sa
from sqlalchemy.sql import text as sql_text
from pyontutils.core import OntGraph, OntId, OntResIri, OntResGit
from pyontutils.utils_fast import TermColors as tc, chunk_list
from pyontutils.identity_bnode import IdentityBNode
from pyontutils.namespaces import definition
from pyontutils.namespaces import makeNamespaces, ILX, NIFRID, ilxtr
from pyontutils.namespaces import rdf, owl
from pyontutils.combinators import annotation
from interlex import exceptions as exc
from interlex.auth import Auth
from interlex.core import printD, makeParamsValues
from interlex.utils import log
from interlex.dump import Queries

log = log.getChild('load')
ilxr, *_ = makeNamespaces('ilxr')


def do_gc():
    log.debug('gc-pre')
    gc.collect()
    log.debug('gc-post')


def async_load(iri=None, data=None, max_wait=10):
    async def dispatch():
        async def sleep_and_return_jobid():
            await sleep(max_wait)

        async with TaskGroup('', wait=any) as tg:
            tg.spawn(sleep_and_return_jobid)
            # NOTE do not cancel the load job
            # just let it do its thing (somehow)


def rapper(serialization, input='rdfxml', output='ntriples'):
    """
    -i FORMAT, --input FORMAT   Set the input format/parser to one of:
    rdfxml          RDF/XML (default)
    ntriples        N-Triples
    turtle          Turtle Terse RDF Triple Language
    trig            TriG - Turtle with Named Graphs
    rss-tag-soup    RSS Tag Soup
    grddl           Gleaning Resource Descriptions from Dialects of Languages
    guess           Pick the parser to use using content type and URI
    rdfa            RDF/A via librdfa
    nquads          N-Quads

    -o FORMAT, --output FORMAT  Set the output format/serializer to one of:
    ntriples        N-Triples (default)
    turtle          Turtle Terse RDF Triple Language
    rdfxml-xmp      RDF/XML (XMP Profile)
    rdfxml-abbrev   RDF/XML (Abbreviated)
    rdfxml          RDF/XML
    rss-1.0         RSS 1.0
    atom            Atom 1.0
    dot             GraphViz DOT format
    json-triples    RDF/JSON Triples
    json            RDF/JSON Resource-Centric
    html            HTML Table
    nquads          N-Quads """
    p = subprocess.Popen(['rapper', '-i', input, '-o', output, '-', 'DEADBEEF'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)

    if input == 'rdfxml':
        # the bug introducing cycles is in rapper NOT rdflib, it is caused by an
        # off by 1 error between rapper and whatever is creating the genids for
        # cl, uberon etc. the end result is that rapper takes the explicit genid
        # blanknodes as is assuming they are correctly aligned -- sometimes they
        # are not, the fix is to change the genid prefix to one that won't
        # collide with the rapper internal genid bnode prefix

        serialization = serialization.replace(
            b'rdf:nodeID="genid', b'rdf:nodeID="nocolgenid')

    out, err = p.communicate(input=serialization)
    return out


def timestats(times):
    deltas = {}
    deltas['total'] = times['end'] - times['begin']
    if 'init_end' in times:  # FIXME how do we miss this!?
        deltas['init'] = times['init_end'] - times['init_begin']
    if 'fetch_end' in times:
        deltas['fetch'] = times['fetch_end'] - times['fetch_begin']
    if 'graph_end' in times:
        deltas['graph'] = times['graph_end'] - times['graph_begin']
    if 'load_end' in times:
        deltas['load'] = times['load_end'] - times['load_begin']
    if 'commit_end' in times:
        deltas['commit'] = times['commit_end'] - times['commit_begin']
    return deltas


# TODO verify that the identity of a graph is the same as the identity of the
# parts that we break it into here, it should be, given the algorithem we use
class GraphIdentities:
    def __init__(self, graph):
        self.debug = False
        self._transaction_cache_identities = set()

        self.graph = graph
        # self._subgraphs = None
        # TODO there are two types of subgraphs
        # named subgraphs, and anonymous subgraphs
        # the anon subgraphs are bound by identity to their data_identity

        # in the event someone is roundtripping an ilx qualifier section
        # this would be the bound meta-meta-data
        self._bound_qualifier = None

        self._curies = None
        self._bound_name = None
        #self._metadata = None  # not actually used
        self._metadata_named = None
        self._metadata_unnamed = None
        #self._data = None  # not actually used
        self._data_named = None
        self._data_unnamed = None

        self._curies_identity = None
        #self._subgraph_identities = None  # not used
        self._connected_subgraph_identities = None
        self._metadata_connected_subgraph_identities = None
        self._data_connected_subgraph_identities = None
        self._free_subgraph_identities = None
        self._connected_and_free_subgraph_identities = None
        self._bound_name_identity = None
        self._metadata_identity = None
        self._data_identity = None

    @property
    def curies_identity(self):
        return self.get_identity('curies')

    @property
    def bound_qualifiers(self):
        """ Note: this is technically bound qualifier identity since quals are hashes """
        # is there any reason NOT to pub this in as part of the metadata
        # rather than as its own section? We already technically taint
        # the serialization identity no matter what, so I don't see the issue
        # FIXME SECURITY we will need to restrict which existing qualifiers can
        # be used as source qualifiers so that someone doesn't accidentally
        # create a qualifier that says 'delete all of interlex' though I suspect
        # that we might be able to be smart about it and translate that into the
        # more efficient "don't show me triples from these sources"
        yield from self.graph[self.bound_name:ilxtr.sourceQualifier:]

    @property
    def bound_name_identity(self):
        if self._bound_name_identity is None:
            ident = IdentityBNode(self.bound_name).identity
            self._bound_name_identity = ident

        return self._bound_name_identity

    @property
    def metadata_identity(self):
        if not hasattr(self, '_cache_mi'):
            self._cache_mi = self.get_identity('metadata')

        return self._cache_mi

    @property
    def data_identity(self):  # FIXME! this should be data + free_subgraph_identities XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        # the head triple in all cases is bound to the ontology name
        if not hasattr(self, '_cache_di'):
            # we cache here even if _data_identity is also cached by get_identity
            moar = sorted(self.free_subgraph_identities)
            self._cache_di = self.get_identity('data')

        return self._cache_di

    @property
    def data_named_subject_identities(self):
        if not hasattr(self, '_cache_dnsi'):
            bn = self.bound_name
            #bids = set(self._blank_identities.values())
            named_subjects = [s for s in self.graph.subjects(unique=True) if isinstance(s, rdflib.URIRef) and s != bn]
            self._cache_dnsi = {IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity: s for s in named_subjects}
            #self._cache_dnsi = {v:k for k, v in self._ibn.subject_embedded_identities.items() if isinstance(k, rdflib.URIRef) and k != bn}

        return self._cache_dnsi

    @property
    def subgraph_identities(self):
        return {**self.connected_subgraph_identities, **self.free_subgraph_identities, **self.connected_and_free_subgraph_identities}

    @property
    def connected_subgraph_identities(self):
        #return {**self.metadata_connected_subgraph_identities, **self.data_connected_subgraph_identities}
        if self._connected_subgraph_identities is None:
            self.process_graph()

        return self._connected_subgraph_identities

    @property
    def metadata_connected_subgraph_identities(self):
        raise NotImplementedError('metadata connected has been merged')
        if self._metadata_connected_subgraph_identities is None:
            self.process_graph()

        return self._metadata_connected_subgraph_identities

    @property
    def data_connected_subgraph_identities(self):
        raise NotImplementedError('data connected has been merged')
        if self._data_connected_subgraph_identities is None:
            self.process_graph()

        return self._data_connected_subgraph_identities

    @property
    def free_subgraph_identities(self):
        if self._free_subgraph_identities is None:
            self.process_graph()

        return self._free_subgraph_identities

    @property
    def connected_and_free_subgraph_identities(self):
        if self._connected_and_free_subgraph_identities is None:
            self.process_graph()

        return self._connected_and_free_subgraph_identities

    # the things themselves
    @property
    def curies(self):
        """ Could be abstracted to 'local naming conventions' """
        # NOTE that locally unique prefixes can match full names as well
        # TODO these are only associated with one ore more serialization identifiers
        # we will keep them around only so that we can reproduce the original convetions
        # exactly
        if self._curies is None:
            self._curies = tuple(sorted(
                #(locally_unique_prefix, globally_unique_prefix)
                (curie_prefix, iri_prefix)
                for curie_prefix, iri_prefix in self.graph.namespaces()
            ))  # FIXME uniqueness :/

        return self._curies

    @property
    def bound_name(self):
        if self._bound_name is None:
            subjects = list(self.graph.boundIdentifiers)
            #subjects = self.graph[:rdf.type:owl.Ontology]  # FIXME use OntResIri
            # FIXME this should be erroring on no bound names?
            if subjects:
                self._bound_name = subjects[0]
                if len(subjects) > 1:
                    raise exc.LoadError(
                        'More than one owl:Ontology in this file!\n'
                        f'{self.bound_name}\n{subjects[1:]}\n', 409)

        return self._bound_name

    @property
    def metadata(self):
        yield from self.metadata_named
        # FIXME getting triples to condense up to pairs is going to be a pita
        yield from self.metadata_unnamed

    @property
    def metadata_raw(self):
        _metadata_subject_or_dangle_bnodes = set()
        nexts = [self.bound_name]
        for i in range(9999):  # avoid infinite loop
            if not nexts:
                break

            _nexts = []
            for s in nexts:
                for p, o in self.graph[s::]:
                    # XXX metadata is NOT pairs as soon as bnodes appear
                    # the subject might be None at the top ... ugh this
                    # makes things annoying
                    yield s, p, o
                    if isinstance(o, rdflib.BNode):
                        _nexts.append(o)
                        _metadata_subject_or_dangle_bnodes.add(o)
            nexts = _nexts

        else:
            breakpoint()
            raise ValueError('cycle in graph ???')

        self._metadata_subject_or_dangle_bnodes = _metadata_subject_or_dangle_bnodes

    @property
    def metadata_named(self):
        # FIXME this is utterly broken now too :/
        # the question is whether the named subset includes only triples without any bnodes
        # and I think historically named has to do with whether the object is a bnode
        # not whether the subject is a uriref
        for s, p, o in self.metadata_raw:
            if not isinstance(s, rdflib.BNode) and not isinstance(o, rdflib.BNode):
                yield None, p, o

    @property
    def metadata_unnamed(self):
        if not hasattr(self, '_blank_identities'):
            self.process_graph()

        for s, p, o in self.metadata_raw:
            if isinstance(s, rdflib.BNode) or isinstance(o, rdflib.BNode):
                if isinstance(s, rdflib.URIRef):
                    s = None
                else:
                    try:
                        sid = self._blank_identities[s]
                        ssgid, srep, sind = self._subgraph_and_integer[s]
                        _s = sid, srep, sind, ssgid
                    except KeyError as e:
                        if p in (rdf.rest, rdf.first):
                            _s = s
                            srep = None
                        else:
                            raise e

                    s = _s

                if isinstance(o, rdflib.BNode):
                    try:
                        oid = self._blank_identities[o]
                        osgid, orep, oind = self._subgraph_and_integer[o]
                        _o = oid, orep, oind, osgid
                    except KeyError as e:
                        if p in (rdf.rest, rdf.first):
                            _o = o
                            orep = None
                        else:
                            raise e

                    o = _o

                yield s, p, o

    @property
    def data(self):
        yield from self.data_named
        yield from self.data_unnamed

    @property
    def data_raw(self):
        bn = self.bound_name
        list(self.metadata_raw)  # populate self._metadata_subject_or_dangle_bnodes
        # FIXME this is now quite a bit slower than it was originally
        # and it is doing a whole lot of rework :/
        yield from (t for t in self.graph if t[0] != bn and t[0] not in self._metadata_subject_or_dangle_bnodes)

    @property
    def data_named(self):
        for t in self.data_raw:
            if not any(isinstance(e, rdflib.BNode) for e in t):
                yield t

    @property
    def data_unnamed(self):
        if not hasattr(self, '_blank_identities'):
            self.process_graph()

        for s, p, o in self.data_raw:
            if any(isinstance(e, rdflib.BNode) for e in (s, p, o)):  # to ensure symmetry with data_named above
                if isinstance(s, rdflib.BNode):
                    try:
                        sid = self._blank_identities[s]
                        ssgid, srep, sind = self._subgraph_and_integer[s]
                        _s = sid, srep, sind, ssgid
                    except KeyError as e:
                        if p in (rdf.rest, rdf.first):
                            _s = s
                            srep = None
                        else:
                            raise e
                else:
                    _s = s

                _p = p

                if isinstance(o, rdflib.BNode):
                    try:
                        oid = self._blank_identities[o]
                        osgid, orep, oind = self._subgraph_and_integer[o]
                        _o = oid, orep, oind, osgid
                    except KeyError as e:
                        if p in (rdf.rest, rdf.first):
                            _o = o
                            orep = None
                        else:
                            raise e
                else:
                    _o = o

                yield _s, _p, _o

    @property
    def subgraphs(self):
        # TODO axioms and annotations as special kinds of subgraphs?
        yield from self.subgraph_identities.values()

    @property
    def connected_subgraphs(self):
        yield from self.metadata_connected_subgraphs
        yield from self.data_connected_subgraphs

    @property
    def metadata_connected_subgraphs(self):
        yield from self.metadata_connected_subgraph_identities.values()

    @property
    def data_connected_subgraphs(self):
        yield from self.data_connected_subgraph_identities.values()

    @property
    def free_subgraphs(self):
        yield from self.free_subgraph_identities.values()

    # counts

    @property
    def bound_name_count(self):
        return len(list(self.graph.boundIdentifiers))  # see self.graph.metadata_type_markers
        #if self.bound_name:
            #return 1

    @property
    def curies_count(self):
        return len(self.curies)

    @property
    def metadata_named_count(self):  # FIXME unnamed should be called tainted
        return len(list(self.metadata))

    @property
    def metadata_connected_counts(self):
        return {i:len(sg) for i, sg in self.metadata_connected_subgraph_identities.items()}

    @property
    def metadata_count(self):
        #return self.metadata_named_count + sum(self.metadata_connected_counts.values())
        if self.bound_name:
            return len(list(self.graph.subject_triples(self.bound_name)))
        else:
            return 0

    @property
    def data_named_count(self):  # FIXME unnamed should be called tainted
        return len(list(self.data_named))

    @property
    def data_connected_counts(self):
        return {i:len(sg) for i, sg in self.data_connected_subgraph_identities.items()}

    @property
    def data_named_subject_counts(self):
        # FIXME TODO make sure these match on roundtrip
        return {k:
                #len(self._ibn.subject_identities[k])
                len(self._ibn._alt_debug['subject_identities'][k])
                for k in self.data_named_subject_identities}

    @property
    def data_count(self):
        return len(list(self.data))  # self.data is already data_named + data_unnamed ... aka data_connected ...
        #return self.data_named_count + sum(self.data_connected_counts.values())

    @property
    def connected_counts(self):
        # NOTE this double counts if added to metadata_counts and data_counts
        return {i:len(sg) for i, sg in self.connected_subgraph_identities.items()}
        #return {**self.data_connected_counts, **self.data_connected_counts}

    @property
    def free_counts(self):
        return {i:len(sg) for i, sg in self.free_subgraph_identities.items()}

    @property
    def connected_and_free_counts(self):
        return {i:len(sg) for i, sg in self.connected_and_free_subgraph_identities.items()}

    @property
    def counts(self):
        # FIXME i think we want the whole graph too yeah?
        counts = {self.curies_identity:self.curies_count,
                  self.metadata_identity:self.metadata_count,
                  self.data_identity:self.data_count,
                  **self.data_named_subject_counts,
                  **self.connected_counts,
                  **self.free_counts,
                  **self.connected_and_free_counts,
                  }

        if self.bound_name_count is not None:
            counts[self.bound_name_identity] = self.bound_name_count

        return counts

    # functions

    def get_identity(self, type_name):
        real_name = '_' + type_name + '_identity'
        real_value = getattr(self, real_name)
        if real_value is None:
            real_value = self.digest(type_name)
            setattr(self, real_name, real_value)
            self._transaction_cache_identities.add(real_value)  # FIXME

        return real_value

    def digest(self, type_name):
        value = getattr(self, type_name)
        return IdentityBNode(value).identity

    def process_graph(self):
        def normalize(cmax, t, existing, sgid, replica):
            for e in t:
                if isinstance(e, rdflib.BNode):
                    if e not in existing:
                        cmax += 1
                        existing[e] = cmax
                        if e in self._subgraph_and_integer:
                            breakpoint()
                        self._subgraph_and_integer[e] = sgid, replica, cmax

                    yield existing[e]
                else:
                    yield e

            yield cmax

        def bnode_last(e):
            return 'z' * 10 if isinstance(e, rdflib.BNode) else e

        def sortkey(triple):
            s, p, o = triple
            s = bnode_last(s)
            o = bnode_last(o)
            return p, o, s

        def normgraph(head_subject, subgraph, sgid, none_subject=None):  # , connected_and_free=False, free_and_connected=False):
            """ replace the bnodes with local integers inside the graph """
            # make sure we are working only on the subject_triples
            # since we technically aren't supposed to use IdentityBNode.subgraph_mappings
            # since it is polluted
            _osg = subgraph
            try:
                g = OntGraph().populate_from_triples((((none_subject if s is None else s), p, o) for s, p, o in subgraph))
            except Exception as e:
                breakpoint()
                raise e
            subgraph = list(g.subject_triples(head_subject))

            cmax = 0

            if head_subject in self._non_injective:
                reps = self._itbni[self._blank_identities[head_subject]]
                # replica ordering is arbitrary but also doesn't really matter
                replica = reps.index(head_subject)
            else:
                replica = 0

            if head_subject in self._subgraph_and_integer:
                breakpoint()

            self._subgraph_and_integer[head_subject] = sgid, replica, cmax
            existing = {head_subject:0}  # FIXME the head of a list is arbitrary :/
            normalized = []
            for trip in sorted(subgraph, key=sortkey):
                s, p, o = trip
                if o == head_subject:
                    if not isinstance(s, rdflib.BNode):
                        #printD(tc.red('Yep working'), trip, o)
                        continue  # this has already been entered as part of data_unnamed
                    else:
                        # this branch happens e.g. if the subgraph is malformed
                        # and e.g. contains other bits of graph that e.g. have
                        # head_subject in the object position because they are
                        # from the raw subgraph_mappings that are used for debug
                        # this particular example is avoided above via subject_triples
                        raise TypeError('This should never happen!')

                *ntrip, cmax = normalize(cmax, trip, existing, sgid, replica)
                normalized.append(tuple(ntrip))  # today we learned that * -> list
            return tuple(normalized)

        # hey kids watch this
        ibn = IdentityBNode(self.graph, debug=True)  # FIXME TODO should be able to compute data id by removing the metadata id from the final listing
        if list(self.metadata_raw):
            #self._metadata_identity = ibn.subject_embedded_identities[self.bound_name]
            metadata_seid = IdentityBNode(self.bound_name, as_type='(s ((p o) ...))', in_graph=self.graph)
            self._metadata_identity = metadata_seid.identity
        else:
            self._metadata_identity = ibn.null_identity  # FIXME not sure if want?

        # this definition for _metadata_identity is not quite the same as the old way
        # the old way is equivalent to IdentityBNode([ibn.subject_embedded_identities[self.bound_name]]
        # we don't use the subject condensed identity here because we do actually need to know that the
        # metadata was for this particular ontology, and while it might be strage for ontology metadata
        # to be the same between different ontologies, consider the case where there is only the ontid
        # TODO see if we need to use the list variant that is equivalent to the old way
        #self._data_identity = ibn.ordered_identity(*[v for v in ibn.all_idents_new if v != self._metadata_identity], separator=False)
        ibn_seids = IdentityBNode(self.graph, as_type='(s ((p o) ...)) ...')  # XXX watch out this one isn't normal because .identitiy is a list
        seids = ibn_seids.identity
        self._data_identity = ibn.ordered_identity(*sorted([v for v in seids if v != self._metadata_identity]), separator=False)
        # FIXME how to deal with files that have multiple metadata records and thus multiple metadata identities ???
        # this def for _data_identity produces the same result as the traditional way of IdentityBNode(self.data_raw)
        # note that IdentityBNode(self.data) produces different results due to the presence of checksums directly
        # howevever IdentityBNode([back_convert_sigh(*t) for t in self.data]) should produce the same result, except
        # when dealing with the non-injective case where there are duplicate unnamed subgraphs which is a FIXME TODO
        self._subgraph_and_integer = {}
        #self._blank_identities = {**ibn.bnode_identities, **ibn.unnamed_subgraph_identities}
        #if ibn.bnode_identities:
            #breakpoint()

        subgraph_mappings = ibn._alt_debug['transitive_triples']
        _bnodes = set(e for t in self.graph for e in t if isinstance(e, rdflib.BNode))
        self._blank_identities = {bn: IdentityBNode(bn, as_type='(s ((p o) ...))', in_graph=self.graph).identity for bn in _bnodes}
        itb = {}  # XXX FIXME unfortunately non-injectivity is a giant pita because of how we pass stuff around when generating rows
        non_injective = set()
        for v, k in self._blank_identities.items():
            if k in itb:
                ev = itb[k]
                if isinstance(ev, list):
                    ev.append(v)
                    non_injective.add(v)
                else:
                    itb[k] = [ev, v]
                    non_injective.add(v)
                    non_injective.add(ev)

                log.log(9, f'free subgraph duplication! {k.hex()}: {itb[k]}')

            else:
                itb[k] = v

        self._itbni = itb
        self._non_injective = non_injective
        self._identity_to_bnode = {v:k for k, v in self._blank_identities.items()}
        # FIXME figure out how to reduce the recomputation of the graph subsets since
        # ibn already does this and we don't want to be using debug
        self._connected_subgraph_identities = {
            IdentityBNode(o, as_type='(s ((p o) ...))', in_graph=self.graph).identity
            #ibn.bnode_identities[o]
            :
            normgraph(o, subgraph_mappings[o],
                      #ibn.bnode_identities[o]
                      IdentityBNode(o, as_type='(s ((p o) ...))', in_graph=self.graph).identity,
                      )
            for o in
            #ibn.connected_heads
            ibn._alt_debug['connected_heads']
            if o not in ibn._alt_debug['free_heads']
        }
        self._free_subgraph_identities = {
            #identity
            IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
            :
            normgraph(s, subgraph_mappings[s],
                      #identity
                      IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
                      )
            for s in
            #ibn.unnamed_subgraph_identities.items()
            ibn._alt_debug['free_heads']
            if s not in ibn._alt_debug['connected_heads']
        }
        self._connected_and_free_subgraph_identities = {
            IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
            :
            normgraph(s, subgraph_mappings[s],
                      IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
                      )
            for s in
            (ibn._alt_debug['free_heads'] & ibn._alt_debug['connected_heads'])
        }

        self._subgraph_mappings = subgraph_mappings  # for debug
        self._ibn = ibn  # for debug
        self._are_you_kidding_me = {v:k for k, v in self._subgraph_and_integer.items()}  # if you want to invert something invert something >_<
        self._transaction_cache_identities.update(self._blank_identities.values())  # XXX likely redundant
        self._transaction_cache_identities.update(self._free_subgraph_identities)
        self._transaction_cache_identities.update(self._connected_subgraph_identities)
        #breakpoint()
        return

        """
        datas = ('metadata', self.metadata_raw), ('data', self.data_raw)
        self._blank_identities = {}
        self._identity_to_bnode = {}
        self._free_subgraph_identities = {}
        self._subgraph_and_integer = {}
        for name, data in datas:
            log.debug(f'running {name} identity')
            idents = IdentityBNode(data, debug=True)
            setattr(self, '_' + name + '_raw_identity', idents)  # FIXME this will interfere with setting transaction cache contents in get_identity ???
            self._transaction_cache_identities.add(idents)
            # also we want to make sure our rewritten graph has the same identity as the raw form

            log.debug(f'running {name} free subgraph identities')
            free_subgraph_identities = {  # FIXME this is ideneity free subgraphs
                # idents.unnamed_subgraph_identities[s]
                identity:normgraph(s, idents.subgraph_mappings[s], identity)
                for s, identity in idents.unnamed_subgraph_identities.items()
            }

            self._free_subgraph_identities.update(free_subgraph_identities)  # technically a noop for metadata

            log.debug(f'running {name} blank/bnode identities')
            # XXX using bnode_identities instead of idents._blank_identities
            # I think it is working but we need to do some roundtrip checks

            self._blank_identities.update(idents.bnode_identities)
            self._blank_identities.update(idents.unnamed_subgraph_identities)
            inverse = {v:k for k, v in idents.bnode_identities.items()}
            inverse.update({v:k for k, v in idents.unnamed_subgraph_identities.items()})
            self._identity_to_bnode.update(inverse)  # XXX it is stupid and silly to be going back and forth so many times >_<

            # FIXME isn't this doing ... nothing ??? other than trying to produce a key error ???
            #log.debug(f'running {name} connected object identities (though not sure why?)')
            #for identity, o in idents.connected_object_identities.items():
                #idents.subgraph_mappings[o]

            log.debug(f'running {name} connected subgraph identities')

            csi_subject = self.bound_name if name == 'metadata' else None
            connected_subgraph_identities = {  # FIXME this is identity subgraphs ...
                idents.bnode_identities[o]:normgraph(o, idents.subgraph_mappings[o], idents.bnode_identities[o], none_subject=csi_subject)
                for o in idents.connected_heads}

            setattr(self, '_' + name + '_connected_subgraph_identities',
                    connected_subgraph_identities)

            if self._blank_identities:
                #printD(self._blank_identities)
                if self.debug:
                    breakpoint()

        self._transaction_cache_identities.update(self._blank_identities.values())  # XXX likely redundant
        self._transaction_cache_identities.update(self._free_subgraph_identities)
        self._transaction_cache_identities.update(self._data_connected_subgraph_identities)
        self._transaction_cache_identities.update(self._metadata_connected_subgraph_identities)
        """


class GraphLoader(GraphIdentities):

    @staticmethod
    def make_row(s, p, o, subgraph_and_integer, identity_to_bnode, self, subgraph_identity=None,):
        # IT'S NOT A METHOD

        ot = s, p, o

        fix = None

        """
        if isinstance(s, tuple):
            s_subgraph_identity, s_blank = s
            subgraph_identity = s_subgraph_identity
            s = s_blank

        if isinstance(o, tuple):
            o_subgraph_identity, o_blank = o
            subgraph_identity = o_subgraph_identity
            o = s_blank

        if s_subgraph_identity is not None and o_subgraph_identity is not None:
            assert s_subgraph_identity == o_subgraph_identity, f'sgid mismatch {s_subgraph_identity} != {o_subgraph_identity}'
        """

        def str_None(thing):
            return str(thing) if thing is not None else thing

        def ols(o_lit, record, i):
            # TODO check performance on this
            o_lit_strip = o_lit.strip()
            if o_lit_strip != o_lit:
                l = list(record)
                l[i] = o_lit_strip
                return tuple(l)

        s_subgraph_identity, o_subgraph_identity = None, None
        replica, s_replica, o_replica = None, None, None

        if type(s) == tuple:
            sid, s_replica, sind, s_subgraph_identity = s
            #sbn = self._are_you_kidding_me[s_subgraph_identity, s_replica, sind]
            s = sind
            subgraph_identity = s_subgraph_identity
        elif type(s) == rdflib.BNode:
            sid = None
            sbn = s
            s_subgraph_identity, s_replica, s = subgraph_and_integer[sbn]
            subgraph_identity = s_subgraph_identity

        if type(o) == tuple:
            oid, o_replica, oind, o_subgraph_identity = o
            #obn = self._are_you_kidding_me[o_subgraph_identity, o_replica, oind]
            o = oind
            subgraph_identity = o_subgraph_identity
        elif type(o) == rdflib.BNode:
            oid = None
            obn = o
            o_subgraph_identity, o_replica, o = subgraph_and_integer[obn]
            subgraph_identity = o_subgraph_identity

        if type(s) == int and type(o) == int and s == o:
            tsigh = (sbn, p, obn)
            if tsigh not in self.graph:
                breakpoint()
                # gotta be something with how the replica value is being set/determined
                raise NotImplementedError('how is this even possible')

            sigh_s, sigh_o = sbn in self._non_injective, obn in self._non_injective
            sigh = (
                # sigh clearly shows the problem along with derp_o
                # it is that somehow o is somehow selecting the wrong replica, the right one can be
                # seen in derp_o but is not the one specified by o_replica :/ maybe o_replica is being overwritten ???
                (s, s_replica, sid, sbn, s_subgraph_identity),
                (o, o_replica, oid, obn, o_subgraph_identity),
            )
            if sigh_s:
                derp_s = [self._subgraph_and_integer[sbn] for sbn in self._itbni[sid]]
            if sigh_o:
                # FIXME somehow we have replicate 0 and 2 but not 1 ?!?!
                derp_o = [self._subgraph_and_integer[obn] for obn in self._itbni[oid]]
            breakpoint()
            raise NotImplementedError('ugh')

        if s_subgraph_identity is not None and o_subgraph_identity is not None:
            if s_subgraph_identity != o_subgraph_identity:
                # FIXME I'm betting this is another non-injective issue :/
                # yes, but in a different place, specifically in the subgraph_and_integer place it seems
                # because you can have complex expressions inside lists in rdf :/ ... ah no ... some
                # XXX hrm, not quite so simple it seems
                # seems like cases where there is a bnode that was the head of a list may head the sgid
                # to be different somehow

                # fixed most of these but still having issues related to lists where the full list is duplicated as the annotation target (eek?!)
                # there should be duplicated structure? or rather, there is another injective point when mapping subgraph identity to bnode identity?
                # XXX the reason why we don't detect this case in normgraph is because the object in question is
                # in a subgraph in a list so the object id is never entered except possibly in ibn.bnode_identities ???
                breakpoint()
            assert s_subgraph_identity == o_subgraph_identity, f'sgid mismatch {s_subgraph_identity} != {o_subgraph_identity}'

        if s_replica is not None and o_replica is not None:
            #msg = f'should not be possible to have both s and o replica not None {s_replica} {o_replica}'
            if s_replica != o_replica:
                msg = f'mismatch s and o replica not None {s_replica} {o_replica}'
                raise ValueError(msg)
            replica = s_replica
        elif s_replica is not None:
            replica = s_replica
        elif o_replica is not None:
            replica = o_replica

        if (type(ot[0]) == tuple or type(ot[-1]) == tuple) and replica is None:
            breakpoint()
            raise NotImplementedError('wat')

        _replica = replica

        # assume p is uriref, issues should be caught before here
        p = str(p)

        # FIXME TODO triple identity is not straight forward right now
        # we technically don't need it for subgraphs because those
        # pretty much always have to be pulled in together, so only
        # the named subset will get triple ids that are distinct from
        # a subgraph id, the alternative would be to also provided
        # triple identities for triples with blank nodes, but that
        # isn't actually helpful because it already requires having
        # digested the whole subgraph to get the deterministic checksum
        # for all the objects, so it doesn't speed anything up more
        # than what we already have with the identified subgraphs
        # making sure that the subgraph identifier is what we expect
        # and documenting exactly which value it uses is thus critical

        triple_identity = None
        subject_embedded_identity = None
        replica_helper = None
        if isinstance(s, rdflib.URIRef) and isinstance(o, rdflib.URIRef):
            """
            _helper_ibn = IdentityBNode('')
            tis = dict(
                triple_identity = IdentityBNode((s, ot[1], o)),
                triple_identity_alt_1 = IdentityBNode((str(s), p, str(o))),
                triple_identity_alt_2 = IdentityBNode((s, p, o)),
                triple_identity_alt_3 = IdentityBNode(((s, p, o),)),
                triple_identity_alt_4 = IdentityBNode((s, p, o), pot=True),  # this is the one we want and works like (s (p o)) as of v3
                triple_identity_alt_5 = _helper_ibn.triple_identity(s, p, o).hex(),  # XXX this is an old version 1 thing, don't use it
                ti_t = IdentityBNode((s + p + o,)),
                ti_s1 = IdentityBNode(str(s) + str(p) + str(o)),
                ti_s2 = IdentityBNode((str(s + p + o),)),
                ti_s3 = IdentityBNode(str(s + p + o)),
                ti_s4 = IdentityBNode(str(s + ' ' + p + ' ' + o)),
                WAAAAA = IdentityBNode(s + p + o),  # XXX hilariously broken right now
            )
            """
            #subject_embedded_identity = self._ibn.subject_embedded_identities[s]
            #subject_embedded_identity = self._ibn.subject_embedded_identities[s]
            subject_embedded_identity = IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
            triple_identity = IdentityBNode((s, p, o), pot=True).identity
            columns = 's, p, o, triple_identity'
            record = (str(s),
                      p,
                      str(o),
                      triple_identity)

        elif isinstance(s, rdflib.URIRef) and isinstance(o, rdflib.Literal):
            #subject_embedded_identity = self._ibn.subject_embedded_identities[s]
            subject_embedded_identity = IdentityBNode(s, as_type='(s ((p o) ...))', in_graph=self.graph).identity
            triple_identity = IdentityBNode((s, p, o), pot=True).identity
            columns = 's, p, o_lit, datatype, language, triple_identity'
            o_lit = str(o)
            record = (str(s),
                      p,
                      o_lit,
                      str_None(o.datatype),
                      str_None(o.language),
                      triple_identity)
            fix = ols(o_lit, record, 2)

        elif isinstance(s, rdflib.URIRef) and isinstance(o, int) and subgraph_identity is not None:
            replica_helper = str(s), None, p, subgraph_identity, replica
            columns = 's, p, o_blank, subgraph_identity'
            record = (str(s),
                      p,
                      o,
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, int) and subgraph_identity is not None:
            if s == 0:
                replica_helper = None, s, p, subgraph_identity, replica
            columns = 's_blank, p, o_blank, subgraph_identity'
            record = (s,
                      p,
                      o,
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, rdflib.URIRef) and subgraph_identity is not None:
            if s == 0:
                replica_helper = None, s, p, subgraph_identity, replica
            columns = 's_blank, p, o, subgraph_identity'
            record = (s,
                      p,
                      str(o),
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, rdflib.Literal) and subgraph_identity is not None:
            if s == 0:
                replica_helper = None, s, p, subgraph_identity, replica
            columns = 's_blank, p, o_lit, datatype, language, subgraph_identity'
            o_lit = str(o)
            record = (s,
                      p,
                      o_lit,
                      str_None(o.datatype),
                      str_None(o.language),
                      subgraph_identity)
            fix = ols(o_lit, record, 2)

        else:
            # expecting to land here when we get bnodes from rdf lists
            breakpoint()
            raise ValueError(f'{s} {p} {o} {subgraph_identity} has an unknown or invalid type signature')

        #lc, lr = len(columns.split(', ')), len(record)
        #assert lc == lr, f'lengths {lc} != {lr} do not match {columns!r} {record}'
        return columns, record, fix, _replica, subject_embedded_identity, triple_identity, replica_helper

    def check_triple(self, s, p, o):  # XXX TODO
        # see [[file:../docs/explaining.org::*Do we allow no =/base/= triples in the triples table?]]
        return
        # FIXME looks like we will need to pass reference_host in here somehow :/
        # it is better to do this check while iterating over all the triples during
        # load instead of trying to iterate through them multiple times (even though
        # we already do that e.g. to compute identities)
        reference_host = 'uri.interlex.org'
        scheme = 'http'  # FIXME also need the scheme
        uri_prefix = f'{scheme}://{reference_host}/base/'
        # NOTE this particular check is handled by postgres itself
        def check_ent(e):
            if reference_host in e and '/uris/' not in e and not e.startswith(uri_prefix):
                msg = 'please only upload /base/ iris in ontologies'
                raise ValueError(msg)

        for e in (s, p, o):
            check_ent(e)

    def make_load_records(self, serialization_identity, curies_done, metadata_done, data_done, ident_exists):
        # if you need to test, pass in lambda i:False for ident_exists
        # TODO resursive on type?
        # s, s_blank, p, o, o_lit, datatype, language, subgraph_identity
        debug = True
        if debug:
            all_trips = set(self.graph)
            done_trips = set()

        if not curies_done:
            c = []
            # FIXME serialization_identity is not always present if triples never passed through
            # a definite serialized form, fortunately
            to_insert = {'serialization_identity, curie_prefix, iri_prefix':c}
            to_fix = {}
            for curie_prefix, iri_prefix in sorted(self.curies):  # FIXME ordering issue
                c.append((serialization_identity, curie_prefix, iri_prefix))

            yield 'INSERT INTO curies', '', to_insert, to_fix

        def back_convert_sigh(s, p, o, replica):
            _os, _oo = s, o
            # FIXME SO DUMB
            # FIXME is this somehow non-injective !??!?! YES YES IT IS :D
            # so, if there are somehow duplicate unnamed graphs we don't catch them
            if type(s) == tuple:
                sid, s_replica, sind, ssgid = s
                s = self._are_you_kidding_me[ssgid, s_replica, sind]
                if s_replica != replica:
                    breakpoint()
                assert s_replica == replica, f'sigh {s_replica} {replica}'

            if type(o) == tuple:
                oid, o_replica, oind, osgid = o
                o = self._are_you_kidding_me[osgid, o_replica, oind]
                if o_replica != replica:
                    breakpoint()
                assert o_replica == replica, f'sigh {o_replica} {replica}'

            return s, p, o

        def sortkey(triple):  # FIXME this a bad way to sort...
            return tuple(e if isinstance(e, str) else str(e) for e in triple)

        identity_triples = []
        replicas = []
        prefix = 'INSERT INTO triples'
        suffix = 'ON CONFLICT DO NOTHING'  # FIXME BAD
        # NOTE we cannot use ON CONFICT (s, p, o) DO SOMETHING because we actually need to match multiple unique constraints
        # which postgres currently cannot achieve, so if a triple identity is missing then we are out of luck
        # and have to issue a manual fix
        bn = self.bound_name
        if not metadata_done:
            to_insert = defaultdict(list)  # should all be unique
            to_fix = defaultdict(list)
            mi = self.metadata_identity
            for s, p, o in sorted(self.metadata, key=sortkey):  # FIXME resolve bnode ordering issue?
                s = bn if s is None else s
                self.check_triple(s, p, o)
                columns, record, fix, replica, seid, tid, rh = self.make_row(s, p, o, self._subgraph_and_integer, self._identity_to_bnode, self)
                if seid is not None:
                    # FIXME seid here should always be the same as metadata_identity which will simplify insert
                    if seid != mi:
                        breakpoint()
                    assert seid == mi
                    identity_triples.append((seid, tid))

                if rh is not None:
                    rrow = mi, *rh
                    if rrow not in replicas:
                        replicas.append(rrow)

                to_insert[columns].append(record)
                if fix is not None:
                    to_fix[columns].append((record, fix))

                if debug:
                    done_trips.add(back_convert_sigh(s, p, o, replica))
                    #[done_trips.add(t) for t in back_convert_sigh(s, p, o)]

            yield prefix, suffix, to_insert, to_fix

        if not data_done:
            to_insert = defaultdict(list)  # should all be unique
            to_fix = defaultdict(list)
            di = self.data_identity
            # FIXME between data_named and subgraph_identities we have
            # the set of triples that have a named subject and bn object
            # those are needed to complete the graph but are not easily accessible :/
            # and the rules from the go with the subgraph identities :/
            # FIXME if we iterate over self.data here then we dont need to go over subgraph identities below ya?
            # but we could also just fill blank_ids here except for the slight misalignment issue where s, p, blank triples never get added
            log.debug('data sort start')
            _uh_hrm = sorted(self.data, key=sortkey)  # this takes a bit but not really all that long?
            log.debug('data make rows start')
            for s, p, o in _uh_hrm:  # FIXME resolve bnode ordering issue? or was it already?
                # FIXME wait, how did this ever work, make_row has always needed identity for bnodes
                # if there was a subgraph involved also, data includes cases where the subject is a bnode ... wtf
                self.check_triple(s, p, o)
                # FIXME TODO profile this to see where the issues are
                columns, record, fix, replica, seid, tid, rh = self.make_row(s, p, o, self._subgraph_and_integer, self._identity_to_bnode, self)
                if seid is not None:
                    identity_triples.append((seid, tid))

                if rh is not None:
                    rrow = di, *rh
                    if rrow not in replicas:
                        replicas.append(rrow)

                to_insert[columns].append(record)
                if fix is not None:
                    to_fix[columns].append((record, fix))

                if debug:
                    done_trips.add(back_convert_sigh(s, p, o, replica))
                    #[done_trips.add(t) for t in back_convert_sigh(s, p, o)]

            yield prefix, suffix, to_insert, to_fix

        log.debug('data make rows done')

        # identity triples mapping, we need the triple id to subject embedded identity, which for bnode headed subgraphs is the same
        to_insert = defaultdict(list)
        to_fix = defaultdict(list)
        prefix = 'INSERT INTO identity_named_triples_ingest'
        suffix = ''
        #suffix = 'ON CONFLICT DO NOTHING'
        to_insert['subject_embedded_identity, triple_identity'] = identity_triples
        #'INSERT INTO identities (reference_name, identity, type, triples_count VALUES'
        #'INSERT INTO identity_relations'
        yield prefix, suffix, to_insert, to_fix

        # replicas
        to_insert = defaultdict(list)
        to_fix = defaultdict(list)
        prefix = 'INSERT INTO subgraph_replicas'
        suffix = ''
        # only once we have all the replicas collected can we identify
        # cases where a subgraph appears in the object position first
        # and cull other references to that same replica, dedupe happens
        # above because if a head bnode is the subject in multiple triples
        # then a row will be added each time and that is easier to handle above
        #rep_object_starts = set([(d, i) for d, s, b, p, i, r in replicas if s is not None])
        #_replicas_deobj = [  # FIXME this is too restrictive because there are cases where a bnode is both free and a connector (multi-and-no-parent)
            #(d, s, b, p, i, r) for d, s, b, p, i, r in replicas
            #if not ((d, i) in rep_object_starts and s is None)]
        replicas_deobj = replicas
        #breakpoint()
        to_insert['data_or_metadata_identity, s, s_blank, p, subgraph_identity, replica'] = replicas_deobj
        # yes, we do expect multiple duplicate replica rows because a single bnode may appear
        # in an arbitrary number of places in the graph it is an explicit bnode and the data
        # that gets inserted into the replicas table will look
        if False:
            from collections import Counter
            wat = Counter(replicas).most_common()
            hrm = self.subgraph_identities[wat[0][0][-2]]
            zz = Counter(replicas_deobj).most_common()
            qq = self.subgraph_identities[zz[0][0][-2]]
            breakpoint()
        yield prefix, suffix, to_insert, to_fix

        def int_str(e, pref=' ' * 5):
            return pref + f'{e:0>5}' if isinstance(e, int) else e

        def intfirst(triple):
            # I find it hard to believe there will be a subgraph with more than 5 digits of bnodes
            s, p, o = triple
            si = s
            s = int_str(s)
            o = int_str(o)

            if si == 0:
                out = s, p, o
            else:
                #out = p, s, o
                out = p, o, s

            return out

        # connected and free
        to_insert = defaultdict(list)  # should all be unique due to having already been identified
        to_fix = defaultdict(list)
        def has_bnodes(g):
            for s, p, o in g:
                for e in (s, o):
                    if isinstance(e, rdflib.BNode):
                        return True

        # FIXME all this is _supposed_ to have already been handled when we iterate over data above ????? data unnamed should have this stuff in it ???
        """
        assert self.subgraph_identities or not has_bnodes(self.graph), 'missing subgraph identities in a graph with bnodes'
        for identity, subgraph in self.subgraph_identities.items():
            if self.debug:
                printD(identity)
                [print(*(OntId(e).curie if
                         isinstance(e, rdflib.URIRef) else
                         repr(e) for e in t))
                 for t in sorted(subgraph, key=intfirst)]

            if not ident_exists(identity):  # we run a batch check before
                for t in sorted(subgraph, key=intfirst):
                    columns, record, fix = self.make_row(*t, self._subgraph_and_integer, self._identity_to_bnode, subgraph_identity=identity)
                    to_insert[columns].append(record)
                    if fix is not None:
                        to_fix[columns].append((record, fix))
                    # FIXME insertion order will be broken because of this
                    # however the order can be reconstructed on the way out...
                    # the trick however is to know which identities we need to
                    # insert for free subgraphs?
                    if debug:
                        #done_trips.add(t)
                        done_trips.add(back_convert_sigh(*t))
                        #[done_trips.add(t) for t in back_convert_sigh(*t)]

        """
        prefix = 'INSERT INTO triples'
        suffix = 'ON CONFLICT DO NOTHING'  # FIXME BAD
        if to_insert:
            yield prefix, suffix, {k:v for k, v in to_insert.items()}, dict(to_fix)

        if debug:
            oops_trips = done_trips - all_trips
            if oops_trips:
                breakpoint()
                raise NotImplementedError('NotImplementedCorrectlyError more like ...')

            missing_trips = all_trips - done_trips
            if self._non_injective:
                # FIXME this is still not right because it removes ALL the subjects
                # without properly checking for matched sets ...
                injes = [v for v in self._identity_to_bnode.values() if isinstance(v, list)]
                omt = missing_trips
                missing_trips = set(t for t in missing_trips
                                    if t[0] not in self._non_injective
                                    # yes, seemingly duplicate linker triples can get left out too
                                    # if the identity of the connected subgraph is also a free subgraph!
                                    # ARGH
                                    and t[2] not in self._non_injective)
                due_to_non_injective = omt - missing_trips
                if due_to_non_injective:
                    msg = f'the following trips have non-injective issues {due_to_non_injective}'
                    log.warning(msg)
            else:
                due_to_non_injective = set()

            msg = ''
            if missing_trips:
                # XXX the non-injective nature of free subgraphs means that a file might have multiple
                # copies of the same graph and when we run back_convert_sigh it normalizes those to the
                # same going the other way, to insert happens twice but the database knows it is the same
                # triple so it will deduplicate it, however this check here does not know, and also how
                # the heck are we generating duplicate annotations !??!? i think these are probably coming
                # from duplicate annotations on synonym type ???

                # XXX in this case though it is EVEN weirder because somehow the EXACT SAME TRIPLE WITH
                # THE EXACT SAME BNODE has been inserted into the graph twice or something ???
                # how can that even happen ??!!? or no, that isn't what happened, it is just that
                # idents.bnode_identities assumes injectivity incorrectly and there are two identical
                # graphs in the input that use different bnode ids but we can't recover one of them because
                # we don't get the full list ... ok, it is clear where to start fixing this
                msg = f'the following trips were not prepared for insert: {missing_trips}'

            if due_to_non_injective:
                _msg = f'the following trips were not prepared for insert due to non-injective issues: {due_to_non_injective}'
                if msg:
                    msg += '\nin addition ' + _msg
                else:
                    msg = _msg

            if msg:
                breakpoint()
                raise exc.LoadError(msg)



class LoadProv:
    def __init__(self, user, group, graphqual):
        name
        graphqual.identity

    def sql_to_make_change(self):
        # emit_changes was the old name ?
        pass


class GraphQual:
    """ Compute hash info """
    def __init__(self, basicdb, loader):
        queries = basicdb.queries

        reference_name  # system name for subest
        current_qualifier_rn = queries.getCurrentQualifierForReferenceName(reference_name)  # TODO
        bound_name = loader.bound_name
        current_qualifier_bn = queries.getCurrentQualifierForBoundName(bound_name)  # TODO
        # TODO figure out if we need both
        # 1) bn/rn issues should already have been resolved when this is called
        current_qualifier = current_qualifier_rn

        current_graph_sql = queries.getByQualifier(current_qualifier, with_qualifier=True)  # TODO
        cloader = TripleExporter()()

        # if a user is editing 'all' of interlex we can easily restrict the
        # scope of the changes to just the single term, not that I really
        # want to have per-term qualifiers, but it seems like a reasonable
        # compromise, I do serialize them after all TODO
        # XXX the above is incorrect, because individual users
        # histories all start from a blank slate and we do a sort of
        # auto merge of their contributions, which is why we have excludeQualifier
        # it is used to mask out triples that they 'change' rather than trying
        # to delete them, now, inside of interlex this works because we are able
        # to keep track of which triples they "don't want" but if they are doing
        # a bulk upload, the we can only infer that for card-1 predicates
        # otherwise they have to give a signal which says 'overwrite all content for this class'
        # and then we can go and pull whatever triples we have for that class (s, p, and o)
        # another simple way to deal with this is that if people work on a subset of terms
        # they can download them and the download qualifier will be what we use to create the
        # reference, then the qualifiers triples tracks the rest for us
        exclude_qualifier_if_any = graphDiff(loader, cloader)  # TODO pretty sure I already wrote this somewhere? or maybe that was for curies

    def graphDiff(self):
        # using upsert is bad

        # 0) check the identities on each section in case we already have what we want
        # 1) insert 'new' into temp table
        # 2) union or full outer join with triples -> gives list of existing ids
        #    do this using the usual null pattern technique on the subset
        # 3) compare the resulting list of triple ids with the current qualifier ids
        # 4) create the exclude qualifier from the ones in current that were not in the join
        # 5) compare the resulting list of temp id to the total temp ids
        # 6) insert triples with temp ids that were not in the join into triples returning id
        # 7) insert the new triple ids along with the triple ids that were in the join with includeQualifier
        # 8) if feeling very paranoid compute identities to compare with the python repr

        # pretty sure there are other steps that will crop up

        # for the triples table I think we can come up with a reasonable approach for
        # efficient diffing that will only cause issues if
        # select _all_ qualifiers for that name and select them into a temporary table
        pass

    def parent_qualifier(self):
        self.query

    def qualifier(self):
        # NOTE the disadvantage of this approach
        # is _in theory_ tampering
        # EXCEPT that if the original qualifier
        # has been published _WITH THE IDENTS_ of its parts
        # AS HAVE THE PRIOR QUALIFIERS
        # the boom, merkelish tree, by accident
        # it means that the prior history before zero will
        # always be 'off chain' that that is actually a good thing

        # iq include qualifier
        # eq exclude qualifier
        # pq prior qualifier
        # h hash
        # uh unbound hash

        def express(*tuple_or_generator):
            for tog in tuple_or_generator:
                if isinstance(tog, tuple):
                    yield tog
                else:
                    yield from tog

        # FIXME TODO I think that the zeroth q should probably be the hash of a uuid
        # that we use as a random seed, it could also be the hash of the reference host
        # along with the user in question, which probably makes the most sense
        # also super handy for finding the first commit ^_^

        q = 0  # nice thing about this? if we want to reconstruct prior history there's plenty of space
        # TODO q should probably be?? integer? hash of what? not sure
        # NOTE nice sideeffect of this is that we should be able to run
        # an internal integrity check on the history so that the data
        # identities that we get 'add' up to the identities of the diff
        # in _theory_ we could make the qualifier id the hash of the state
        # of the subest of the graph that it encompases at the moment, but that
        # means that large graphs could take a ... very long time to compute
        # identities for .. on the other hand, we do imagine that the total
        # number of names that we will ever need should be much less than 5 billion

        # integers are easier to read ... annoying they require a single global
        # index ... EXCEPT that as along as we prefix the qualifier with domain
        # that was managing the index at the time, then we should be good to go
        # sure, some future programmer is going to loose their mind because
        # I've forced an arbitrary id in as part of the identity, but what's a
        # vanity here and there ;)

        qualifier = 'https://uilx.org/q/{q}'
        # remember: just because there is a merke tree
        # doesn't mean that there we can't recombine individual
        # qualifiers _AS IF_ they didn't have a history
        # we still have their constituent ids which can be used
        # for all sorts of stuff

        def include(*include_parent_hashes):
            for ihash in include_parent_hashes:
                # TODO consider base64 encoding these ...
                # "sha256 hash value"^^ilx:base64
                yield qualifier, ilxtr.iq, rdflib.Literal(ihash)

        def exclude(*exclude_parent_hashes):
            for ehash in exclude_parent_hashes:
                yield qualifier, ilxtr.eq, rdflib.Literal(ehash)  # TODO encoding

        # NOTE when creating a new group there are a number of complexities
        # that need to be considered, specifically that if they want to merge
        # multiple other groups or other ontologies, then we will need them to
        # reconcile conflicts in the cardinality 1 case and we should probably
        # offer them a way to determine whether that particular merge of the graph
        # will conconsistent or not, the easiest case is that they simply take the
        # latest or curated and start from there since it is much easier to work
        # from a merge commit than to compute a new history from scratch
        # NOTE there is also the ilx:alwaysExclude qualifier relation which i think
        # i have discussed before, though that could create some issues
        include_hashes = self.get_parent_qualifiers_for_current_reference_name()
        exclude_hashes = self.compute_exclude_and_create_qualifier()
        triples = express(
            (qualifier, rdf.type, ilxtr.q),
            include(*include_hashes),  # allow octopus merge
            exclude(*exclude_hashes),
            (qualifier, ilxtr.dataHash, ),
            (qualifier, ilxtr.sgHash, ),
            (qualifier, ilxtr.dsgHash, ),
        )

        # the last step is to hash all the previous qualifiers and publish
        # this unbound hash (bound hashes are impossible)
        # the question is whether this triple id goes in the with a qualifier to itself
        # I think probably yes, since we do want hashes to be pesudo bound
        # (so that we can do the reverse lookups) it is also ok to have bound
        # identities the reference other subsections of the document
        # in fact we could add those on the way back out in many cases ...
        # ilxto:my-ont a owl:Ontology; ilx:boundSectionHash "some hash"^^ilx:base64
        (qualifier, ilxtr.unboundHash, qualifier_total_identity)

        # we have the identities table which will be more efficient than a pure triple version
        # but being able to articulate the pure triple version is criticl for securin the export



class BasicDBFactory:
    _cache_groups = {}
    def ___new__(cls, *args, **kwargs):
        # NOTE this should NOT be tagged as a classmethod
        # it is accessed at cls time already and tagging it
        # will cause it to bind to the original insource parent
        return super().__new__(cls)

    def __new__(cls, session):
        newcls = cls.bindSession(session)
        newcls.__new__ = cls.___new__
        newcls.queries = Queries(session)
        return newcls

    @classmethod
    def bindSession(cls, session):
        new_name = cls.__name__.replace('Factory','')
        classTypeInstance = type(new_name,
                                 (cls,),
                                 dict(session=session,
                                      _execute=session.execute,
                                      auth=Auth(session),
                                      process_type=new_name))
        return classTypeInstance

    @classmethod
    def refresh(cls):
        """ Reset any 'global' state. """
        BasicDBFactory._cache_groups = {}

    def __init__(self, group, user, token, read_only=True):  # safe by default
        # FIXME make sure that each on of these is really its own instance and never reused
        # so that there is no chance of letting users spoof as using a race condition
        # it looks like the __new__ functionality is used to bind per session, but make sure
        self.read_only = read_only
        auth_group, auth_user = self.auth.decodeTokenSimple(token)
        if group != auth_group or user != auth_user:
            g = f'{group} {auth_group} {user} {auth_user}'
            msg = f'FIXME this needs to be a logged auth consistency error {g}'
            raise ValueError(msg)
        self.group = group
        self.user = user
        #self.user_role = 'lol'  # TODO this works but testing
        # read only does not need to be enforced in the database becuase user role
        # is the ultimate defense and that _is_ in the database
        # it is more of a convenience reminder

    def execute(self, sql, params=None):
        log.warning("shouldn't this move to self.session_execute? self.execute is fairly ancient ya?")
        return self._execute(sql_text(sql), params=params)

    def session_execute(self, sql, params=None):
        return self.session.execute(sql_text(sql), params=params)

    @property
    def reference_host(self):
        return self.queries.reference_host

    @property
    def group(self):
        return self._group

    @group.setter
    def group(self, value):
        if hasattr(self, '_group'):
            raise ValueError(f'{self} has already set group!')
        id, role = self.check_group(value)
        self._group = value
        self.group_id = id
        self.group_role = role

    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, value):
        if hasattr(self, '_user'):
            raise ValueError(f'{self} has already set user!')
        id, role = self.check_user(value)
        self._user = value
        self.user_id = id
        self.user_role = role

    def check_user(self, user):
        if self.read_only and user is None:
            return None, None
        else:
            return self.check_group(user)

    def check_group(self, group):
        if group not in self._cache_groups:
            sql = ('SELECT * FROM groups '
                   "WHERE own_role < 'pending' AND groupname = :name")
            try:
                res = next(self.session_execute(sql, dict(name=group)))
                self._cache_groups[group] = res.id, res.own_role
                return res.id, res.own_role
            except StopIteration:
                raise exc.NotGroup(f'{group} is not a group')
        else:
            return self._cache_groups[group]

    @property
    def read_only(self):
        return self._read_only

    @read_only.setter
    def read_only(self, value):
        # load_logger.error
        # sec critical this function should not be modified
        # to prevent any long range affects from sneeking in here
        if hasattr(self, '_read_only'):
            raise ValueError(f'{self} read_only can only be set in __init__!')

        self._read_only = value

    @property
    def user_role(self):
        return self._user_role

    @user_role.setter
    def user_role(self, value):
        # load_logger.error
        # sec critical this function should not be modified
        # to prevent any long range affects from sneeking in here
        if hasattr(self, '_user_role'):
            raise ValueError(f'{self} user_role can only be set in __init__!')

        self._user_role = value

    @property
    def user_id(self):
        return self._user_id

    @user_id.setter
    def user_id(self, value):
        # load_logger.error
        # sec critical this function should not be modified
        # to prevent any long range affects from sneeking in here
        if hasattr(self, '_user_id'):
            raise ValueError(f'{self} user_id can only be set in __init__!')

        self._user_id = value


class UnsafeBasicDBFactory(BasicDBFactory):
    def __init__(self, group, user, read_only=True):
        self.read_only = read_only
        self.group = group
        self.user = user


class TripleLoaderFactory(UnsafeBasicDBFactory):
    scheme = 'http'  # sadface
    _cache_names = set() # FIXME make sure that reference hosts don't get crossed up
    _cache_identities = set()
    formats = {  # FIXME this is backward from OntRes stuff
        'text/turtle':'turtle',
        'application/rdf+xml': 'xml',
        #'text/owl-functional': '???',
        'ttl':'turtle',
        'owl':'xml',
        'n3':'n3',
        'nt':'nt',
    }

    @classmethod
    def refresh(cls):
        TripleLoaderFactory._cache_names = set()
        TripleLoaderFactory._cache_identities = set()
        super().refresh()

    def __init__(self, group, user, reference_name):
        super().__init__(group, user, read_only=False)  # FIXME WARNING
        self.debug = False
        self.preinit()
        printD(group, user, reference_name, self.reference_host)
        self._reference_name = None
        self.reference_name_in_db = None

        # FIXME reference names should NOT have file type extensions
        # we can have a default file type and resolve types
        # interlex is not a flat file, it will resolve types
        # but it does not have to use then in identifiers so it does not

        """  # TODO for the future, distinguish between the external bound and internal
        ext = PurePath(reference_name).suffix
        if ext:
            reference_name = reference_name.rstrip(ext)
        """

            #self.extension = ext[1:]
            # extension is set by name not reference_name
            # we might want to track this for stats reasons...

        if reference_name is not None:
            self.reference_name = reference_name

    def preinit(self):
        self.times = {}

        self._name = None
        self._expected_bound_name = None  # TODO multiple bound names can occure eg via versionIRI?
        self._transaction_cache_names = set()

        self._extension = None
        self._mimetype = None
        self._format = None

        self._header = None
        self._serialization = None
        self._graph = None
        self._Loader = None

        self._serialization_identity = None  # ALA representation_identity
        self._transaction_cache_identities = set()

        self._identity_triple_count = None

        self._safe = True

    def __enter__(self):
        self.preinit()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # TODO rollback on >= 400? no, should all be handled locally
        self.__enter__()  # the paranoia is real
        self._safe = False
        printD('exit')

    def check(self, name):
        """ set the remote name source """
        self.name = name
        # TODO expected filesize to determine live or batch load
        return False

    @exc.hasErrors(exc.LoadError)
    def __call__(self, expected_bound_name):
        if not self.times:
            self.times = {'begin':time.time()}
        self.times['init_begin'] = time.time()
        printD(self.name, expected_bound_name)
        # FIXME this is a synchronous interface
        # if we want it to be async it will require
        # more work
        # perhaps a POST to add with a response covering permissions etc
        # followed by a second post asking to ingest from remote?
        # how do we deal with the issue of names?
        if not self._safe:
            raise RuntimeError(f'{self} is not in safe mode, '
                               'did you call it using \'with\'?'
                               'Alternately, run preinit() to clear latent state.')
        else:
            self._safe = False

        bde_switch = self.bound_database_expected(expected_bound_name)

        if self.name is None:
            printD(tc.red('self.name is none'))
            breakpoint()

        stop = bde_switch(self.Loader.bound_name, self.expected_bound_name, expected_bound_name)
        self.times['init_end'] = time.time()
        if stop is not None:  # this is redundant but helps with type readability
            return stop

    def bound_database_expected(self, expected_bound_name):
        """ This function is a stateful nightmare used to sort out
            what to do given the expected bound name, the actual bound name
            and what we have in the database on both of them """

        def ___n(value): return value is None
        def NOTN(value): return value is not None
        def make_switch(switch_spec):
            def match(test, case):
                return all(f(v) for f, v in zip(test, case))

            def switch(*case):
                for test, dispatch, *args in switch_spec:
                    if match(test, case):
                        return dispatch(case, *args)

            return switch

        nbn_base = f'No bound name found in {self.name}! '
        def pairs(case, message):
            a, b = (a for a in case if a is not None)
            if a != b:
                return message + f'\n{a!r}\n{b!r}'
            elif not self.reference_name_in_db:
                self.expected_bound_name = self.Loader.bound_name

        def bn_none(case, value, *message):
            b, d, e = case
            if value is None and message:
                if d != e:
                    return nbn_base + ('In addition existing expected and new '
                                       'expected bound name do not match\n{d} != {e}')
                else:
                    value = d

            return nbn_base + 'Expected {value}', 400

        def all_nn(case):
            b, d, e = case
            if not b == d == e:
                return f'Bound names do not match! {b!r} {d!r} {e!r}', 400

        def all_none(case):
            if self.reference_name != f'https://{self.reference_host}/{self.group}/upload':
                return 'No bound name, please use your upload endpoint', 400

        def set_d(case):
            self.expected_bound_name = self.Loader.bound_name

        # bound database expected
        bde_switch = make_switch((
            ((NOTN, NOTN, NOTN), all_nn),
            ((___n, ___n, ___n), all_none),  # fail if not on
            ((NOTN, ___n, ___n), set_d),  # OK bn as ebn
            ((___n, NOTN, ___n), bn_none, self.expected_bound_name),  # FIXME resolving ebn at switch definition time vs at call time
            ((___n, ___n, NOTN), bn_none, expected_bound_name),
            ((___n, NOTN, NOTN), bn_none, None, 'existing expected bound name exists and does not match new'),
            ((NOTN, ___n, NOTN), pairs, 'bound name does not match new expected bound name'),
            ((NOTN, NOTN, ___n), pairs, 'bound name does not match existing expected bound name'),
            ))

        return bde_switch

    @exc.hasErrors(exc.LoadError)
    def load(self, commit=True):
        output = ''
        try:
            output += self.load_event()
            if commit:
                self.times['commit_begin'] = time.time()
                self.session.commit()
                self.times['commit_end'] = time.time()
                self.cache_on_success()

            return output
        except BaseException as e:
            self.session.rollback()
            if type(e) == exc.LoadError:
                raise e

            breakpoint()
            if hasattr(e, 'orig'):
                raise e.orig
            else:
                raise e
            output += 'ERROR ' + str(e)
            return output, 500
        finally:
            self.times['end'] = time.time()
            printD(timestats(self.times))  # TODO happy stats
            self.times = None

        """
        if expected_bound_name is not None:  # implicit new or attempt at new
            # TODO various failure messages
            # TODO sometimes you can't get an ontology from its bound name >_<
            try:
                self.expected_bound_name = expected_bound_name
            except sa.exc.IntegrityError:
                self.session.rollback()
                if expected_bound_name != self.expected_bound_name:
                    return (f'Existing expected bound name {self.expected_bound_name} '
                            f'!= {expected_bound_name}'), 400
                else:
                    output += (f'WARNING: Existing expected bound name {self.expected_bound_name} '
                               f'already exists for reference name {self.reference_name}.\n')
        """

    # names
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        # TODO
        self._name = value  # set this first to preven accidentally not setting it
        if value not in self._cache_names or self._transaction_cache_names:
            try:
                sql = 'INSERT INTO names VALUES (:name)'
                self.session_execute(sql, dict(name=value))
            except sa.exc.IntegrityError:
                # name was already in but not cached
                self.session.rollback()

            self._transaction_cache_names.add(value)

    @property
    def reference_name(self):
        return self._reference_name

    @reference_name.setter
    def reference_name(self, value):
        self.reference_name_setter(value)

    @property
    def reference_name_in_db(self):
        return self._reference_name_in_db

    @reference_name_in_db.setter
    def reference_name_in_db(self, value):
        self._reference_name_in_db = value

    @property
    def expected_bound_name(self):
        if self._expected_bound_name is None:
            if self.reference_name_in_db is None:
                self.reference_name
            #sql = 'SELECT expected_bound_name FROM reference_names WHERE name = :name'
            #r = next(self.execute(sql, dict(name=self.reference_name)))
            #self._expected_bound_name = r.expected_bound_name

        return self._expected_bound_name

    @expected_bound_name.setter
    def expected_bound_name(self, value):
        if self.expected_bound_name == value:
            printD('WARNING: trying to set expected bound name again!')
        elif self.expected_bound_name is not None:
            # NOTE this is also enforced in the database
            raise exc.LoadError('Cannot change expected bound names once they have been set!')
        else:
            if self.reference_name_in_db:
                sql = ('UPDATE reference_names SET expected_bound_name = :e WHERE name = :r')
            else:
                sql = ('INSERT INTO reference_names (name, expected_bound_name, group_id) '
                       'VALUES (:r, :e, :group_id)')

            # FIXME this is not wrapped with a rollback because...
            # that shouldn't happen? are we sure?
            self.session_execute(sql, dict(r=self.reference_name, e=value, group_id=self.group_id))
            self._expected_bound_name = value
            self.reference_name_in_db = True  # ok to set again
            #breakpoint()

    # serialization type
    @property
    def extension(self): return self._extension

    @extension.setter
    def extension(self, value):
        """ Used for cases where the name itself does not specify the type. """
        self._extension = value

    @property
    def mimetype(self): return self._mimetype

    @property
    def format(self):
        if self._format is None:
            if self.extension not in self.formats and self.mimetype not in self.formats:
                # TODO use ttlfmt parser attempter
                raise exc.LoadError(f"Don't know how to parse either {self.extension} or {self.mimetype}", 415)
            elif self.extension not in self.formats:
                self._format = self.formats[self.mimetype]
            else:
                self._format = self.formats[self.extension]

        return self._format

    # identities
    @property
    def serialization_identity(self):
        if self._serialization_identity is None:
            ident = IdentityBNode(self.serialization).identity
            if self.ident_exists(ident):
                # TODO user options for what to do about qualifiers
                raise exc.LoadError(f'The exact file dereferenced to by {self.name} is already in InterLex', 202)
            self._serialization_identity = ident
            self._transaction_cache_identities.add(ident)

        return self._serialization_identity

    # the things themselves
    @property
    def serialization(self): return self._serialization  # intentionally errors

    @property
    def graph(self):
        if self._graph is None:
            self.times['graph_begin'] = time.time()
            self._graph = OntGraph() #rdflib.Graph()
            try:
                if False and self.format == 'xml':  # XXX not clear this offers a speed up these days?
                    data = rapper(self.serialization)
                    self._graph.namespace_manager.populate_from(metadata_graph)  # TODO
                    self._graph.parse(data=data, format='nt')  # FIXME this destroys any file level prefixes
                else:
                    self._graph.parse(data=self.serialization, format=self.format)
            except TypeError as e:
                breakpoint()
                raise e
            finally:
                self.times['graph_end'] = time.time()

            # cycle check until we get the issue sorted in ibnode
            cps = self._graph.cycle_check()
            if cps:
                wat = OntGraph().populate_from_triples([t for t in self._graph if t[0] in cps])
                wat.debug()
                msg = 'computing identities of graphs with bnode cycles in them is currently not working'
                # one way to fix it is to do something like what lisps do with the read cycles
                # and compute everything as if the bnode value was 0 for the first cyclical ref
                # 1 for the next, etc.
                raise NotImplementedError(msg)

        return self._graph

    @property
    def Loader(self):
        if self._Loader is None:
            self._Loader = GraphLoader(self.graph)  # TODO caches?

        return self._Loader

    #functions
    def reference_name_setter(self, value):  # ... setters don't inherit wat
        if self._reference_name is None:
            self._reference_name = value
            sql = 'SELECT name, expected_bound_name FROM reference_names WHERE name = :name'
            try:
                res = next(self.session_execute(sql, dict(name=self._reference_name)))
                self._expected_bound_name = rdflib.URIRef(res.expected_bound_name)
                self.reference_name_in_db = True
            except StopIteration:
                # set it by setting self.expected_bound_name = something (including None)
                self.reference_name_in_db = False
                printD('WARNING reference name has not been created yet!\n')
        elif self._reference_name != value:
            raise exc.LoadError('cannot change reference names', 409)

    def batch_ident_check(self, *idents):
        batchsize = 20000
        sql = 'SELECT identity FROM identities WHERE identity IN '
        sql_params = []
        for chunk in chunk_list(idents, batchsize):
            # chunk is in a tuple because a list of bytes is an iterable of iterables
            values_template, params = makeParamsValues((chunk,))
            sql_params.append((sql + values_template, params))

        existing = set()
        for sql_vt, params in sql_params:
            res = self.session_execute(sql_vt, params)
            existing.update(set(r.identity for r in res))
            self._cache_identities.update(existing)

        # FIXME OOF inefficient but yeah
        for ident in idents:
            yield ident in existing

    def ident_exists(self, ident):
        # TODO check to make sure that the load succeeded
        # transactions probably take care of this
        # but need to make sure
        if ident in self._cache_identities:
            return True

        sql = ('SELECT * FROM identities ' #' as i JOIN load_processes'
               'WHERE identity = :ident')
        try:
            next(self.session_execute(sql, dict(ident=ident)))
            self._cache_identities.add(ident)
            return True
        except StopIteration:
            return False

    def cache_on_success(self):
        self._cache_names.update(self._transaction_cache_names)
        self._cache_identities.update(self._transaction_cache_identities)
        self._cache_identities.update(self.Loader._transaction_cache_identities)
        # FIXME identities from Loader directly without having to cache...
        # TODO names

    def identity_triple_count(self, identity):
        """ Note: these are unique triple counts on normalized subgraphs """
        if self._identity_triple_count is None:
            # we should be able to abstrac this using
            # data + structure of data + decoupling rules + identity function on data
            # eg bound_name is raw bytes + rdf:type owl:Ontology as subset rule
            counts = self.Loader.counts
            counts[self.serialization_identity] = self.Loader.data_count + self.Loader.metadata_count
            self._identity_triple_count = counts

        return self._identity_triple_count[identity]

        """
            bound_name_count = 0
            curies_count = len(self.curies)
            mtc = len(list(self.metadata))
            m_connected_counts = {i:len(sg) for i, sg in self.metadata_connected_subgraph_identities.items()}
            metadata_count = mtc + sum(m_connected_counts.values())
            dtc = len(list(self.data))
            d_connected_counts = {i:len(sg) for i, sg in self.data_connected_subgraph_identities.items()}
            data_count = dtc + sum(d_connected_counts.values())
            connected_counts = {**m_connected_counts, **d_connected_counts}
            free_counts = {i:len(sg) for i, sg in self.free_subgraph_identities.items()}
            itc = {self.serialization_identity:data_count,
                   self.curies_identity:curies_count,
                   self.bound_name_identity:bound_name_count,
                   self.metadata_identity:metadata_count,
                   self.data_identity:data_count,
                   **connected_counts,
                   **free_counts}
            self._identity_triple_count = itc

        return self._identity_triple_count[identity]  # this should never key error
        """

    def load_event(self):
        # FIXME only insert on success...
        si = self.serialization_identity

        # TODO need a way to pass in si

        # TODO always insert metadata first so that in-database integrity checks
        # can run afterward and verify roundtrip identity
        #ni = self.ident_exists(self.bound_name_identity)  # FIXME usually a waste

        log.debug(f'load start for {si.hex()}')
        self.times['load_begin'] = time.time()
        sgids = tuple(self.Loader.subgraph_identities)
        # FIXME don't we want to include the full graph id too? ...
        idents = (self.Loader.curies_identity,
                  self.Loader.metadata_identity,
                  self.Loader.data_identity,
                  *sgids)

        # FIXME don't bother with the sgids if data is done already ???
        curies_done, metadata_done, data_done, *sg_done = self.batch_ident_check(*idents)
        sgids_done = [_ for _, d in zip(sgids, sg_done) if d]
        sg_done = None

        #curies_done = self.ident_exists(self.curies_identity)
        #metadata_done = self.ident_exists(self.metadata_identity)
        #data_done = self.ident_exists(self.data_identity)

        # (:s, 'hasPart', :o)
        # FIXME only insert the anon subgraphs and definitely better
        # not to use identities on annotations
        # also pretty sure that the connected subgraphs don't go in the idents table
        # FIXME I need to know which subgraphs need to be parented ser
        sql_ident_base = 'INSERT INTO identities (reference_name, identity, type, triples_count) VALUES '
        types_idents = (('serialization', self.serialization_identity),  # TODO abstract... type + ident
                        ('local_naming_conventions', self.Loader.curies_identity),
                        #('bound_name', self.bound_name_identity),
                        ('metadata', self.Loader.metadata_identity),
                        ('data', self.Loader.data_identity),
                        ('subject_graph', *self.Loader.data_named_subject_identities),  # these ids are for non bnode only, the identity is computed over the whole subject graph, but only the named set of triples need to be inserted into the identities to triples table
                        # FIXME I'm pretty sure that free subgraph identities aren't mapped anywhere else
                        # XXX proceed with plan to implement all of this in OntGraph directly since it will
                        # be infinitely easier to test and verify than this stack of crazyness
                        # FIXME TODO maybe free -> serialization and connected -> data or metadata?
                        ('subgraph', *self.Loader.subgraph_identities))
        assert not any(v is None for t, *vs in types_idents
                       for v in vs), f'oops! {[(t, v) for t, v in types if v is None]}'
        values = [(i, type, self.identity_triple_count(i))
                  for type, *identities in types_idents
                  for i in identities]

        batchsize = 20000
        sql_ident_params = []
        for chunk in chunk_list(values, batchsize):
            try:
                wat = makeParamsValues(chunk, constants=(':rn',))
                vt, params_i = wat
            except Exception as e:
                breakpoint()  # FIXME SIGH some nonsense here
                raise e

            params_i['rn'] = self.reference_name
            sql_ident = sql_ident_base + vt + ' ON CONFLICT DO NOTHING'  # TODO FIXME XXX THIS IS BAD
            sql_ident_params.append((sql_ident, params_i))
            #breakpoint()  # TODO

        log.debug(f'load identities for {si.hex()}')
        n = len(sql_ident_params)
        if len(sql_ident_params) > 1:
            do_gc()
        for i, (sql_ident, params_i) in enumerate(sql_ident_params):
            self.session_execute(sql_ident, params_i)
            #if i % 10 == 0:
                #log.debug('gc-pre')  # ugh 4 seconds at this point
                #gc.collect()
                #log.debug('gc-post')
            msg = f'{((i + 1) / n) * 100:3.0f}% done with batched load of identities for {si.hex()}'
            log.debug(msg)

        if len(sql_ident_params) > 1:
            do_gc()

        values = None
        sql_ident_params = None

        # TODO INSERT INTO name_to_identity

        log.debug(f'starting preload prep for identity_relations for {si.hex()}')
        sql_ident_rel_base = 'INSERT INTO identity_relations (p, s, o) VALUES '
        values_ident_rel = [(self.serialization_identity, part_ident)
                            for _part, *part_idents in types_idents[1:]
                            if _part != 'subject_graph'
                            # subject graph is linked via the data, it
                            # is an extra join in the query but cuts
                            # the table size in half
                            for part_ident in part_idents
                            ]
        log.debug(f'starting named subjects for identity_relations for {si.hex()}')
        # FIXME this is somehow insasnely slow for loading with cdes
        di = self.Loader.data_identity
        values_ident_rel += [
            (di, dnsi) for dnsi in self.Loader.data_named_subject_identities]

        log.debug(f'starting chunking for identity_relations for {si.hex()}')
        sql_irel_params = []
        for chunk in chunk_list(values_ident_rel, batchsize):
            # TODO dereferencedTo for name -> identity
            vt, params_ir = makeParamsValues(chunk, constants=(':p',))
            params_ir['p'] = 'hasPart'
            sql_rel_ident = sql_ident_rel_base + vt
            sql_irel_params.append((sql_rel_ident, params_ir))

        log.debug(f'load identity_relations for {si.hex()}')
        n = len(sql_irel_params)
        if len(sql_irel_params) > 1:
            do_gc()
        for i, (sql_rel_ident, params_ir) in enumerate(sql_irel_params):
            self.session_execute(sql_rel_ident, params_ir)
            msg = f'{((i + 1) / n) * 100:3.0f}% done with batched load of identity_relations for {si.hex()}'
            log.debug(msg)

        if len(sql_irel_params) > 1:
            do_gc()
        values_ident_rel = None
        sql_irel_params = None
        # 'INSERT INTO qualifiers (identity, group_id)'
        # FIXME this should happen automatically in the database
        # we just need to get the value back out

        params_le = dict(si=si, g=self.group, u=self.user)
        sql_le = ('INSERT INTO load_events (serialization_identity, group_id, user_id) '
                  'VALUES (:si, idFromGroupname(:g), idFromGroupname(:u))')
        log.debug(f'load load_events for {si.hex()}')
        self.session_execute(sql_le, params_le)  # FIXME why is the table always empty ?!?!??!

        # TODO get the qualifier id so that it can be 

        def sortkey(kv):
            k, v = kv
            return k  # FIXME TODO this needs to be checked and improved to control insert order

        batchsize = 20000  # keep maximum memory usage under control XXX also in sync probably centralize this?
        # 20k better than 80k or 40k probably due to less alloc when parsing or something
        separate = False
        separates = []
        value_sets = []
        statements = []
        fixes = []
        for prefix, suffix, to_insert, to_fix in self.Loader.make_load_records(
                self.serialization_identity,
                curies_done, metadata_done,
                data_done, self.ident_exists):
            if to_fix:
                fixes.append(to_fix)
            for columns, values in sorted(to_insert.items(), key=sortkey):
                if len(values) > batchsize:
                    separate = True
                    value_sets.append(list(chunk_list(values, batchsize)))
                    separates.append(True)
                else:
                    value_sets.append(values)
                    separates.append(False)

                statement = ' '.join((prefix, f'({columns}) VALUES', '{}', suffix))
                statements.append(statement)

        if self.debug:
            # test to see whether the named triples we insert into triples matches identity_named_triples_ingest
            hrm = [v for s, v in zip(statements, value_sets) if 'triple_identity) VALUES' in s and 'identity_named_triples_ingest' not in s]
            # FIXME a bit worrying that somehow separates is needed at a more granular level now ???
            tis = sorted([row[-1] for sep, h in zip(separates, hrm) for row in
                          ((row for vs_chunk in h for row in vs_chunk)
                           if sep else
                           h)])
            stis = set(tis)
            if len(tis) != len(stis):
                breakpoint()
            assert len(tis) == len(stis)
            idtt = [v for s, v in zip(statements, value_sets) if 'identity_named_triples_ingest' in s][0]
            idtis = sorted(([p[-1] for ps in idtt for p in ps]
                            if separate else
                            [p[-1] for p in idtt]))
            sidtis = set(idtis)
            if len(idtis) != len(sidtis):
                breakpoint()
            assert len(idtis) == len(sidtis)
            extra_in_id_to_trips = sidtis - stis
            missing_in_id_to_trips = stis - sidtis
            if sidtis != stis:
                breakpoint()
            assert sidtis == stis
            # ... so according to my check here all the triple identities should
            # be getting inserted, or at least the sets match exactly, which is
            # obvious from how they are consturcted, but just to make sure we
            # are sane here on the other end too ... so the problem is after this
            # XXX maybe related to chunking? surely not
            #breakpoint()
            hrm, tis, stis, idtt, idtis, sidtis = None, None, None, None, None, None

        if any(separates):
            nexecs = sum([len(vals) if sep else 1 for sep, vals in zip(separates, value_sets)])
            msg = f'running statements individually batch at {batchsize} with {nexecs} total executions'
            log.debug(msg)
            def run_statement(values, statement):
                value_templates, params = makeParamsValues(values)
                sql = statement.format(value_templates)
                self.session_execute(sql, params)

            # TODO FIXME handle error cases and probably figure out how to roll back or something
            # the other possible source of the high memory usage might be the fact that this is all in one transaction?
            # and we commit at the end ... explore the possibility of commiting at checkpoints?
            count = 0
            def _logm():
                percent = (count / nexecs) * 100
                msg = f'loading approximately {percent:3.0f}% done for triples for {si.hex()}'
                log.debug(msg)

            # FIXME this whole thing is massively blocked on disk on the postgres side?
            # is it all the index updates or what ... this is nutso, possibly the batchsize is too large for triples?
            # currently looks like it is taking 8 hours !? what the heck is the batch size !?
            # except that the speed is incredibly variable now up to 50% and was going at an incredibly rapid pace
            # only to grind to a halt again ??? except no way ... all the triples should have been done first ???

            # memory usage hits up to 27 gigs and then drops to 23, wat

            # with well placed gcs memory usage is down to 15 gigs at this point
            # but still seeing stalls, possibly on disk? or maybe it is the batchsize for these? the triple rows are larger?
            # also might be the indexes that are an issue? but no those shouldn't be causing this level of slowdown
            do_gc()
            for i, (separate, values, statement) in enumerate(zip(separates, value_sets, statements)):
                if separate:
                    for j, chunk in enumerate(values):
                        count += 1
                        run_statement(chunk, statement)
                        _logm()
                else:
                    count += 1
                    run_statement(values, statement)
                    _logm()
            do_gc()

        else:
            *value_templates, params = makeParamsValues(*value_sets)
            sql = ';\n'.join(statements).format(*value_templates)
            # FIXME will fail if query is empty e.g. if all terms are already present ????
            self.session_execute(sql, params)
            if self.debug:
                printD()
                [print(k, v) for k, v in params.items()]

        self.times['load_end'] = time.time()
        # TODO create qualifiers

        # TODO immediately insert fixes as a new qualifier noting that they are
        # automated changes so that they are part of the same transaction

        #if fixes:
            #breakpoint()
        #return 'aaaaaaaaaaaaaaaaTODO\n'  # FIXME returning this makes downstream think we are in error
        return ''


class InterLexFactory(TripleLoaderFactory):
    def __call__(self, user, triples):
        pass
        # note, we don't revert history,
        # we just add triples back in a new transaction
        # the joys of invariance


class FileFromBaseFactory(TripleLoaderFactory):
    immediate_loading_limit_mb = 2

    def check(self, name):
        maybe_error = super().check(name)
        if maybe_error:
            return maybe_error
        else:
            # size checks!
            # TODO in theory we might also want to have the gzipped identity
            # or simply pull down smallish gzipped files and test to see if
            # they are already in the db, if they aren't and are too big to
            # load quickly, then we can just send back the timeout message

            # FIXME we probably shouldn't implicitly call
            # self.serialization here? or what? maybe ok?

            # TODO should already be doing these loads in another process
            # that way if we can just set an actual timeout not a fake size
            # timeout and just send the job number (which we need to create anyway)
            return not (self.isGzipped and
                        self.content_length_mb < 0.5 and
                        self.actual_length_mb < self.immediate_loading_limit_mb
                        or
                        self.content_length_mb < self.immediate_loading_limit_mb)

    @property
    def isGzipped(self):
        # overwrite
        return False

    @property
    def content_length(self):
        # overwrite this to e.g. get this from a header
        return self.actual_length

    @property
    def content_length_mb(self):
        return self.content_length / 1024 ** 2

    @property
    def actual_length(self):
        # DO NOT TRUST THE HEADER
        return len(self.serialization)

    @property
    def actual_length_mb(self):
        return self.actual_length / 1024 ** 2

    @property
    def extension(self):
        if self._extension is None:
            path = PurePath(self.name)
            self._extension = path.suffix[1:]

        return self._extension


class FileFromFileFactory(FileFromBaseFactory):
    def __init__(self, group, user, reference_name=None):
        if reference_name is None:
            # FIXME the way this is implemented will be one way to check to make
            # sure that users/groups match the reference_name?
            reference_name = f'http://{self.reference_host}/{group}/upload/test'
        super().__init__(group, user, reference_name)

    def check(self, name):
        self.path = Path(name).resolve().absolute()
        name = self.path.as_uri()
        return super().check(name)

    def __call__(self, expected_bound_name):
        setup_failed = super().__call__(expected_bound_name)
        # XXX leaving this as a warning don't pass graph in directly
        # to this class it _should_ fail subclasss TripleLoader if you need that
        # make sure we have populated values before unsetting path
        # in the event that graph is patched in
        # self.format
        # self.serialization
        self.path = None  # avoid poluting the class namespace
        return setup_failed

    @property
    def serialization(self):
        if self._serialization is None:
            with open(self.path.as_posix(), 'rb') as f:
                self._serialization = f.read()

        return self._serialization


class FileFromIRIFactory(FileFromBaseFactory):
    maxsize_mbgz = 5
    maxsize_mb = 20
    lfmessage = (f'You appear to by trying to load a file bigger than {maxsize_mb}MB. '
                 'Please get in touch with us if you want this included in InterLex.')

    def check(self, name):
        # in any case where this function is called name should not equal reference name
        # it should either be a filename or something like that
        if name == self.reference_name:
            # FIXME this is if the iri is give, obviously the bound name will
            # match and everything should work, do need to figure out how to
            # handle this case properly though... name = None and _serialization already set
            # NOTE for direct user contributions name should be their orcid
            # or the interface/api endpoint they were using if we want to track that?
            raise exc.NoSelfLoadError('you cannot load an ontology into itself from '
                                      'itself unless you are interlex itself')
        elif self.reference_host in name:
            # TODO provide an alternative
            # FIXME the error messages should not be sent here
            # these need to be translated into load errors
            raise exc.NoCopyingError('you cannot copy content from one '
                                     'reference name to another in this way')

        return super().check(name)

    @exc.hasErrors(exc.LoadError)
    def __call__(self, expected_bound_name=None):
        if 'begin' not in self.times:
            self.times['begin'] = time.time()
        # expected_bound_name should only be supplied if it differes from name for the inital load
        # self.name = name  # TODO this is not quite ready yet, loading from arbitrary uris/filenames needs one more level

        # TODO logic when bound_name = reference_name, seems to be handled below correctly...
        if expected_bound_name is None:
            expected_bound_name = self.name  # TODO better error for when prepare has not been called

        return super().__call__(expected_bound_name)

    @property
    def header(self):
        if self._header is None:
            # TODO break this into its own property
            s = requests.Session()
            printD(self.name)
            head = requests.head(self.name)  # check on the size to make sure no troll

            while head.is_redirect and head.status_code < 400:  # FIXME redirect loop issue
                head = s.send(head.next)
                if not head.is_redirect:
                    break

            if head.status_code >= 400:
                raise exc.LoadError(f'Nothing found at {self.name}\n')

            self._header = head.headers

        return self._header

    @property
    def isGzipped(self):
        return 'Content-Encoding' in self.header and self.header['Content-Encoding'] == 'gzip'

    @property
    def content_length(self):
        return int(self.header['Content-Length'])

    @property
    def mimetype(self):
        if self._mimetype is None:
            if 'Content-Type' in self.header:
                self._mimetype = self.header['Content-Type'] 
            else:
                self._mimetype = None

        return self._mimetype

    @property
    def serialization(self):
        if self._serialization is not None:
            return self._serialization

        self.times['fetch_begin'] = time.time()

        # unauthorized people can get here because we don't know the size of the payload apriori
        # HOWEVER IF they control the server that hosts the IRI they can spoof the content length
        # header so we need to check and make sure that they have not lied to us
        # obviously if we have someone with admin in base doing this we are toast anyway but
        # sometimes it might also happen by accident because someone misconfigured their server
        permissions_sql = 'SELECT * from user_permissions WHERE user_id = idFromGroupname(:group)'
        admin_check_sql = permissions_sql + " AND group_id = 0 AND user_role = 'admin'"
        admin_check_args = dict(group=self.user)

        printD(admin_check_sql, admin_check_args)
        try:
            indeed = next(self.session_execute(admin_check_sql, admin_check_args))
            print(indeed)
            is_admin = True
        except StopIteration:
            is_admin = False
        
        printD('user is admin?', is_admin)

        if self.isGzipped:
            if self.content_length_mb > self.maxsize_mbgz:
                if not is_admin:
                    raise exc.LoadError(self.lfmessage, 413)  # TODO error handling

        if self.content_length_mb > self.maxsize_mb:
            if not is_admin:
                raise exc.LoadError(self.lfmessage, 413)

        ori = OntResIri(self.name)  # TODO probably want this at the class level for a variety of reasons
        #meta = ori.metadata()
        #meta.graph.debug()  # ah magic
        # XXX this mimics the old way, but there are better ways to achieve similar use cases
        # now without holding stupid amounts of raw data in memory
        self._serialization = b''.join(ori.data)
        self._mimetype = ori.format

        self.times['fetch_end'] = time.time()
        #breakpoint()
        return self._serialization

        # TODO check declared ontology_iri vs actually ontology_iri

        # TODO just parse ontology header where possible?
        # graph.parse(filepath, format=format)


class FileFromPostFactory(FileFromIRIFactory):
    def __init__(self, group, user, reference_name=None):
        super().__init__(group, user, reference_name)

    def check(self, header):  # FIXME ... reference names and stuff
        self._header = {k:v for k, v in header.items()}
        # NOTE content length will be longer than actual length
        # since there is additional form data
        return not (self.content_length_mb < self.immediate_loading_limit_mb)

    @exc.hasErrors(exc.LoadError)
    def __call__(self, file_meta, serialization, create):
        if not self.times:
            self.times = {'begin':time.time()}
        self.create = create

        self.name = f'file://{file_meta.filename}'
        #self._extension = file.filename.rsplit('.', 1)[-1]
        self._mimetype = file_meta.mimetype
        self._serialization = serialization

        self.reference_name
        return super().__call__(self.expected_bound_name)

    @property
    def serialization(self):
        if self._serialization is None:
            raise exc.ShouldNotHappenError('How did you manage this one!?')

        return self._serialization

    @property
    def reference_name(self):
        if self._reference_name is None and self.Loader.bound_name is not None:
            # FIXME name_prefix should probably be usable more broadly
            name_prefix = os.path.join(self.reference_host, self.group, 'ontologies')
            if name_prefix in self.Loader.bound_name:
                name_type = 'name'
            elif self.reference_host in self.Loader.bound_name:
                raise LoadError(f'Group does not match bound name group!\n'
                                '{self.group} not in {self.Loader.bound_name}')
            else:
                name_type = 'expected_bound_name'

            sql = ('SELECT name, expected_bound_name FROM reference_names '
                   f'WHERE {name_type} = :name')
            try:
                res = next(self.session_execute(sql, dict(name=self.Loader.bound_name)))
                self._reference_name = rdflib.URIRef(res.name)
                self._expected_bound_name = rdflib.URIRef(res.expected_bound_name)
                self.reference_name_in_db = True
            except StopIteration:
                if self.create:
                    # TODO proper group assignment for ownership
                    # along with the proper notifications regarding
                    # whether the user is acting on behalf of the group
                    # or whether they are acting on their own in which
                    # case the group is notified
                    if name_type == 'name':
                        self.reference_name = self.Loader.bound_name
                        self.name = self.Loader.bound_name
                    elif name_type == 'expected_bound_name':
                        url = urlparse(self.Loader.bound_name)
                        name_suffix = url.path[1:]
                        #breakpoint()  # FIXME TODO we need the host in there too for this and TODO need to detect external ontid vs internal ontid
                        name = f'{self.scheme}://' + os.path.join(name_prefix, name_suffix)
                        self.reference_name = rdflib.URIRef(name)
                        self.expected_bound_name = self.Loader.bound_name  # FIXME a hack to trigger INSERT ...
                    else:
                        raise BaseException('wat this should never happen')

                else:
                    raise LoadError(f'bound_name {self.Loader.bound_name} has not been '
                                    'attached to a reference_name and `{"create":true}` '
                                    'was not set.\n'
                                    'Please set create = true or POST directly to '
                                    'the desired endpoint (reference_name).', )
                    self.reference_name_in_db = False
                printD('WARNING reference name has not been created yet!\n')

        return self._reference_name

    @reference_name.setter
    def reference_name(self, value):
        super().reference_name_setter(value)


class FileFromVCSFactory(TripleLoaderFactory):
    pass
