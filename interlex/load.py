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
from pyontutils.core import OntId
from pyontutils.utils import TermColors as tc
from pyontutils.namespaces import definition
from pyontutils.namespaces import makeNamespaces, ILX, NIFRID, ilxtr
from pyontutils.combinators import annotation
from pyontutils.closed_namespaces import rdf, rdfs, owl, oboInOwl
from interlex import exc
from interlex.exc import hasErrors, bigError
from interlex.auth import Auth
from interlex.core import printD, bnodes, makeParamsValues, IdentityBNode, synonym_types, dbUri
from interlex.dump import Queries
from IPython import embed

ilxr, *_ = makeNamespaces('ilxr')


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
        #self._connected_subgraph_identities = None  # not used
        self._metadata_connected_subgraph_identities = None
        self._data_connected_subgraph_identities = None
        self._free_subgraph_identities = None
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
        # FIXME SECURITY we will need restrict which existing qualifiers can
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
        return self.get_identity('metadata')

    @property
    def data_identity(self):  # FIXME! this should be data + free_subgraph_identities XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        # the head triple in all cases is bound to the ontology name
        moar = sorted(self.free_subgraph_identities)
        return self.get_identity('data')

    @property
    def subgraph_identities(self):
        return {**self.connected_subgraph_identities, **self.free_subgraph_identities}

    @property
    def connected_subgraph_identities(self):
        return {**self.metadata_connected_subgraph_identities, **self.data_connected_subgraph_identities}

    @property
    def metadata_connected_subgraph_identities(self):
        if self._metadata_connected_subgraph_identities is None:
            self.process_graph()

        return self._metadata_connected_subgraph_identities

    @property
    def data_connected_subgraph_identities(self):
        if self._data_connected_subgraph_identities is None:
            self.process_graph()

        return self._data_connected_subgraph_identities

    @property
    def free_subgraph_identities(self):
        if self._free_subgraph_identities is None:
            self.process_graph()

        return self._free_subgraph_identities

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
            subjects = self.graph[:rdf.type:owl.Ontology]
            # FIXME this should be erroring on no bound names?
            self._bound_name = str(next(subjects))
            try:
                extra = next(subjects)
                raise exc.LoadError('More than one owl:Ontology in this file!\n'
                                    '{self.ontology_iri}\n{extra}\n', 409)
            except StopIteration:
                pass

        return self._bound_name

    @property
    def metadata(self):
        yield from self.metadata_named
        yield from self.metadata_unnamed

    @property
    def metadata_raw(self):
        yield from self.graph[self.bound_name::]

    @property
    def metadata_named(self):
        for p, o in self.metadata_raw:
            if not isinstance(o, rdflib.BNode):
                yield p, o

    @property
    def metadata_unnamed(self):
        if not hasattr(self, '_blank_identities'):
            self.process_graph()

        for p, o in self.metadata_raw:
            if isinstance(o, rdflib.BNode):
                yield p, self._blank_identities[o]

    @property
    def data(self):
        yield from self.data_named
        yield from self.data_unnamed

    @property
    def data_raw(self):
        bn = self.bound_name
        yield from (t for t in self.graph if t[0] != bn)

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
            if not isinstance(s, rdflib.BNode) and isinstance(o, rdflib.BNode):
                # TODO this does not cover free trips
                yield s, p, self._blank_identities[o]

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
        if self.bound_name:
            return 1

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
        return self.metadata_named_count + sum(self.metadata_connected_counts.values())

    @property
    def data_named_count(self):  # FIXME unnamed should be called tainted
        return len(list(self.data))

    @property
    def data_connected_counts(self):
        return {i:len(sg) for i, sg in self.data_connected_subgraph_identities.items()}

    @property
    def data_count(self):
        return self.data_named_count + sum(self.data_connected_counts.values())

    @property
    def connected_counts(self):
        # NOTE this double counts if added to metadata_counts and data_counts
        return {**self.data_connected_counts, **self.data_connected_counts}

    @property
    def free_counts(self):
        return {i:len(sg) for i, sg in self.free_subgraph_identities.items()}

    @property
    def counts(self):
        counts = {self.curies_identity:self.curies_count,
                  self.metadata_identity:self.metadata_count,
                  self.data_identity:self.data_count,
                  **self.connected_counts,
                  **self.free_counts}

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
        def normalize(cmax, t, existing):
            for e in t:
                if isinstance(e, rdflib.BNode):
                    if e not in existing:
                        cmax += 1
                        existing[e] = cmax

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

        def normgraph(head_subject, subgraph):
            cmax = 0
            existing = {head_subject:0}  # FIXME the head of a list is arbitrary :/
            normalized = []
            for trip in sorted(subgraph, key=sortkey):
                s, p, o = trip
                if o == head_subject:
                    if not isinstance(s, rdflib.BNode):
                        #printD(tc.red('Yep working'), trip, o)
                        continue  # this has already been entered as part of data_unnamed
                    else:
                        raise TypeError('This should never happen!')

                *ntrip, cmax = normalize(cmax, trip, existing)
                normalized.append(tuple(ntrip))  # today we learned that * -> list
            return tuple(normalized)

        datas = ('metadata', self.metadata_raw), ('data', self.data_raw)
        for name, data in datas:
            idents = IdentityBNode(data, debug=True)

            free_subgraph_identities = {identity:normgraph(s, idents.subgraph_mappings[s])
                                        for s, identity in idents.unnamed_subgraph_identities.items()}

            self._blank_identities = idents.blank_identities
            inverse = {v:k for k, v in idents.blank_identities.items()}

            if name == 'data':
                self._free_subgraph_identities = free_subgraph_identities

            for identity, o in idents.connected_object_identities.items():
                idents.subgraph_mappings[o]

            connected_subgraph_identities = {identity:normgraph(o, idents.subgraph_mappings[o])
                                          for identity, o in idents.connected_object_identities.items()}

            setattr(self, '_' + name + '_connected_subgraph_identities',
                    connected_subgraph_identities)

            if self._blank_identities:
                #printD(self._blank_identities)
                if self.debug:
                    embed()


class GraphLoader(GraphIdentities):

    @staticmethod
    def make_row(s, p, o, subgraph_identity=None):

        def str_None(thing):
            return str(thing) if thing is not None else thing

        # assume p is uriref, issues should be caught before here
        p = str(p)

        if type(o) == bytes:
            # if an identity is supplied as an object shift it automatically
            subgraph_identity = o
            o = 0

        if isinstance(s, rdflib.URIRef) and isinstance(o, rdflib.URIRef):
            columns = 's, p, o'
            record = (str(s),
                      p,
                      str(o))

        elif isinstance(s, rdflib.URIRef) and isinstance(o, rdflib.Literal):
            columns = 's, p, o_lit, datatype, language'
            record = (str(s),
                      p,
                      str(o),
                      str_None(o.datatype),
                      str_None(o.language))

        elif isinstance(s, rdflib.URIRef) and isinstance(o, int) and subgraph_identity is not None:
            columns = 's, p, o_blank, subgraph_identity'
            record = (str(s),
                      p,
                      o,
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, int) and subgraph_identity is not None:
            columns = 's_blank, p, o_blank, subgraph_identity'
            record = (s,
                      p,
                      o,
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, rdflib.URIRef) and subgraph_identity is not None:
            columns = 's_blank, p, o, subgraph_identity'
            record = (s,
                      p,
                      str(o),
                      subgraph_identity)

        elif isinstance(s, int) and isinstance(o, rdflib.Literal) and subgraph_identity is not None:
            columns = 's_blank, p, o_lit, datatype, language, subgraph_identity'
            record = (s,
                      p,
                      str(o),
                      str_None(o.datatype),
                      str_None(o.language),
                      subgraph_identity)

        else:
            raise ValueError(f'{s} {p} {o} {subgraph_identity} has an unknown or invalid type signature')

        #lc, lr = len(columns.split(', ')), len(record)
        #assert lc == lr, f'lengths {lc} != {lr} do not match {columns!r} {record}'
        return columns, record

    def make_load_records(self, serialization_identity, curies_done, metadata_done, data_done, ident_exists):
        # if you need to test pass in lambda i:False for ident_exists
        # TODO resursive on type?
        # s, s_blank, p, o, o_lit, datatype, language, subgraph_identity
        if not curies_done:
            c = []
            to_insert = {'serialization_identity, curie_prefix, iri_prefix':c}
            for curie_prefix, iri_prefix in sorted(self.curies):  # FIXME ordering issue
                c.append((serialization_identity, curie_prefix, iri_prefix))

            yield 'INSERT INTO curies', '', to_insert

        def sortkey(triple):  # FIXME this a bad way to sort...
            return tuple(e if isinstance(e, str) else str(e) for e in triple)

        prefix = 'INSERT INTO triples'
        suffix = 'ON CONFLICT DO NOTHING'  # FIXME BAD
        bn = self.bound_name
        if not metadata_done:
            to_insert = defaultdict(list)  # should all be unique
            for p, o in sorted(self.metadata, key=sortkey):  # FIXME resolve bnode ordering issue?
                columns, record = self.make_row(bn, p,  o)
                to_insert[columns].append(record)

            yield prefix, suffix, to_insert

        if not data_done:
            to_insert = defaultdict(list)  # should all be unique
            for s, p, o in sorted(self.data, key=sortkey):  # FIXME resolve bnode ordering issue? or was it already?
                columns, record = self.make_row(s, p, o)
                to_insert[columns].append(record)

            yield prefix, suffix, to_insert

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
        for identity, subgraph in self.subgraph_identities.items():
            if self.debug:
                printD(identity)
                [print(*(OntId(e).curie if
                         isinstance(e, rdflib.URIRef) else
                         repr(e) for e in t))
                 for t in sorted(subgraph, key=intfirst)]

            if not ident_exists(identity):  # we run a batch check before
                for t in sorted(subgraph, key=intfirst):
                    columns, record = self.make_row(*t, subgraph_identity=identity)
                    to_insert[columns].append(record)
                    # FIXME insertion order will be broken because of this
                    # however the order can be reconstructed on the way out...
                    # the trick however is to know which identities we need to
                    # insert for free subgraphs?

        prefix = 'INSERT INTO triples'
        suffix = 'ON CONFLICT DO NOTHING'  # FIXME BAD
        if to_insert:
            yield prefix, suffix, {k:v for k, v in to_insert.items()}


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
                                      execute=session.execute,
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
            raise ValueError('FIXME this needs to be a logged auth consistency error {g}')
        self.group = group
        self.user = user
        #self.user_role = 'lol'  # TODO this works but testing
        # read only does not need to be enforced in the database becuase user role
        # is the ultimate defense and that _is_ in the database
        # it is more of a convenience reminder

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
                res = next(self.session.execute(sql, dict(name=group)))
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
    formats = {
        'text/turtle':'turtle',
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

    @hasErrors(exc.LoadError)
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
            embed()

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
                return 'Bound names do not match! {b} {d} {e}', 400

        def all_none(case):
            if self.reference_name != 'https://{self.reference_host}/{self.group}/upload':
                return 'No bound name, please use your upload endpoint', 400

        def set_d(case):
            self.expected_bound_name = self.Loader.bound_name

        # bound database expected
        bde_switch = make_switch((
            ((NOTN, NOTN, NOTN), all_nn),
            ((___n, ___n, ___n), all_none),  # fail if not on
            ((NOTN, ___n, ___n), set_d),  # OK bn as ebn
            ((___n, NOTN, ___n), bn_none, self.expected_bound_name),
            ((___n, ___n, NOTN), bn_none, expected_bound_name),
            ((___n, NOTN, NOTN), bn_none, None, 'existing expected bound name exists and does not match new'),
            ((NOTN, ___n, NOTN), pairs, 'bound name does not match new expected bound name'),
            ((NOTN, NOTN, ___n), pairs, 'bound name does not match existing expected bound name'),
            ))

        return bde_switch

    @hasErrors(exc.LoadError)
    def load(self):
        output = ''
        try:
            output += self.load_event()
            self.times['commit_begin'] = time.time()
            self.session.commit()
            self.times['commit_end'] = time.time()
            self.cache_on_success()
            return output
        except BaseException as e:
            self.session.rollback()
            if type(e) == exc.LoadError:
                raise e

            embed()
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
                self.session.execute(sql, dict(name=value))
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
            self.execute(sql, dict(r=self.reference_name, e=value, group_id=self.group_id))
            self._expected_bound_name = value
            self.reference_name_in_db = True  # ok to set again
            #printD('embedding')
            #embed()

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
            self._graph = rdflib.Graph()
            try:
                if self.format == 'xml':
                    data = rapper(self.serialization)
                    self._graph.parse(data=data, format='nt')  # FIXME this destroys any file level prefixes
                else:
                    self._graph.parse(data=self.serialization, format=self.format)
            except TypeError as e:
                embed()
                raise e
            finally:
                self.times['graph_end'] = time.time()

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
                res = next(self.session.execute(sql, dict(name=self._reference_name)))
                self._expected_bound_name = res.expected_bound_name
                self.reference_name_in_db = True
            except StopIteration:
                # set it by setting self.expected_bound_name = something (including None)
                self.reference_name_in_db = False
                printD('WARNING reference name has not been created yet!\n')
        elif self._reference_name != value:
            raise exc.LoadError('cannot change reference names', 409)

    def batch_ident_check(self, *idents):
        sql = 'SELECT identity FROM identities WHERE identity IN '
        values_template, params = makeParamsValues((idents,))
        res = self.session.execute(sql + values_template, params)
        existing = set(r.identity for r in res)
        self._cache_identities.update(existing)
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
            next(self.session.execute(sql, dict(ident=ident)))
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
            counts[self.serialization_identity] = self.Loader.data_count
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

        self.times['load_begin'] = time.time()
        sgids = tuple(self.Loader.subgraph_identities)
        idents = (self.Loader.curies_identity,
                  self.Loader.metadata_identity,
                  self.Loader.data_identity,
                  *sgids)

        curies_done, metadata_done, data_done, *sg_done = self.batch_ident_check(*idents)

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
                        ('subgraph', *self.Loader.free_subgraph_identities))
        assert not any(v is None for t, *vs in types_idents
                       for v in vs), f'oops! {[(t, v) for t, v in types if v is None]}'
        values = ((i, type, self.identity_triple_count(i))
                  for type, *identities in types_idents
                  for i in identities)
        vt, params_i = makeParamsValues(values, constants=(':rn',))
        params_i['rn'] = self.reference_name
        sql_ident = sql_ident_base + vt + ' ON CONFLICT DO NOTHING'  # TODO FIXME XXX THIS IS BAD
        #embed()  # TODO
        self.session.execute(sql_ident, params_i)

        sql_ident_rel_base = 'INSERT INTO identity_relations (p, s, o) VALUES '
        values_ident_rel = ((self.serialization_identity, part_ident)
                            for _, *part_idents in types_idents[1:]
                            for part_ident in part_idents)
        # TODO dereferencedTo for name -> identity
        vt, params_ir = makeParamsValues(values_ident_rel, constants=(':p',))
        params_ir['p'] = 'hasPart'
        sql_rel_ident = sql_ident_rel_base + vt
        self.session.execute(sql_rel_ident, params_ir)

        # 'INSERT INTO qualifiers (identity, group_id)'
        # FIXME this should happen automatically in the database
        # we just need to get the value back out

        params_le = dict(si=si, g=self.group, u=self.user)
        sql_le = ('INSERT INTO load_events (serialization_identity, group_id, user_id) '
                  'VALUES (:si, idFromGroupname(:g), idFromGroupname(:u))')
        self.session.execute(sql_le, params_le)

        # TODO get the qualifier id so that it can be 

        def sortkey(kv):
            k, v = kv
            return k  # FIXME TODO this needs to be checked an improved to control insert order

        value_sets = []
        statements = []
        for prefix, suffix, to_insert in self.Loader.make_load_records(self.serialization_identity,
                                                                       curies_done, metadata_done,
                                                                       data_done, self.ident_exists):
            for columns, values in sorted(to_insert.items(), key=sortkey):
                value_sets.append(values)
                statement = ' '.join((prefix, f'({columns}) VALUES', '{}', suffix))
                statements.append(statement)

        *value_templates, params = makeParamsValues(*value_sets)
        sql = ';\n'.join(statements).format(*value_templates)
        self.execute(sql, params)
        if self.debug:
            printD()
            [print(k, v) for k, v in params.items()]

        self.times['load_end'] = time.time()
        # TODO create qualifiers
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
        setup_ok = super().__call__(expected_bound_name)
        # XXX leaving this as a warning don't pass graph in directly
        # to this class it _should_ fail subclasss TripleLoader if you need that
        # make sure we have populated values before unsetting path
        # in the event that graph is patched in
        # self.format
        # self.serialization
        self.path = None  # avoid poluting the class namespace
        return setup_ok

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

    @hasErrors(exc.LoadError)
    def __call__(self, expected_bound_name=None):
        if 'begin' not in self.times:
            self.times['begin'] = time.time()
        # expected_bound_name should only be supplied if it differes from name for the inital load
        # self.name = name  # TODO this is not quite ready yet, loading from arbitrary uris/filenames needs one more level

        # TODO logic when bound_name = reference_name, seems to be handled below correctly...
        if expected_bound_name is None:
            expected_bound_name = self.name  # TODO better error for when prepare has not been called

        super().__call__(expected_bound_name)

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
            indeed = next(self.session.execute(admin_check_sql, admin_check_args))
            print(indeed)
            is_admin = True
        except StopIteration:
            is_admin = False
        
        printD('user is admin?', is_admin)

        if self.isGzipped:
            if self.content_length_mb > self.maxsize_mbgz:
                if not is_admin:
                    raise exc.LoadError(self.lfmessage, 413)  # TODO error handling
            resp = requests.get(self.name)
        else:
            resp = None

        if self.content_length_mb > self.maxsize_mb:
            if not is_admin:
                raise exc.LoadError(self.lfmessage, 413)

        if resp is None:
            resp = requests.get(self.name)

        self._serialization = resp.content
        self.times['fetch_end'] = time.time()
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

    @hasErrors(exc.LoadError)
    def __call__(self, file_meta, serialization, create):
        if not self.times:
            self.times = {'begin':time.time()}
        self.create = create

        self.name = f'file://{file_meta.filename}'
        #self._extension = file.filename.rsplit('.', 1)[-1]
        self._mimetype = file_meta.mimetype
        self._serialization = serialization

        self.reference_name
        super().__call__(self.expected_bound_name)

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
                res = next(self.session.execute(sql, dict(name=self.Loader.bound_name)))
                self._reference_name = res.name
                self._expected_bound_name = res.expected_bound_name
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
                        name_suffix = urlparse(self.Loader.bound_name).path[1:]
                        name = f'{self.scheme}://' + os.path.join(name_prefix, name_suffix)
                        self.reference_name = name
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


# get interlex
class InterLexLoad:
    stype_lookup = synonym_types
    def __init__(self, Loader, do_cdes=False, debug=False):
        import socket
        from sqlalchemy import create_engine, inspect
        from interlex import config
        self.loader = Loader('tgbugs', 'tgbugs', 'http://uri.interlex.org/base/interlex')

        self.queries = Queries(self.loader.session)
        self.do_cdes = do_cdes
        self.debug = debug
        self.admin_engine = create_engine(dbUri(user='interlex-admin'), echo=True)
        self.admin_exec = self.admin_engine.execute
        from pyontutils.utils import mysql_conn_helper
        DB_URI = 'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{db}'
        if socket.gethostname() in config.dev_remote_hosts:
            dbconfig = mysql_conn_helper('localhost', 'nif_eelg', 'nif_eelg_secure', 33060)  # see .ssh/config
        else:
            dbconfig = mysql_conn_helper('nif-mysql.crbs.ucsd.edu', 'nif_eelg', 'nif_eelg_secure')
        self.engine = create_engine(DB_URI.format(**dbconfig), echo=True)
        dbconfig = None
        del(dbconfig)
        self.insp = inspect(self.engine)
        self.graph = None

    def setup(self):
        self.existing_ids()
        self.user_iris()
        self.make_triples()
        self.ids()

    @bigError
    def local_load(self):
        from pyontutils.core import makeGraph
        loader = self.loader
        loader.session.execute(self.ilx_sql, self.ilx_params)
        loader.session.execute(self.eid_sql, self.eid_params)
        loader.session.execute(self.uid_sql, self.uid_params)
        # FIXME this probably requires admin permissions
        self.admin_exec(f"SELECT setval('interlex_ids_seq', {self.current}, TRUE)")  # DANGERZONE
        if self.graph is None:
            self.graph = rdflib.Graph()
            self.loader._graph
            mg = makeGraph('', graph=self.graph)  # FIXME I swear I fixed this already
            [mg.add_trip(*t) for t in self.triples]
        self.loader._graph = self.graph
        name = 'http://toms.ilx.dump/TODO'
        self.loader.Loader._bound_name = name
        #self.loader.expected_bound_name = name
        self.loader._serialization = repr((name, self.triples)).encode()
        expected_bound_name = name
        setup_ok = self.loader(expected_bound_name)

        if setup_ok is not None:
            raise LoadError(setup_ok)

    @bigError
    def remote_load(self):
        self.loader.load()
        printD('Yay!')

    def load(self):
        self.local_load()
        self.remote_load()

    def ids(self):
        rows = self.engine.execute('SELECT DISTINCT ilx FROM terms ORDER BY ilx ASC')
        values = [(row.ilx[4:],) for row in rows]
        vt, self.ilx_params = makeParamsValues(values)
        self.ilx_sql = 'INSERT INTO interlex_ids VALUES ' + vt + ' ON CONFLICT DO NOTHING'  # FIXME BAD
        self.current = int(values[-1][0].strip('0'))
        printD(self.current)

    def cull_bads(self, eternal_screaming, values, ind):
        verwat = defaultdict(list)
        for row in sorted(eternal_screaming, key=lambda r:r[ind('version')], reverse=True):
            verwat[row[ind('ilx')][4:]].append(row)

        vervals = list(verwat.values())

        ver_curies = defaultdict(lambda:[None, set()])
        for ilx, rows in verwat.items():
            for row in rows:
                iri = row[ind('iri')]
                curie = row[ind('curie')]
                ver_curies[iri][0] = ilx
                ver_curies[iri][1].add(curie)

        mult_curies = {k:v for k, v in ver_curies.items() if len(v[1]) > 1}

        maybe_mult = defaultdict(list)
        versions = defaultdict(list)
        for ilx, iri, ver in sorted(values, key=lambda t:t[-1], reverse=True):
            versions[ilx].append(ver)
            maybe_mult[iri].append(ilx)

        multiple_versions = {k:v for k, v in versions.items() if len(set(v)) > 1}

        any_mult = {k:v for k, v in maybe_mult.items() if len(v) > 1}

        dupe_report = {k:tuple(f'http://uri.interlex.org/base/ilx_{i}' for i in v)
                       for k, v in maybe_mult.items()
                       if len(set(v)) > 1}
        readable_report = {OntId(k):tuple(OntId(e) for e in v) for k, v in dupe_report.items()}
        _ = [print(repr(k), '\t', *(f'{e!r}' for e in v)) for k, v in sorted(readable_report.items())]

        dupes = tuple(dupe_report) + tuple(mult_curies)

        # dupes = [u for u, c in Counter(_[1] for _ in values).most_common() if c > 1]  # picked up non-unique ilx which is not what we wanted

        skips = []
        bads = []
        bads += [(a, b) for a, b, _ in values if b in dupes]
        # TODO one of these is incorrect can't quite figure out which, so skipping entirely for now
        for id_, iri, version in values:  # FIXME
            if ' ' in iri:  # sigh, skip these for now since pguri doesn't seem to handled them
                bads.append((id_, iri))
            elif 'neurolex.org/wiki' in iri:
                skips.append((id_, iri))

        bads = sorted(bads, key=lambda ab:ab[1])
        _ins_values = [(ilx, iri) for ilx, iri, ver in values if
                       (ilx, iri) not in bads and
                       (ilx, iri) not in skips]
        ins_values = [v for v in _ins_values if 'interlex.org' not in v[1]]
        user_iris = [v for v in _ins_values if 'interlex.org' in v[1] and 'org/base/' not in v[1]]
        base_iris = [v for v in _ins_values if 'interlex.org' in v[1] and 'org/base/' in v[1]]
        assert len(ins_values) + len(user_iris) + len(base_iris) == len(_ins_values)
        #ins_values += [(v[0], k) for k, v in mult_curies.items()]  # add curies back now fixed
        if self.debug:
            embed()
        return ins_values, bads, skips, user_iris

    def existing_ids(self):
        insp, engine = self.insp, self.engine

        terms = [c['name'] for c in insp.get_columns('terms')]
        term_existing_ids = [c['name'] for c in insp.get_columns('term_existing_ids')]
        header = term_existing_ids + terms

        def ind(name):
            if name in header:
                return header.index(name)
            else:
                raise IndexError()

        if self.do_cdes:
            query = engine.execute('SELECT * FROM term_existing_ids as teid '
                                   'JOIN terms as t '
                                   'ON t.id = teid.tid')
        else:
            query = engine.execute('SELECT * FROM term_existing_ids as teid '
                                   'JOIN terms as t '
                                   'ON t.id = teid.tid WHERE t.type != "cde"')

        #data = query.fetchall()
        #cdata = list(zip(*data))

        #def datal(head):
            #return cdata[header.index(head)]

        #values = [(row.ilx[4:], row.iri, row.version) for row in query if row.ilx not in row.iri]
        eternal_screaming = list(query)

        start_values = [(row[ind('ilx')][4:], row[ind('iri')], row[ind('version')])
                        for row in eternal_screaming
                        if row[ind('ilx')] not in row[ind('iri')]]

        values, bads, skips, user_iris = self.cull_bads(eternal_screaming, start_values, ind)

        sql_base = 'INSERT INTO existing_iris (group_id, ilx_id, iri) VALUES '
        values_template, params = makeParamsValues(values, constants=('idFromGroupname(:group)',))
        params['group'] = 'base'
        sql = sql_base + values_template + ' ON CONFLICT DO NOTHING'  # TODO return id? (on conflict ok here)
        self.eid_raw = eternal_screaming
        self.eid_starts = start_values
        self.eid_values = values
        self.eid_sql = sql
        self.eid_params = params
        self.eid_bads = bads
        self.eid_skips = skips
        self.eid_user_iris = user_iris
        if self.debug:
            printD(bads)
        return sql, params

    def user_iris(self):
        if not hasattr(self, 'eid_user_iris'):
            self.existing_ids()

        bads = []
        def iri_to_group_uripath(iri):
            if 'interlex.org' not in iri:
                raise ValueError(f'goofed {iri}')

            # FIXME do we really want this ... yes... because we don't want to
            # have to look inside uris to enforce mapping rules per user

            _, user_uris_path = iri.split('interlex.org/', 1)
            user, uris_path = user_uris_path.split('/', 1)
            if not uris_path.startswith('uris'):
                msg = f'not a user uris path {iri}'
                bads.append(msg)
                return None, None

            try:
                _, path = uris_path.split('/', 1)  # TODO in the actual impl this needs to be sanitized
            except ValueError:
                path = None
                bads.append(f'what is going on here!? {iri}')

            return user, path

        _values = [(ilx_id, *iri_to_group_uripath(iri))
                    for ilx_id, iri in self.eid_user_iris]

        if bads:
            raise ValueError('\n'.join(bads))

        gidmap = self.queries.getGroupIds(*sorted(set(u for _, u, _ in _values)))
        print(gidmap)
        values = [(ilx_id, gidmap[g], uri_path)
                  for ilx_id, g, uri_path in _values]
        sql_base = 'INSERT INTO uris (ilx_id, group_id, uri_path) VALUES '
        values_template, params = makeParamsValues(values)
        sql = sql_base + values_template + ' ON CONFLICT DO NOTHING'  # FIXME BAD
        self.uid_sql = sql
        self.uid_params = params

    def make_triples(self):
        insp, engine = self.insp, self.engine
        #ilxq = ('SELECT * FROM term_existing_ids as teid '
                #'JOIN terms as t ON t.id = teid.tid '
                #'WHERE t.type != "cde"')
        header_object_properties = [d['name'] for d in insp.get_columns('term_relationships')]
        header_subClassOf = [d['name'] for d in insp.get_columns('term_superclasses')]
        header_terms = [d['name'] for d in insp.get_columns('terms')]
        queries = dict(
            terms = f'SELECT * from terms WHERE type != "cde"',
            synonyms = "SELECT * from term_synonyms WHERE literal != ''",
            subClassOf = 'SELECT * from term_superclasses',
            object_properties = 'SELECT * from term_relationships',
            annotation_properties = 'SELECT * from term_annotations',  # FIXME we are missing these?
            )
        if self.do_cdes:
            queries['terms'] = 'SELECT * FROM terms'
        else:
            queries['cde_ids'] = 'SELECT id, ilx FROM terms where type = "cde"'
        data = {name:engine.execute(query).fetchall()
                for name, query in queries.items()}
        ilx_index = {}
        id_type = {}
        triples = [(ILX[ilx], oboInOwl.hasDbXref, iri) for ilx, iri in self.eid_skips]
        type_to_owl = {'term':owl.Class,
                       'cde':owl.Class,
                       'fde':owl.Class,
                       'annotation':owl.AnnotationProperty,
                       'relationship':owl.ObjectProperty}

        def addToIndex(id, ilx, class_):
            if ilx not in ilx_index:
                ilx_index[ilx] = []
            ilx_index[ilx].append(id)
            if id not in id_type:
                id_type[id] = []
            id_type[id].append(class_)

        if not self.do_cdes:
            [addToIndex(row.id, row.ilx[4:], owl.Class) for row in data['cde_ids']]

        bads = []
        for row in data['terms']:
            #id, ilx_with_prefix, _, _, _, _, label, definition, comment, type_
            ilx = row.ilx[4:]
            uri = f'http://uri.interlex.org/base/ilx_{ilx}'

            try:
                class_ = type_to_owl[row.type]
            except KeyError as e:
                bads.append(row)
                # fixed this particular case with
                # update terms set type = 'term' where id = 304434;
                continue

            triples.extend((
                # TODO consider interlex internal? ilxi.label or something?
                (uri, rdf.type, class_),
                (uri, rdfs.label, rdflib.Literal(row.label)),
                (uri, definition, row.definition),
            ))

            # this is the wrong way to do these, have to hit the superless at the moment
            #if row.type == 'fde':
                #triples.append((uri, rdfs.subClassOf, ilxtr.federatedDataElement))
            #elif row.type == 'cde':
                #triples.append((uri, rdfs.subClassOf, ilxtr.commonDataElement))

            addToIndex(row.id, ilx, class_)

        versions = {k:v for k, v in ilx_index.items() if len(v) > 1}  # where did our dupes go!?
        tid_to_ilx = {v:k
                    for k, vs in ilx_index.items()
                    for v in vs}

        multi_type = {tid_to_ilx[id]:types for id, types in id_type.items() if len(types) > 1}

        def baseUri(e):
            return f'http://uri.interlex.org/base/ilx_{tid_to_ilx[e]}'

        synWTF = []
        for row in data['synonyms']:
            synid, tid, literal, type, version, time = row
            # TODO annotation with synonym type
            if not literal:
                synWTF.append(row)
            else:
                t = baseUri(tid), ilxr.synonym, rdflib.Literal(literal)
                triples.append(t)
                if type:  # yay for empty string! >_<
                    stype =  self.stype_lookup[type]
                    triples.extend(annotation(t, (ilxtr.synonymType, stype)).value)

        WTF = []
        for row in data['object_properties']:
            _, s_id, o_id, p_id, *rest = row
            ids_triple = s_id, p_id, o_id
            try:
                t = tuple(baseUri(e) for e in ids_triple)
                triples.append(t)
            except KeyError as e:
                WTF.append(row)

        WTF2 = []
        for row in data['subClassOf']:
            _, s_id, o_id, *rest = row
            try:
                s, o = baseUri(s_id), baseUri(o_id)
            except KeyError as e:
                WTF2.append(row)
                continue

            # TODO for multi type properties we only need the overlap
            s_type = id_type[s_id][0]
            o_type = id_type[o_id][0]
            assert s_type == o_type, f'types do not match! {s_type} {o_type}'
            # FIXME XXX it was possible to insert subPropertyOf on Classes :/ and the errors were silent
            if s_type == owl.Class:
                p = rdfs.subClassOf
            else:
                p = rdfs.subPropertyOf
            t = s, p, o
            triples.append(t)

        #engine.execute()
        #embed()
        self.triples = triples
        self.wat = bads, WTF, WTF2
        if self.debug and (bads or WTF or WTF2):
            printD(bads[:10])
            printD(WTF[:10])
            printD(WTF2[:10])
            embed()
            raise ValueError('BADS HAVE ENTERED THE DATABASE AAAAAAAAAAAA')
        return triples
