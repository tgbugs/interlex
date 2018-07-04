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
from pyontutils.core import rdf, owl, OntId
from pyontutils.utils import TermColors as tc
from interlex.exc import hasErrors, LoadError, NotGroup
from interlex.core import printD, permissions_sql, bnodes, makeParamsValues, IdentityBNode
from IPython import embed

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
        #self._linked_subgraph_identities = None  # not used
        self._metadata_linked_subgraph_identities = None
        self._data_linked_subgraph_identities = None
        self._free_subgraph_identities = None
        self._bound_name_identity = None
        self._metadata_identity = None
        self._data_identity = None

    @property
    def curies_identity(self):
        return self.get_identity('curies')

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
        return {**self.linked_subgraph_identities, **self.free_subgraph_identities}

    @property
    def linked_subgraph_identities(self):
        return {**self.metadata_linked_subgraph_identities, **self.data_linked_subgraph_identities}

    @property
    def metadata_linked_subgraph_identities(self):
        if self._metadata_linked_subgraph_identities is None:
            self.process_graph()

        return self._metadata_linked_subgraph_identities

    @property
    def data_linked_subgraph_identities(self):
        if self._data_linked_subgraph_identities is None:
            self.process_graph()

        return self._data_linked_subgraph_identities

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
                raise LoadError('More than one owl:Ontology in this file!\n'
                                '{self.ontology_iri}\n{extra}\n')
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
    def linked_subgraphs(self):
        yield from self.metadata_linked_subgraphs
        yield from self.data_linked_subgraphs

    @property
    def metadata_linked_subgraphs(self):
        yield from self.metadata_linked_subgraph_identities.values()

    @property
    def data_linked_subgraphs(self):
        yield from self.data_linked_subgraph_identities.values()

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
    def metadata_linked_counts(self):
        return {i:len(sg) for i, sg in self.metadata_linked_subgraph_identities.items()}

    @property
    def metadata_count(self):
        return self.metadata_named_count + sum(self.metadata_linked_counts.values())

    @property
    def data_named_count(self):  # FIXME unnamed should be called tainted
        return len(list(self.data))

    @property
    def data_linked_counts(self):
        return {i:len(sg) for i, sg in self.data_linked_subgraph_identities.items()}

    @property
    def data_count(self):
        return self.data_named_count + sum(self.data_linked_counts.values())

    @property
    def linked_counts(self):
        # NOTE this double counts if added to metadata_counts and data_counts
        return {**self.data_linked_counts, **self.data_linked_counts}

    @property
    def free_counts(self):
        return {i:len(sg) for i, sg in self.free_subgraph_identities.items()}

    @property
    def counts(self):
        counts = {self.curies_identity:self.curies_count,
                  self.metadata_identity:self.metadata_count,
                  self.data_identity:self.data_count,
                  **self.linked_counts,
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

            for identity, o in idents.linked_object_identities.items():
                idents.subgraph_mappings[o]

            linked_subgraph_identities = {identity:normgraph(o, idents.subgraph_mappings[o])
                                          for identity, o in idents.linked_object_identities.items()}

            setattr(self, '_' + name + '_linked_subgraph_identities',
                    linked_subgraph_identities)

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
            columns = 's_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity'
            record = (s,
                      p,
                      str(o),
                      str_None(o.datatype),
                      str_None(o.language),
                      subgraph_identity)
        else:
            raise ValueError(f'{s} {p} {o} {subgraph_identity} has an unknown or invalid type signature')

        return columns, record

    def make_load_records(self, curies_done, metadata_done, data_done, ident_exists):
        # if you need to test pass in lambda i:False for ident_exists
        # TODO resursive on type?
        # s, s_blank, p, o, o_lit, datatype, language, subgraph_identity
        if not curies_done:
            c = []
            to_insert = {'serialization_identity, curie_prefix, iri_prefix':c}
            for curie_prefix, iri_prefix in sorted(self.curies):  # FIXME ordering issue
                c.append((self.serialization_identity, curie_prefix, iri_prefix))

            yield 'INSERT INTO curies', '', to_insert

        def sortkey(triple):  # FIXME this a bad way to sort...
            return tuple(e if isinstance(e, str) else str(e) for e in triple)

        prefix = 'INSERT INTO triples'
        suffix = 'ON CONFLICT DO NOTHING'
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

        # linked and free
        to_insert = defaultdict(list)  # should all be unique due to having already been identified
        for identity, subgraph in self.Loader.subgraph_identities.items():
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
        suffix = 'ON CONFLICT DO NOTHING'
        if to_insert:
            yield prefix, suffix, {k:v for k, v in to_insert.items()}


class BasicDB:
    _cache_groups = {}
    def ___new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __new__(cls, session):
        cls.process_type = cls.__name__
        cls.session = session
        cls.execute = session.execute
        cls.__new__ = cls.___new__
        return cls

    def __init__(self, group, user):
        self.group = group
        self.user = user

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
        id, role = self.check_group(value)
        self._user = value
        self.user_id = id
        self.user_role = role

    def check_group(self, group):
        if group not in self._cache_groups:
            sql = ('SELECT * FROM groups '
                   "WHERE own_role < 'pending' AND groupname = :name")
            try:
                res = next(self.session.execute(sql, dict(name=group)))
                self._cache_groups[group] = res.id, res.own_role
                return res.id, res.own_role
            except StopIteration:
                raise NotGroup(f'{group} is not a group')
        else:
            return self._cache_groups[group]


class TripleLoader(BasicDB):
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
    def __init__(self, group, user, reference_name, reference_host):
        super().__init__(group, user)
        self.debug = False
        self.preinit()
        printD(group, user, reference_name, reference_host)
        self.reference_host = reference_host
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
        self.times = None

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

    @hasErrors(LoadError)
    def __call__(self, name, expected_bound_name):
        if not self.times:
            self.times = {'begin':time.time()}
        self.times['init_begin'] = time.time()
        printD(name, expected_bound_name)
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

        self.name = name
        self.expected_bound = expected_bound_name

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

        if self.name is None:
            embed()

        stop = bde_switch(self.Loader.bound_name, self.expected_bound_name, expected_bound_name)
        self.times['init_end'] = time.time()
        if stop is not None:  # this is redundant but helps with type readability
            return stop
        
    @hasErrors(LoadError)
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
            if type(e) == LoadError:
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
            raise LoadError('Cannot change expected bound names once they have been set!')
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
                raise LoadError(f"Don't know how to parse either {self.extension} or {self.mimetype}")
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
                raise LoadError(f'The exact file dereferenced to by {self.name} is already in InterLex')
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
                    self._graph.parse(data=data, format='nt')
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
            raise LoadError('cannot change reference names')

    def batch_ident_check(self, *idents):
        sql = 'SELECT identity FROM identities WHERE identity IN '
        values_template, params = makeParamsValues((idents,))
        res = self.session.execute(sql + values_template, params)
        existing = set(r.identity.tobytes() for r in res)
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
            m_linked_counts = {i:len(sg) for i, sg in self.metadata_linked_subgraph_identities.items()}
            metadata_count = mtc + sum(m_linked_counts.values())
            dtc = len(list(self.data))
            d_linked_counts = {i:len(sg) for i, sg in self.data_linked_subgraph_identities.items()}
            data_count = dtc + sum(d_linked_counts.values())
            linked_counts = {**m_linked_counts, **d_linked_counts}
            free_counts = {i:len(sg) for i, sg in self.free_subgraph_identities.items()}
            itc = {self.serialization_identity:data_count,
                   self.curies_identity:curies_count,
                   self.bound_name_identity:bound_name_count,
                   self.metadata_identity:metadata_count,
                   self.data_identity:data_count,
                   **linked_counts,
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
        # also pretty sure that the linked subgraphs don't go in the idents table
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
        sql_ident = sql_ident_base + vt + ' ON CONFLICT DO NOTHING'  # TODO FIXME
        embed()
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
        for prefix, suffix, to_insert in self.Loader.make_load_records(curies_done, metadata_done,
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
        return 'TODO\n'


class InterLex(TripleLoader):
    def __call__(self, user, triples):
        pass
        # note, we don't revert history,
        # we just add triples back in a new transaction
        # the joys of invariance

class FileFromBase(TripleLoader):
    @property
    def extension(self):
        if self._extension is None:
            path = PurePath(self.name)
            self._extension = path.suffix[1:]

        return self._extension

class FileFromFile(FileFromBase):
    def __init__(self, group='tgbugs', user='tgbugs',
                 reference_name=None, reference_host='uri.interlex.org'):
        if reference_name is None:
            # FIXME the way this is implemented will be one way to check to make
            # sure that users/groups match the reference_name?
            reference_name = f'http://uri.interlex.org/{group}/upload/test'
        super().__init__(group, user, reference_name, reference_host)

    def __call__(self, name, expected_bound_name):
        self.path = Path(name).resolve().absolute()
        name = self.path.as_uri()
        setup_ok = super().__call__(name, expected_bound_name)
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

class FileFromIRI(FileFromBase):
    maxsize_mbgz = 5
    maxsize_mb = 20
    lfmessage = (f'You appear to by trying to load a file bigger than {maxsize_mb}MB. '
                 'Please get in touch with us if you want this included in InterLex.')

    @hasErrors(LoadError)
    def __call__(self, name, expected_bound_name=None):
        if not self.times:
            self.times = {'begin':time.time()}
        # expected_bound_name should only be supplied if it differes from name for the inital load
        # self.name = name  # TODO this is not quite ready yet, loading from arbitrary uris/filenames needs one more level

        # in any case where this function is called name should not equal reference name
        # it should either be a filename or something like that
        if name == self.reference_name:
            # FIXME this is if the iri is give, obviously the bound name will
            # match and everything should work, do need to figure out how to
            # handle this case properly though... name = None and _serialization already set
            # NOTE for direct user contributions name should be their orcid
            # or the interface/api endpoint they were using if we want to track that?
            return 'you cannot load an ontology into itself from itself unless you are interlex itself', 400
        elif self.reference_host in name:
            # TODO provide an alternative
            return 'you cannot copy content from one reference name to another in this way', 400

        # TODO logic when bound_name = reference_name, seems to be handled below correctly...
        if expected_bound_name is None:
            expected_bound_name = name

        super().__call__(name, expected_bound_name)

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
                raise LoadError(f'Nothing found at {self.name}\n')

            self._header = head.headers

        return self._header

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
        size_mb = int(self.header['Content-Length']) / 1024 ** 2
        admin_check_sql = permissions_sql + " AND group_id = 0 AND user_role = 'admin'"
        printD(admin_check_sql)
        try:
            indeed = next(self.session.execute(admin_check_sql, dict(group=self.user)))
            is_admin = True
        except StopIteration:
            is_admin = False
        
        printD('user is admin?', is_admin)

        if 'Content-Encoding' in self.header and self.header['Content-Encoding'] == 'gzip':
            if size_mb > self.maxsize_mbgz:
                if not is_admin:
                    raise LoadError(self.lfmessage)  # TODO error handling
            resp = requests.get(self.name)
            size_mb = len(resp.content) / 1024 ** 2
        else:
            resp = None

        if size_mb > self.maxsize_mb:
            if not is_admin:
                raise LoadError(self.lfmessage)

        if resp is None:
            resp = requests.get(self.name)

        self._serialization = resp.content
        self.times['fetch_end'] = time.time()
        return self._serialization

        # TODO check declared ontology_iri vs actually ontology_iri

        # TODO just parse ontology header where possible?
        # graph.parse(filepath, format=format)


class FileFromPost(FileFromIRI):
    def __init__(self, group, user, reference_host, reference_name=None):
        super().__init__(group, user, reference_name, reference_host)

    @hasErrors(LoadError)
    def __call__(self, file, header, create):
        if not self.times:
            self.times = {'begin':time.time()}
        self.create = create

        self.name = f'file://{file.filename}'
        #self._extension = file.filename.rsplit('.', 1)[-1]
        self._mimetype = file.mimetype
        self._header = {k:v for k, v in header.items()}

        self.file = file
        self.reference_name
        super().__call__(self.name, self.expected_bound_name)
        self.file = None  # cleanup

    @property
    def serialization(self):
        if self._serialization is None:
            self._serialization = self.file.stream.read()  # we may need to parse more than once

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
                                    'the desired endpoint (reference_name).')
                    self.reference_name_in_db = False
                printD('WARNING reference name has not been created yet!\n')

        return self._reference_name

    @reference_name.setter
    def reference_name(self, value):
        super().reference_name_setter(value)

class FileFromVCS(TripleLoader):
    pass



