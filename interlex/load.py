from pathlib import Path, PurePath
import rdflib
import hashlib
import requests
import sqlalchemy as sa
from pyontutils.core import rdf, owl
from pyontutils.utils import OrderInvariantHash
from pyontutils.ttlser import DeterministicTurtleSerializer
from interlex.exc import hasErrors, LoadError
from interlex.core import printD, permissions_sql, bnodes, makeParamsValues
from IPython import embed

class TripleLoader:
    _cache_names = set() # FIXME make sure that reference hosts don't get crossed up
    _cache_identities = set()
    formats = {
        'ttl':'turtle',
        'owl':'xml',
        'n3':'n3',
    }
    def ___new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __new__(cls, session, cypher=hashlib.sha256, encoding='utf-8'):
        cls.process_type = cls.__name__
        cls.session = session
        cls.execute = session.execute
        cls.cypher = cypher
        cls.encoding = encoding
        cls.orderInvariantHash = OrderInvariantHash(cypher, encoding)
        cls.__new__ = cls.___new__
        return cls

    def _old__init__(self, session, cypher=hashlib.sha256, encoding='utf-8'):
        # FIXME this stuff should go in new
        self.process_type = self.__class__.__name__
        self.session = session
        self.execute = session.execute
        self.cypher = cypher
        self.encoding = encoding
        self.orderInvariantHash = OrderInvariantHash(cypher, encoding)
        self._safe = False
        #self.reference_host = next(self.session.execute('SELECT reference_host()'))
        #printD(self.reference_host)

    def __init__(self, group, user, reference_name, reference_host):
        self.preinit()
        printD(group, user, reference_name, reference_host)
        self.reference_host = reference_host
        self._reference_name = None
        self._reference_name_in_db = None
        self.group = group
        self.user = user

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
            
        self.reference_name = reference_name

    def preinit(self):
        self._name = None
        self._expected_bound_name = None  # TODO multiple bound names can occure eg via versionIRI?
        self._transaction_cache_names = set()

        self._extension = None
        self._mimetype = None
        self._format = None

        self._header = None
        self._serialization = None
        self._graph = None
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

        self._serialization_identity = None  # ALA representation_identity
        self._curies_identity = None
        #self._subgraph_identities = None  # not used
        self._linked_subgraph_identities = None
        self._free_subgraph_identities = None
        self._bound_name_identity = None
        self._metadata_identity = None
        self._data_identity = None
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
    def __call__(self, name, expected_bound_name=None):
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

        # expected_bound_name should only be supplied if it differes from name for the inital load
        # self.name = name  # TODO this is not quite ready yet, loading from arbitrary uris/filenames needs one more level

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

        self.name = name
        # in any case where this function is called name should not equal reference name
        # it should either be a filename or something like that

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
                self.expected_bound_name = self.bound_name

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
            self.expected_bound_name = self.bound_name

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

        stop = bde_switch(self.bound_name, self.expected_bound_name, expected_bound_name)
        if stop is not None:
            return stop
        
    def load(self):
        output = ''
        try:
            output += self.load_event()
            self.session.commit()
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
        if value not in self._cache_names or self._transaction_cache_names:
            try:
                sql = 'INSERT INTO names VALUES (:name)'
                self.session.execute(sql, dict(name=value))
            except sa.exc.IntegrityError:
                # name was already in but not cached
                self.session.rollback()

            self._transaction_cache_names.add(value)
            self._name = value

    @property
    def reference_name(self):
        return self._reference_name

    @reference_name.setter
    def reference_name(self, value):
        if self._reference_name is None:
            self._reference_name = value
            sql = 'SELECT name, expected_bound_name FROM reference_names WHERE name = :name'
            try:
                res = next(self.session.execute(sql, dict(name=self._reference_name)))
                self._expected_bound_name = res.expected_bound_name
                self._reference_name_in_db = True
            except StopIteration:
                # set it by setting self.expected_bound_name = something (including None)
                self._reference_name_in_db = False
                printD('WARNING reference name has not been created yet!\n')
        elif self._reference_name != value:
            raise LoadError('cannot change reference names')

    @property
    def reference_name_in_db(self):
        self._reference_name_in_db = True

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
        if self.expected_bound_name is not None:
            # NOTE this is also enforced in the database
            raise LoadError('Cannot change expected bound names once they have been set!')
        elif self.expected_bound_name == value:
            printD('WARNING: trying to set expected bound name again!')
        else:
            if self.reference_name_in_db:
                sql = ('UPDATE reference_names SET expected_bound_name = :e WHERE name = :r')
            else:
                sql = ('INSERT INTO reference_names (name, expected_bound_name, group_id) '
                       'VALUES (:r, :e, idFromGroupname(:g))')

            # FIXME this is not wrapped with a rollback because...
            # that shouldn't happen? are we sure?
            self.execute(sql, dict(r=self.reference_name, e=value, g=self.group))
            self._expected_bound_name = value

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
                raise LoadError(f"Don't know how to parse either {extension} or {mimetype}")
            elif self.extension not in self.formats:
                self._format = self.formats[self.mimetype]
            else:
                self._format = self.formats[self.extension]

        return self._format

    # identities
    @property
    def serialization_identity(self):
        if self._serialization_identity is None:
            m = self.cypher()
            m.update(self.serialization)
            ident = m.digest()
            if self.ident_exists(ident):
                # TODO user options for what to do about qualifiers
                raise LoadError(f'The exact file derferenced to by {self.name} is already in InterLex')
            self._serialization_identity = ident
            self._transaction_cache_identities.add(ident)

        return self._serialization_identity

    @property
    def curies_identity(self):
        return self.get_identity('curies')

    @property
    def bound_name_identity(self):
        if self._bound_name_identity is None:
            m = self.cypher()
            m.update(str(self.bound_name).encode(self.encoding))
            self._bound_name_identity = m.digest()

        return self._bound_name_identity

    @property
    def metadata_identity(self):
        return self.get_identity('metadata')

    @property
    def data_identity(self):
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
    def serialization(self): return self._serialization  # intentionally errors

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
            self._bound_name = str(next(subjects))
            try:
                extra = next(subjects)
                raise LoadError('More than one owl:Ontology in this file!\n'
                                '{self.ontology_iri}\n{extra}\n')
            except StopIteration:
                pass

        return self._bound_name

    @property
    def graph(self):
        if self._graph is None:
            self._graph = rdflib.Graph()
            try:
                self._graph.parse(data=self.serialization, format=self.format)
            except TypeError as e:
                embed()
                raise e

        return self._graph

    @property
    def metadata(self):
        yield from self.metadata_named
        yield from self.metadata_unnamed

    @property
    def metadata_named(self):
        if self._metadata_named is None:
            self.process_graph()
        return self._metadata_named

    @property
    def metadata_unnamed(self):
        if self._metadata_unnamed is None:
            self.process_graph()
        return self._metadata_unnamed

    @property
    def data(self):
        yield from self.data_named
        yield from self.data_unnamed

    @property
    def data_named(self):
        if self._data_named is None:
            self.process_graph()
        return self._data_named

    @property
    def data_unnamed(self):
        if self._data_unnamed is None:
            self.process_graph()
        return self._data_unnamed

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

    # functions
    def get_identity(self, type_name):
        real_name = '_' + type_name + '_identity'
        real_value = getattr(self, real_name)
        if real_value is None:
            real_value = self.digest(type_name)
            setattr(self, real_name, real_value)
            self._transaction_cache_identities.add(real_value)

        return real_value

    def digest(self, type_name):
        value = getattr(self, type_name)
        return self.orderInvariantHash(value)

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
        # TODO names

    def identity_triple_count(self, identity):
        """ Note: these are unique triple counts on normalized subgraphs """
        if self._identity_triple_count is None:
            # we should be able to abstrac this using
            # data + structure of data + decoupling rules + identity function on data
            # eg bound_name is raw bytes + rdf:type owl:Ontology as subset rule
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

    def process_graph(self):
        self.bound_name  # TODO what to do about graphs that don't have a bound name?
        printD('processing graph')
        dts = DeterministicTurtleSerializer(self.graph)
        gsortkey = dts._globalSortKey
        psortkey = lambda p: dts.predicate_rank[p]

        def sortkey(triple):
            s, p, o = triple
            return gsortkey(s), psortkey(p), gsortkey(o)

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

        def intlast(triple):
            return tuple('zzzzzzzzzzzzzzzzzzzzzzz' + str(e)
                            if isinstance(e, int)
                            else e
                            for e in triple)

        subgraph_mapping = {}
        subgraphs = []

        metadata_named = []
        data_named = []  # no uri uri blank triples
        # sorted means that I always see the subject first ?
        for t in sorted(self.graph, key=sortkey):
            s, p, o = t
            if not any(isinstance(e, rdflib.BNode) for e in t):
                if s == self.bound_name:
                    metadata_named.append((p, o))
                else:
                    data_named.append(t)
            else:
                if s in subgraph_mapping:
                    ss = subgraph_mapping[s]
                else:
                    ss = False

                if o in subgraph_mapping:
                    os = subgraph_mapping[o]
                else:
                    os = False

                if ss and os:
                    if ss is not os:  # this should only happen for 1:1 bnodes
                        new = ss + [t] + os
                        try:
                            subgraphs.remove(ss)
                            subgraphs.remove(os)
                            subgraphs.append(new)
                            for bn in bnodes(ss):
                                subgraph_mapping[bn] = new
                            for bn in bnodes(os):
                                subgraph_mapping[bn] = new
                        except ValueError as e:
                            print(e)
                            embed()
                        '''
                        for t_ in ss: [print(e) for e in t_]
                        print()
                        [print(e) for e in t]
                        print()
                        for t_ in os: [print(e) for e in t_]
                        '''
                        # FIXME there are some ordering issues I think?
                        # or maybe not and these are just the true bnodes
                        # that do actually have no ambiguity

                        #raise TypeError('wat')
                    else:
                        ss.append(t)
                elif not (ss or os):
                    new = [t]
                    subgraphs.append(new)
                    if isinstance(s, rdflib.BNode):
                        subgraph_mapping[s] = new
                    if isinstance(o, rdflib.BNode):
                        subgraph_mapping[o] = new
                elif ss:
                    ss.append(t)
                    if isinstance(o, rdflib.BNode):
                        subgraph_mapping[o] = ss
                elif os:
                    os.append(t)
                    if isinstance(s, rdflib.BNode):
                        subgraph_mapping[s] = os

        metadata_linked_subgraph_identities = {}
        data_linked_subgraph_identities = {}
        free_subgraph_identities = {}
        metadata_unnamed = []
        data_unnamed = []
        #normalized = []
        #bnode_to_identity = {}
        #wat = {}
        #[g for g in subgraphs if any(all(isinstance(e, rdflib.URIRef) for e in t) for t in g)]
        for g in subgraphs:  # TODO make sure g is properly sorted, it should be from above
            fs, fp, fo = ft = g[0]
            if isinstance(fs, rdflib.BNode):
                start = 0
            else:
                start = 1
            cmax = -1
            existing = {}
            normalized = []
            for t in g[start:]:
                s, p, o, cmax = normalize(cmax, t, existing)
                normalized.append((s, p, o))

            normalized = tuple(sorted(normalized, key=intlast))
            identity = self.orderInvariantHash(normalized)  # FIXME intlast... sort may be needed to be passed in?
            if start:
                if fs == self.bound_name:
                    metadata_unnamed.append((fp, identity))
                    metadata_linked_subgraph_identities[identity] = normalized
                else:
                    data_unnamed.append((fs, fp, identity))
                    data_linked_subgraph_identities[identity] = normalized
            else:
                free_subgraph_identities[identity] = normalized  # (identity,) + 
                
        assert not [k for k, v in metadata_linked_subgraph_identities.items() if not v], 'HRM'
        assert not [k for k, v in data_linked_subgraph_identities.items() if not v], 'HRM'
        assert not [k for k, v in free_subgraph_identities.items() if not v], 'HRM'

            #normalized.append(tuple(sorted(subgraph, key=intlast)))  # FIXME do we really need to sort?

        # TODO dedupe metadata and data code so any bound data can be supported
        self._metadata_named = metadata_named
        self._metadata_unnamed = metadata_unnamed
        self._data_named = data_named
        self._data_unnamed = data_unnamed
        self._metadata_linked_subgraph_identities = metadata_linked_subgraph_identities
        self._data_linked_subgraph_identities = data_linked_subgraph_identities
        self._free_subgraph_identities = free_subgraph_identities
        return

    def make_load_records(self, ci, mi, di):
        # TODO resursive on type?
        # s, s_blank, p, o, o_lit, datatype, language, subgraph_identity
        if not ci:
            ct = c, ccols, *_ = [], 'serialization_identity, curie_prefix, iri_prefix', (':ident',), {'ident':self.serialization_identity}
            for curie_prefix, iri_prefix in self.curies:
                c.append((curie_prefix, iri_prefix))

            yield ct,

        if not mi:
            mt = m, mcols = [], 's, p, o'
            mlt = ml, mlcols = [], 's, p, o_lit, datatype, language'
            for p, o in self.metadata_named:
                p = str(p)
                if isinstance(o, rdflib.URIRef):
                    m.append((self.bound_name, p, str(o)))
                else:
                    o_lit = o
                    datatype = str(o.datatype) if o.datatype is not None else o.datatype
                    ml.append((self.bound_name, p, str(o_lit), datatype, o.language))

            mbt = mb, mbcols = [], 's, p, o_blank, subgraph_identity'
            for p, subgraph_identity in self.metadata_unnamed:
                p = str(p)
                mb.append((self.bound_name, p, 0, subgraph_identity))

            yield mt, mlt, mbt

        if not di:
            dt = d, dcols = [], 's, p, o'
            dlt = dl, dlcols = [], 's, p, o_lit, datatype, language'
            for s, p, o in self.data_named:
                s, p = str(s), str(p)
                if isinstance(o, rdflib.URIRef):
                    d.append((s, p, str(o)))
                else:
                    o_lit = o
                    datatype = str(o.datatype) if o.datatype is not None else o.datatype
                    dl.append((s, p, str(o_lit), datatype, o.language))

            dbt = db, dbcols = [], 's, p, o_blank, subgraph_identity'
            for s, p, subgraph_identity in self.data_unnamed:
                s, p = str(s), str(p)
                db.append((s, p, 0, subgraph_identity))

            sgt = sg, sgcols = [], 's_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity'
            for subgraph_identity, subgraph in self.subgraph_identities.items():
                for s, p, o in subgraph:
                    p = str(p)
                    if isinstance(o, rdflib.URIRef):
                        sg.append((s, p, str(o), None, None, None, None, subgraph_identity))
                    elif isinstance(o, int):
                        sg.append((s, p, None, None, None, None, o, subgraph_identity))
                    else:  # FIXME not clear we ever have these Literal cases...
                        o_lit = o
                        datatype = str(o.datatype) if o.datatype is not None else o.datatype
                        sg.append((s, p, None, str(o_lit), datatype, o.language, None, subgraph_identity))

            yield dt, dlt, dbt, sgt
 
    def load_event(self):
        # FIXME only insert on success...
        si = self.serialization_identity

        # TODO need a way to pass in si

        # TODO always insert metadata first so that in-database integrity checks
        # can run afterward and verify roundtrip identity
        #ni = self.ident_exists(self.bound_name_identity)  # FIXME usually a waste
        ci = self.ident_exists(self.curies_identity)
        mi = self.ident_exists(self.metadata_identity)
        di = self.ident_exists(self.data_identity)
        sgi = {k:v in self._cache_identities for k, v in self.subgraph_identities.items()}

        # (:s, 'hasPart', :o)
        # FIXME only insert the anon subgraphs and definitely better
        # not to use identities on annotations
        # also pretty sure that the linked subgraphs don't go in the idents table
        # FIXME I need to know which subgraphs need to be parented ser
        sql_ident_base = 'INSERT INTO identities (reference_name, identity, type, triples_count) VALUES '
        types_idents = (('serialization', self.serialization_identity),  # TODO abstract... type + ident
                        ('local_naming_conventions', self.curies_identity),
                        #('bound_name', self.bound_name_identity),
                        ('metadata', self.metadata_identity),
                        ('data', self.data_identity),
                        ('subgraph', *self.free_subgraph_identities))
        assert not any(v is None for t, *vs in types_idents
                       for v in vs), f'oops! {[(t, v) for t, v in types if v is None]}'
        values = ((i, type, self.identity_triple_count(i))
                  for type, *identities in types_idents
                  for i in identities)
        vt, params_i = makeParamsValues(values, constants=(':rn',))
        params_i['rn'] = self.reference_name
        sql_ident = sql_ident_base + vt + ' ON CONFLICT DO NOTHING'  # TODO FIXME
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

        sql_base = 'INSERT INTO triples'
        suffix = ' ON CONFLICT DO NOTHING'
        sqls = []

        for sections in self.make_load_records(ci, mi, di):
            for values, sql_columns, *constParams in sections:
                if constParams:
                    printD(constParams)
                    constants, const_params = constParams
                else:
                    constants, params = tuple(), {}

                if values:
                    values_template, params = makeParamsValues(values, constants=constants)
                    params.update(const_params)
                    if constants:
                        # FIXME HACK resolve how we are going to represent and store curies
                        # ie as (/<user>/curies iri_prefix curie) in triples or elsewhere
                        # with a /<user>/curies rdf:type ilxr:Curies
                        # or a /identities/curies or some such
                        base = 'INSERT INTO curies '
                        sql = base + f' ({sql_columns}) VALUES ' + values_template
                    else:
                        sql = sql_base + f' ({sql_columns}) VALUES ' + values_template + suffix
                    self.execute(sql, params)

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
        return self._serialization

        # TODO check declared ontology_iri vs actually ontology_iri

        # TODO just parse ontology header where possible?
        # graph.parse(filepath, format=format)


class FileFromPost(FileFromIRI):  # FIXME vs InterLexFile ?
    pass

class FileFromVCS(TripleLoader):
    pass



