#!/usr/bin/env python3.6

import sys
import socket
import hashlib
from pathlib import Path, PurePath
from tempfile import gettempdir
from functools import partialmethod
from collections import Counter, defaultdict
import rdflib
import requests
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect, MetaData, Table, types
from sqlalchemy.sql import expression
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql.expression import bindparam
# from sqlalchemy.orm import Session
from flask import Flask, url_for, redirect, request, render_template, render_template_string
from flask import make_response, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.routing import BaseConverter
from pyontutils.core import makeGraph, OntId
from pyontutils.utils import TermColors as tc, injective_dict
from pyontutils.config import devconfig
from pyontutils.ttlser import DeterministicTurtleSerializer, CustomTurtleSerializer
from pyontutils.namespaces import PREFIXES as uPREFIXES, ilxtr
from pyontutils.combinators import annotation
from pyontutils.closed_namespaces import rdf, rdfs, owl, oboInOwl
from interlex import config
from interlex.utils import printD, makeSimpleLogger
from IPython import embed

logger = makeSimpleLogger('ilx_core')
synonym_types = {'abbrev':ilxtr['synonyms/abbreviation']}
default_prefixes = {'rdf':str(rdf),
                    'rdfs':str(rdfs),
                    'owl':str(owl)}


class uri(types.UserDefinedType):
    def __init__(self, uri):
        self.uri = uri
        pass

    def get_col_spec(self, **kw):
        return "uri(%s)" % self.uri

    def bind_processor(self, dialect):
        def process(value):
            #return rdflib.URIRef(value)
            return value
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            return rdflib.URIRef(value)
        return process

def bnodes(ts): return set(e for t in ts for e in t if isinstance(e, rdflib.BNode))

def dbUri(user=config.user, host='localhost', port=5432, database=config.database):
    if socket.gethostname() in config.dev_remote_hosts:
        port = 54321
    if hasattr(sys, 'pypy_version_info'):
        dialect = 'psycopg2cffi'
    else:
        dialect = 'psycopg2'
    return f'postgresql+{dialect}://{user}@{host}:{port}/{database}'
    # engine = create_engine
    # return engine, inspect(engine)

def mqUri():
    return config.broker_url

def getScopedSession(dburi=dbUri()):
    engine = create_engine(dburi)
    session_factory = sessionmaker(bind=engine)
    ScopedSession = scoped_session(session_factory)
    return ScopedSession

def makeParamsValues(*value_sets, constants=tuple(), types=tuple()):
    # TODO variable sized records and
    # common value names
    if constants and not all(':' in c for c in constants):
        raise ValueError(f'All constants must pass variables in via params {constants}')

    class getName:
        def __init__(self):
            self.counter = 0
            self.value_to_name = {}

        def valueCheck(self, value):
            if isinstance(value, dict):
                value = hash(frozenset((k, self.valueCheck(v)
                                        if isinstance(v, list) or isinstance(v, dict)
                                        else v)
                                        for k, v in value.items()))
            elif isinstance(value, list):
                value = tuple(self.valueCheck(e) for e in value)
            else:
                pass

            return value

        def __call__(self, value):
            value = self.valueCheck(value)
            if value in self.value_to_name:
                return self.value_to_name[value]
            else:
                name = 'v' + str(self.counter)
                self.counter += 1
                self.value_to_name[value] = name
                return name

    getname = getName()

    params = {}
    if types:
        bindparams = []
        itertypes = (t for ts in types for t in ts)
    for i, values in enumerate(value_sets):
        # proto_params doesn't need to be a dict
        # values will be reduced when we create params as a dict
        proto_params = [(tuple(getname(value) for value in row), row) for row in values]

        values_template = ', '.join('(' + ', '.join(constants +
                                                    tuple(':' + name
                                                          for name in names)) + ')'
                                    for names, _ in proto_params)
        yield values_template
        for names, values in proto_params:
            for name, value in zip(names, values):
                params[name] = value
                if types:
                    maybe_type = next(itertypes)
                    if maybe_type is not None:
                        bindparams.append(bindparam(name, type_=maybe_type))

    yield params
    if types:
        yield bindparams  # TODO not sure if there are dupes here

class FakeSession:
    def __init__(self):
        self._return_value = None

    @property
    def current_return_value(self):
        return self._return_value

    @current_return_value.setter
    def current_return_value(self, value):
        self._return_value = value

    def execute(self, sql, params):
        printD('Fake executing')
        if len(sql) < 2000:
            print(sql)
        rv = self.current_return_value
        self.current_return_value = (_ for _ in range(0))
        return rv

    def commit(self):
        printD('Fake commit')

    def rollback(self):
        printD('Fake rollback')


class IdentityBNode(rdflib.BNode):
    # TODO this requires a new serialization rule which 'disambiguates'
    # subgraphs with the same identity that appear as an object in
    # different triples
    """ An identity blank node is a blank node that is identified by
        the output of some identity function on the subgraph that it
        identifies. IBNodes do not need to be linked into quads for
        the named parts of a graph because they will fail to bind on
        any set of triples whose identity does not match their identity.

        However, for graphs that are unnamed, practically they should be
        bound as quads to prevent collisions. When serialized to triples
        it is reasonable to use the identity as a prefix for the local
        node ordering.

        IBNodes should only be used at the head of an unnamed graph or
        a collection of triples. Even if the triples around bound to a
        name by convention, the IBNode should still be used to identify them.

        When calculating the identity, it may be useful to use the identity
        function to provide a total ordering on all nodes.

        When directly mapping an IBNode to a set of pairs that has a name
        the identity can be reattached, but it must be by convention, otherwise
        the identity of the pairs will change.

        This is also true for lists. Note that IBNodes bound by convention are
        NOT cryptographically secure because it is trivial to tamper with the
        contents of the message and regenerate the IBNode. IBNodes are therefore
        not useful as bound identifiers, but only as unbound or pointing identifiers.
    """
    cypher = hashlib.sha256
    cypher_field_separator = ' '
    encoding = 'utf-8'
    sortlast = b'\xff' * 64

    def __new__(cls, triples_or_pairs_or_thing, symmetric_predicates=tuple(), debug=False):
        self = super().__new__(cls)  # first time without value
        self.debug = debug
        self.id_lookup = {}
        m = self.cypher()
        m.update(self.to_bytes(self.cypher_field_separator))
        self.cypher_field_separator_hash = m.digest()  # prevent accidents
        self.cypher_check()
        m = self.cypher()
        self.null_identity = m.digest()
        self.symmetric_predicates = symmetric_predicates  # FIXME this is ok, but a bit awkward
        self._thing = triples_or_pairs_or_thing
        self.identity = self.identity_function(triples_or_pairs_or_thing)
        real_self = super().__new__(cls, self.identity)
        if debug == True:
            return self

        real_self.debug = debug
        real_self.identity = self.identity
        real_self.null_identity = self.null_identity
        real_self.symmetric_predicates = self.symmetric_predicates
        real_self.cypher_field_separator_hash = self.cypher_field_separator_hash
        return real_self

    def check(self, other):
        return self.identity == self.identity_function(other)

    def cypher_check(self):
        m1 = self.cypher()
        m2 = self.cypher()
        assert m1.digest() == m2.digest(), f'Cypher {self.cypher} does not have a stable starting point!'

        if not hasattr(self, 'cypher_field_separator_hash'):
            m1.update(b'12')
            m1.update(b'3')

            m2.update(b'123')
            assert m1.digest() != m2.digest() , f'Cypher {self.cypher} is invariant to the number of updates'
        else:
            m1.update(b'12')
            m1.update(self.cypher_field_separator_hash)
            m1.update(b'3')

            m2.update(b'123')
            assert m1.digest() != m2.digest() , f'Cypher {self.cypher} is invariant to the number of updates'

    def to_bytes(self, thing):
        if isinstance(thing, bytes):
            raise TypeError(f'{thing} is already bytes')
        elif type(thing) == str:
            return thing.encode(self.encoding)
        else:
            return str(thing).encode(self.encoding)

    def ordered_identity(self, *things, separator=True):
        """ this assumes that the things are ALREADY ordered correctly """
        m = self.cypher()
        for i, thing in enumerate(things):
            if separator and i > 0:  # insert field separator
                m.update(self.cypher_field_separator_hash)
            if thing is None:  # all null are converted to the starting hash
                thing = self.null_identity
            if type(thing) != bytes:
                raise TypeError(f'{type(thing)} is not bytes, did you forget to call to_bytes first?')
            m.update(thing)

        identity = m.digest()
        if self.debug:
            self.id_lookup[identity] = tuple(self.id_lookup[t] if
                                             t in self.id_lookup else
                                             t for t in things)

        return identity

    def triple_identity(self, subject, predicate, object):
        """ Compute the identity of a triple.
            Also handles symmetric predicates.

            NOTE that ordering for sympreds is on the bytes representation
            of a node, regardless of whether it is has already been digested """

        bytes_s, bytes_p, bytes_o = self.recurse((subject, predicate, object))
        if predicate in self.symmetric_predicates and bytes_s < bytes_o:
            return self.ordered_identity(bytes_o, bytes_p, bytes_s)
        else:
            return self.ordered_identity(bytes_s, bytes_p, bytes_o)

    def add_to_subgraphs(self, thing, subgraphs, subgraph_mapping):
        # useful for debug and load use cases
        # DO NOT USE FOR COMPUTING IDENTITY
        t = s, p, o = thing
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
                    printD(e)
                    embed()
                    raise e
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

    def recurse(self, triples_or_pairs_or_thing, bnodes_ok=False):
        for thing in triples_or_pairs_or_thing:
            if thing is None:
                yield self.null_identity
            elif isinstance(thing, bytes):
                yield thing
            elif type(thing) == str:  # exact match, the rest are instances of str
                yield self.to_bytes(thing)
            elif isinstance(thing, rdflib.URIRef):
                yield self.to_bytes(thing)
            elif isinstance(thing, rdflib.Literal):
                # "http://asdf.asdf" != <http://asdf.asdf>
                # need str(thing) breaks recursion on rdflib.Literal
                yield self.ordered_identity(*self.recurse((str(thing), thing.datatype, thing.language)))
            elif isinstance(thing, IdLocalBNode) or isinstance(thing, IdentityBNode):
                yield thing.identity # TODO check that we aren't being lied to?
            elif isinstance(thing, rdflib.BNode):
                if bnodes_ok:
                    yield thing
                else:
                    raise ValueError('BNodes only have names or collective identity...')
            else:
                lt = len(thing)
                if lt == 3 or lt == 2:
                    if not any(isinstance(e, rdflib.BNode) for e in thing):
                        if lt == 3:
                            yield self.triple_identity(*thing)
                        elif lt == 2:
                            yield self.ordered_identity(*self.recurse(thing))
                        else:
                            raise NotImplemented('shouldn\'t ever get here ...')
                    else:
                        if self.debug:
                            self.add_to_subgraphs(thing, self.subgraphs, self.subgraph_mappings)

                        if lt == 3:
                            s, p, o = thing
                        elif lt == 2:
                            s = None  # safe, only isinstance(o, rdflib.BNode) will trigger below
                            p, o = thing

                        if isinstance(p, rdflib.BNode):
                            raise TypeError(f'predicates cannot be blank {thing}')
                        elif p == rdf.rest:
                            if o == rdf.nil:
                                self.to_lift.add(thing)
                            else:
                                if o in self.find_heads:
                                    raise ValueError('this should never happen')
                                self.find_heads[o] = s
                                self.to_skip.add(thing)
                                if isinstance(o, rdflib.BNode):
                                    self.bobjects.add(o)

                            self.bsubjects.add(s)
                            continue
                        elif p == rdf.first:
                            self.to_lift.add(thing)
                            self.bsubjects.add(s)
                            if isinstance(o, rdflib.BNode):
                                self.bobjects.add(o)
                            continue

                        if isinstance(s, rdflib.BNode) and isinstance(o, rdflib.BNode):
                            self.bsubjects.add(s)
                            self.bobjects.add(o)
                            # we have to wait until the end to run this since we don't know
                            # how many triples will have the object as a subject until we have
                            # looked at all of them ... another fun issue with rdf
                            self.awaiting_object_identity[s].add(thing)
                        elif isinstance(s, rdflib.BNode):
                            self.bsubjects.add(s)
                            # leaves
                            ident = self.triple_identity(None, p, o)
                            self.bnode_identities[s].append(ident)
                        elif isinstance(o, rdflib.BNode):
                            self.bobjects.add(o)
                            # named head
                            self.named_heads.add(s)
                            self.linked_heads.add(o)
                            self.awaiting_object_identity[s].add(thing)
                        else:
                            raise ValueError('should never get here')

                else:
                    raise ValueError('wat, dont know how to compute the identity of this thing')

    def resolve_bnode_idents(self):
        # resolve lifts and skips
        for t in self.to_lift:
            s, p, o = t
            assert isinstance(s, rdflib.BNode)
            upstream = s
            while upstream in self.find_heads:
                upstream = self.find_heads[upstream]
                assert isinstance(upstream, rdflib.BNode)

            if isinstance(o, rdflib.BNode):
                self.awaiting_object_identity[upstream].add((upstream, p, o))
            else:
                ident = self.triple_identity(None, p, o)
                self.bnode_identities[upstream].append(ident)

        # resolve dangling cases
        for o in self.dangling_objs:
            self.bnode_identities[o].append(self.null_identity)

        def process_awaiting_triples(subject, triples, subject_idents=None):
            done = True
            for t in list(triples):  # list to allow remove from set
                s, p, o = t
                assert s == subject, 'oops'
                if o not in self.awaiting_object_identity and o in self.bnode_identities:
                    object_ident = self.bnode_identities[o]
                    if type(object_ident) == self.bnode_identities.default_factory:
                        done = False  # dealt with in while loop
                    else:
                        if subject_idents is not None:  # leaf case
                            ident = self.triple_identity(None, p, object_ident)
                            subject_idents.append(ident)
                        elif isinstance(subject, rdflib.BNode):  # unnamed case
                            subject_idents = self.bnode_identities[s]
                            ident = self.triple_identity(None, p, object_ident)
                            subject_idents.append(ident)
                        else:  # named case
                            ident = self.triple_identity(s, p, object_ident)
                            self.named_subgraph_identities[s, p].append(ident)
                            self.linked_object_identities[object_ident] = o

                        # in a sane world ...
                        # there is only single triple where a
                        # bnode is an object so it is safe to pop
                        gone = self.bnode_identities.pop(o)
                        if self.debug and o in self.linked_heads or o in self.unnamed_heads:
                            self.blank_identities[o] = gone
                        assert gone == object_ident, 'something weird is going on'
                        triples.remove(t)
                else:
                    done = False

            return done

        count = 0
        while self.awaiting_object_identity:
            # first process all bnodes that already have identities
            for subject, subject_idents in list(self.bnode_identities.items()):  # list to pop from dict
                # it is safe to pop here only if all objects attached to the bnode are not in awaiting
                if subject in self.awaiting_object_identity:
                    assert type(subject_idents) != bytes, 'hrm'
                    triples = self.awaiting_object_identity[subject]
                    subject_done = process_awaiting_triples(subject, triples, subject_idents)
                    if subject_done:
                        self.awaiting_object_identity.pop(subject)
                else:
                    subject_done = True

                if subject_done:
                    if type(subject_idents) == bytes:  # already calculated but not yet used
                        subject_identity = subject_idents
                    else:
                        # this is where we assign a single identity to a subgraph
                        # when hashing ordered identities do not use a separator
                        subject_identity = self.ordered_identity(*sorted(subject_idents), separator=False)
                        gone = self.bnode_identities.pop(subject)
                        assert gone == subject_idents, 'something weird is going on'

                    if subject in self.unnamed_heads:
                        # question: should we assign a single identity to each unnamed subgraph
                        #  or just include the individual triples?
                        # answer: we need to assign a single identity otherwise we will have loads
                        #  if identical identities since bnodes are all converted to null
                        self.unnamed_subgraph_identities[subject] = subject_identity
                    elif subject not in self.bnode_identities:  # we popped it off above
                        self.bnode_identities[subject] = subject_identity

            # second complete any nodes that have are fully identified
            for subject, triples in list(self.awaiting_object_identity.items()):  # list to pop from dict
                if process_awaiting_triples(subject, triples):
                    # we do not need to consolidate identifiers for named subgraphs
                    # the subject does disambiguation for us in a way that is consistent
                    # with how we identify other named triples
                    self.awaiting_object_identity.pop(subject)

    def identity_function(self, triples_or_pairs_or_thing):
        if isinstance(triples_or_pairs_or_thing, bytes):  # serialization
            return self.ordered_identity(triples_or_pairs_or_thing)
        elif isinstance(triples_or_pairs_or_thing, str):  # a node
            return next(self.recurse((triples_or_pairs_or_thing,)))
        else:
            if self.debug:
                self.subgraphs = []
                self.subgraph_mappings = {}
                self.blank_identities = {}

            self.awaiting_object_identity = defaultdict(set)
            self.bnode_identities = defaultdict(list)
            self.linked_heads = set()
            self.named_heads = set()
            self.bsubjects = set()
            self.bobjects = set()
            self.to_skip = set()
            self.to_lift = set()
            self.find_heads = {}
            self.named_identities = tuple(self.recurse(triples_or_pairs_or_thing))  # memory :/

            self.unnamed_heads = self.bsubjects - self.bobjects
            self.dangling_objs = self.bobjects - self.bsubjects

            self.unnamed_subgraph_identities = {}
            self.named_subgraph_identities = defaultdict(list)
            self.linked_object_identities = {}  # needed for proper identity calculation?
            self.resolve_bnode_idents()

            free = list(self.unnamed_subgraph_identities.values())
            assert all(type(i) == bytes for i in free), 'free contains a non identity!'
            linked = [i for ids in self.named_subgraph_identities.values() for i in ids]
            assert all(type(i) == bytes for i in linked), 'linked contains a non identity!'
            self.free_identities = free
            self.linked_identities = linked

            self.all_idents = sorted(self.named_identities +
                                     tuple(self.linked_identities) +
                                     tuple(self.free_identities))

            return self.ordered_identity(*self.all_idents)

    def __repr__(self):
        id = str(self)
        return f'{self.__class__.__name__}({id!r})'

    def __str__(self):
        return self.identity.hex()


class IdLocalBNode(rdflib.BNode):
    """ For use inside triples.
        Local ids should be consecutive integers.
        Ordering can be by sub-identity or by string ordering
        on the named portions of the graph.
    """
    def __init__(self, identity, local_id):
        self.identity = identity
        self.local_id = local_id

    def __str__(self):
        return f'{self.identity}_{self.local_id}'


def server_api(db=None, dburi=dbUri()):
    app = Flask('InterLex api server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    #engine = create_engine(
    #db = SQLAlchemy(app)
    #db.reflect(app=app)
    database = db
    session = db.session
    #metadata = db.MetaData(db.engine)
    #Base = db.make_declarative_base(metadata)
    #Base = db.make_declarative_base(db.Model)
    #class Core(Base):
        #__tablename__ = 'core'
        #s = sa.Column(primary_key=True)
        #p = sa.Column(primary_key=True)
        #o = sa.Column(primary_key=True)
        #qualifier_id = sa.Column(primary_key=True)
        #transform_rule_id = sa.Column()

    def make_qualified_triples(*triples):
        engine.execute(
            Core.__table__.insert(),
            [{'s':s,
              'p':p,
              'o':o,
              'qualifier_id':qual_id,
              'transform_rule_id':0,}
             for s, p, o in triples])
        ('INSERT INTO core (s, p, o, qualifier_id, transform_rule_id) VALUES '
            '(:subject, :predicate, :object, qual_id, 0);')

    def make_qualified_triples_complex(*trip_and_trans):
        ('INSERT INTO core (s, p, o, qualifier_id, transform_rule_id) VALUES '
            '(:subject, :predicate, :object, qual_id, :trans_id);')

    @app.route('/terms/add', methods=['POST'])
    def new_term():
        label = request.args['label']
        superclass_ilx_id = request.args['superclass_ilx_id']
        # first check that the label does not match and that the super class does not match
        params = dict(subject = requests.args['subject'],
                      predicate = requests.args['predicate'],
                      object = requests.args['object'],
                      trans_id = 0)
        sql = (
            'DECLARE prev_qual integer;'
            'DECLARE source_qual integer;'
            'SELECT last_value INTO STRICT prev_qual FROM qualifiers_id_seq;'
            'SELECT id INTO STRICT source_qual FROM qualifiers as q '
                'WHERE q.user_id = :user_id AND q.source_qualifier_id = 0;'
            #"SELECT currval('qualifiers_id_seq');"  # within a single session
            'INSERT INTO qualifiers (group_id, source_qualifier_id, previous_qualifier_id) '
                'VALUES (:user_id, group_qual, prev_qual) RETURNING id INTO qual_id;'
            'INSERT INTO interlex_ids DEFAULT VALUES RETURNING id INTO last_id;'
            'INSERT INTO core (s, p, o, qualifier_id, transform_rule_id) VALUES '
                '(:subject, :rdf_type, :term_type, qual_id, :trans_id);'
            'INSERT INTO core (s, p, o, qualifier_id, transform_rule_id) VALUES '
                '(:subject, :predicate, :object, qual_id, :trans_id);'
        )
        # ideally use id in the transaction to populate existing ids etc

    def new_terms_from_uris():
        pass

    @app.route('/triples/fromurl', methods=['POST'])
    def triples_fromurl():
        if 'url' not in request.args:
            return 'missing required url argument\n', 400

        url = request.args['url']
        user = 'tgbugs'
        # TODO process for staging changes for review and comparison to see
        #  where triples are already present so that they can be removed
        # TODO core_uris, core_lits for lifted interlex representation
        src_qual = next(session.execute(('SELECT id FROM qualifiers WHERE group_id = idFromGroupname(:group) '
                                         'AND source_qualifier_id = 0'), dict(group=user))).id

        sql, params = make_load_triples(graph, src_qual)

        # TODO return comparison using temp tables prior to full merge
        return 'ok\n'

    @app.route('/triples/bulk', methods=['POST'])
    def triples_bulk():
        #file = Path(devconfig.git_local_base) / devconfig.ontology_repo / 'ttl' / 'nif.ttl'
        graph = rdflib.Graph()

        #file = Path(devconfig.git_local_base) / devconfig.ontology_repo / 'ttl' / 'NIF-GrossAnatomy.ttl'
        #file = Path(devconfig.git_local_base) / devconfig.ontology_repo / 'ttl' / 'bridge' / 'anatomy-bridge.ttl'
        #graph.parse(file.as_posix(), format='ttl')
        #graph.parse('http://purl.obolibrary.org/obo/uberon.owl')
        file = Path(devconfig.git_local_base) / devconfig.ontology_repo / 'ttl' / 'external' / 'uberon.owl'
        user = 'uberon'
        graph.parse(file.as_posix())

        # FIXME getIdFromGroupname ... sigh naming
        src_qual = next(session.execute(('SELECT id FROM qualifiers WHERE group_id = idFromGroupname(:group) '
                                         'AND source_qualifier_id = 0'), dict(group=user))).id
        qual_id = 0
        # 206112
        # URIRef vs str(URIRef) wtf!
        # 205523
        values = set(tuple(str(e) for e in t) + (src_qual, 0) for t in graph if not any(isinstance(e, rdflib.BNode) for e in t))
        # FIXME I have NO idea how I am getting duplicate values, something must be happening in makeParamsValues
        # FIXME I have NO idea why Literal with type URIRef was causing an issue :/ annoying
        # must be a weird thing with sqla
        printD(len(values))
        values_template, params = makeParamsValues(values)
        sql_base = 'INSERT INTO core (s, p, o, qualifier_id, transform_rule_id) VALUES '
        sql = sql_base + values_template
        """  # debugging issue with Literal with type URIRef (putative cause?) doubling entries
        dtrips = {}
        for k, v in params.items():
            i, j = (int(_) for _ in k.strip('values').split('_'))
            if j > 2:
                continue
            elif i not in dtrips:
                dtrips[i] = v,
            else:
                dtrips[i] += v,
        a = len(list(dtrips.values()))
        b = len(set(dtrips.values()))
        values = [t + (src_qual, 0) for t in dtrips.values()
                  if rdflib.URIRef('http://purl.obolibrary.org/obo/UBERON_0000007') in t or
                  'http://purl.obolibrary.org/obo/UBERON_0000007' in t]
        values_template, params = makeParamsValues(values)
        sql = sql_base + values_template
        """

        #embed()
        printD('starting execution')
        """
        thing = (Core.__table__.insert(),
                 [{'s':s,
                   'p':p,
                   'o':o,
                   'qualifier_id':qual_id,
                   'transform_rule_id':0,}
             for s, p, o in triples])
        #session.execute(*thing)  # this is hilariously slow for 22k triples like multiple minutes
        """
        try:
            session.execute(sql, params)  # this took 2 seconds
            printD('starting commit')
            session.commit()
            return 'ok\n', 200
        except BaseException as e:
            session.rollback()
            return e.orig.pgerror, 404

    @app.route('/curies/<group>/add', methods=['POST'])
    def curies_add(group):
        # TODO group -> group_id
        values = tuple((1, cp, ip) for cp, ip in uPREFIXES.items())
        proto_params = {tuple(f'values{i}_{j}'
                              for j, e in enumerate(v)):v
                        for i, v in enumerate(values)}
        values_template = ', '.join('(' + ', '.join(':' + e for e in v) + ')'
                                    for v in proto_params)
        params = {name:value for names, values in proto_params.items()
                  for name, value in zip(names, values)}
        sql = 'INSERT INTO curies (group_id, curie_prefix, iri_prefix) VALUES ' + values_template
        #printD(sql)
        #printD(params)
        try:
            resp = session.execute(sql, params)
            session.commit()
            return 'ok', 200
        except sa.exc.IntegrityError as e:
            session.rollback()
            return f'Curie exists\n{e.args[0]}', 409  # conflict

    @app.route('/users/add', methods=['POST'])
    def user_add():
        groupname = request.args['groupname']
        email = request.args['email']
        orcid = request.args['orcid']
        params = dict(groupname=groupname, orcid=orcid, email=email)
        sql = ('INSERT INTO groups (groupname) VALUES :groupname RETURNING id INTO last_id;'
               'INSERT INTO user_emails (user_id, email, email_primary) VALUES (last_id :email :email_primary);'
               'INSERT INTO user_orcid (user_id, orcid) VALUES (last_id :orcid);'
        )
        session.execute(sql, params)

    return app

def make_paths(parent_child, parent='<user>', options=tuple(), limit=9999, depth=0):
    def inner(child, parent, idepth):
        for path in make_paths(parent_child, child, options=options, limit=limit, depth=idepth):
            #printD('PATH:', path)
            if parent in options:
                for option in options[parent][:limit]:
                    yield '/' + option + path
            else:
                yield '/' + parent + path

    if parent in parent_child:
        for child in parent_child[parent]:
            #printD('CHILD:', child)
            if child in options:
                todo = options[child][:limit]
                if child in parent_child:  # only branches need to go again
                    todo += (child,)
                for option in todo:
                    yield from inner(option, parent, depth + 1)
            else:
                yield from inner(child, parent, depth + 1)
    else:
        if parent in options:
            for option in options[parent][:limit]:
                path = '/' + option
                yield path
        elif parent is None:  # branches that are also terminals
            yield '/'
        elif parent == depth:
            # branchers that are also terminals at a given depth
            # where the depth should be considered as the zero indexed
            # depth of the empty string following the slash
            yield '/'
        elif isinstance(parent, int):
            pass  # skip other depths
        else:
            path = '/' + parent
            #printD('PATH:', path)
            yield path


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super().__init__(url_map)
        self.regex = items[0]


def diffCuries(old, new):
    err = False, None, None

    if not new:
        existing = {}
        return True, new, existing, 'How did we git here?!'

    try:
        n_curs = injective_dict(new)
    except injective_dict.NotInjectiveError as e:
        return (*err, e)

    if not old:
        return True, new, old, f'New curies added. No existing curies.\n{new}'

    o_curs = injective_dict(old)
    o_iris = o_curs.inverted()

    snc = set(n_curs)
    soc = set(o_curs)

    only_new_curies = snc - soc
    to_add = {}
    errors = []
    for cur in only_new_curies:  # hilariously inefficient
        try:
            o_curs[cur] = n_curs[cur]
            to_add[cur] = n_curs[cur]
        except injective_dict.NotInjectiveError as e:
            # trying to bind a new curie to and old iri
            errors.append(e)

    existing_curies = snc & soc
    existing = {}
    for cur in existing_curies:
        try:
                o_curs[cur] = n_curs[cur]
                existing[cur] = n_curs[cur]
        except injective_dict.NotInjectiveError as e:
            # trying to bind an old curie to a new iri
            errors.append(e)

    if errors:
        return (*err, '\n'.join(str(e) for e in errors))

    return True, to_add, existing, f'\nNew curies added. Existing were not modified.\n{to_add}\n'


def server_curies(db=None):
    app = Flask('InterLex curies server')
    @app.route('/<prefix_curie>')
    def curie(prefix_curie):
        return redirect(f'http://uri.olympiangods.org/base/curies/{prefix_curie}', 301)
        return redirect(f'http://uri.interlex.org/base/curies/{prefix_curie}', 301)  # TODO
    return app

def run_api():
    return server_api(db=SQLAlchemy())

def run_curies():
    return server_curies(db=SQLAlchemy())
