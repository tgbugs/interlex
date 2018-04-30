#!/usr/bin/env python3.6
# 2018-04-20T19:55Z-07:00 - 2018-04-20T22:45Z-07:00
# 2018-04-21T13:00Z-07:00 - 2018-04-22T02:00Z-07:00
# 2018-04-22T13:30Z-07:00 - 2018-04-23T04:00Z-07:00
# 2018-04-23T13:30Z-07:00 - 2018-04-23T??:00Z-07:00
""" InterLex python implementaiton

Usage:
    interlex api [options]
    interlex uri [options]
    interlex curies [options]
    interlex test [options]
    interlex dbsetup [options]
    interlex post curies [options] <user>
    interlex post ontology [options] <user>

Options:
    -d --debug              enable debug mode
    -l --local              run against local

    -a --api=API            SciGraph api endpoint
    -k --key=APIKEY         apikey for SciGraph instance
    -f --input-file=FILE    don't use SciGraph, load an individual file instead
    -o --outgoing           if not specified defaults to incoming
    -b --both               if specified goes in both directions

"""
port_api = 8500
port_uri = 8505
port_curies = 8510

import os
import sys
import json
import socket
import hashlib
from urllib.parse import urlparse
from pathlib import Path, PurePath
from tempfile import gettempdir
from functools import partialmethod
import rdflib
import requests
from docopt import docopt, parse_defaults
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect, MetaData, Table, types
from sqlalchemy.sql import expression
# from sqlalchemy.orm import Session
from flask import Flask, url_for, redirect, request, render_template, render_template_string
from flask import make_response, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.routing import BaseConverter
from protcur.core import atag, htmldoc
from protcur.server import table_style, details_style, render_table
from pyontutils.config import devconfig
from pyontutils.utils import OrderInvariantHash, TermColors as tc
from pyontutils.core import makeGraph, makePrefixes, PREFIXES as uPREFIXES, rdf, rdfs, owl, definition
from pyontutils.core import yield_recursive
from pyontutils.ontutils import url_blaster
from pyontutils.ttlser import DeterministicTurtleSerializer, CustomTurtleSerializer
from IPython import embed

try:
    from misc.debug import TDB
    tdb=TDB()
    printD=tdb.printD
    #printFuncDict=tdb.printFuncDict
    #tdbOff=tdb.tdbOff
except ImportError:
    print('WARNING: you do not have tgbugs misc on this system')
    printD = print

formats = {
    'ttl':'ttl',
    'owl':'owl',
    'n3':'n3',
}

permissions_sql = 'SELECT * from user_permissions WHERE user_id = idFromGroupname(:group)'

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

def dbUri(user='interlex-user', host='localhost', port=5432, db='interlex_test2'):
    if socket.gethostname() != 'orpheus':
        port = 54321
    if hasattr(sys, 'pypy_version_info'):
        dialect = 'psycopg2cffi'
    else:
        dialect = 'psycopg2'
    return f'postgresql+{dialect}://{user}@{host}:{port}/{db}'
    # engine = create_engine
    # return engine, inspect(engine)

def makeParamsValues(values, constants=tuple()):
    if constants and not all(':' in c for c in constants):
        raise ValueError(f'All constants must pass variables in via params {constants}')
    proto_params = {tuple(f'values{i}_{j}'
                          for j, e in enumerate(v)):v
                    for i, v in enumerate(values)}
    values_template = ', '.join('(' + ', '.join(constants + tuple(':' + e for e in v)) + ')'
                                for v in proto_params)
    params = {name:value for names, values in proto_params.items()
                for name, value in zip(names, values)}
    return values_template, params

class TripleExporter:
    #def __init__(self, triples, subgraphs):  # TODO
    def triple(self, s, p, o, o_lit, datatype, language, o_blank):
        if o is not None:
            o = rdflib.URIRef(o)
        elif o_lit is not None:
            o = rdflib.Literal(o_lit, datatype=datatype, language=language)
        elif o_blank is not None:
            # TODO resolve subgraphs here?
            o = rdflib.BNode()  # TODO
        return rdflib.URIRef(s), rdflib.URIRef(p), o

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

class TripleLoader:
    reference_host = None
    _cache_names = set() # FIXME make sure that reference hosts don't get crossed up
    _cache_identities = set()
    def __init__(self, session, cypher=hashlib.sha256, encoding='utf-8'):
        self.process_type = self.__class__.__name__
        self.session = session
        self.execute = session.execute
        self.cypher = cypher
        self.encoding = encoding
        self.orderInvariantHash = OrderInvariantHash(cypher, encoding)
        self._safe = False
        #self.reference_host = next(self.session.execute('SELECT reference_host()'))
        #printD(self.reference_host)

    def __enter__(self, exit=False):
        if not exit:
            printD('entering')

        self.group = None
        self.user = None

        self._name = None
        self._reference_name = None
        self._reference_name_in_db = None
        self._expected_bound_name = None  # TODO multiple bound names can occure eg via versionIRI?

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

        self._identity_triple_count = None

        self._safe = True

        # graph load (usually)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # TODO rollback on >= 400? no, should all be handled locally
        self.__enter__(True)  # the paranoia is real
        self._safe = False
        printD('exit')

    def __call__(self, group, user, reference_name, name, expected_bound_name=None):
        printD(group, user, reference_name, name, expected_bound_name)
        # FIXME this is a synchronous interface
        # if we want it to be async it will require
        # more work
        # perhaps a POST to add with a response covering permissions etc
        # followed by a second post asking to ingest from remote?
        # how do we deal with the issue of names?
        if not self._safe:
            raise RuntimeError(f'{self} is not in safe mode, did you call it using \'with\'?')
        self.group = group
        self.user = user

        # expected_bound_name should only be supplied if it differes from name for the inital load
        # self.name = name  # TODO this is not quite ready yet, loading from arbitrary uris/filenames needs one more level

        if name == reference_name:
            # NOTE for direct user contributions name should be their orcid
            # or the interface/api endpoint they were using if we want to track that?
            return 'you cannot load an ontology into itself from itself unless you are interlex itself', 400
        elif self.reference_host in name:
            # TODO provide an alternative
            return 'you cannot copy content from one reference name to another in this way', 400

        # TODO logic when bound_name = reference_name, seems to be handled below correctly...
        if expected_bound_name is None:
            expected_bound_name

        self.name = name
        self.reference_name = reference_name
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
                return message + '\n{a} {b}'
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
        
        output = ''
        try:
            output += self.load_event()
            self.session.commit()
            return output
        except BaseException as e:
            self.session.rollback()
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
        if value not in self._cache_names:
            try:
                sql = 'INSERT INTO names VALUES (:name)'
                self.session.execute(sql, dict(name=value))
            except sa.exc.IntegrityError:
                # name was already in but not cached
                self.session.rollback()

            self._cache_names.add(value)
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
                print('WARNING reference name has not been created yet!\n')
        elif self._reference_name != value:
            raise ValueError('cannot change reference names')

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
            raise ValueError('Cannot change expected bound names once they have been set!')
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
            if self.extension not in formats and self.mimetype not in formats:
                # TODO use ttlfmt parser attempter
                raise TypeError(f"Don't know how to parse either {extension} or {mimetype}")
            elif self.extension not in formats:
                self._format = formats[self.mimetype]
            else:
                self._format = formats[self.extension]

        return self._format

    # identities
    @property
    def serialization_identity(self):
        if self._serialization_identity is None:
            m = self.cypher()
            m.update(self.serialization)
            self._serialization_identity = m.digest()

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
    def serialization(self): raise NotImplementedError('Implement this in the subclass')

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
            self._bound_name = next(subjects)
            try:
                extra = next(subjects)
                raise ValueError('More than one owl:Ontology in this file!\n'
                                 '{self.ontology_iri}\n{extra}\n')
            except StopIteration:
                pass

        return self._bound_name

    @property
    def graph(self):
        if self._graph is None:
            self._graph = rdflib.Graph()
            self._graph.parse(data=self.serialization, format=self.format)

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

        return real_value

    def digest(self, type_name):
        value = getattr(self, type_name)
        return self.orderInvariantHash(value)

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
        printD('processing graph')
        dts = DeterministicTurtleSerializer(self.graph)
        gsortkey = dts._globalSortKey
        psortkey = lambda p: dts.predicate_rank[p]

        def sortkey(triple):
            s, p, o = triple
            return (gsortkey(s),
                    psortkey(p),
                    gsortkey(o))

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

    def make_load_records(self, mi, di):
        # TODO resursive on type?
        # s, s_blank, p, o, o_lit, datatype, language, subgraph_identity
        if not mi:
            mt = m, mcols = [], 's, p, o'
            mlt = ml, mlcols = [], 's, p, o_lit, datatype, language'
            for p, o in self.metadata_named:
                p = str(p)
                if isinstance(o, rdflib.URIRef):
                    m.append((self.bound_name, p, str(o)))
                else:
                    ml.append((self.bound_name, p, str(o), str(o.datatype), o.language))

            mbt = mb, mbcols = [], 's, p, o_blank, subgraph_identity'
            for p, subgraph_identity in self.metadata_unnamed:
                p = str(p)
                mb.append((self.bound_name, p, 0, subgraph_identity))

        if not di:
            dt = d, dcols = [], 's, p, o'
            dlt = dl, dlcols = [], 's, p, o_lit, datatype, language'
            for s, p, o in self.data_named:
                s, p = str(s), str(p)
                if isinstance(o, rdflib.URIRef):
                    d.append((s, p, str(o)))
                else:
                    dl.append((s, p, str(o), str(o.datatype), o.language))

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
                        sg.append((s, p, None, str(o), str(o.datatype), o.language, None, subgraph_identity))

        return mt, mlt, mbt, dt, dlt, dbt, sgt
 
    def load_event(self):
        # FIXME only insert on success...
        si = self.serialization_identity

        if si in self._cache_identities:
            # TODO give the user options to say yes i want this explicitly in my graph
            #self.execute(sql_prov, params)
            return 'already in\n'

        # TODO need a way to pass in si

        # TODO always insert metadata first so that in-database integrity checks
        # can run afterward and verify roundtrip identity
        ni = self.bound_name_identity in self._cache_identities  # self.identities_add?
        mi = self.metadata_identity in self._cache_identities
        di = self.data_identity in self._cache_identities
        sgi = {k:v in self._cache_identities for k, v in self.subgraph_identities.items()}

        # (:s, 'hasPart', :o)
        # FIXME only insert the anon subgraphs and definitely better
        # not to use identities on annotations
        # also pretty sure that the linked subgraphs don't go in the idents table
        # FIXME I need to know which subgraphs need to be parented ser
        sql_ident_base = 'INSERT INTO identities (reference_name, identity, type, triples_count) VALUES '
        types_idents = (('serialization', self.serialization_identity),  # TODO abstract... type + ident
                        ('local_naming_conventions', self.curies_identity),
                        ('bound_name', self.bound_name_identity),
                        ('metadata', self.metadata_identity),
                        ('data', self.data_identity),
                        ('subgraph', *self.free_subgraph_identities))
        values = ((i, type, self.identity_triple_count(i))
                  for type, *identities in types_idents
                  for i in identities)
        vt, params_i = makeParamsValues(values, constants=(':rn',))
        params_i['rn'] = self.reference_name
        sql_ident = sql_ident_base + vt
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
        for values, sql_columns in self.make_load_records(mi, di):
            if values:
                values_template, params = makeParamsValues(values)
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
    def __call__(self, name, group='tgbugs', user='tgbugs', reference_name=None):
        self.reference_host = 'uri.interlex.org'
        self.path = Path(name).resolve().absolute()
        name = self.path.as_uri()
        if reference_name is None:
            # FIXME the way this is implemented will be one way to check to make
            # sure that users/groups match the reference_name?
            reference_name = f'http://uri.interlex.org/{group}/upload/test'
        super().__call__(group, user, reference_name, name)
        self.reference_host = None
        self.path = None  # avoid poluting the class namespace

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
            head = requests.head(self.name)  # check on the size to make sure no troll

            if head.status_code >= 400:
                return f'Error: nothing found at {self.name}\n', 400

            while head.is_redirect:  # FIXME redirect loop issue
                head = s.send(head.next)
                if not head.is_redirect:
                    break

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
        if 'Content-Encoding' in self.header and self.header['Content-Encoding'] == 'gzip':
            if size_mb > self.maxsize_mbgz:
                is_admin = self.session.execute(admin_check_sql, dict(group=user))
                printD('user is admin?', is_admin)
                return lfmessage, 400
            resp = requests.get(self.name)
            size_mb = len(resp.content) / 1024 ** 2
        else:
            resp = None

        if size_mb > self.maxsize_mb:
            is_admin = self.session.execute(admin_check_sql, dict(group=user))
            printD('user is admin?', is_admin)
            return lfmessage, 400

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

        # get interlex
        def interlex_load():
            from pyontutils.utils import mysql_conn_helper
            DB_URI = 'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{db}'
            if socket.gethostname() != 'orpheus':
                config = mysql_conn_helper('localhost', 'nif_eelg', 'nif_eelg_secure', 33060)  # see .ssh/config
            else:
                config = mysql_conn_helper('nif-mysql.crbs.ucsd.edu', 'nif_eelg', 'nif_eelg_secure')
            engine = create_engine(DB_URI.format(**config), echo=True)
            config = None
            del(config)
            insp = inspect(engine)

            #ilxq = ('SELECT * FROM term_existing_ids as teid '
                    #'JOIN terms as t ON t.id = teid.tid '
                    #'WHERE t.type != "cde"')
            queries = dict(
                terms = 'SELECT * from terms WHERE type != "cde"',
                sups = 'SELECT * from term_superclasses',
                ops = 'SELECT * from term_relationships',
                # aps = 'SELECT * from term_annotations',  # not quite yet
                )
            data = {name:engine.execute(query).fetchall()
                    for name, query in queries.items()}
            ilx_index = {}
            id_type = {}
            triples = []
            type_to_owl = {'term':owl.Class,
                        'annotation':owl.AnnotationProperty,
                        'relationship':owl.ObjectProperty}
            for row in data['terms']:
                ilx = row[1][4:]
                uri = f'http://uri.interlex.org/base/ilx_{ilx}'
                class_ = type_to_owl[row[9]]
                triples.extend((
                    # TODO consider interlex internal? ilxi.label or something?
                    (uri, rdf.type, class_),
                    (uri, rdfs.label, ),
                    (uri, definition, ),
                ))
                #print(ilx)
                id = row[0]
                if ilx not in ilx_index:
                    ilx_index[ilx] = []
                ilx_index[ilx].append(id)
                if id not in id_type:
                    id_type[id] = []
                id_type[id] = class_

            versions = {k:v for k, v in ilx_index.items() if len(v) > 1}  # where did our dupes go!?
            tid_to_ilx = {v[0]:k
                        for k, v in ilx_index.items()}
            def baseUri(e):
                return f'http://uri.interlex.org/base/ilx_{tid_to_ilx[e]}'

            for _, s_id, o_id, p_id, *rest in data['ops']:
                t = tuple(baseUri(e) for e in (s_id, p_id, o_id))
                triples.append(t)

            for _, s_id, o_id, *rest in data['sups']:
                s, o = baseUri(s_id), baseUri(o_id)
                s_type = id_type[s_id]
                o_type = id_type[o_id]
                assert s_type == o_type
                if type_ == owl.Class:
                    p = rdfs.subClassOf
                else:
                    p = rdfs.subPropertyOf
                t = s, p, o
                triples.append(t)

            #engine.execute()
            #embed()
            return 'ok\n', 200

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
        return interlex_load()

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

def make_paths(parent_child, parent='<user>', options=tuple(), limit=9999):
    def inner(child, parent):
        for path in make_paths(parent_child, child, options=options, limit=limit):
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
                    yield from inner(option, parent)
            else:
                yield from inner(child, parent)
    else:
        if parent in options:
            for option in options[parent][:limit]:
                path = '/' + option
                yield path
        elif parent is None:  # branches that are also terminals
            yield '/'
        else:
            path = '/' + parent
            #printD('PATH:', path)
            yield path


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super().__init__(url_map)
        self.regex = items[0]


def uriStructure():
    ilx_pattern = 'ilx_<regex("[0-9]{7}"):id>'
    basic = [ilx_pattern, 'readable']
    branches = ['uris', 'curies', 'ontologies', 'versions']
    compare = ['own', 'diff']
    version_compare = []  # TODO? probably best to deal with the recursion in make_paths
    versioned_ids = basic + ['curies', 'uris']
    intermediate_filename = ['<filename>.<extension>', '<filename>']
    parent_child = {
        '<user>':              basic + branches + compare + ['contributions', 'prov'],
        '<other_user>':        branches,  # no reason to access /user/own/otheruser/ilx_ since identical to /user/ilx_
        '<other_user_diff>':   basic + branches, 
        'readable':            ['<word>'],
        'versions':            ['<epoch_verstr_id>'],
        '<epoch_verstr_id>':   versioned_ids + version_compare,
        'ontologies':          ['<path:ont_path>'] + intermediate_filename,  # TODO /ontologies/external/<iri> ? how? where?
        # TODO distinguish between ontology _files_ and 'ontologies' which are the import closure?
        # ya, identified vs unidentified imports, owl only supports unidentified imports
        '<path:ont_path>':     intermediate_filename,  # FIXME this would seem to only allow a single extension?
        '<filename>':          ['version'],
        'version':             ['<epoch_verstr_ont>'],
        '<epoch_verstr_ont>':  ['<filename_terminal>.<extension>'],
        'curies':              [None, '<prefix_iri_curie>'],  # external onts can be referenced from here...
        'uris':                ['<path:uri_path>'],
        'own':                 ['<other_user>'],
        'diff':                ['<other_user_diff>'],

        # TODO considerations here
        'upload':              [None],  # smart endpoint that hunts down bound names or tracks unbound sets
        'contributions':       [None, 'interlex', 'external', 'curation'],  # None implies any direct to own
        'prov':                ['identities'],
        'identities':          ['<identity>'],
    }
    node_methods = {'curies_':['GET', 'POST'],
                    #'<prefix_iri_curie>':[],  only prefixes can be updated...?
                    ilx_pattern:['GET', 'PATCH'],
                    '<word>':['GET', 'PATCH'],
                    '<filename>.<extension>':['GET', 'POST'],
                    '<filename_terminal>.<extension>':['GET', 'POST'],
    }
    return ilx_pattern, parent_child, node_methods


def makeTestRoutes(limit=1):
    ilx_pattern, parent_child, node_methods = uriStructure()
    users = 'base', 'origin', 'tgbugs'  # base redirects to default/curated ...
    other_users = 'latest', 'curated', 'bob'
    ilx_patterns = 'ilx_1234567', 'ilx_0090000'
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

def server_uri(db=None, structure=uriStructure, dburi=dbUri()):
    app = Flask('InterLex uri server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    #db.reflect(app=app)
    database = db
    app.url_map.converters['regex'] = RegexConverter
    ilx_pattern, parent_child, node_methods = structure()

    class Endpoints:
        db = database
        reference_host = None
        def __init__(self):
            self.session = self.db.session
            self.filefromiri = FileFromIRI(self.session)  # FIXME need a way to pass ref host?

        def reference_name(self, user, path):
            # need this for testing, in an ideal world we read from headers
            return os.path.join(f'https://{self.reference_host}', user, path) 

        def getGroupCuries(self, group, epoch_verstr=None):
            # TODO retrieve base/default curies
            params = dict(group=group)
            if epoch_verstr is not None:
                # TODO
                sql = ('SELECT curie_prefix, iri_prefix FROM curies as c '
                       'WHERE c.group_id = (SELECT id FROM groups WHERE groupname = :group)')
            else:
                sql = ('SELECT curie_prefix, iri_prefix FROM curies as c '
                       'WHERE c.group_id = (SELECT id FROM groups WHERE groupname = :group)')  # FIXME idFromGroupname??
            resp = self.session.execute(sql, params)
            currentHost = request.headers['Host']
            PREFIXES = {cp:ip.replace('uri.interlex.org', currentHost) if app.debug else ip
                        # TODO app.debug should probably be switched out for something configurable
                        for cp, ip in resp}
            #printD(PREFIXES)
            if not PREFIXES:
                PREFIXES = makePrefixes('rdfs', 'owl')
            g = makeGraph(group + '_curies_helper', prefixes=PREFIXES)
            return PREFIXES, g

        @staticmethod
        def iriFromPrefix(prefix, *ordered_prefix_sets):
            for PREFIXES in ordered_prefix_sets:
                try:
                    return PREFIXES[prefix]  # redirect(iri, 302)
                except KeyError:
                    pass
            else:
                return f'Unknown prefix {prefix}', 404


        def get_func(self, nodes):
            mapping = {
                ilx_pattern:self.ilx,
                'readable':self.readable,
                'uris':self.uris,
                'curies_':self.curies_,
                'curies':self.curies,
                'ontologies':self.ontologies,
                'version':self.ontologies_version,  # FIXME collision prone?
                'contributions_':self.contributions_,
                'contributions':self.contributions,
                'prov':self.prov,
            }
            for node in nodes[::-1]:
                if node in mapping:
                    return mapping[node]
            else:
                raise KeyError(f'could not find any value for {nodes}')

        # TODO PATCH
        def ilx(self, user, id):
            # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}
            # printD(tc.red('AAAAA'), user, id)
            if user != 'base' and user != 'latest':
                args = dict(id=id, user=user)
                #sql = ('SELECT ou.username, t.id FROM interlex_ids as t, org_user_view as ou '
                       #'WHERE t.id = :id AND ou.username = :user')
                #sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       #'SELECT groups AS g JOIN users AS u ON g.id = u.id WHERE g.groupname = :user UNION '
                       #'SELECT groups AS g JOIN orgs AS o ON g.id = o.id WHERE g.groupname = :user')
                # TODO it seems WAY more efficient to add a 'verfied' column to groups
                #sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       # doesn't work because doesn't fail on no id
                       #"SELECT id::text FROM groups WHERE own_role < 'pending' AND groupname = :user")
                #sql = ('SELECT t.id, g.id FROM interlex_ids AS t, groups AS g '
                       #'WHERE t.id = :id AND g.validated = TRUE AND g.groupname = :user')

                sql = ('SELECT t.id, g.id FROM interlex_ids AS t, groups AS g '
                       "WHERE t.id = :id AND g.own_role < 'pending' AND g.groupname = :user")
                try:
                    id, gid = next(self.session.execute(sql, args))
                    printD(id, gid)
                except StopIteration:
                    return abort(404)

            uri = f'http://uri.interlex.org/base/ilx_{id}'
            args = dict(uri=uri, id=id)
            #sql = ('SELECT e.iri, c.p, c.o, c.qualifier_id, c.transform_rule_id '
                   #'FROM existing_iris as e JOIN core as c ON c.s = e.iri OR c.s = :uri '
                   #'WHERE e.ilx_id = :id')
            #sql = ('SELECT e.iri, tu.p, tu.o::text FROM existing_iris as e '
                   #'JOIN triples_uri as tu ON tu.s = e.iri OR tu.s = :uri '
                   #'UNION '
                   #'SELECT e.iri, tl.p, tl.o FROM existing_iris as e '
                   #'JOIN triples_literal as tl ON tl.s = e.iri OR tl.s = :uri')

            # don't use t.s because it will include the base iri? or no
            sql = ('SELECT t.s, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank '
                   'FROM existing_iris as e '
                   'JOIN triples as t '
                   #'JOIN triples as tb'  # TODO efficient subgraph retrieval?
                   #'JOIN triples as tb2 '
                   'ON t.s = e.iri '
                   'OR t.s = :uri '
                   #'OR t.o_blank = t.id '
                   #'AND tb1 = tb2)'
                   'WHERE e.ilx_id = :id')
            resp = list(self.session.execute(sql, args))
            #printD(resp)
            PREFIXES, g = self.getGroupCuries(user)
            te = TripleExporter()
            _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting
            cts = CustomTurtleSerializer(g.g)
            trips = ((atag(e, g.qname(e))
                      if isinstance(e, rdflib.URIRef) and e.startswith('http')
                      else str(e)
                      for e in t)
                     for t in sorted(g.g, key=lambda t: (cts.object_rank[t[0]],
                                                         cts.predicate_rank[t[1]],
                                                         cts.object_rank[t[2]])))

            # TODO list users with variants from base and/org curated
            # we need an 'uncurated not latest' or do we?
            return htmldoc(render_table(trips, 'subject', 'predicate', 'object'),
                           title=f'ilx.{user}:ilx_{id}',
                           styles=(table_style,))

        # TODO PATCH only admin can change the community readable mappings just like community curies
        def readable(self, user, word):
            return request.path

        def contributions_(self, user):
            # without at type lands at the additions and deletions page
            return 'TODO identity for user contribs directly to interlex'

        def contributions(self, *args, **kwargs):
            return 'TODO slicing on contribs ? or use versions?'

        # TODO POST ?private if private PUT (to change mapping) PATCH like readable 
        def uris(self, user, uri_path):
            # owl:Class, owl:*Property
            # owl:Ontology
            # /<user>/ontologies/obo/uberon.owl << this way
            # /<user>/uris/obo/uberon.owl << no mapping to ontologies here
            return request.path

        # TODO POST PUT PATCH
        def curies_(self, user):
            # TODO auth
            PREFIXES, g = self.getGroupCuries(user)
            if request.method == 'POST':
                # TODO diff against existing
                if request.json is None:
                    return 'No curies were sent\n', 400
                values = tuple((cp, ip) for cp, ip in request.json.items())
                values_template, params = makeParamsValues(values,
                                                           safe_constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
                params['group'] = user
                sql = 'INSERT INTO curies (group_id, curie_prefix, iri_prefix) VALUES ' + values_template
                try:
                    resp = self.session.execute(sql, params)
                    self.session.commit()
                    return 'ok\n', 200
                except sa.exc.IntegrityError as e:
                    self.session.rollback()
                    return f'Curie exists\n{e.orig.pgerror}', 409  # conflict
                    return f'Curie exists\n{e.args[0]}', 409  # conflict


            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        # TODO POST PATCH PUT
        def curies(self, user, prefix_iri_curie):
            PREFIXES, g = self.getGroupCuries(user)
            qname, expand = g.qname, g.expand
            if prefix_iri_curie.startswith('http') or prefix_iri_curie.startswith('file'):  # TODO decide about urlencoding
                iri = prefix_iri_curie
                curie = qname(iri)
                return curie
            elif ':' in prefix_iri_curie:
                curie = prefix_iri_curie
                try:
                    iri = expand(curie)
                except KeyError:
                    prefix, *_ = curie.split(':')
                    return f'Unknown prefix {prefix}', 404
                if 'local' in request.args and request.args['local'].lower() == 'true':
                    # FIXME super inefficient even with index?
                    sql = ('SELECT ilx_id FROM existing_iris AS e WHERE e.iri = :iri '
                           'AND (e.group_id = idFromGroupname(:group) OR e.group_id = 1)')
                    try:
                        resp = next(self.session.execute(sql, dict(iri=iri, group=user)))
                        return redirect(url_for(f'Endpoints.ilx /<user>/{ilx_pattern}',
                                                user=user, id=resp.ilx_id), code=302)
                    except StopIteration:
                        return abort(404)
                        pass

                    #return redirect('https://curies.interlex.org/' + curie, code=302)  # TODO abstract
                return redirect(iri, code=302)
            else:
                prefix = prefix_iri_curie
                if prefix not in PREFIXES:
                    # TODO query for user failover preferences
                    bPREFIXES, g = self.getGroupCuries('base')  # FIXME vs curated
                    ordered_prefix_sets = bPREFIXES,
                else:
                    ordered_prefix_sets = PREFIXES,

                return self.iriFromPrefix(prefix, *ordered_prefix_sets)

        # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
        # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
        # TODO HEAD -> return owl:Ontology section
        def ontologies(self, user, filename, extension, ont_path=''):
            # on POST for new file check to make sure that that the ontology iri matches the post endpoint
            # response needs to include warnings about any parts of the file that could not be lifted to interlex
            # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
            # we should be able to track file 'renames' without too much trouble
            printD(user, filename, extension, ont_path)
            group = user  #  FIXME
            user = 'tgbugs'  # FIXME from api token decryption
            match_path = os.path.join(ont_path, filename + '.' + extension)
            path = 'ontologies' + match_path  # FIXME get middle from request?
            #request_reference_name = request.headers['']
            reference_name = self.reference_name(group, path)
            printD(request.headers)
            if request.method == 'HEAD':
                # TODO return bound_name + metadata
                return 'HEAD TODO\n'
            if request.method == 'POST':
                existing = False  # TODO check if the file already exists
                # check what is being posted
                #embed()
                #if requests.args:
                    #printD(request.args)
                #elif request.json is not None:  # jsonld u r no fun
                    #printD(request.json)
                    #{'iri':'http://purl.obolibrary.org/obo/uberon.owl'}
                #elif request.data:
                    #printD(request.data)

                if not existing:
                    if request.files:
                        # TODO retrieve and if existing-iri make sure stuff matches
                        printD(request.files)
                    if request.json is not None:  # jsonld u r no fun
                        printD(request.json)
                        if 'name' in request.json:
                            name = request.json['name']  # FIXME not quite right?
                            if 'bound-name' in request.json:
                                expected_bound_name = request.json['bound-name']
                            else:
                                expected_bound_name = None

                            # FIXME this should be handled elsewhere for user
                            if match_path not in name and match_path not in expected_bound_name:
                                return f'No common name between {expected_bound_name} and {reference_name}', 400
                            with self.filefromiri as f:
                                # TODO get actual user from the api key
                                #print()
                                out = f(group, user, reference_name, name, expected_bound_name)
                                # out = f(user, filepath, ontology_iri, new=True)
                                #embed()
                                printD('should be done running?')

                            # TODO return loading stats etc
                            return out

                    #if 'external-iri' in request.args:
                        # cron jobs and webhooks... for the future on existing iris
                        # frankly we can just peek
                        #external_iri = request.args['external-iri']
                    # elif 'crawl' in request.args['']


                return 'POST TODO\n'

            # much easier to implement this way than current attempts
            return request.path + '\n'

        def ontologies_version(self, user, filename, epoch_verstr_ont,
                               filename_terminal, extension, ont_path=''):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'

        def prov(self, *args, **kwargs):
            return 'TODO\n'


    class Versions(Endpoints):
        # TODO own/diff here could make it much easier to view changes
        def ilx(self, user, epoch_verstr_id, id):
            # TODO epoch and reengineer how ilx is implemented
            # so that queries can be conducted at a point in time
            # sigh dataomic
            # or just give up on the reuseabilty of the query structure?
            return super().ilx(user, id)

        def readable(self, user, epoch_verstr_id, word):
            return request.path

        def uris(self, user, epoch_verstr_id, uri_path):
            return request.path

        def curies_(self, user, epoch_verstr_id):
            PREFIXES, g = self.getGroupCuries(user, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, epoch_verstr_id, prefix_iri_curie):
            return request.path


    class Own(Endpoints):
        def uris(self, user, other_user, uri_path):
            return request.path

        def curies_(self, user, other_user):
            PREFIXES, g = self.getGroupCuries(user)
            otherPREFIXES, g = self.getGroupCuries(other_user)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, other_user, prefix_iri_curie):
            return request.path
        def ontologies(self, user, other_user, filename, extension, ont_path=''):
            return request.path
        def ontologies_version(self, user, other_user, filename, epoch_verstr_ont,
                               filename_terminal, extension, ont_path=''):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'


    class OwnVersions(Own, Versions):
        def ilx(self, user, other_user, epoch_verstr_id, id):
            return request.path
        def readable(self, user, other_user, epoch_verstr_id, word):
            return request.path
        def uris(self, user, other_user, epoch_verstr_id, uri_path):
            return request.path

        def curies_(self, user, other_user, epoch_verstr_id):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, other_user, epoch_verstr_id, prefix_iri_curie):
            return request.path


    class Diff(Endpoints):
        def ilx(self, user, other_user_diff, id):
            return request.path
        def readable(self, user, other_user_diff, word):
            return request.path
        def uris(self, user, other_user_diff, uri_path):
            return request.path

        def curies_(self, user, other_user_diff):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user_diff)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, other_user_diff, prefix_iri_curie):
            return request.path
        def ontologies(self, user, other_user_diff, filename, extension, ont_path=''):
            return request.path
        def ontologies_version(self, user, other_user_diff, filename,
                               epoch_verstr_ont, filename_terminal, extension, ont_path=''):
            if filename != filename_terminal:
                return abort(404)
            else:
                return 'TODO\n'


    class DiffVersions(Diff, Versions):
        def ilx(self, user, other_user_diff, epoch_verstr_id, id):
            return request.path
        def readable(self, user, other_user_diff, epoch_verstr_id, word):
            return request.path
        def uris(self, user, other_user_diff, epoch_verstr_id, uri_path):
            return request.path

        def curies_(self, user, other_user_diff, epoch_verstr_id):
            PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
            otherPREFIXES, g = self.getGroupCuries(other_user_diff, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, other_user_diff, epoch_verstr_id, prefix_iri_curie):
            return request.path


    class VersionsOwn(Endpoints):
        pass  # TODO


    class VersionsDiff(Endpoints):
        pass  # TODO

    @app.before_first_request
    def runonce():
        # FIXME this is a reasonably safe way to make sure that we have a db connection
        TripleLoader.reference_host = next(db.session.execute('SELECT reference_host()'))[0]
        Endpoints.reference_host = next(db.session.execute('SELECT reference_host()'))[0]
        printD(Endpoints.reference_host)

    endpoints = Endpoints()
    versions = Versions()
    own = Own()
    ownversions = OwnVersions()
    diff = Diff()
    diffversions = DiffVersions()

    routes = list(make_paths(parent_child))
    for route in routes:
        nodes = route.split('/')
        if 'diff' in nodes:
            if 'versions' in nodes:
                inst = diffversions
            else:
                inst = diff
        elif 'own' in nodes:
            if 'versions' in nodes:
                inst = ownversions
            else:
                inst = own
        elif 'versions' in nodes:
            inst = versions
        else:
            inst = endpoints

        if nodes[-1] == '':
            if 'curies' in nodes:
                nodes = tuple(nodes[::-2]) + ('curies_',)
                printD('terminal nodes', nodes)
            if 'contributions' in nodes:
                nodes = tuple(nodes[::-2]) + ('contributions_',)
                printD('terminal nodes', nodes)

        function = inst.get_func(nodes)
        name = inst.__class__.__name__ + '.' + function.__name__ + ' ' + route
        if nodes[-1] in node_methods:
            methods = node_methods[nodes[-1]]
        else:
            methods = ['GET', 'HEAD']
        app.add_url_rule(route, name, function, methods=methods)

    for k, v in app.view_functions.items():
        printD(k, v)

    return app

def server_curies(db=None):
    app = Flask('InterLex curies server')
    @app.route('/<curie>')
    def curie(curie):
        return 
    return app

def test(server='localhost:8505'):

    def test_routes():
        routes = makeTestRoutes()
        # TODO a way to mark expected failures
        urls = [
            'http://localhost:8505/tgbugs/curies/BIRNLEEX:796?local=true',
            'http://localhost:8505/tgbugs/curies/BIRNLEX:796?local=true',
            'http://localhost:8505/tgbugs/curies/BIRNLEEX:796',
            'http://localhost:8505/tgbugs/curies/BIRNLEX:796',
            ]
        urls = [f'http://{server}{r}' for r in routes] + urls
        printD(urls)
        url_blaster(urls, 0)

    def test_loader():
        session = FakeSession()
        fff = FileFromFile(session)
        ttl = Path(devconfig.ontology_local_repo) / 'ttl'
        names =  (ttl/'NIF-GrossAnatomy.ttl',
                  #ttl/'NIF-Chemical.ttl',
                  #ttl/'external'/'uberon.owl',  # FIXME to big for testing w/o pypy3
                  #ttl/'external'/'uberon.ttl',
                  #ttl/'generated'/'parcellation'/
                  ttl/'generated'/'parcellation-artifacts.ttl',
                  ttl/'nif.ttl',)
        name = names[0]
        for name in names[::-1]:
            with fff as f:
                f(name.as_posix())

    test_loader()

def run_api():
    return server_api(db=SQLAlchemy())

def run_uri():
    return server_uri(db=SQLAlchemy())

def run_curies():
    return server_uris(db=SQLAlchemy())

def main():
    from docopt import docopt
    args = docopt(__doc__, version='interlex 0.0.0')
    if args['test']:
        if args['--debug']:
            embed()
            return
        else:
            test()
            return
    if args['post']:
        user = args['<user>']
        if args['--local']:
            host = f'localhost:{port_uri}'
            scheme = 'http'
        else:
            host = 'uri.olympiangods.org'
            scheme = 'https'
        if args['curies']:
            url = f'{scheme}://{host}/{user}/curies/'  # https duh
            #printD(url, args)
            # FIXME /curies redirects to get...
            resp = requests.post(url, json=uPREFIXES)
            printD(resp.text)
        elif args['ontology']:
            j = {'name':'http://purl.obolibrary.org/obo/uberon.owl'}
            ontology_iri = 'http://ontology.neuinfo.org/NIF/ttl/NIF-GrossAnatomy.ttl'
            u = urlparse(ontology_iri)
            j = {'name':ontology_iri}
            url = f'{scheme}://{host}/{user}/ontologies/' + u.path[1:]
            resp = requests.post(url, json=j)
            printD(resp.text)
        return
            
    if args['dbsetup']:
        #dburi = dbUri()
        # app.config['SQLALCHEMY_DATABASE_URI']
        #engine, insp = database()
        #meta = MetaData(engine)
        #db = SQLAlchemy()
        #meta.reflect()
        # Session = sessionmaker(engine)
        # TODO use sessions to manage transations for safety
        sql_new_id = 'INSERT INTO interlex_ids DEFAULT VALUES RETURNING id'

        sql_group = 'INSERT INTO groups (groupname) VALUES (%s) RETURNING id'
        args_group = 'tgbugs'
        engine.execute(sql_group, args_group)
        sql_new_user = 'INSERT INTO new_users (id, putative_orcid, putative_email) VALUES (%s, %s, %s)'
        args_new_user = 1, 'https://orcid.org/0000-0002-7509-4801', 'tgbugs@gmail.com'
        engine.execute(sql_new_user, args_new_user)

        # TODO use a trigger for this, should never do this from python...
        sql = 'INSERT INTO users (id, username, orcid) VALUES (%s, %s, %s)'
        args = 1, 'tgbugs', 'https://orcid.org/0000-0002-7509-4801'
        engine.execute(sql, args)

        embed()
        return

    db = SQLAlchemy()

    if args['api']:
        app = server_api(db=db)
        port = port_api
    elif args['uri']:
        app = server_uri(db=db)
        port = port_uri
    elif args['curies']:
        app = server_curies(db=db)
        port = port_curies

    app.debug = args['--debug']
    app.run(host='localhost', port=port, threaded=True)  # FIXME gunicorn

if __name__ == '__main__':
    main()
