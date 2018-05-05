#!/usr/bin/env python3.6

import sys
import socket
import hashlib
from pathlib import Path, PurePath
from tempfile import gettempdir
from functools import partialmethod
from collections import Counter
import rdflib
import requests
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect, MetaData, Table, types
from sqlalchemy.sql import expression
# from sqlalchemy.orm import Session
from flask import Flask, url_for, redirect, request, render_template, render_template_string
from flask import make_response, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.routing import BaseConverter
from pyontutils.config import devconfig
from pyontutils.utils import TermColors as tc
from pyontutils.core import PREFIXES as uPREFIXES, rdf, rdfs, owl, definition
from pyontutils.core import makeGraph, yield_recursive
from pyontutils.ttlser import DeterministicTurtleSerializer, CustomTurtleSerializer
from interlex.exc import bigError
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

def dbUri(user='interlex-user', host='localhost', port=5432, db='interlex_test'):
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
        name by convetion, the IBNode should still be used to identify them.

        When calculating the identity, it may be useful to use the identity
        function to provide a total ordering on all nodes.

        When directly mapping an IBNode to a set of pairs that has a name
        the identity can be reattached, but it must be by convetion, otherwise
        the identity of the pairs will change.

        This is also true for lists. Note that IBNodes bound by convention are
        NOT cryptographically secure because it is trivial to tamper with the
        contents of the message and regenerate the IBNode. IBNodes are therefore
        not useful as bound identifiers, but only as unbound or pointing identifiers.
    """
    cypher = hashlib.sha256
    encoding = 'utf-8'
    depth_invariant_predicates = rdf.rest,

    def __new__(cls, triples_or_pairs_or_thing, debug=False):
        self = super().__new__(cls)  # first time without value
        self.debug = debug
        self.id_lookup = {}
        self.cypher_check()
        self.dip_idents = tuple(self.atomic(p) for p in self.depth_invariant_predicates)
        self.identity = self.identity_function(triples_or_pairs_or_thing)
        real_self = super().__new__(cls, self.identity)
        if debug == True:
            return self
            
        real_self.debug = debug
        real_self.identity = self.identity
        real_self.dip_idents = self.dip_idents
        return real_self

    def check(self, other):
        return self.identity == self.identity_function(other)

    def cypher_check(self):
        m1 = self.cypher()
        m2 = self.cypher()
        assert m1.digest() == m2.digest(), f'Cypher {self.cypher} does not have a stable starting point!'

    def atomic(self, thing):
        m = self.cypher()
        if thing is not None:
            if isinstance(thing, bytes):
                to_hash = thing
            else:
                to_hash = str(thing).encode(self.encoding)
            m.update(to_hash)
        else:
            to_hash = None

        identity = m.digest()
        if self.debug:
            self.id_lookup[identity] = to_hash

        return identity

    def ordered_identity(self, *things):
        """ this assumes that the things are ALREADY ordered correctly """
        m = self.cypher()
        for thing in things:
            if type(thing) != bytes:
                raise TypeError(f'{type(thing)} is not bytes, did you forget to call atomic first?')
            if thing is None:  # all null are converted to the starting hash
                thing = self.atomic(None)
            #thing = self.atomic(thing)  # FIXME careful on double hash?
            m.update(thing)

        identity = m.digest()
        if self.debug:
            self.id_lookup[identity] = tuple(self.id_lookup[t] if
                                             t in self.id_lookup else
                                             t for t in things)

        return identity

    def add_to_subgraphs(self, thing):
        #printD(thing)
        t = s, p, o = thing  # FIXME how to deal with pairs?
        if s in self.subgraph_mapping:
            ss = self.subgraph_mapping[s]
        else:
            ss = False

        if o in self.subgraph_mapping:
            os = self.subgraph_mapping[o]
        else:
            os = False

        if ss and os:
            if ss is not os:  # this should only happen for 1:1 bnodes
                new = ss + [t] + os
                try:
                    self.subgraphs.remove(ss)
                    self.subgraphs.remove(os)
                    self.subgraphs.append(new)
                    for bn in bnodes(ss):
                        self.subgraph_mapping[bn] = new
                    for bn in bnodes(os):
                        self.subgraph_mapping[bn] = new
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
            self.subgraphs.append(new)
            if isinstance(s, rdflib.BNode):
                self.subgraph_mapping[s] = new
            if isinstance(o, rdflib.BNode):
                self.subgraph_mapping[o] = new
        elif ss:
            ss.append(t)
            if isinstance(o, rdflib.BNode):
                self.subgraph_mapping[o] = ss
        elif os:
            os.append(t)
            if isinstance(s, rdflib.BNode):
                self.subgraph_mapping[s] = os

    def sort_subgraph(self, subgraph):
        sortlast = b'\xff' * 64
        objects = set(o for s, p, o in subgraph)
        double_blank_objects = set(o for s, p, o in subgraph if
                                   isinstance(s, rdflib.BNode) and
                                   isinstance(o, rdflib.BNode))

        heads = set(s for s, p, o in subgraph if
                    isinstance(s, rdflib.BNode) and
                    s not in objects and
                    isinstance(o, rdflib.BNode))

        distance_value = {}

        # FIXME this is _still_ broken for lists
        # because list order has no semantics
        # but persists, sigh

        # FIXME ambiguity when we have multiple blank, named, blank as in lists
        # FIXME these are subgraphs of subgraphs...
        # they are connected but we still need to calculate and identity for them
        # rank by closest named objects, ties are broken by the 2nd closest named etc.

        def inner(obj):  # FIXME this kills the crab
            if obj not in distance_value:
                distance_value[obj] = set()
            for s, p, o in subgraph:
                if s == obj:
                    if isinstance(o, rdflib.BNode):
                        for depth, value in inner(o):
                            if p not in self.dip_idents:
                                depth += 1

                            dv = depth, value
                            distance_value[obj].add(dv)
                            yield dv
                    else:
                        dv = 1, o
                        distance_value[obj].add(dv)
                        yield dv
                        

        for o in double_blank_objects | heads:
            list(inner(o))

        double_ranks = {k:str(i+1).encode(self.encoding)
                        for i, (k, v) in enumerate(sorted(distance_value.items(),
                                                          key=lambda kv:sorted(kv[1])))}

        def sortkey(thing):
            return tuple((sortlast + double_ranks[t] if
                          t in double_ranks else
                          sortlast + b'0') if
                         isinstance(t, rdflib.BNode) else
                         t
                         for t in thing)

        def normalize(thing, cmax, existing):
            thing_out = []
            for e in thing:
                if isinstance(e, rdflib.BNode):
                    if e not in existing:
                        cmax += 1
                        existing[e] = cmax

                    thing_out.append(existing[e])
                else:
                    thing_out.append(e)

            yield tuple(thing_out)
            yield cmax

        def intlast(thing):
            return tuple(sortlast + str(e).encode(self.encoding)
                         if isinstance(e, int)
                         else e
                         for e in thing)

        # total ordering on the identities of the the named elements of the subgraph
        # if there is a name as a subject it will appear first due to the fffffff
        phase1 = sorted(subgraph, key=sortkey)

        cmax = -1
        existing = {}

        # number the bnodes preserving their linking structure
        phase2 = []
        for thing in phase1:
            nthing, cmax = normalize(thing, cmax, existing)
            phase2.append(nthing)

        # reorder based on the linking structure putting integers last
        phase2 = tuple(sorted(phase2, key=intlast))

        if self.debug and distance_value:
            #printD(self.id_lookup.keys())
            printD()
            _ = [(print(k[:5], *((c, self.id_lookup[e]) for c, e in v)), print())
                 for k, v in sorted(distance_value.items())]
            #embed()

        return phase2

    def subgraph_identities(self):
        # TODO fail on dangling nodes
        named_linked, linked, free = {}, {}, {}
        for subgraph in self.subgraphs:
            normalized = self.sort_subgraph(subgraph)
            if isinstance(normalized[0][0], int):  # is free
                head = None
                ngraph = normalized
            else:
                head, *ngraph = normalized

            ident = self.ordered_identity(
                *(self.ordered_identity(*(str(e).encode(self.encoding) if
                                          isinstance(e, int) else  # FIXME recurse?? except that we already hash the non bnodes...
                                          # FIXME this makes the identity not match the graph?
                                          e
                                          for e in tuple_))
                  for tuple_ in ngraph))

            if head is None:
                free[ident] = ngraph
            else:
                named_linked[ident] = head
                linked[ident] = ngraph

        return named_linked, linked, free

    def recurse(self, triples_or_pairs_or_thing, bnodes_ok=False):
        for thing in triples_or_pairs_or_thing:
            if thing is None:
                yield self.atomic(thing)
            elif isinstance(thing, bytes):
                # do NOT assume that this has already been hashed,
                # if bytes is encountered here, it should be hashed
                yield self.atomic(thing)
            elif type(thing) == str:  # exact match since all the rest are instances of string
                yield self.atomic(thing)
            elif isinstance(thing, rdflib.URIRef):
                yield self.atomic(thing)
            elif isinstance(thing, rdflib.Literal):
                # "http://asdf.asdf" != <http://asdf.asdf>
                # TODO hash individual bits first or no?, I think no
                # update, yes hash first for consistency, always recurse before calling an atomic
                # need str(thing) here to break recursion on literal type
                yield self.ordered_identity(*self.recurse((str(thing), thing.datatype, thing.language)))
            elif isinstance(thing, IdLocalBNode) or isinstance(thing, IdentityBNode):
                # TODO check that we aren't being lied to?
                yield thing.identity
            elif isinstance(thing, rdflib.BNode):
                if bnodes_ok:
                    yield thing
                else:
                    raise ValueError('BNodes only have names or collective identity...')
            else:
                if any(isinstance(e, rdflib.BNode) for e in thing):
                    #self.add_to_subgraphs(tuple(str(t).encode(self.encoding) if
                                                #not isinstance(t, rdflib.BNode) else
                                                #t
                                                #for t in thing))
                    self.add_to_subgraphs(tuple(self.recurse(thing, bnodes_ok=True)))
                else:
                    if len(thing) == 3 or len(thing) == 2:  # FIXME assumes contents are atomic
                        yield self.ordered_identity(*self.recurse(thing))
                    else:
                        raise ValueError('wat')
                        yield self.ordered_identity(*sorted(self.recurse(thing)))

    def identity_function(self, triples_or_pairs_or_thing):
        if isinstance(triples_or_pairs_or_thing, bytes):  # serialization
            return self.atomic(triples_or_pairs_or_thing)
        elif isinstance(triples_or_pairs_or_thing, str):  # a node
            return next(self.recurse((triples_or_pairs_or_thing,)))
        else:
            self.subgraph_mapping = {}
            self.subgraphs = []
            self.named_identities = tuple(self.recurse(triples_or_pairs_or_thing))  # memory :/
            self.named_linked, self.linked_identities, self.free_identities = self.subgraph_identities()
            # named linked are the 'head' triples that do not participate in the
            # calculation of the linked identity but that we do need to map
            #assert tuple(named_linked) == tuple(linked)
            self.all_idents = sorted(self.named_identities +
                                    tuple(self.linked_identities) +
                                    tuple(self.free_identities))

            return self.ordered_identity(*self.all_idents)

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

# get interlex
class InterLexLoad:
    def __init__(self, Loader):
        self.loader = Loader('tgbugs', 'tgbugs', 'http://uri.interlex.org/base/interlex', 'uri.interlex.org')
        self.admin_engine = create_engine(dbUri(user='interlex-admin'), echo=True)
        self.admin_exec = self.admin_engine.execute
        from pyontutils.utils import mysql_conn_helper
        DB_URI = 'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{db}'
        if socket.gethostname() != 'orpheus':
            config = mysql_conn_helper('localhost', 'nif_eelg', 'nif_eelg_secure', 33060)  # see .ssh/config
        else:
            config = mysql_conn_helper('nif-mysql.crbs.ucsd.edu', 'nif_eelg', 'nif_eelg_secure')
        self.engine = create_engine(DB_URI.format(**config), echo=True)
        config = None
        del(config)
        self.insp = inspect(self.engine)
        self.graph = None

    @bigError
    def load(self):
        loader = self.loader
        self.loader.session.execute(self.ilx_sql, self.ilx_params)
        loader.session.execute(self.eid_sql, self.eid_params)
        # FIXME this probably requires admin permissions
        self.admin_exec(f"SELECT setval('interlex_ids_seq', {self.current}, TRUE)")  # DANGERZONE
        if self.graph is None:
            self.graph = rdflib.Graph()
            self.loader._graph
            mg = makeGraph('', graph=self.graph)  # FIXME I swear I fixed this already
            [mg.add_trip(*t) for t in self.triples]
        self.loader._graph = self.graph
        name = 'http://toms.ilx.dump/TODO'
        self.loader._bound_name = name
        self.loader.expected_bound_name = name
        self.loader._serialization = repr((name, self.triples)).encode()
        setup_ok = self.loader(name)

        if setup_ok is not None:
            raise LoadError(setup_ok)
        
        self.loader.load()
        printD('Yay!')

    def ids(self):
        rows = self.engine.execute('SELECT DISTINCT ilx FROM terms ORDER BY ilx ASC')
        values = [(row.ilx[4:],) for row in rows]
        vt, self.ilx_params = makeParamsValues(values)
        self.ilx_sql = 'INSERT INTO interlex_ids VALUES ' + vt
        self.current = int(values[-1][0].strip('0'))
        printD(self.current)

    def existing_ids(self):
        insp, engine = self.insp, self.engine

        terms = [c['name'] for c in insp.get_columns('terms')]
        term_existing_ids = [c['name'] for c in insp.get_columns('term_existing_ids')]
        header = term_existing_ids + terms

        query = engine.execute('SELECT * FROM term_existing_ids as teid JOIN terms as t ON t.id = teid.tid WHERE t.type != "cde"')

        #data = query.fetchall()
        #cdata = list(zip(*data))

        #def datal(head):
            #return cdata[header.index(head)]

        values = [(row.ilx[4:], row.iri, row.version) for row in query if row.ilx not in row.iri]

        asdf = {}
        for ilx, iri, ver in values :
            if iri not in asdf:
                asdf[iri] = set()

            asdf[iri].add(ilx)

        dupe_report = {k:tuple(f'http://uri.interlex.org/base/ilx_{i}' for i in v)
         for k, v in asdf.items()
         if len(v) > 1}
        _ = [print(k, '\t', *v) for k, v in sorted(dupe_report.items())]

        dupes = tuple(dupe_report)

        # dupes = [u for u, c in Counter(_[1] for _ in values).most_common() if c > 1]  # picked up non-unique ilx which is not what we wanted

        bads = []
        bads += [(a, b) for a, b in values if b in dupes]
        # TODO one of these is incorrect can't quite figure out which, so skipping entirely for now

        for id_, iri in values:  # FIXME
            if ' ' in iri:  # sigh, skip these for now since pguri doesn't seem to handled them
                bads.append((id_, iri))
        values = [v for v in values if v not in bads]
        self.user_iris = [v for v in values if 'interlex.org' in v[1]]  # TODO
        values = [v for v in values if 'interlex.org' not in v[1]]


        sql_base = 'INSERT INTO existing_iris (group_id, ilx_id, iri) VALUES '
        values_template, params = makeParamsValues(values, constants=('idFromGroupname(:group)',))
        params['group'] = 'base'
        sql = sql_base + values_template
        self.eid_values = values
        self.eid_sql = sql
        self.eid_params = params
        self.eid_bads = bads
        printD(bads)
        return sql, params

    def triples(self):
        insp, engine = self.insp, self.engine
        #ilxq = ('SELECT * FROM term_existing_ids as teid '
                #'JOIN terms as t ON t.id = teid.tid '
                #'WHERE t.type != "cde"')
        header_object_properties = [d['name'] for d in insp.get_columns('term_relationships')]
        header_subClassOf = [d['name'] for d in insp.get_columns('term_superclasses')]
        header_terms = [d['name'] for d in insp.get_columns('terms')]
        queries = dict(
            terms = 'SELECT * from terms WHERE type != "cde"',
            subClassOf = 'SELECT * from term_superclasses',
            object_properties = 'SELECT * from term_relationships',
            annotation_properties = 'SELECT * from term_annotations limit 10000',  # not quite yet also slow
            cde_ids = 'SELECT id, ilx FROM terms where type = "cde"',
            )
        data = {name:engine.execute(query).fetchall()
                for name, query in queries.items()}
        ilx_index = {}
        id_type = {}
        triples = []
        type_to_owl = {'term':owl.Class,
                    'cde':owl.Class,
                    'annotation':owl.AnnotationProperty,
                    'relationship':owl.ObjectProperty}

        def addToIndex(id, ilx, class_):
            if ilx not in ilx_index:
                ilx_index[ilx] = []
            ilx_index[ilx].append(id)
            if id not in id_type:
                id_type[id] = []
            id_type[id].append(class_)

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
            addToIndex(row.id, ilx, class_)

        versions = {k:v for k, v in ilx_index.items() if len(v) > 1}  # where did our dupes go!?
        tid_to_ilx = {v:k
                    for k, vs in ilx_index.items()
                    for v in vs}

        multi_type = {tid_to_ilx[id]:types for id, types in id_type.items() if len(types) > 1}

        def baseUri(e):
            return f'http://uri.interlex.org/base/ilx_{tid_to_ilx[e]}'

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
        if bads or WTF or WTF2:
            printD(bads[:10])
            printD(WTF[:10])
            printD(WTF2[:10])
            raise ValueError('BADS HAVE ENTERED THE DATABASE AAAAAAAAAAAA')
        return triples

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

def server_curies(db=None):
    app = Flask('InterLex curies server')
    @app.route('/<prefix_curie>')
    def curie(prefix_curie):
        return redirect('http://uri.interlex.org/base/curies/{prefix_curie}', 301)
    return app

def run_api():
    return server_api(db=SQLAlchemy())

def run_curies():
    return server_uris(db=SQLAlchemy())
