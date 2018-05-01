#!/usr/bin/env python3.6

import sys
import socket
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

        values = [(row.ilx[4:], row.iri) for row in query if row.ilx not in row.iri]

        # TODO :/
        dupes = [u for u, c in Counter(_[1] for _ in values).most_common() if c > 1]

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
