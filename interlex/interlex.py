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
    interlex post curies <user>
    interlex post ontology <user>

Options:
    -d --debug              enable debug mode

    -a --api=API            SciGraph api endpoint
    -k --key=APIKEY         apikey for SciGraph instance
    -f --input-file=FILE    don't use SciGraph, load an individual file instead
    -o --outgoing           if not specified defaults to incoming
    -b --both               if specified goes in both directions

"""
port_api = 8500
port_uri = 8505
port_curies = 8510

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
from pyontutils.utils import orderInvariantHash
from pyontutils.core import makeGraph, makePrefixes, PREFIXES as uPREFIXES, rdf, rdfs, owl, definition
from pyontutils.ontutils import url_blaster
from pyontutils.ttlser import CustomTurtleSerializer
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

cypher = hashlib.sha256

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
    proto_params = {tuple(f'values{i}_{j}'
                          for j, e in enumerate(v)):v
                    for i, v in enumerate(values)}
    values_template = ', '.join('(' + ', '.join(constants + tuple(':' + e for e in v)) + ')'
                                for v in proto_params)
    params = {name:value for names, values in proto_params.items()
                for name, value in zip(names, values)}
    return values_template, params

class TripleLoader:
    def __init__(self, session, cypher=cypher):
        self.process_type = self.__class__.__name__
        self.session = session
        self.cypher = cypher

    def __enter__(self, exit=False):
        # graph preload
        if not exit:
            printD('entering')
        self.new = False  # insurance
        self.source_iri = None
        self.source = None
        self.source_serialization_hash = None
        self.source_triples_hash = None

        # graph load (usually)
        self.ontology_iri = None
        self.graph = None
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.__enter__(True)  # the paranoia is real
        printD('exit')

    def __call__(self):
        # FIXME this is impossible to follow :/

        name
        bound_name
        reference_name

        serialization_identity
        bound_name_identity
        metadata_identity
        data_identity



        # external names
        if self.new:
            sql = ''
            params = dict(owner_group_id = self.user,
                          interlex_source_path = self.ont_path,
                          external_external_source_iri = self.source_iri)
            self.session.execute(sql, params)

        self.graph_preload()

        # external hash
        params = dict(source_serialization_hash = self.source_serialization_hash,)

        self.graph_load()

        # internal name
        params = dict(internal_external_source_iri = self.ontology_iri,)

        self.triples_preload()

        # internal hash
        params = dict(source_triples_hash = self.source_triples_hash,)
        return self.triples_load()

    def graph_preload(self):
        if isinstance(self.source, bytes):
            m = self.cypher()
            m.update(self.source)
            self.source_serialization_hash = m.digest()
            'INSERT INTO source'
        elif isinstance(self.source, tuple) or isinstance(self.source, rdflib.Graph):
            self.source_serialization_hash = self.source_triples_hash = orderInvariantHash(self.source, self.cypher)
        else:
            raise TypeError(f'Dont know how to hash {type(self.source)}')

    def graph_load(self):
        if isinstance(self.source, rdflib.Graph):
            self.graph = self.source
        else:
            self.graph = rdflib.Graph()
            if isinstance(self.source, tuple):
                [self.graph.add(t) for t in self.source]
            else:
                self.graph.parse(data=self.source, format=self.format)
                ont_type_trips = self.graph[:rdf.type:owl.Ontology]
                self.ontology_iri = next(ont_type_trips)  # TODO warn on > 1
                try:
                    extra = next(ont_type_trips)
                    raise ValueError('More than one owl:Ontology in this file!\n'
                                     '{self.ontology_iri}\n{extra}\n')
                except StopIteration:
                    pass

    def triples_preload(self):
        if self.source_triples_hash is None:
            self.source_triples_hash = orderInvariantHash(self.graph)

    def _triples_make_load(self):
        #graph, src_qual):
        """
        urirefs = set(tuple(str(e) for e in t) + (src_qual, 0)
                        for t in graph
                        if all(isinstance(e, rdflib.URIRef) for e in t))
        literals = set(tuple(str(e) for e in t) + (t[2].datatype, src_qual,)
                        for t in graph
                        if not any(isinstance(e, rdflib.BNode) for e in t)
                        and isinstance(t[2], rdflib.Literal))
        # this one is a bit more complex
        HEAD = 0  # TODO
        unlifted = set(tuple(str(e) for e in t) + (t[2].__class__.__name__, HEAD, src_qual)
                        # TODO type info since these can be all 3
                        # class name only covers high level, we also need to accomodate literal types :/
                        for t in graph
                        if any(isinstance(e, rdflib.BNode) for e in t))

        uri_template, uri_params = makeParamsValues(urirefs)
        uri_sql_base = 'INSERT INTO triples_uri (s, p, o) VALUES '
        uri_sql = uri_sql_base + uri_template
        lit_template, lit_params = makeParamsValues(literals)
        lit_sql_base = 'INSERT INTO triples_literal (s, p, o, datatype, lang) VALUES '
        lit_sql = lit_sql_base + lit_template
        unlifted_template, unlifted_params = makeParamsValues(unlifted)
        unlifted_sql_base = 'INSERT INTO triples_unlifted (s, p, o, o_type, head_node, qualifier_id) VALUES '
        unlifted_sql = unlifted_sql_base + unlifted_template
        """

        suffix = ' ON CONFLICT (s, p, o) DO NOTHING'
        sqls = (
            'INSERT INTO triples_uri      (s, p, o) VALUES ',
            'INSERT INTO triples_literal  (s, p, o, datatype, lang) VALUES ',
            # 'INSERT INTO triples_blank    (s, p, o) VALUES ',  # TODO
            # 'INSERT INTO triples_subgraph (s, p, o, o_type, head_node, qualifier_id) VALUES ',  # TODO
        )

        trips = triples_uri, triples_literal, triples_blank, triples_subgraph = tuple(set() for _ in range(4))
        printD(len(self.graph))
        for s, p, o in self.graph:
            t = s, p, o
            if all(isinstance(e, rdflib.URIRef) for e in t):
                triples_uri.add(t)
            if isinstance(s, rdflib.BNode):
                triples_subgraph.add(t)
            if isinstance(o, rdflib.BNode):
                triples_blank.add(t)
            else:
                if isinstance(o, rdflib.URIRef):
                    datatype = rdflib.XSD.anyURI
                    lang = None
                else:
                    datatype = o.datatype
                    lang = o.language
                triples_literal.add((s, p, o, datatype, lang))

        def make_sql_params(triples, sql_base):
            triples = (tuple(str(e) for e in t) for t in triples)  # FIXME ANNOYING
            template, params = makeParamsValues(triples)
            sql = sql_base + template + suffix
            return sql, params

        # TODO complex triples that _have_ been lifted

        for triples, sql_base in zip(trips, sqls):
            yield make_sql_params(triples, sql_base)

    def triples_make_load(self):

        sufixes = (' ON CONFLICT (s, p, o) DO NOTHING',
                   ' ON CONFLICT (s, p, o_list, datatype, language) DO NOTHING')
        sqls = (
            'INSERT INTO triples (s, p, o) VALUES ',
            'INSERT INTO triples (s, p, o_lit, datatype, lang) VALUES ',
            # 'INSERT INTO triples (s, p, o_blank) VALUES ',  # TODO
            # 'INSERT INTO triples_subgraph (s, p, o, o_type, head_node, qualifier_id) VALUES ',  # TODO
        )

        trips = triples_uri, triples_literal, triples_blank, triples_subgraph = tuple(set() for _ in range(4))
        printD(len(self.graph))
        for s, p, o in self.graph:
            t = s, p, o
            if all(isinstance(e, rdflib.URIRef) for e in t):
                triples_uri.add(t)
            if isinstance(s, rdflib.BNode):
                triples_subgraph.add(t)
            if isinstance(o, rdflib.BNode):
                triples_blank.add(t)
            else:
                if isinstance(o, rdflib.URIRef):
                    datatype = rdflib.XSD.anyURI  # FIXME
                    lang = None
                else:
                    datatype = o.datatype
                    lang = o.language
                triples_literal.add((s, p, o, datatype, lang))

        def make_sql_params(triples, sql_base, suffix):
            triples = (tuple(str(e) for e in t) for t in triples)  # FIXME ANNOYING double entry issues
            template, params = makeParamsValues(triples)
            sql = sql_base + template + suffix
            return sql, params

        # TODO complex triples that _have_ been lifted

        for triples, sql_base, suffix in zip(trips, sqls, suffixes):
            yield make_sql_params(triples, sql_base, suffix)

    def triples_load(self):#, sql, params):
        for sql, params in self.triples_make_load():
            try:
                self.session.execute(sql, params)
                self.session.commit()
                # TODO stats
                return 'ok\n'
            except BaseException as e:
                self.session.rollback()
                printD(e.orig.pgerror)
                return e.orig.pgerror
        else:
            return 'No triples were loaded!?', 400
                

class InterLex(TripleLoader):
    def __call__(self, user, triples):
        pass
        # note, we don't revert history,
        # we just add triples back in a new transaction
        # the joys of invariance

class FileFromIRI(TripleLoader):
    maxsize_mbgz = 5
    maxsize_mb = 20
    lfmessage = (f'You appear to by trying to load a file bigger than {maxsize_mb}MB. '
                 'Please get in touch with us if you want this included in InterLex.')

    def __call__(self, user, ont_path, source_iri, new=False):
        self.new = new
        self.ont_path = ont_path
        printD('ffiri call?')
        path = PurePath(source_iri)
        filename = path.name
        filetype = path.suffix[1:]
        format = formats[filetype]

        s = requests.Session()
        head = requests.head(source_iri)  # check on the size to make sure no troll

        if head.status_code >= 400:
            return f'Error: nothing found at {source_iri}\n', 400

        while head.is_redirect:
            head = s.send(head.next)
            if not head.is_redirect:
                break

        if 'Content-Type' in head.headers:
            mimetype = head.headers['Content-Type'] 

        if format not in formats and mimetype not in formats:
            return f"Don't know how to parse either {format} or {mimetype}", 400
        elif format not in formats:
            format = mimetype

        size_mb = int(head.headers['Content-Length']) / 1024 ** 2
        admin_check_sql = permissions_sql + " AND group_id = 0 AND user_role = 'admin'"
        print(admin_check_sql)
        if 'Content-Encoding' in head.headers and head.headers['Content-Encoding'] == 'gzip':
            if size_mb > self.maxsize_mbgz:
                is_admin = self.session.execute(admin_check_sql, dict(group=user))
                print('user is admin?', is_admin)
                return lfmessage, 400
            resp = requests.get(source_iri)
            size_mb = len(resp.content) / 1024 ** 2
        else:
            resp = None

        if size_mb > self.maxsize_mb:
            is_admin = self.session.execute(admin_check_sql, dict(group=user))
            print('user is admin?', is_admin)
            return lfmessage, 400

        if resp is None:
            resp = requests.get(source_iri)

        self.source_iri = source_iri
        self.format = format
        self.source = resp.content
        return super().__call__()

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
        print(len(values))
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
        print('starting execution')
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
            print('starting commit')
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
        #print(sql)
        #print(params)
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
            #print('PATH:', path)
            if parent in options:
                for option in options[parent][:limit]:
                    yield '/' + option + path
            else:
                yield '/' + parent + path

    if parent in parent_child:
        for child in parent_child[parent]:
            #print('CHILD:', child)
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
            #print('PATH:', path)
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
    ilx_pattern, parent_child = uriStructure()
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
        def __init__(self):
            self.session = self.db.session
            self.filefromiri = FileFromIRI(self.session)

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
            #print(PREFIXES)
            if not PREFIXES:
                PREFIXES = makePrefixes('rdfs', 'owl')
            g = makeGraph(group + '_curies_helper', prefixes=PREFIXES)
            return PREFIXES, g

        def get_func(self, nodes):
            mapping = {
                ilx_pattern:self.ilx,
                'readable':self.readable,
                'uris':self.uris,
                'curies_':self.curies_,
                'curies':self.curies,
                'ontologies':self.ontologies,
                'version':self.ontologies_version,  # FIXME collision prone?
            }
            for node in nodes[::-1]:
                if node in mapping:
                    return mapping[node]

        # TODO PATCH
        def ilx(self, user, id):
            # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}
            #printD(user, id)
            if user != 'base' or user != 'latest':
                args = dict(id=id, user=user)
                #sql = ('SELECT ou.username, t.id FROM interlex_ids as t, org_user_view as ou '
                       #'WHERE t.id = :id AND ou.username = :user')
                #sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       #'SELECT groups AS g JOIN users AS u ON g.id = u.id WHERE g.groupname = :user UNION '
                       #'SELECT groups AS g JOIN orgs AS o ON g.id = o.id WHERE g.groupname = :user')
                # TODO it seems WAY more efficient to add a 'verfied' column to groups
                sql = ('SELECT id FROM interlex_ids WHERE id = :id UNION '
                       "SELECT id::text FROM groups WHERE own_role < 'pending' AND groupname = :user")
                #sql = ('SELECT t.id, g.id FROM interlex_ids AS t, groups AS g '
                       #'WHERE t.id = :id AND g.validated = TRUE AND g.groupname = :user')
                try:
                    resp = self.session.execute(sql, args)
                    #printD(resp)
                    id, gid = list(e.id for e in resp)
                    printD(id, gid)
                except StopIteration:
                    return 'stopping', 404
                    #return abort(404)

            uri = f'http://uri.interlex.org/base/ilx_{id}'
            args = dict(uri=uri, id=id)
            #sql = ('SELECT e.iri, c.p, c.o, c.qualifier_id, c.transform_rule_id '
                   #'FROM existing_iris as e JOIN core as c ON c.s = e.iri OR c.s = :uri '
                   #'WHERE e.ilx_id = :id')
            sql = ('SELECT e.iri, tu.p, tu.o::text FROM existing_iris as e '
                   'JOIN triples_uri as tu ON tu.s = e.iri OR tu.s = :uri '
                   'UNION '
                   'SELECT e.iri, tl.p, tl.o FROM existing_iris as e '
                   'JOIN triples_literal as tl ON tl.s = e.iri OR tl.s = :uri')
            resp = list(self.session.execute(sql, args))
            printD(resp)
            PREFIXES, g = self.getGroupCuries(user)
            _ = [g.add_trip(s, p, o) for s, p, o in resp]  # FIXME ah type casting
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
                                                           constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
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
                iri = PREFIXES[prefix]
                return iri

        # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
        # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
        # TODO HEAD -> return owl:Ontology section
        def ontologies(self, user, filename, extension, ont_path=''):
            # on POST for new file check to make sure that that the ontology iri matches the post endpoint
            # response needs to include warnings about any parts of the file that could not be lifted to interlex
            # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
            # we should be able to track file 'renames' without too much trouble
            printD(user, filename, extension, ont_path)
            filepath = ont_path + '/' + filename + '.' + extension
            if request.method == 'HEAD':
                # TODO serialize just the owl:Ontology and minimal prefixes
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
                        if 'external-iri' in request.json:
                            ontology_iri = request.json['external-iri']
                            #embed()
                            if filepath not in ontology_iri:  # FIXME this matches filesnames...
                                # TODO normalize uris
                                return f'No common name between {ontology_iri} and {filepath}', 400
                            with self.filefromiri as f:
                                # TODO get actual user from the api key
                                out = f(user, filepath, ontology_iri, new=True)
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

        def ontologies_version(self, user, ont_path, filename, epoch_verstr_ont, filename_terminal, extension):
            if filename != filename_terminal:
                return abort(404)
            else:
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
            PREFIXES, _, _ = self.getGroupCuries(user, epoch_verstr=epoch_verstr_id)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, epoch_verstr_id, prefix_iri_curie):
            return request.path


    class Own(Endpoints):
        def uris(self, user, other_user, uri_path):
            return request.path

        def curies_(self, user, other_user):
            PREFIXES, _, _ = self.getGroupCuries(user)
            otherPREFIXES, _, _ = self.getGroupCuries(other_user)
            return 'TODO\n'
            return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

        def curies(self, user, other_user, prefix_iri_curie):
            return request.path
        def ontologies(self, user, other_user, ont_path, filename, extension):
            return request.path
        def ontologies_version(self, user, other_user, ont_path, filename, epoch_verstr_ont,
                               filename_terminal, extension):
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
        def ontologies(self, user, other_user_diff, ont_path, filename, extension):
            return request.path
        def ontologies_version(self, user, other_user_diff, ont_path, filename,
                               epoch_verstr_ont, filename_terminal, extension):
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
                print('terminal nodes', nodes)
            if 'contributions' in nodes:
                nodes = tuple(nodes[::-2]) + ('contributions_',)
                print('terminal nodes', nodes)

        function = inst.get_func(nodes)
        name = inst.__class__.__name__ + '.' + function.__name__ + ' ' + route
        if nodes[-1] in node_methods:
            methods = node_methods[nodes[-1]]
        else:
            methods = ['GET', 'HEAD']
        app.add_url_rule(route, name, function, methods=methods)

    for k, v in app.view_functions.items():
        print(k, v)

    return app

def server_curies(db=None):
    app = Flask('InterLex curies server')
    @app.route('/<curie>')
    def curie(curie):
        return 
    return app

def test(server='localhost:8505'):
    routes = makeTestRoutes()
    urls = [
        'http://localhost:8505/tgbugs/curies/BIRNLEEX:796?local=true',
        'http://localhost:8505/tgbugs/curies/BIRNLEX:796?local=true',
        'http://localhost:8505/tgbugs/curies/BIRNLEEX:796',
        'http://localhost:8505/tgbugs/curies/BIRNLEX:796',
        ]
    urls = [f'http://{server}{r}' for r in routes] + urls
    print(urls)
    url_blaster(urls, 0)

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
        test()
        return
    if args['post']:
        user = args['<user>']
        if args['curies']:
            #url = f'http://localhost:{port_uri}/{user}/curies/'
            url = f'https://uri.olympiangods.org/{user}/curies/'  # https duh
            #printD(url, args)
            # FIXME /curies redirects to get...
            resp = requests.post(url, json=uPREFIXES)
            printD(resp.text)
        elif args['ontology']:
            j = {'external-iri':'http://purl.obolibrary.org/obo/uberon.owl'}
            ontology_iri = 'http://ontology.neuinfo.org/NIF/ttl/NIF-GrossAnatomy.ttl'
            u = urlparse(ontology_iri)
            j = {'external-iri':ontology_iri}
            url = f'https://uri.olympiangods.org/{user}/ontologies/' + u.path[1:]
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
