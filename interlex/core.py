#!/usr/bin/env python3.7

import sys
import socket
from pathlib import Path, PurePath
from tempfile import gettempdir
from functools import partialmethod
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
from ttlser import DeterministicTurtleSerializer, CustomTurtleSerializer
from pyontutils.core import makeGraph, OntId, OntGraph
from pyontutils.utils import TermColors as tc, injective_dict
from pyontutils.namespaces import PREFIXES as uPREFIXES
from pyontutils.namespaces import ilxtr, rdf, rdfs, owl, oboInOwl, NIFRID
from pyontutils.combinators import annotation
from pyontutils.identity_bnode import IdentityBNode, IdLocalBNode
from interlex import config
from interlex.utils import printD, log
from interlex.config import auth
from interlex.namespaces import fma

synonym_types = {'abbrev':ilxtr['synonyms/abbreviation'],
                 'oboInOwl:hasBroadSynonym': ilxtr['synonyms/broad'],  # FIXME just use oboInOwl?
                 'oboInOwl:hasExactSynonym': ilxtr['synonyms/exact'],
                 'oboInOwl:hasNarrowSynonym': ilxtr['synonyms/narrow'],
                 'oboInOwl:hasRelatedSynonym': ilxtr['synonyms/related'],
                 'fma:synonym': fma.synonym,  # perserved for prov
                 'NIFRID:synonym': NIFRID.synonym,
}
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


def dbUri(dbuser=config.user, host='localhost', port=5432, database=config.database):
    if hasattr(sys, 'pypy_version_info'):
        dialect = 'psycopg2cffi'
    else:
        dialect = 'psycopg2'
    return f'postgresql+{dialect}://{dbuser}@{host}:{port}/{database}'
    # engine = create_engine
    # return engine, inspect(engine)

def mqUri():
    return config.broker_url

def getScopedSession(dburi=dbUri()):
    engine = create_engine(dburi)
    session_factory = sessionmaker(bind=engine)
    ScopedSession = scoped_session(session_factory)
    return ScopedSession


class getName:
    class MyBool:
        """ python is dumb """

    def __init__(self):
        self.counter = -1
        self.value_to_name = {}

    def valueCheck(self, value):
        if isinstance(value, dict):
            value = hash(frozenset((k, self.valueCheck(v)
                                    if isinstance(v, list) or isinstance(v, dict)
                                    else v)
                                    for k, v in value.items()))
        elif isinstance(value, list):
            value = tuple(self.valueCheck(e) for e in value)
        elif isinstance(value, bool):
            value = self.MyBool, value
        else:
            pass

        return value

    def __call__(self, value):
        value = self.valueCheck(value)
        if value in self.value_to_name:
            return self.value_to_name[value]
        else:
            self.counter += 1
            name = 'v' + str(self.counter)

            self.value_to_name[value] = name

            return name


def makeParamsValues(*value_sets, constants=tuple(), types=tuple()):
    # TODO variable sized records and
    # common value names
    if constants and not all(':' in c for c in constants):
        raise ValueError(f'All constants must pass variables in via params {constants}')

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
        group = 'tgbugs'
        # TODO process for staging changes for review and comparison to see
        #  where triples are already present so that they can be removed
        # TODO core_uris, core_lits for lifted interlex representation
        src_qual = next(session.execute(('SELECT id FROM qualifiers WHERE group_id = idFromGroupname(:group) '
                                         'AND source_qualifier_id = 0'), dict(group=group))).id

        sql, params = make_load_triples(graph, src_qual)

        # TODO return comparison using temp tables prior to full merge
        return 'ok\n'

    @app.route('/triples/bulk', methods=['POST'])
    def triples_bulk():
        #file = auth.get_path('git-local-base') / auth.get('ontology-repo') / 'ttl/nif.ttl'
        graph = OntGraph()

        #file = auth.get_path('git-local-base') / auth.get('ontology-repo') / 'ttl/NIF-GrossAnatomy.ttl'
        #file = auth.get_path('git-local-base') / auth.get('ontology-repo') / 'ttl/bridge/anatomy-bridge.ttl'
        #graph.parse(file.as_posix(), format='ttl')
        #graph.parse('http://purl.obolibrary.org/obo/uberon.owl')
        file = auth.get_path('git-local-base') / auth.get('ontology-repo') / 'ttl/external/uberon.owl'
        group = 'uberon'
        graph.parse(file.as_posix())

        # FIXME getIdFromGroupname ... sigh naming
        src_qual = next(session.execute(('SELECT id FROM qualifiers WHERE group_id = idFromGroupname(:group) '
                                         'AND source_qualifier_id = 0'), dict(group=group))).id
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

        #breakpoint()
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


def make_paths(parent_child, parent='<group>', options=tuple(), limit=9999, depth=0, path_names=tuple()):
    """ path_names is actually a dict, but hey mutable defaults """

    def inner(child, parent, idepth):
        for path in make_paths(parent_child, child, options=options, limit=limit, depth=idepth,
                               path_names=path_names):
            #printD('PATH:', path)
            if parent in options:
                for option in options[parent][:limit]:
                    if parent == '<group>':
                        prefix = '', option
                    else:
                        prefix = option,

                    yield prefix + path

            elif parent == '<group>':
                yield ('', parent) + path
            else:
                yield (parent,) + path


    if parent in parent_child:
        for child in parent_child[parent]:
            #printD('CHILD:', child)
            if child in options:
                todo = options[child][:limit]
                if child in parent_child:  # only branches need to go again
                    todo += child,
                for option in todo:
                    yield from inner(option, parent, depth + 1)
            else:
                yield from inner(child, parent, depth + 1)
    else:
        if parent in options:
            for option in options[parent][:limit]:
                path += option,
                yield path
        elif parent is None:  # branches that are also terminals
            yield '',
        elif parent == depth:
            # branchers that are also terminals at a given depth
            # where the depth should be considered as the zero indexed
            # depth of the empty string following the slash
            yield '',
        elif isinstance(parent, int):
            pass  # skip other depths
        else:
            yield parent,


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
