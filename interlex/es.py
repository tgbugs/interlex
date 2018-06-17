import json
import rdflib
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from interlex.uri import dbUri
from interlex.dump import TripleExporter
from pyontutils.core import makeGraph, OntId, qname, PREFIXES as uPREFIXES  # FIXME get base prefixes...
from pyontutils.core import NIFRID, rdf, rdfs, skos, definition, ilxtr, oboInOwl
from dump import Queries
from IPython import embed

if True:
    from desc.prof import profile_me
else:
    profile_me = lambda f:f

connSpec = [{'host':'localhost', 'port':9200}]
es = Elasticsearch(connSpec)

es.index(index='test_index', doc_type='rdf:type record', id=1, body={
    'iri':'http://uri.interlex.org/tgbugs/readable/test',
    'curie':'ilxtr:test',
    'label':'test',
    'synonyms':['yet another test'],
    'definition':'this term is used for testing things',
})

with open('es-settings.json', 'rt') as f:
    # other options
    # "catenate_words": true
    # TODO consider using not_analyzed for curies
    index_settings = json.load(f)

#embed()
es.indices.close('test_index')
es.indices.put_settings(index_settings, 'test_index')
es.indices.open('test_index')

def get(id):
    return es.get(index='test_index', doc_type='rdf:type record', id=id)

def esAdd(**record):
    id = record['user_iri']
    return es.index(index='test_index', doc_type='rdf:type record', id=id, body=record)

def trynext(gen):
    try:
        return next(gen)
    except StopIteration:
        pass

def makeRecord(graph, user, id=None):
    iris = sorted(set(s for s in graph.subjects() if
                      isinstance(s, rdflib.URIRef)))
    user_iri = next(_ for _ in iris if 'uri.interlex.org/base' in _).replace('/base/', f'/{user}/')
    record = dict(iri = iris,
                  curie = sorted(OntId(i).curie for i in iris),
                  user_iri = user_iri,
                  synonyms = [o for _, o in graph[:NIFRID.synonym]],
                  label = trynext(o for _, o in graph[:rdfs.label]),  # FIXME > 1 issue as always
                  note = trynext(o for _, o in graph[:skos.editorialNote]),
                  definition = trynext(o for _, o in graph[:definition]),
                  comment = trynext(o for _, o in graph[:rdfs.comment]),)
    return record

def makeRecords(graph, user=None):  # as usual this is stupidly faster in pypy3
    for iri in set(graph.subjects()):
        if user is not None:
            user_iri = iri.replace('/base/', f'/{user}/')
        else:
            user_iri = iri
        record = dict(iri=iri,
                      curie=qname(iri),
                      user_iri=user_iri,
                      existing_iris=[],
                      existing_curies=[],
                      alts=[],
                      xrefs=[],
                      types=[],
                      all_labels=set(),
                      synonyms=set(),
                      abbreviations=set(),
                      all_definitions=set(),
                      predicate_objects=[],
                      subClassOf=[],  # TODO transitive closure
        )
        for p, o in graph[iri]:
            if isinstance(o, rdflib.BNode):
                continue
            o = str(o)  # es chockes on dates I think
            if p == ilxtr.hasExistingIri:
                record['existing_iris'].append(o)
                qn = qname(o)
                if qn != o:
                    record['existing_curies'].append(qn)
            elif p == oboInOwl.hasAlternativeId:
                # FIXME these are existing ids that should be resolved but not issued
                record['alts'].append(o)
            elif p == oboInOwl.hasDbXref:
                # TODO these are a mix of ontology and non-ontology identifiers
                # when coming from obo the ontology ids should be lifted to existing
                # as part of the standard interlex transform/lifing process
                record['xrefs'].append(o)
            elif p == rdf.type:
                record['types'].append(o)
            elif p in (rdfs.label, skos.prefLabel, skos.altLabel):  # TODO alts
                if 'label' not in record:  # FIXME first one should be from qualified latest base
                    record['label'] = o
                record['all_labels'].add(o)
            elif p in (NIFRID.synonym, oboInOwl.hasExactSynonym,
                       oboInOwl.hasRelatedSynonym, oboInOwl.hasNarrowSynonym):
                # FIXME has related synonym pulls in misnomers... sigh
                # FIXME synonym types... for raking...
                record['synonyms'].add(o)
            elif p in (NIFRID.abbrev, NIFRID.acronym):
                record['abbreviations'].add(o)  # TODO get this from annotations on synonyms...
            elif p in (definition, skos.definition):
                if 'definition' not in record:
                    record['definition'] = o
                record['all_definitions'].add(o)
            elif p == skos.editorialNote:  # TODO alts
                record['note'] = o
            elif p == rdfs.comment:
                record['comment'] = o
            elif p == rdfs.subClassOf:
                record['subClassOf'].append(o)
            elif 'Date' in p:
                continue  # FIXME need to debug why es treats string dates as date type instead of string...
            else:
                record['predicate_objects'].append({'predicate':p.toPython(), 'object':o})

        yield {k:sorted(v) if isinstance(v, set) else v
               for k, v in record.items()}

def simple_query(string):
    return {'query':{'multi_match':{'query':string,
                                    #'type':'best_fields',
                                    'type':'phrase',
                                    'fields':['label^4',
                                              #'synonyms.literal^4',
                                              'synonyms^2',
                                              'definition^1.2',
                                              'predicate_objects.object'
                                              'existing_curies', 'existing_iris',
                                              'curie^1.2', 'iri',
                                    ],
                                    'tie_breaker':.3,}}}

def ident_query(string):
    return {'query':{'multi_match':{'query':string,
                                    #'type':'best_fields',
                                    'type':'phrase',
                                    'fields':['existing_curies', 'existing_iris',
                                              'curie^3', 'iri^2',
                                              'label^4', 'synonyms', 'definition'],
                                    'tie_breaker':.3,}}}

def search(string, prefixes=uPREFIXES, debug=False):
    def dq(res):
        if debug:
            return res
        else:
            return res['hits']['hits']

    if ':' in string:
        prefix, suffix = string.split(':')
        if prefix in prefixes:
            q = ident_query(string)
            if debug: print(q)
            return dq(es.search(index='test_index', body=q))

    q = simple_query(string)
    if debug: print(q)
    return dq(es.search(index='test_index', body=q))

def getAll():
    #TransportError: TransportError(500, 'search_phase_execution_exception', 'Result window is too large, from + size must be less than or equal to: [10000] but was [100000]. See the scroll api for a more efficient way to request large data sets. This limit can be set by changing the [index.max_result_window] index level setting.')
    return es.search(index='test_index', body={
        'size':10000,
        'from':0,
        'query':{'match_all':{}}})

def getDb(dburi):
    app = Flask('fake server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)
    return db

def convert_for_bulk(records, index_name, doc_type_name):
    for record in records:
        yield {'_index': index_name,
               '_type': doc_type_name,
               '_id': record['user_iri'],
               '_source': record}

class Thing:
    def __init__(self, queries, es):
        self.queries = queries
        self.es = es

    def allGraph(self, user='base', unmapped=False):
        # TODO qualifier etc
        prefixes = self.queries.getGroupCuries(user)
        uri_base = 'http://uri.interlex.org/base/ilx_{}'
        resp = [[uri_base.format(id) if 'http' not in id else id] + rest
                for id, *rest in self.queries.getAll(unmapped=unmapped)]
        # FIXME getAll needs to use qualifiers, the current implementation has nasty issues with
        # conflating subjects in ways that are inappropriate and often extremely confusing
        existing = [(uri_base.format(id), iri, group_id)
                    for id, iri, group_id in self.queries.getExistingIris()]
        # TODO merge with existing ids
        @profile_me
        def graphFromResp(resp, existing):
            g = makeGraph('temp', prefixes=prefixes)
            te = TripleExporter()
            # this whole thing is going to fit in memory basically forever
            # so just get everything all at once
            _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting
            _ = [g.g.add((rdflib.URIRef(id), ilxtr.hasExistingIri, rdflib.URIRef(iri)))
                for id, iri, _ in existing]

            return g

        g = graphFromResp(resp, existing)
        self.g = g
        return g

    @profile_me
    def reindex(self, index='test_index'):
        records = makeRecords(self.g.g)
        print('records done')
        #es.indices.delete('test_index')
        success, maybefail = bulk(self.es, convert_for_bulk(records, index, 'rdf:type record'))
        print(success)

    def tests(self):
        assert search('brain')[0]['_source']['curie'] == 'ILX:0101431'
        assert search('Alzheimer')[0]['_source']['curie'] in ('DOID:10652', 'ILX:0100524')
        assert search('Alzheimers')[0]['_source']['curie'] in ('DOID:10652', 'ILX:0100524')
        assert search('Alzheimer\'s')[0]['_source']['curie'] in ('DOID:10652', 'ILX:0100524')
        search('hippocampus')[0]  # a complete CF
        assert search('hippocampal formation')[0]['_source']['curie'] == 'ILX:0105009'

        # roundtrips
        # TODO pick 100 curies at random
        # [qname(s) for s in pick100(g.g.subjects())]
        for curie in curies:
            assert search(curie)[0]['_source']['curie'] == curie


def _main():
    user = 'tgbugs'
    def byId(id, user):
        resp = q.getById(id, user)
        g = makeGraph('temp', prefixes=PREFIXES)
        te = TripleExporter()
        _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting
        record = makeRecord(g.g, user)
        return record

    def addById(id, user):
        record = byId(id, user)
        return esAdd(**record)

    #asdf = search('test')
    #print(asdf)
    #out = byId('0100100', user)
    #print(out)
    #success = [addById(f'{i:0>7}', user)  # FIXME super slow, should batch...
    #for i in range(100100, 100500)]
    # single shot?
    record = [byId(f'{i:0>7}', user)  # FIXME super slow to get the bnodes :/
              for i in range(100100, 100101)]

    derp = search('UBERON:0000955')  # FIXME now this is broken, can't even hit the exact match >_<
    #print(derp[:3])

def main():
    db = getDb(dbUri())
    q = Queries(db.session)
    stats = es.indices.stats()

    user = 'tgbugs'
    PREFIXES = q.getGroupCuries(user)

    thing = Thing(q, es)
    list = profile_me(list)
    g = thing.allGraph()
    recs = list(makeRecords(g.g))
    ga = thing.allGraph(unmapped=True)  # -> about 15 seconds in pypy3 after fetch for 1mil trips
    recsa = list(makeRecords(ga.g))  # -> aboug 30 seconds in pypy3 for 1mil trips

    # delete index
    #es.indices.delete('test_index')
    # reindex
    #g = thing.reindex()

    embed()

if __name__ == '__main__':
    main()
