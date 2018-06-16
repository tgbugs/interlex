import rdflib
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from interlex.uri import dbUri
from interlex.dump import TripleExporter
from pyontutils.core import makeGraph, OntId, qname
from pyontutils.core import NIFRID, rdf, rdfs, skos, definition, ilxtr
from dump import Queries
from IPython import embed

connSpec = [{'host':'localhost', 'port':9200}]
es = Elasticsearch(connSpec)

es.index(index='test_index', doc_type='rdf:type record', id=1, body={
    'iri':'http://uri.interlex.org/tgbugs/readable/test',
    'curie':'ilxtr:test',
    'label':'test',
    'synonyms':['yet another test'],
    'definition':'this term is used for testing things',
})

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

def makeRecords(graph, user):
    for iri in set(graph.subjects()):
        user_iri = iri.replace('/base/', f'/{user}/')
        record = dict(iri = iri,
                      curie = OntId(iri).curie,
                      user_iri = user_iri,  # FIXME TODO retrieve info on whether they have any differences
                      existing_iris = list(graph[iri:ilxtr.hasExistingId]),
                      existing_curies = [qname(o) for o in graph[iri:ilxtr.hasExistingId] if o != qname(o)],
                      # FIXME OntId.curie breaks on some of our iris here...
                      types = list(graph[iri:rdf.type]),
                      label = trynext(graph[iri:rdfs.label]),  # FIXME > 1 issue as always
                      synonyms = list(graph[iri:NIFRID.synonym]),
                      definition = trynext(graph[iri:definition]),
                      note = trynext(graph[iri:skos.editorialNote]),
                      comment = trynext(graph[iri:rdfs.comment]),)
        yield record

def simple_query(string):
    return {'query':{'multi_match':{'query':string,
                                    'type':'best_fields',
                                    'fields':['existing_curies', 'existing_iris',
                                              'curie', 'iri',
                                              'label', 'synonyms', 'definition'],
                                    'tie_breaker':.3,}}}

def search(string):
    return es.search(index='test_index', body=simple_query(string))['hits']['hits']

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

def main():
    db = getDb(dbUri())
    q = Queries(db.session)

    user = 'tgbugs'
    PREFIXES = q.getGroupCuries(user)

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

    asdf = search('test')
    print(asdf)
    out = byId('0100100', user)
    print(out)
    #success = [addById(f'{i:0>7}', user)  # FIXME super slow, should batch...
    #for i in range(100100, 100500)]

    record = [byId(f'{i:0>7}', user)  # FIXME super slow to get the bnodes :/
              for i in range(100100, 100101)]

    uri_base = 'http://uri.interlex.org/base/ilx_{}'
    resp = [[uri_base.format(id)] + rest for id, *rest in q.getAll()]
    existing = [(uri_base.format(id), iri, group_id) for id, iri, group_id in q.getExistingIris()]
    # TODO merge with existing ids
    def graphFromResp(resp, existing):
        g = makeGraph('temp', prefixes=PREFIXES)
        te = TripleExporter()
        _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting
        _ = [g.g.add((rdflib.URIRef(id), ilxtr.hasExistingId, rdflib.URIRef(iri)))
             for id, iri, _ in existing]

        return g

    g = graphFromResp(resp, existing)
    records = makeRecords(g.g, user)

    print('records done')
    #es.indices.delete('test_index')
    success, maybefail = bulk(es, convert_for_bulk(records, 'test_index', 'rdf:type record'))
    print(success)
    stats = es.indices.stats()
    derp = search('UBERON:0000955')  # FIXME now this is broken, can't even hit the exact match >_<
    print(derp[:3])

    embed()

if __name__ == '__main__':
    main()
