import rdflib
from pyontutils.core import rdf, rdfs, owl, ilxtr, definition, NIFRID

class MysqlExport:
    def __init__(self, session):
        self.session = session

    def __call__(self, id):
        ilx_fragment = 'ilx_' + id
        baseiri = rdflib.URIRef('http://uri.interlex.org/base/' + ilx_fragment)

        #args = dict(ilx=request.url.rsplit('/', 1)[-1])
        args1 = dict(ilx = ilx_fragment)
        sql1 = 'select * from terms where ilx = :ilx'

        rp = self.session.execute(sql1, dict(ilx = ilx_fragment))
        term = next(rp)
        try:
            next(rp)
            raise ValueError(f'too many results for {ilx_fragment}')
        except StopIteration:
            pass

        id = term.id

        sql2 = 'select preferred, iri from term_existing_ids te where tid = :id'
        args2 = dict(id=id)
        pref_iris = self.session.execute(sql2, args2)
        existing = []
        for maybe_pref, iri in pref_iris:
            print(maybe_pref, iri)
            if maybe_pref == '1':  # lol mysql
                preferred = rdflib.URIRef(iri)
            if iri == baseiri:
                continue
            else:
                existing.append(rdflib.URIRef(iri))

        yield preferred, rdfs.label, rdflib.Literal(term.label)
        if term.definition:
            yield preferred, definition, rdflib.Literal(term.definition)

        for oo in existing:
            if oo != preferred:
                yield preferred, ilxtr.hasExistingId, oo

        if preferred != baseiri:
            yield preferred, ilxtr.hasIlxId, baseiri

        sql3 = f'''
        select {str(NIFRID.synonym)!r}, literal from term_synonyms where literal != '' and tid = :id
        union
        select te.iri, value from term_annotations as ta
            join term_existing_ids as te
            on ta.annotation_tid = te.tid
            where ta.tid = :id and te.preferred = '1'
        union
        select te1.iri, te2.iri from term_relationships as tr
            join term_existing_ids as te1
            on te1.tid = tr.relationship_tid
            join term_existing_ids as te2
            on te2.tid = tr.term2_id
            where tr.term1_id = :id and te1.preferred = '1' and te2.preferred = '1'
        union
        select {str(rdfs.subClassOf)!r}, te.iri from term_superclasses as tsc
            join term_existing_ids as te
            on te.tid = tsc.superclass_tid
            where tsc.tid = :id and te.preferred = '1'
        '''

        predicate_objects = self.session.execute(sql3, args2)
        for p, o in predicate_objects:
            print(p, o)
            if o.startswith('http'):  # and this is why we need types in the database :/
                oo = rdflib.URIRef(o)
            else:
                oo = rdflib.Literal(o)
            
            yield preferred, rdflib.URIRef(p), oo


class TripleExporter:
    #def __init__(self, triples, subgraphs):  # TODO
    def __init__(self):
        self._subgraph_counter = -1
        self.subgraph_identities = {}

    @property
    def subgraph_counter(self):
        self._subgraph_counter += 1
        return self._subgraph_counter

    def triple(self, s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity):
        if subgraph_identity is not None:
            if subgraph_identity not in self.subgraph_identities:
                self.subgraph_identities[subgraph_identity] = self.subgraph_counter

            si = 'sg_' + str(self.subgraph_identities[subgraph_identity])

        if s is not None:
            s = rdflib.URIRef(s)
        if s_blank is not None:
            s = rdflib.BNode(si + '_' + str(s_blank))

        if o is not None: o = rdflib.URIRef(o)
        elif o_lit is not None:
            o = rdflib.Literal(o_lit, datatype=datatype, lang=language)
        if o_blank is not None:
            o = rdflib.BNode(si + '_' + str(o_blank))

        return s, rdflib.URIRef(p), o

# FIXME this is a really bad way to do this... it would be much better to be able
# to connect by other means that flasksqlalchemy...

class Queries:
    class Sql:
        pass
    sql = Sql()

    def __init__(self, session, endpoints):
        self.endpoints = endpoints
        self.session = session

    @property
    def reference_host(self):
        return self.endpoints.reference_host

    def getBuiltinGroups(self):
        return list(self.session.execute("SELECT * FROM groups WHERE own_role = 'builtin'"))

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
        PREFIXES = {cp:ip for cp, ip in resp}
        if not PREFIXES:  # we get the base elsewhere
            PREFIXES = {'rdf':str(rdflib.RDF),
                        'rdfs':str(rdflib.RDFS),
                        'owl':str(rdflib.OWL)}

        return PREFIXES

    def getAll(self, qualifier=None, unmapped=False):  # TODO qualit
        # NOTE no blanknodes, but this is for indexing, so it is ok
        sql = ('SELECT e.ilx_id, '
               't.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity '
               'FROM existing_iris as e '
               'JOIN triples as t '
               'ON t.s = e.iri')
        # wow it seems way faster not to use UNION here
        sql2 = ('SELECT s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity '
                'FROM triples AS t '
                # iri should be distinct...
                'WHERE t.s IS NOT NULL AND t.s NOT IN (SELECT iri FROM existing_iris)')
        resp = list(self.session.execute(sql))
        if unmapped:
            resp += list(self.session.execute(sql2))
        return resp

    def getExistingIris(self):
        sql = 'SELECT * FROM existing_iris'
        return self.session.execute(sql)

    def getExistingFromIri(self, *iris):
        args = dict(iris=iris)
        sql = ('SELECT s, iri FROM triples JOIN existing_iris '
               'ON s = iri WHERE s IN :iris')
        resp = list(self.session.execute(sql, args))
        return resp

    def getExistingIrisForIlxId(self, *iris):
        args = dict(iris=list(iris))
        sql = ('SELECT i, iri FROM unnest(ARRAY[:iris]) WITH ORDINALITY i '
               'JOIN existing_iris ON i = ilx_id')
        resp = list(self.session.execute(sql, args))
        return resp

    def getById(self, id, user):
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
        # FIXME wow is this slow for multiple queries...
        _sql = ('SELECT t.s, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank '
                'FROM existing_iris as e '
                'JOIN triples as t '
                #'JOIN triples as tb'  # TODO efficient subgraph retrieval?
                #'JOIN triples as tb2 '
                'ON t.s = e.iri '
                'OR t.s = :uri '
                #'OR t.o_blank = t.id '
                #'AND tb1 = tb2)'
                'WHERE e.ilx_id = :id')
        # TODO user's view...

        # remember kids! don't use left join!
        sql = '''
        WITH graph AS (
            SELECT s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity
            FROM triples as t JOIN existing_iris as e
            ON s = iri
            WHERE ilx_id = :id
            UNION
            SELECT s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity
            FROM triples
            WHERE s = :uri
        ), subgraphs AS (
            SELECT sg.s, sg.s_blank, sg.p, sg.o,
                    sg.o_lit, sg.datatype, sg.language,
                    sg.o_blank, sg.subgraph_identity
            FROM triples as sg, graph as g
            WHERE sg.subgraph_identity = g.subgraph_identity AND sg.s is NULL
        )
        SELECT * FROM graph UNION SELECT * from subgraphs;
        '''

        # forget it, do it as two queries for now
        sql2 = f'''
        SELECT *
            FROM ({sql}) as sq
            LEFT JOIN existing_iris
            ON ilx_id = ilxIdFromIri(sq.o)
            WHERE uri_host(sq.o) = reference_host();  -- OR TRUE; -- works but super slow
        '''

        sql3 = f'''
        WITH woo AS ({sql})
        SELECT * FROM woo JOIN ...
        '''


        if not hasattr(self.sql, 'getById'):
            self.sql.getById = sql

        resp = list(self.session.execute(self.sql.getById, args))
        return resp

    def getResponseExisting(self, resp, type='o'):
        rh = self.reference_host
        # TODO filter by user?
        def gt(e):
            return getattr(e, type)

        id_existing_iris = self.getExistingIrisForIlxId(*set(gt(r).rsplit('/', 1)[-1][4:]
                                                        for r in resp
                                                        if gt(r) and rh in gt(r)))
        base_to_existing = [(f'http://uri.interlex.org/base/ilx_{id}', iri)
                              # FIXME centralize the iri <-> id functions
                              for id, iri in id_existing_iris]

        return base_to_existing
