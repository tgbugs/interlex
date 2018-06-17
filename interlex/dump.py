import rdflib

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

        if o is not None:
            o = rdflib.URIRef(o)
        elif o_lit is not None:
            o = rdflib.Literal(o_lit, datatype=datatype, lang=language)
        if o_blank is not None:
            o = rdflib.BNode(si + '_' + str(o_blank))

        return s, rdflib.URIRef(p), o

# FIXME this is a really bad way to do this... it would be much better to be able
# to connect by other means that flasksqlalchemy...

class Queries:
    def __init__(self, session):
        self.session = session

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
        if not PREFIXES:
            PREFIXES = makePrefixes('rdfs', 'owl')

        return PREFIXES

    def getAll(self, qualifier=None):  # TODO qualit
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
        resp = list(self.session.execute(sql)) + list(self.session.execute(sql2))
        return resp

    def getExistingIris(self):
        sql = 'SELECT * FROM existing_iris'
        return self.session.execute(sql)

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
        sql = '''
        WITH graph AS (
            SELECT s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity
            FROM triples as t JOIN existing_iris as e
            ON s = iri OR s = :uri
            WHERE ilx_id = :id
        ), subgraphs AS (
            SELECT sg.s, sg.s_blank, sg.p, sg.o,
                    sg.o_lit, sg.datatype, sg.language,
                    sg.o_blank, sg.subgraph_identity
            FROM triples as sg, graph as g
            WHERE sg.subgraph_identity = g.subgraph_identity AND sg.s is NULL
        )
        SELECT * FROM graph UNION SELECT * from subgraphs;
        '''
        resp = list(self.session.execute(sql, args))
        return resp
