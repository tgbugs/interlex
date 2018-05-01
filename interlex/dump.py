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

