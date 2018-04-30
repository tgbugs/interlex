import rdflib

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

