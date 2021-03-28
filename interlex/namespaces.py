from rdflib import Namespace
from pyontutils import namespaces as ns

ilxr, fma = ns.makeNamespaces('ilxr', 'fma')
ilxrtype = Namespace(ns.interlex_namespace('base/readable/type/'))
