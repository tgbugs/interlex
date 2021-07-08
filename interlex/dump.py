import rdflib
from pyontutils import sneechenator as snch
from pyontutils.core import OntId
from pyontutils.utils import TermColors as tc
from pyontutils.utils_extra import check_value
from pyontutils.namespaces import NIFRID, ilxtr, definition
from pyontutils.namespaces import rdf, rdfs, owl, skos
from pyontutils.combinators import annotation
from interlex import exceptions as exc
from interlex.core import log, makeParamsValues, synonym_types
from interlex.namespaces import ilxr, ilxrtype


class MysqlExport:
    types = {'term': owl.Class,
             'annotation': owl.AnnotationProperty,
             'relationship': owl.ObjectProperty,
             'cde': owl.Class,
             'fde': owl.Class,
             'pde': owl.Class,  # FIXME or is it a named individual?
             'TermSet': ilxr.TermSet,  # FIXME vs owl:Ontology view
             }

    _group_community = {
        'sparc': 'SPARC Anatomical Working Group',
    }
    _group_include_full_objects = {
        'sparc': (OntId('ILX:0738400').u,  # ilx.includeForSPARC
                  OntId('ilx.includeForSPARC:').u,
        ),
    }
    def __init__(self, session):
        self.session = session

    def getGroupCuries(self, group, epoch_verstr=None):
        # NOTE no support for group in the mysql version, but match the api
        sql = 'SELECT prefix, namespace FROM term_curie_catalog'
        args = dict()
        resp = self.session.execute(sql, args)
        return {prefix:namespace for prefix, namespace in resp}

    def group_terms(self, group):
        name = self._group_community[group]

        sql = ('SELECT * from terms WHERE '
               'status != -2 AND '
               'orig_cid = (SELECT id FROM communities WHERE name = :name) '
               'UNION '
               'SELECT * from terms WHERE '
               'status != -2 AND '
               'terms.id IN (SELECT * FROM (SELECT tc.tid FROM term_communities AS tc '
               'JOIN communities AS c ON '
               'tc.cid = c.id WHERE c.name = :name AND tc.status = "approved") AS subquery)')

        args = dict(name=name)
        yield from self.session.execute(sql, args)

    def existing_ids(self, id):
        sql = 'SELECT preferred, iri FROM term_existing_ids WHERE tid = :id'
        args = dict(id=id)
        yield from self.session.execute(sql, args)

    def existing_ids_triples(self, ids):
        if not ids:
            return

        sql = ('SELECT te_s.iri, te.preferred, te.iri FROM term_existing_ids as te'
               '  JOIN term_existing_ids as te_s '
               '    ON te.tid = te_s.tid '
               ' WHERE te.tid in :ids'
               "   AND te_s.curie like 'ILX:%'")
        args = dict(ids=tuple(ids))
        yield from self.session.execute(sql, args)

    def existing_in_namespace(self, namespace):
        """ for now only check a single namespace at a time """
        sql = ('SELECT te.iri, te_o.iri FROM term_existing_ids as te'
               '  JOIN term_existing_ids as te_o '
               '    ON te.tid = te_o.tid '
               " WHERE te.iri LIKE CONCAT(:namespace, '%')"
               "   AND te_o.curie like 'ILX:%'")
        args = dict(namespace=namespace)
        yield from self.session.execute(sql, args)

    def index_triples(self, namespace):
        for s, o in self.existing_in_namespace(namespace):
            yield rdflib.URIRef(s), ilxtr.hasIlxId, rdflib.URIRef(o)

    def existing_mapped(self, iris, namespace=None):
        sql = ('SELECT te.iri, te_o.iri FROM term_existing_ids as te'
                '  JOIN term_existing_ids as te_o '
                '    ON te.tid = te_o.tid '
                ' WHERE te.iri in :iris'
                "   AND te_o.curie LIKE 'ILX:%'")
        args = dict(iris=tuple(iris))
        if namespace is not None:
            sql += " AND te.iri LIKE CONCAT(:namespace, '%')"
            args['namespace'] = namespace

        # the user has to tell us namespace anyway so make use of it
        # yes we could implement a generic iri mapping facility
        # but to be efficient it probably makes more sense to create
        # an temporary index of the set of iris to map or something
        yield from self.session.execute(sql, args)

    def alreadyMapped(self, iris, namespace=None):
        for s, o in self.existing_mapped(iris, namespace):
            yield rdflib.URIRef(s), ilxtr.hasIlxId, rdflib.URIRef(o)

    def term(self, ilx_fragment):
        #args = dict(ilx=request.url.rsplit('/', 1)[-1])
        args = dict(ilx=ilx_fragment)
        sql = 'SELECT * FROM terms WHERE ilx = :ilx'

        rp = self.session.execute(sql, args)
        term = next(rp)
        try:
            next(rp)
            raise exc.ShouldNotHappenError(f'too many results for {ilx_fragment}')
        except StopIteration:
            pass

        return term

    def terms(self, ilx_fragments):
        args = dict(fragments=ilx_fragments)
        sql = 'SELECT * FROM terms where ilx in :fragments'
        yield from self.session.execute(sql, args)

    def id_triples(self, ids):
        if not ids:
            return

        args = dict(ids=tuple(ids))
        # FIXME urg the ILX:%
        sql = f'''
        SELECT te.iri, ts.type, ts.literal FROM term_synonyms as ts
          JOIN term_existing_ids AS te
            ON te.tid = ts.tid
         WHERE ts.tid in :ids
           AND ts.literal != ''
           AND te.curie like 'ILX:%'
        UNION
        SELECT te1.iri, te2.iri, value FROM term_annotations AS ta
          JOIN term_existing_ids AS te1
            ON ta.tid = te1.tid
          JOIN term_existing_ids AS te2
            ON ta.annotation_tid = te2.tid
         WHERE ta.tid in :ids
           AND te1.curie like 'ILX:%'
           AND te2.curie like 'ILX:%'
        UNION
        SELECT te.iri, te1.iri, te2.iri FROM term_relationships AS tr
          JOIN term_existing_ids AS te
            ON te.tid = tr.term1_id
          JOIN term_existing_ids AS te1
            ON te1.tid = tr.relationship_tid
          JOIN term_existing_ids AS te2
            ON te2.tid = tr.term2_id
         WHERE tr.term1_id in :ids
           AND tr.withdrawn != '1'
           AND te.curie like 'ILX:%'
           AND te1.curie like 'ILX:%'
           AND te2.curie like 'ILX:%'
        UNION
        SELECT te1.iri, {str(ilxtr.subThingOf)!r}, te2.iri FROM term_superclasses AS tsc
          JOIN term_existing_ids AS te1
            ON te1.tid = tsc.tid
          JOIN term_existing_ids AS te2
            ON te2.tid = tsc.superclass_tid
         WHERE tsc.tid in :ids
           AND te1.curie like 'ILX:%'
           AND te2.curie like 'ILX:%'
        '''

        yield from self.session.execute(sql, args)

    def predicate_objects(self, id):
        args = dict(id=id)
        # FIXME urg the ILX:%
        sql = f'''
        SELECT type, literal FROM term_synonyms
         WHERE literal != ''
           AND tid = :id
        UNION
        SELECT te.iri, value FROM term_annotations AS ta
          JOIN term_existing_ids AS te
            ON ta.annotation_tid = te.tid
         WHERE ta.tid = :id
           AND te.curie like 'ILX:%'
           -- AND te.preferred = '1'
        UNION
        SELECT te1.iri, te2.iri FROM term_relationships AS tr
          JOIN term_existing_ids AS te1
            ON te1.tid = tr.relationship_tid
          JOIN term_existing_ids AS te2
            ON te2.tid = tr.term2_id
         WHERE tr.term1_id = :id
           AND tr.withdrawn != '1'
           AND te1.curie like 'ILX:%'
           -- AND te1.preferred = '1'
           AND te2.curie like 'ILX:%'
           -- AND te2.preferred = '1'
        UNION
        SELECT {str(ilxtr.subThingOf)!r}, te.iri FROM term_superclasses AS tsc
          JOIN term_existing_ids AS te
            ON te.tid = tsc.superclass_tid
         WHERE tsc.tid = :id
           AND te.curie like 'ILX:%'
           -- AND te.preferred = '1'
        '''

        yield from self.session.execute(sql, args)

    def __call__(self, ilx_id):
        ilx_fragment = 'ilx_' + ilx_id
        return self._call_fragment(ilx_fragment)

    def _call_fragment(self, ilx_fragment):
        term = self.term(ilx_fragment)  # FIXME handle value error or no?
        return self._terms_triples((term,))

    def _call_fragments(self, ilx_fragments):
        yield from self._terms_triples(self.terms(ilx_fragments))

    def _call_group(self, group):
        # FIXME horrible implementation
        include_full_object_predicates = self._group_include_full_objects[group]
        yield from self._terms_triples(self.group_terms(group),
                                       include_full_object_predicates=include_full_object_predicates)

    def _terms_triples(self, terms, include_full_object_predicates=tuple(), done=tuple()):
        def basics(term):
            id = term.id
            ilx_fragment = term.ilx
            baseiri = rdflib.URIRef('http://uri.interlex.org/base/' + ilx_fragment)
            done.add(baseiri)
            type = self.types[term.type]
            ilxtype = ilxrtype[term.type]
            preferred_iri = baseiri
            return id, baseiri, preferred_iri, type, ilxtype, ilx_fragment

        done = set() if not done else done
        predobjs = set()
        ids = set()
        #prids = {}
        for term in terms:
            id, baseiri, preferred_iri, type, ilxtype, ilx_fragment = basics(term)
            ids.add(id)
            done.add(baseiri)
            preferred_iri = baseiri  # XXX dealt with by render prefs instead i.e. TripleRender.default_prefix_ranking
            yield preferred_iri, rdf.type, type
            yield preferred_iri, ilxr.type, ilxtype
            yield preferred_iri, rdfs.label, rdflib.Literal(term.label)
            if term.definition:
                yield preferred_iri, definition, rdflib.Literal(term.definition)

            # TODO hasIlxId sco hasRefId, hasMutualId for non ref ids
            yield preferred_iri, ilxtr.hasIlxId, baseiri

            #prids[preferred_iri] = ilx_fragment

        for ilx_iri, pref, o in self.existing_ids_triples(ids):
            ilx_iri = rdflib.URIRef(ilx_iri)
            o = rdflib.URIRef(o.rstrip())  # FIXME ARGH rstrip
            predobjs.add(o)

            yield ilx_iri, ilxtr.hasExistingId, o

            if ilx_iri == o:  # don't bother with more checks dupe trips are ok
                yield ilx_iri, ilxtr.hasIlxId, o

            if ilx_iri != o and 'uri.interlex.org' not in o:
                yield ilx_iri, ilxtr.hasExternalId, o

            if pref == '1':
                yield ilx_iri, ilxtr.hasIlxPreferredId, o

        more_terms_ilx_fragments = set()
        for preferred_iri, p, o in self.id_triples(ids):  # FIXME not actually preferred
            preferred_iri = rdflib.URIRef(preferred_iri)
            oo = check_value(o)
            if isinstance(oo, rdflib.URIRef):
                predobjs.add(oo)
                if ' ' in oo:
                    # there are a few wiki urls that have spaces in them >_< sigh
                    oo = str(oo)
                    log.warning(tc.red('bad iri {oo!r}'))

            if p == '' or p is None:  # we are in synonym space also FIXME because this is dumb
                p = NIFRID.synonym
            elif p == 'abbrev':
                stype = synonym_types[p]
                p = NIFRID.synonym
                triple = preferred_iri, p, oo
                yield from annotation(triple, (ilxtr.synonymType, stype))()
            elif [_ for _ in ('fma:', 'NIFRID:', 'oboInOwl:') if p.startswith(_)]:
                p = OntId(p).u
            else:
                p = rdflib.URIRef(p)

            predobjs.add(p)
            #print(p, oo)
            if p == rdf.type:
                type = p
            elif p == ilxtr.subThingOf:
                if type == owl.Class:
                    p = rdfs.subClassOf
                else:
                    p = rdfs.subPropertyOf

            yield preferred_iri, p, oo

            if p in include_full_object_predicates:
                # this can be vastly more efficient in 
                more_terms_ilx_fragments.add(oo.rsplit('/', 1)[-1])  # get the fragment from the iri

        if more_terms_ilx_fragments:
            yield from self._terms_triples(self.terms(tuple(more_terms_ilx_fragments)), done=done)  # NOTE done MUTATES

        while 1:
            todo = ['ilx_' + i.suffix for i in [OntId(i) for i in predobjs - done] if i.prefix == 'ILX']
            if not todo:  # oh hey, a walrus use case!
                break

            predobjs = set()
            ids = set()
            for term in self.terms(todo):
                id, baseiri, preferred_iri, type, ilxtype, ilx_fragment = basics(term)
                ids.add(id)
                done.add(baseiri)
                preferred_iri = baseiri  # XXX dealt with by render prefs instead i.e. TripleRender.default_prefix_ranking
                yield preferred_iri, rdf.type, type
                yield preferred_iri, rdfs.label, rdflib.Literal(term.label)

            for ilx_iri, pref, o in self.existing_ids_triples(ids):  # FIXME not actually preferred
                ilx_iri = rdflib.URIRef(ilx_iri)
                o = rdflib.URIRef(o.rstrip())  # FIXME ARGH rstrip
                predobjs.add(o)

                yield ilx_iri, ilxtr.hasExistingId, o

                if ilx_iri == o:  # don't bother with extra checks duplicate triples are ok
                    yield ilx_iri, ilxtr.hasIlxId, o

                if ilx_iri != o and 'uri.interlex.org' not in o:
                    yield ilx_iri, ilxtr.hasExternalId, o

                if pref == '1':
                    yield ilx_iri, ilxtr.hasIlxPreferredId, o


class TripleExporter:
    #def __init__(self, triples, subgraphs):  # TODO
    # TODO implement a version of this that is an rdflib store
    def __init__(self):
        self._subgraph_counter = -1
        self.subgraph_identities = {}

    @property
    def subgraph_counter(self):
        self._subgraph_counter += 1
        return self._subgraph_counter

    def star_triple(self, id, s, s_blank, p, o, o_lit, o_blank, datatype, language, subgraph_identity):
        return self.triple(s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity)

    def nt(self, id, s, s_blank, p, o, o_lit, o_blank, datatype, language, subgraph_identity):
        """ For dump. """
        if subgraph_identity is not None:
            if subgraph_identity not in self.subgraph_identities:
                self.subgraph_identities[subgraph_identity] = self.subgraph_counter

            si = 'sg_' + str(self.subgraph_identities[subgraph_identity])

        if s is not None:
            s = f'<{s}> '.encode()
        elif s_blank is not None:
            s = f'_:{si}_{s_blank} '.encode()

        p = f'<{p}> '.encode()  # FIXME _:asdf is allowed for predicates or no?

        if o is not None:
            o = f'<{o}> '.encode()
        elif o_lit is not None:
            b = rdflib.Literal(o_lit).n3()
            if datatype:
                o = f'{b}^^<{datatype}> '.encode()
            elif language:
                o = f'{b}@{language} '.encode()
            else:
                o = b.encode()

        elif o_blank is not None:
            o = f'_:{si}_{o_blank} '.encode()

        return s + p + o + b'.\n'

    def triple(self, s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity):
        if subgraph_identity is not None:
            if subgraph_identity not in self.subgraph_identities:
                self.subgraph_identities[subgraph_identity] = self.subgraph_counter

            si = 'sg_' + str(self.subgraph_identities[subgraph_identity])

        if s is not None:
            s = rdflib.URIRef(s)
        elif s_blank is not None:
            s = rdflib.BNode(si + '_' + str(s_blank))

        if o is not None:
            o = rdflib.URIRef(o)
        elif o_lit is not None:
            o = rdflib.Literal(o_lit, datatype=datatype, lang=language)
        elif o_blank is not None:
            o = rdflib.BNode(si + '_' + str(o_blank))
        else:
            raise ValueError(f'What have you done!\n{o}\n{o_lit}\n{o_blank}\n'
                             f'{s} {p} {datatype} {language}')

        return s, rdflib.URIRef(p), o

# FIXME this is a really bad way to do this... it would be much better to be able
# to connect by other means that flasksqlalchemy...

class Queries:
    class Sql:
        pass
    sql = Sql()

    def __init__(self, session):
        self.session = session
        self.__reference_host = None

    @property
    def reference_host(self):
        if self.__reference_host is None:
            # NOTE this means you can't call this queries until you have set up the database
            self.__reference_host = next(self.session.execute('SELECT reference_host()')).reference_host
        return self.__reference_host

    def getBuiltinGroups(self):
        return list(self.session.execute("SELECT * FROM groups WHERE own_role = 'builtin'"))

    def getGroupIds(self, *group_names):
        # have to type group_names as list because postgres doesn't know what to do with a tuple
        return {r.g:r[1] for r in self.session.execute('SELECT g, idFromGroupname(g) '
                                                        'FROM unnest(ARRAY[:group_names]) '
                                                        'WITH ORDINALITY g',
                                                        dict(group_names=list(group_names)))}

    def getGroupCuries(self, group, epoch_verstr=None):
        # TODO retrieve base/default curies
        params = dict(group=group)
        if epoch_verstr is not None:
            # TODO
            sql = ('SELECT curie_prefix, iri_prefix FROM curies as c '
                    'WHERE c.group_id = idFromGroupname(:group)')
        else:
            sql = ('SELECT curie_prefix, iri_prefix FROM curies as c '
                    'WHERE c.group_id = idFromGroupname(:group)')  # FIXME idFromGroupname??
        resp = self.session.execute(sql, params)
        PREFIXES = {cp:ip for cp, ip in resp}
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

    def dumpAll(self, user=None):
        """ Every triple we have ever seen. """
        # TODO stick the id on the front as a quad
        # and then dump the actual qualifier table
        #return list(self.session.execute("SELECT * FROM triples WHERE s::text LIKE '%RO_0002005'"))
        return self.session.execute('SELECT * FROM triples')  # this streams

    def dumpAllNt(self, user=None):
        ssc = "substring(encode(subgraph_identity, 'hex'), 0, 20)"
        # so yes, I originally wrote a UNION select version of this, it was monumentally slow
        # this one is blazingly fast
        sep = "'x'"
        return (
            self.session.execute("SELECT '<' || s || '> <' || p || '> <' || o || '> .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o IS NOT NULL"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '@' || language || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '^^<' || datatype || '> .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL"),
            self.session.execute(f"SELECT '<' || s || '> <' || p || '> _:' || {ssc} || {sep} || o_blank::text || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_blank IS NOT NULL"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> _:' || {ssc} || {sep}            || o_blank::text     || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_blank IS NOT NULL"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '@'   || language || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '^^<' || datatype || '> .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL"),
            )

    def dumpSciGraphNt(self, user=None):
        ssc = "substring(encode(subgraph_identity, 'hex'), 0, 20)"
        sep = "'x'"
        subselect = ("SELECT distinct(t.s) FROM triples AS t "
                     "JOIN triples AS t2 ON t.s = t2.s "
                     "WHERE t2.o::text LIKE '%owl#Ontology'")
        condition = f'AND (s NOT IN ({subselect}) OR s IS NULL)'
        return (
            self.session.execute("SELECT '<' || s || '> <' || p || '> <' || o || '> .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o IS NOT NULL {condition}"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL {condition}"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '@' || language || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL {condition}"),
            self.session.execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '^^<' || datatype || '> .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL {condition}"),
            self.session.execute(f"SELECT '<' || s || '> <' || p || '> _:' || {ssc} || {sep} || o_blank::text || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_blank IS NOT NULL {condition}"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> _:' || {ssc} || {sep}          || o_blank::text     || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_blank IS NOT NULL {condition}"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL {condition}"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '@'   || language || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL {condition}"),
            self.session.execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '^^<' || datatype || '> .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL {condition}"),
            )

    def getExistingIris(self):
        sql = 'SELECT * FROM existing_iris'
        return self.session.execute(sql)

    def _getExistingFromCurie(self, curie, user):  # FIXME multiple
        prefix, suffix = curie.split(':', 1)
        # is there a way to do this in a single sql statement?
        # we can always get curies and then getExistingFromIri but that is slow...
        #args = dict(prefix=prefix, suffix=suffix)
        #sql = ('SELECT s, iri FROM triples JOIN existing_iris ')
        return 'TODO'

    def getExistingFromIri(self, *iris):
        args = dict(iris=iris)
        sql = ('SELECT distinct(e2.ilx_id, e1.iri) FROM existing_iris as e1 '
               'JOIN existing_iris as e2 '
               'ON e1.ilx_id = e2.ilx_id '
               'WHERE e2.iri IN :iris')
        resp = list(self.session.execute(sql, args))
        return resp

    def getExistingIrisForIlxId(self, *ilx_ids):
        args = dict(ilx_ids=list(ilx_ids))
        sql = ('SELECT i, iri FROM unnest(ARRAY[:ilx_ids]) WITH ORDINALITY i '
               'JOIN existing_iris ON i = ilx_id')
        resp = list(self.session.execute(sql, args))
        return resp

    def getBySubject(self, subject, user):
        # FIXME ah uri normalization ... what to do about you
        args = dict(uri=subject)
        sql = '''
        WITH graph AS (
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
        SELECT * FROM graph UNION SELECT * from subgraphs
        '''

        resp = list(self.session.execute(sql, args))
        return resp

    def getById(self, id, user):
        """ return all triples associated with an interlex id (curie suffix) """
        uri = f'http://uri.interlex.org/base/ilx_{id}'  # FIXME reference_host from db ...
        args = dict(uri=uri, id=id, p=str(ilxtr.hasExistingId))
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
        SELECT * FROM graph UNION SELECT * from subgraphs
        UNION SELECT :uri, NULL, :p, iri, NULL, NULL, NULL, NULL, NULL FROM existing_iris WHERE ilx_id = :id;
        '''
        # FIXME serialization choices means that any and all ilx ids that are pulled out from here need
        # to have their existing ids pulled in as well, it is just easy to get the existing of the primary
        # in a single query here
        # FIXME is it worth considering not using base but instead using s_ilx p_ilx, and o_ilx since they they have known size?

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

    def getByGroupUriPath(self, group, path, redirect=False):  # TODO bulk versions of these
        args = dict(group=group, path=path)
        sql = ('SELECT ilx_id FROM uris WHERE group_id = idFromGroupname(:group) '
               'AND uri_path = :path')
        # TODO handle the unmapped case (currently literally all of them)
        gen = self.session.execute(sql, args)
        try:
            ilx_id = next(gen).ilx_id
        except StopIteration:
            return tuple()
        # since group_id and uri_path are the primary key
        # each path will map to only 1 ilx_id
        # we also constrain group_id + ilx_id to be unique

        if redirect:
            return ilx_id
        else:
            return self.getById(group, ilx_id)

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

    def getObjectsForPredicates(self, iris, *predicates):
        args = dict(p=predicates, iris=tuple(iris))  # FIXME normalize here or there?
        sql = 'SELECT s, o_lit FROM triples WHERE p in :p AND s in :iris'
        for r in self.session.execute(sql, args):
            yield r.s, r.o_lit  # with multiple iris we have to keep track of the mapping

    def getLabels(self, user, iris):
        yield from self.getObjectsForPredicates(iris, rdfs.label)  # FIXME alts?

    def getDefinitions(self, user, *iris):
        # TODO aggregate/failover to defs from alternate sources where the ilx_id has an existing id
        # requires a different yielding strat
        #value_templates, params = makeParamsValues(iris)
        yield from self.getObjectsForPredicates(iris, definition, skos.definition)

    def getByLabel(self, label, user):
        # TODO user mapping of lexical
        args = dict(p=rdfs.label.toPython(), label=label)
        #sql = f'SELECT s FROM triples WHERE p = :p AND o_lit ~~* :label'  # ~~* is LIKE case insensitive
        sql = 'SELECT s FROM triples WHERE s IS NOT NULL AND p = :p AND LOWER(o_lit) LIKE :label'
        # we can sort out the case sensitivity later if it is an issue
        results = [r.s for r in self.session.execute(sql, args)]
        if not results:
            # NOTE if ambiguation is done by a user, then they keep that mapping
            return False, None  # redlink? ambiguate
        elif len(results) == 1:
            return True, results[0]  # redirect
        else:
            defs = self.getDefinitions(user, *results)
            return False, list(defs)  # disambiguate

    def getTriplesById(self, *triples_ids):
        # when using IN directly we don't have to convert to a list first
        # unlike in the unnest case
        yield from self.session.execute('SELECT * FROM triples WHERE id IN :triples_ids',
                                        dict(triples_ids=triples_ids))

    def tripleIdentity(self, *triples_ids):
        """ light wrapper around built in function """
        for (identity,) in self.session.execute('SELECT tripleIdentity(id)'
                                                'FROM unnest(ARRAY[:triples_ids]) '
                                                'WITH ORDINALITY id',
                                                dict(triples_ids=list(triples_ids))):
            yield identity
