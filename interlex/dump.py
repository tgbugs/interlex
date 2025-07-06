import rdflib
import ontquery as oq
from itertools import chain
from collections import defaultdict
from sqlalchemy.sql import text as sql_text
from sqlalchemy.sql.expression import bindparam
from sqlalchemy.types import UserDefinedType
from sqlalchemy.dialects.postgresql import ARRAY
from pyontutils import sneechenator as snch
from pyontutils.core import OntId
from pyontutils.utils import TermColors as tc
from pyontutils.utils_extra import check_value
from pyontutils.namespaces import NIFRID, ilxtr, definition
from pyontutils.namespaces import rdf, rdfs, owl, skos
from pyontutils.namespaces import ilx_includesTerm, ilx_includesTermSet
from pyontutils.combinators import annotation
from interlex import exceptions as exc
from interlex.core import log, makeParamsValues, synonym_types
from interlex.namespaces import ilxr, ilxrtype


class uri(UserDefinedType):
    def get_col_spec(self):
        return 'uri'


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
        'sparc': 'SPARC Anatomical Working Group',  # 504
        'openminds': 'openMINDS',  # 515
    }
    _group_include_full_objects = {
        'sparc': (OntId('ILX:0738400').u,  # ilx.includeForSPARC
                  OntId('ilx.includeForSPARC:').u,
        ),
    }
    def __init__(self, session):
        self.session = session

    def session_execute(self, sql, params=None):
        return self.session.execute(sql_text(sql), params=params)

    def getGroupCuries(self, group, epoch_verstr=None):
        # NOTE no support for group in the mysql version, but match the api
        sql = 'SELECT prefix, namespace FROM term_curie_catalog'
        args = dict()
        resp = self.session_execute(sql, args)
        return {prefix:namespace for prefix, namespace in resp}

    def expandPrefixIriCurie(self, group, prefix_iri_curie):
        # FIXME takes +two+ two database calls
        log.debug(prefix_iri_curie)
        prefixes = self.getGroupCuries('base')
        oc = oq.OntCuries.new()
        oc(prefixes)
        OntIdx = type('OntIdSigh', (OntId,), dict(_namespaces=oc))
        if ':' not in prefix_iri_curie:
            # assume prefix
            try:
                i = OntIdx(prefix_iri_curie + ':')
                return i,
            except OntIdx.UnknownPrefixError as e:
                return
        else:
            try:
                i = OntIdx(prefix_iri_curie)
            except OntIdx.UnknownPrefixError as e:
                # TODO logu.error(e)
                # FIXME it is REALLY annoying that there is no sane way
                # to avoid either having to have the web know about the
                # internal errors here OR having this manage the aborts
                return

            res = list(self.existing_mapped((i.u,)))
            if res:
                # FIXME HACK ensures lowest first, common denominator last
                def key(iri_ilx, fpr=('cde', 'fde', 'pde', 'set', 'ilx', 'tmp')):  # FIXME hardcoded
                    iri, ilx = iri_ilx
                    for i, frag_pref in enumerate(fpr):
                        if frag_pref + '_' in ilx:
                            return i, ilx

                    return 4, ilx  # XXX unknown prefix

                rr = sorted([ii for ii in res], key=key)
                (iri_res, ilx), *rest = rr
                if rest:
                    log.debug(f'multiple ilx iris: {rr}')

                return OntIdx(iri_res), OntIdx(ilx)

    def group_terms(self, group):
        name = self._group_community[group]

        # XXX NOTE this explicitly EXCLUDES TermSet, which may be
        # confusing, because technically communities can adopt term sets
        # however, the double counting is worse in this case
        sql = ('SELECT * from terms WHERE '
               'terms.type != "TermSet" AND '
               'status != -2 AND '
               'orig_cid = (SELECT id FROM communities WHERE name = :name) '
               'UNION '
               'SELECT * from terms WHERE '
               'terms.type != "TermSet" AND '
               'status != -2 AND '
               'terms.id IN (SELECT * FROM (SELECT tc.tid FROM term_communities AS tc '
               'JOIN communities AS c ON '
               'tc.cid = c.id WHERE c.name = :name AND tc.status = "approved") AS subquery)')

        args = dict(name=name)
        yield from self.session_execute(sql, args)

    def existing_ids(self, id):
        sql = 'SELECT preferred, iri FROM term_existing_ids WHERE tid = :id'
        args = dict(id=id)
        yield from self.session_execute(sql, args)

    def existing_ids_triples(self, ids):
        if not ids:
            return

        sql = ('SELECT te_s.iri, te.preferred, te.iri FROM term_existing_ids as te'
               '  JOIN term_existing_ids as te_s '
               '    ON te.tid = te_s.tid '
               ' WHERE te.tid in :ids'
               "   AND te_s.iri like 'http://uri.interlex.org/base/%'")
        args = dict(ids=tuple(ids))
        yield from self.session_execute(sql, args)

    def existing_in_namespace(self, namespace):
        """ for now only check a single namespace at a time """
        sql = ('SELECT te.iri, te_o.iri FROM term_existing_ids as te'
               '  JOIN term_existing_ids as te_o '
               '    ON te.tid = te_o.tid '
               " WHERE te.iri LIKE CONCAT(:namespace, '%')"
               "   AND te_o.iri like 'http://uri.interlex.org/base/%'")
        args = dict(namespace=namespace)
        yield from self.session_execute(sql, args)

    def index_triples(self, namespace):
        for s, o in self.existing_in_namespace(namespace):
            yield rdflib.URIRef(s), ilxtr.hasIlxId, rdflib.URIRef(o)

    def existing_mapped(self, iris, namespace=None):
        sql = ('SELECT te.iri, te_o.iri FROM term_existing_ids as te'
                '  JOIN term_existing_ids as te_o '
                '    ON te.tid = te_o.tid '
                ' WHERE te.iri in :iris'
                "   AND te_o.iri LIKE 'http://uri.interlex.org/base/%'")
        args = dict(iris=tuple(iris))
        if namespace is not None:
            sql += " AND te.iri LIKE CONCAT(:namespace, '%')"
            args['namespace'] = namespace

        # the user has to tell us namespace anyway so make use of it
        # yes we could implement a generic iri mapping facility
        # but to be efficient it probably makes more sense to create
        # an temporary index of the set of iris to map or something
        yield from self.session_execute(sql, args)

    def alreadyMapped(self, iris, namespace=None):
        for s, o in self.existing_mapped(iris, namespace):
            yield rdflib.URIRef(s), ilxtr.hasIlxId, rdflib.URIRef(o)

    def term(self, ilx_fragment):
        #args = dict(ilx=request.url.rsplit('/', 1)[-1])
        args = dict(ilx=ilx_fragment)
        sql = 'SELECT * FROM terms WHERE ilx = :ilx'

        rp = self.session_execute(sql, args)
        try:
            term = next(rp)
        except StopIteration as e:
            return

        try:
            next(rp)
            raise exc.ShouldNotHappenError(f'too many results for {ilx_fragment}')
        except StopIteration:
            pass

        return term

    def terms(self, ilx_fragments):
        args = dict(fragments=ilx_fragments)
        sql = 'SELECT * FROM terms where ilx in :fragments'
        yield from self.session_execute(sql, args)

    __max_depth = 45
    @staticmethod
    def _superclasses_ids(max_depth=__max_depth):
        return '\n'.join([
            'select',
            ',\n'.join([f't{n + 1}.tid as tid{n + 1}' for n in range(max_depth)]),
            'from term_superclasses as t1',
            '\n'.join([f'left join term_superclasses as t{n + 2} on t{n + 2}.tid = t{n + 1}.superclass_tid'
                       for n in range(max_depth - 1)]),
            'where t1.tid in :ids'])

    @classmethod
    def _superclasses_query(cls, max_depth=__max_depth):
        # have to nest queries because mariadb can join on max 61 tables per (sub)query
        # this also happens to give us a max depth of 60 without having to query twice
        return '\n'.join([
            'select',
            ',\n'.join([('concat("http://uri.interlex.org/base/", '
                         f'ti{n + 1}.ilx), ti{n + 1}.label, ti{n + 1}.id, ti{n + 1}.type')
                        for n in range(max_depth)]),
            'from (',
            cls._superclasses_ids(max_depth),
            ') as traw',
            '\n'.join([f'left join terms as ti{n + 1} on traw.tid{n + 1} = ti{n + 1}.id'
                       for n in range(max_depth)]),
        ])

    def id_supers(self, ids):
        if not ids:
            return

        args = dict(ids=tuple(ids))
        sql = self._superclasses_ids()
        out = set()
        for supers in self.session_execute(sql, args):
            if supers[-1] != None:
                msg = (  # XXX TODO requery from supers[-1] in this case and stitch
                    'the last element of the result superclasses '
                    'was not null, you may be missing parents!')
                log.warning(msg)

            [out.add(s) for s in supers if s is not None]

        return out

    def _supers_triples(self, ids):
        # this isn't really what we want ...
        if not ids:
            return

        def conv(rawp):
            if self.types[rawp] == owl.Class:
                p = rdfs.subClassOf
            else:
                p = rdfs.subPropertyOf

            return p

        sco = rdfs.subClassOf
        rdl = rdfs.label
        args = dict(ids=tuple(ids))
        sql = self._superclasses_query()
        ids = set()
        trips = []  # XXX FIXME have to know type
        for supers in self.session_execute(sql, args):
            if supers[-1] != None:
                msg = (  # XXX TODO requery from supers[-1] in this case and stitch
                    'the last element of the result superclasses '
                    'was not null, you may be missing parents!')
                log.warning(msg)

            ids.update(i for i in supers[2::4] if i is not None)
            trips.extend((rdflib.URIRef(s), conv(rawp), rdflib.URIRef(o))  # XXX FIXME type
                         for s, rawp, o in zip(supers[:-4:4], supers[3::4], supers[4::4]) if s and o)
            trips.extend((rdflib.URIRef(s), rdl, rdflib.Literal(o))
                         for s, o in zip(supers[:-4:4], supers[1:-3:4]) if s and o)

        return ids, trips

    def id_triples(self, ids):
        if not ids:
            return

        args = dict(ids=tuple(ids))
        sql = f'''
        SELECT concat('http://uri.interlex.org/base/', te.ilx), ts.type, ts.literal FROM term_synonyms as ts
          JOIN terms AS te
            ON te.id = ts.tid
         WHERE ts.tid in :ids
           AND ts.literal != ''
        UNION
        SELECT concat('http://uri.interlex.org/base/', te1.ilx), concat('http://uri.interlex.org/base/', te2.ilx), value FROM term_annotations AS ta
          JOIN terms AS te1
            ON ta.tid = te1.id
          JOIN terms AS te2
            ON ta.annotation_tid = te2.id
         WHERE ta.tid in :ids
           AND ta.withdrawn != '1'
        UNION
        SELECT concat('http://uri.interlex.org/base/', te.ilx), concat('http://uri.interlex.org/base/', te1.ilx), concat('http://uri.interlex.org/base/', te2.ilx) FROM term_relationships AS tr
          JOIN terms AS te
            ON te.id = tr.term1_id
          JOIN terms AS te1
            ON te1.id = tr.relationship_tid
          JOIN terms AS te2
            ON te2.id = tr.term2_id
         WHERE tr.term1_id in :ids
           AND tr.withdrawn != '1'
        UNION
        SELECT concat('http://uri.interlex.org/base/', te1.ilx), {str(ilxtr.subThingOf)!r}, concat('http://uri.interlex.org/base/', te2.ilx) FROM term_superclasses AS tsc
          JOIN terms AS te1
            ON te1.id = tsc.tid
          JOIN terms AS te2
            ON te2.id = tsc.superclass_tid
         WHERE tsc.tid in :ids
        '''

        yield from self.session_execute(sql, args)

    def predicate_objects(self, id):
        args = dict(id=id)
        # FIXME urg the ILX:% ok now?
        sql = f'''
        SELECT type, literal FROM term_synonyms
         WHERE literal != ''
           AND tid = :id
        UNION
        SELECT te.iri, value FROM term_annotations AS ta
          JOIN term_existing_ids AS te
            ON ta.annotation_tid = te.tid
         WHERE ta.tid = :id
           AND ta.withdrawn != '1'
           AND te.iri like 'http://uri.interlex.org/base/%'
           -- AND te.preferred = '1'
        UNION
        SELECT te1.iri, te2.iri FROM term_relationships AS tr
          JOIN term_existing_ids AS te1
            ON te1.tid = tr.relationship_tid
          JOIN term_existing_ids AS te2
            ON te2.tid = tr.term2_id
         WHERE tr.term1_id = :id
           AND tr.withdrawn != '1'
           AND te1.iri like 'http://uri.interlex.org/base/%'
           -- AND te1.preferred = '1'
           AND te2.iri like 'http://uri.interlex.org/base/%'
           -- AND te2.preferred = '1'
        UNION
        SELECT {str(ilxtr.subThingOf)!r}, te.iri FROM term_superclasses AS tsc
          JOIN term_existing_ids AS te
            ON te.tid = tsc.superclass_tid
         WHERE tsc.tid = :id
           AND te.iri like 'http://uri.interlex.org/base/%'
           -- AND te.preferred = '1'
        '''

        yield from self.session_execute(sql, args)

    def __call__(self, fragment_prefix, id, ontology=False):
        ilx_fragment = fragment_prefix + '_' + id
        return self._call_fragment(ilx_fragment, ontology=ontology)

    def _call_fragment(self, ilx_fragment, ontology=False):
        term = self.term(ilx_fragment)  # FIXME handle value error or no?
        if term is None:
            return tuple()

        if ontology and term.type == 'TermSet':  # XXX design flaw to have to branch here but oh well
            return self._termset_triples((term,))

        return self._terms_triples((term,))

    def _call_fragments(self, ilx_fragments):
        yield from self._terms_triples(self.terms(ilx_fragments))

    def _call_group(self, group):
        # FIXME horrible implementation
        include_full_object_predicates = self._group_include_full_objects[group]
        yield from self._terms_triples(self.group_terms(group),
                                       include_full_object_predicates=include_full_object_predicates)

    def _termset_triples(self, terms, done=None, recurse=False):
        if done is None:
            done = list(terms)
            not_done_terms = list(terms)
        elif done:
            not_done_terms = []
            for term in terms:
                if term in done:
                    logd.error('CYCLE DETECTED IN TERMSET !!!!')
                    continue
                done.append(term)
                not_done_terms.append(term)

        i_terms = []
        i_termsets = []
        sit = str(ilx_includesTerm)
        sits = str(ilx_includesTermSet)
        rest = tuple()
        for s, p, o in self.id_triples([t.id for t in not_done_terms]):
            if p == sit:
                i_terms.append(o)
            elif p == sits:
                i_termsets.append(o)
            else:
                t, _rest = self._convert_trip((s, p, o), set())
                # usually a mistake to have anything but a label and definition here
                # but sometimes there are legitimate cases
                if recurse:
                    rest = chain(rest, (t,), _rest)
                else:
                    # TODO need basics
                    yield t
                    yield from _rest

        t_frags = [o.rsplit('/',1)[-1] for o in i_terms]

        ts_frags = [o.rsplit('/',1)[-1] for o in i_termsets]
        if ts_frags:
            ts_termset_terms = list(self.terms(ts_frags))
        else:
            ts_termset_terms = []

        all_termsets = list(ts_termset_terms)
        rests = [rest]
        if ts_termset_terms:
            for r_t_frags, r_ts_termset_terms, r_rest in self._termset_triples(
                    ts_termset_terms, done=done, recurse=True):
                t_frags.extend(r_t_frags)
                all_termsets.extend(r_ts_termset_terms)
                rests.extend(r_rest)

        if recurse:
            yield t_frags, all_termsets, rests
            return
        else:  # entrypoint
            # add the starting termset to all termsets
            all_termsets.extend(terms)

        if t_frags:
            t_terms = list(self.terms(t_frags))
            yield from self._terms_triples(t_terms)

        for r in rests:
            log.debug(r)
            yield from r

        ids = set()
        for ts_termset_term in all_termsets:
            yield from self._basic_trips(ts_termset_term, set(), ids, {})

        yield from self._existing_trips(ids, set())

    def _convert_trip(self, t, predobjs):
        rest = tuple()
        preferred_iri, p, o = t
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
            rest = annotation(triple, (ilxtr.synonymType, stype))()
        elif p == 'vocab:synonym':
            p = OntId('NIFRID:synonym').u
        elif [_ for _ in ('fma:', 'NIFRID:', 'oboInOwl:') if p.startswith(_)]:
            p = OntId(p).u
        else:
            p = rdflib.URIRef(p)

        return (preferred_iri, p, oo), rest

    def _basics(self, term):
        id = term.id
        ilx_fragment = term.ilx
        baseiri = rdflib.URIRef('http://uri.interlex.org/base/' + ilx_fragment)
        #done.add(baseiri)  # handled by caller
        type = self.types[term.type]
        ilxtype = ilxrtype[term.type]
        preferred_iri = baseiri
        return id, baseiri, preferred_iri, type, ilxtype, ilx_fragment

    def _basic_trips(self, term, done, ids, types):
        id, baseiri, preferred_iri, type, ilxtype, ilx_fragment = self._basics(term)
        ids.add(id)
        done.add(baseiri)  # FIXME duplicated
        types[baseiri] = type
        preferred_iri = baseiri  # XXX dealt with by render prefs instead i.e. TripleRender.default_prefix_ranking
        yield preferred_iri, rdf.type, type
        yield preferred_iri, ilxr.type, ilxtype
        yield preferred_iri, rdfs.label, rdflib.Literal(term.label)
        if term.definition:
            yield preferred_iri, definition, rdflib.Literal(term.definition)

        # TODO hasIlxId sco hasRefId, hasMutualId for non ref ids
        yield preferred_iri, ilxtr.hasIlxId, baseiri

        #prids[preferred_iri] = ilx_fragment

    def _existing_trips(self, ids, predobjs):
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

    def _terms_triples(self, terms, include_full_object_predicates=tuple(),
                       done=tuple(), include_supers=False):  # XXX this one hack
        done = set() if not done else done
        predobjs = set()
        ids = set()
        #prids = {}
        types = {}
        for term in terms:
            yield from self._basic_trips(term, done, ids, types)

        if include_supers:
            # XXX note that supers do not include the full complement of triples
            sids, strips = self._supers_triples(ids)
            yield from strips
            yield from self._existing_trips(sids, predobjs)

        yield from self._existing_trips(ids, predobjs)

        more_terms_ilx_fragments = set()
        for preferred_iri, p, o in self.id_triples(ids):  # FIXME not actually preferred
            t = (preferred_iri, p, oo), rest = self._convert_trip((preferred_iri, p, o), predobjs)
            if preferred_iri not in done:
                log.error(t)
                continue

            predobjs.add(p)
            #print(p, oo)
            if p == rdf.type:
                pass
            elif p == ilxtr.subThingOf:
                if types[preferred_iri] == owl.Class:
                    p = rdfs.subClassOf
                else:
                    p = rdfs.subPropertyOf

            yield preferred_iri, p, oo
            yield from rest

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
                id, baseiri, preferred_iri, type, ilxtype, ilx_fragment = self._basics(term)
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

    def nt(self, id, s, s_blank, p, o, o_lit, o_blank, datatype, language, subgraph_identity,
           subgraph_replica=None, object_subgraph_identity=None, object_replica=None):
        """ For dump. """
        if subgraph_identity is not None:
            if subgraph_identity not in self.subgraph_identities:
                if self.use_hex:
                    self.subgraph_identities[subgraph_identity] = subgraph_identity.hex()
                else:
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

    use_hex = False
    def triple(self, s, s_blank, p, o, o_lit, datatype, language, o_blank=None, subgraph_identity=None,
               subgraph_replica=None, object_subgraph_identity=None, object_replica=None):
        if subgraph_identity is not None:
            if subgraph_identity not in self.subgraph_identities:
                if self.use_hex:
                    self.subgraph_identities[subgraph_identity] = subgraph_identity.hex()
                else:
                    self.subgraph_identities[subgraph_identity] = self.subgraph_counter

            if subgraph_replica is None:
                # FIXME TODO temp for backward compat, but most queries need to switch over
                # use n instead of zero to make it easier to detect cases where
                # non-replicated are pulled in, we don't have to worry about doubly
                # replicated cases because those can currently be differentiated by
                # the graph bnode

                # THERE CAN BE ONLY NONE
                subgraph_replica = 'n'

            si = 'sg_' + str(self.subgraph_identities[subgraph_identity]) + '_' + str(subgraph_replica)
            if object_subgraph_identity is not None:
                if object_subgraph_identity not in self.subgraph_identities:
                    # can't assume that the object subgraph will always be in first
                    if self.use_hex:
                        self.subgraph_identities[object_subgraph_identity] = object_subgraph_identity.hex()
                    else:
                        self.subgraph_identities[object_subgraph_identity] = self.subgraph_counter

                oi = 'sg_' + str(self.subgraph_identities[object_subgraph_identity]) + '_' + str(object_replica)
            else:
                oi = si

        if s is not None:
            s = rdflib.URIRef(s)
        elif s_blank is not None:
            s = rdflib.BNode(si + '_' + str(s_blank))

        if o is not None:
            o = rdflib.URIRef(o)
        elif o_lit is not None:
            o = rdflib.Literal(o_lit, datatype=datatype, lang=language)
        elif o_blank is not None:
            if object_subgraph_identity is not None:
                o = rdflib.BNode(oi + '_' + str(0))  # if there is an object subgraph identity the target is always the head node 0
            else:
                o = rdflib.BNode(oi + '_' + str(o_blank))
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

    def session_execute(self, sql, params=None, bindparams=None):
        t = sql_text(sql)
        if bindparams:
            t = t.bindparams(*bindparams)

        return self.session.execute(t, params=params)

    @property
    def reference_host(self):
        if self.__reference_host is None:
            # NOTE this means you can't call this queries until you have set up the database
            self.__reference_host = next(self.session_execute('SELECT reference_host()')).reference_host
        return self.__reference_host

    def getBuiltinGroups(self):
        return list(self.session_execute("SELECT * FROM groups WHERE own_role = 'builtin'"))

    def getGroupExisting(self, groupname):
        # we can't use getGroupIds for this because getGroupIds requires
        # that a group already exists and otherwise aborts hard
        return list(self.session_execute(
            'select g.id from groups as g where g.groupname = :groupname',
            params=dict(groupname=groupname)))

    def getGroupIds(self, *group_names):
        # have to type group_names as list because postgres doesn't know what to do with a tuple
        return {r.g:r[1] for r in self.session_execute('SELECT g, idFromGroupname(g) '
                                                        'FROM unnest(ARRAY[:group_names]) '
                                                        'WITH ORDINALITY g',
                                                        dict(group_names=list(group_names)))}

    def getGroupPers(self, *group_names):
        # have to type group_names as list because postgres doesn't know what to do with a tuple
        return {r.g:r[1] for r in self.session_execute('SELECT g, persFromGroupname(g) '
                                                        'FROM unnest(ARRAY[:group_names]) '
                                                        'WITH ORDINALITY g',
                                                        dict(group_names=list(group_names)))}

    def getGroupCuries(self, group, epoch_verstr=None):
        # TODO retrieve base/default curies
        params = dict(group=group)
        if epoch_verstr is not None:
            # TODO
            sql = ('SELECT curie_prefix, iri_namespace FROM curies as c '
                   'WHERE c.perspective = persFromGroupname(:group)')
        else:
            sql = ('SELECT curie_prefix, iri_namespace FROM curies as c '
                   'WHERE c.perspective = persFromGroupname(:group)')
        resp = self.session_execute(sql, params)
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
        resp = list(self.session_execute(sql))
        if unmapped:
            resp += list(self.session_execute(sql2))
        return resp

    def dumpAll(self, user=None):
        """ Every triple we have ever seen. """
        # TODO stick the id on the front as a quad
        # and then dump the actual qualifier table
        #return list(self.session_execute("SELECT * FROM triples WHERE s::text LIKE '%RO_0002005'"))
        return self.session_execute('SELECT * FROM triples')  # this streams

    def dumpAllNt(self, user=None):
        ssc = "substring(encode(subgraph_identity, 'hex'), 0, 20)"
        # so yes, I originally wrote a UNION select version of this, it was monumentally slow
        # this one is blazingly fast
        sep = "'x'"
        return (
            self.session_execute("SELECT '<' || s || '> <' || p || '> <' || o || '> .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o IS NOT NULL"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '@' || language || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '^^<' || datatype || '> .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL"),
            self.session_execute(f"SELECT '<' || s || '> <' || p || '> _:' || {ssc} || {sep} || o_blank::text || ' .\n' "
                                 "FROM triples WHERE s IS NOT NULL AND o_blank IS NOT NULL"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> _:' || {ssc} || {sep}            || o_blank::text     || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_blank IS NOT NULL"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '@'   || language || ' .\n' "
                                 "FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '^^<' || datatype || '> .\n' "
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
            self.session_execute("SELECT '<' || s || '> <' || p || '> <' || o || '> .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o IS NOT NULL {condition}"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL {condition}"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '@' || language || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL {condition}"),
            self.session_execute("SELECT '<' || s || '> <' || p || '> '  || to_json(o_lit)::text || '^^<' || datatype || '> .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL {condition}"),
            self.session_execute(f"SELECT '<' || s || '> <' || p || '> _:' || {ssc} || {sep} || o_blank::text || ' .\n' "
                                 f"FROM triples WHERE s IS NOT NULL AND o_blank IS NOT NULL {condition}"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> _:' || {ssc} || {sep}          || o_blank::text     || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_blank IS NOT NULL {condition}"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NULL AND datatype IS NULL {condition}"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '@'   || language || ' .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND language IS NOT NULL {condition}"),
            self.session_execute(f"SELECT '_:' || {ssc} || {sep} || s_blank::text || ' <' || p || '> '   || to_json(o_lit)::text    || '^^<' || datatype || '> .\n' "
                                 f"FROM triples WHERE s_blank IS NOT NULL AND o_lit IS NOT NULL AND datatype IS NOT NULL {condition}"),
            )

    def getExistingIris(self):
        sql = 'SELECT * FROM existing_iris'
        return self.session_execute(sql)

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
        resp = list(self.session_execute(sql, args))
        return resp

    def getExistingIrisForIlxId(self, *ilx_ids):
        args = dict(ilx_ids=list(ilx_ids))
        sql = ('SELECT i, iri FROM unnest(ARRAY[:ilx_ids]) WITH ORDINALITY i '
               'JOIN existing_iris ON i = ilx_id')
        resp = list(self.session_execute(sql, args))
        return resp

    def getNamesFirstLatest(self, *iris):
        args = dict(uris=iris)
        sql = '''
select n.name, nti.type, n.first_seen as n_first_seen, ids.identity, ids.first_seen as i_first_seen
from names as n
left join name_to_identity as nti on n.name = nti.name
join identities as ids on ids.identity = nti.identity
where n.name in :uris
'''
        names_first_seen = {}
        for r in self.session_execute(sql, args):
            if r.name in names_first_seen:
                names_first_seen[r.name]['type'].append(r.type)
            else:
                names_first_seen[r.name] = {}

        breakpoint()
        return names_first_seen

    def getReplicasByIdentity(self, identity):
        # XXX this should probably not be used, there should be a join variant that will properly attach the replicas for the given identity and produce ALL the duplicated triples in a single pass
        args = dict(identity=identity)
        sql = '''
        select * from subgraph_replicas where graph_bnode_identity = :identity
        '''
        resp = list(self.session_execute(sql, args))
        return resp

    _gclc_stuff = '''
), gclc_idtys_direct as (
  select ids.identity
  from identities as ids
  join name_to_identity as nti on nti.identity = ids.identity
  where ids.type = 'graph_combined_local_conventions' and nti.type = :type and nti.name = :name
  order by first_seen desc limit 1
), gclc_idtys as (
  select ids.identity
  from identity_relations as irs
  right join identities as ids on irs.o = ids.identity
  where ids.identity in (select * from gclc_idtys_direct) or
        irs.p = 'parsedTo' and(ids.type = 'graph_combined_local_conventions') and irs.s in (select * from ser_idtys)
'''
    def getLatestIdentityByName(self, name, type='bound'):
        args = dict(name=name, type=type)
        sql = f'''
with ser_idtys as (
  select ids.identity
  from identities as ids
  join name_to_identity as nti on nti.identity = ids.identity
  where ids.type = 'serialization' and nti.type = :type and nti.name = :name
  order by first_seen desc limit 1 -- only the most recently first seen identity (not always accurate if we ingest earlier versions later in time, but in principle we can insert a first seen value manually)
{self._gclc_stuff}
)
select * from gclc_idtys
'''
        resp = list(self.session_execute(sql, args))
        if resp:
            return resp[0][0].tobytes()

    def getCuriesByName(self, name, type='bound', serialization_identity=None):
        if serialization_identity is None:
            args = dict(name=name, type=type)
            _sql_ser_idtys = '''
  select ids.identity
  from identities as ids
  join name_to_identity as nti on nti.identity = ids.identity
  where ids.type = 'serialization' and nti.type = :type and nti.name = :name
  order by first_seen desc limit 1 -- only the most recently first seen identity (not always accurate if we ingest earlier versions later in time, but in principle we can insert a first seen value manually)
'''

        else:
            args = dict(serialization_identity=serialization_identity, type=None, name=None)
            _sql_ser_idtys = 'select :serialization_identity'


        sql = f'''
with ser_idtys as (
{_sql_ser_idtys}
{self._gclc_stuff}
), lc_idtys as (
  select irs.o
  from identity_relations as irs
  join identities as ids on irs.o = ids.identity
  where irs.p = 'hasLocalConventions' and(ids.type = 'local_conventions') and irs.s in (select * from gclc_idtys)
)
select c.curie_prefix, c.iri_namespace
from curies as c
where c.local_conventions_identity in (select * from lc_idtys)
'''
        resp = list(self.session_execute(sql, args))
        return resp

    def getCuriesBySerializationIdentity(self, serialization_identity):
        return self.getCuriesByName(None, None, serialization_identity=serialization_identity)

    def getGraphByName(self, name, type='bound', serialization_identity=None):
        # defaults to latest probably
        # FIXME need to do a query to get the latest first and then call getGraphByIdentity instead of the direct way we do it here, but this is ok for now
        # if we ran this once there were multiple identities pulled in we would serialize all versions into a single file

        if serialization_identity is None:
            args = dict(name=name, type=type)
            _sql_ser_idtys = '''
  select ids.identity
  from identities as ids
  join name_to_identity as nti on nti.identity = ids.identity
  where ids.type = 'serialization' and nti.type = :type and nti.name = :name
  order by first_seen desc limit 1 -- only the most recently first seen identity (not always accurate if we ingest earlier versions later in time, but in principle we can insert a first seen value manually)
'''

        else:
            args = dict(serialization_identity=serialization_identity, name=None, type=None)
            _sql_ser_idtys = 'select :serialization_identity'

        _sql_common = f'''
with ser_idtys as (
{_sql_ser_idtys}
{self._gclc_stuff}
), gc_idtys as (
  select irs.o
  from identity_relations as irs
  join identities as ids on irs.o = ids.identity
  where irs.p = 'hasGraph' and(ids.type = 'graph_combined') and irs.s in (select * from gclc_idtys)
), named_idtys as (
  select irs.o
  from identity_relations as irs
  join identities as ids on irs.o = ids.identity
  where irs.p = 'hasNamedGraph' and(ids.type = 'named_embedded_seq') and irs.s in (select * from gc_idtys)
), bnode_idtys as (
  select irs.o
  from identity_relations as irs
  join identities as ids on irs.o = ids.identity
  where irs.p = 'hasBnodeGraph' and (ids.type = 'bnode_conn_free_seq') and irs.s in (select * from gc_idtys)
), subgraph_idtys as (
  select irs.o
  from identity_relations as irs
  join identities as ids on irs.o = ids.identity
  where
  irs.p = 'hasBnodeRecord' and
  ids.type = 'bnode_condensed' and
  irs.s in (select * from bnode_idtys)
), reps as (
  select * from subgraph_replicas as sr1
  where sr1.graph_bnode_identity in (select * from bnode_idtys)
), deds as (
  select * from subgraph_deduplication as sd1
  where sd1.graph_bnode_identity in (select * from bnode_idtys)
)
'''
        _old_sql = f'''{_sql_common}
select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity, null::integer as subgraph_replica, null::bytea as object_subgraph_identity, null::integer as object_replica
from identity_relations as ird
join identity_named_triples_ingest as inti on ird.o = inti.named_embedded_identity
join triples as t on inti.triple_identity = t.triple_identity
where ird.p = 'hasNamedRecord' and ird.s in (select * from named_idtys)

UNION

select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity, sr.replica as subgraph_replica , sd.object_subgraph_identity, sd.object_replica
from subgraph_idtys as si
join triples as t on si.o = t.subgraph_identity
-- NOTE join reps -> all replicas, left join reps -> none with risk of extra conn trips
join reps as sr on sr.subgraph_identity = t.subgraph_identity and ((t.s is null and sr.s is null) or (sr.s = t.s and sr.p = t.p))
left join deds as sd on sd.subject_subgraph_identity = sr.subgraph_identity and sd.subject_replica = sr.replica and sd.o_blank = t.o_blank

'''
        _sql_new_part_1 = f'''{_sql_common}
select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language
from identity_relations as ird
join identity_named_triples_ingest as inti on ird.o = inti.named_embedded_identity
join triples as t on inti.triple_identity = t.triple_identity
where t.s is not null and t.triple_identity is not null and ird.p = 'hasNamedRecord' and ird.s in (select * from named_idtys)
'''
        _sql_new_part_1_1 = f'''{_sql_common}
select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity, sr.replica as subgraph_replica, sd.object_subgraph_identity as object_subgraph_identity, sd.object_replica as object_replica
from triples as t
join reps as sr on t.s = sr.s and t.p = sr.p and t.subgraph_identity = sr.subgraph_identity
left join deds as sd on sd.subject_subgraph_identity = sr.subgraph_identity and sd.subject_replica = sr.replica and sd.o_blank = t.o_blank
where t.s is not null and sr.s is not null and t.subgraph_identity is not null
'''
        _sql_new_part_2 = f'''{_sql_common}
select
t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity
from triples as t
where t.s is null and t.subgraph_identity is not null and t.subgraph_identity in (select * from subgraph_idtys)
'''
        _sql_new_part_3 = f'''{_sql_common}
select
sr.s, sr.p, sd.o_blank, sr.subgraph_identity, sr.replica, sd.object_subgraph_identity, sd.object_replica
from reps as sr
left join deds as sd on sr.subgraph_identity = sd.subject_subgraph_identity and sr.replica = sd.subject_replica
'''
        # TODO the other option is to batch out the subgraphs i think?
        yield from self.session_execute(_sql_new_part_1, args)
        #resp1 = list(self.session_execute(_sql_new_part_1, args))
        #resp1 = [(*r, None, None, None) for r in _resp1]  # kwargs handle the nones
        yield from self.session_execute(_sql_new_part_1_1, args)
        #resp1_1 = list(self.session_execute(_sql_new_part_1_1, args))

        resp3 = self.session_execute(_sql_new_part_3, args)
        #resp3 = list(self.session_execute(_sql_new_part_3, args))
        lu = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
        for r in resp3:
            if r.object_replica is None:
                lu[r.subgraph_identity][r.replica]
            else:
                lu[r.subgraph_identity][r.replica][r.o_blank] = (r.object_subgraph_identity, r.object_replica)

        resp2 = self.session_execute(_sql_new_part_2, args)
        #resp2 = list(self.session_execute(_sql_new_part_2, args))
        #derp = []
        for r in resp2:
            for replica, o_blanks in lu[r.subgraph_identity].items():
                if r.o_blank in o_blanks:
                    object_subgraph_identity, object_replica = o_blanks[r.o_blank]
                    nr = (None, *r, replica, object_subgraph_identity, object_replica)
                else:
                    nr = (None, *r, replica, None, None)

                yield nr
                #derp.append(nr)

    def getGraphBySerializationIdentity(self, serialization_identity):
        return self.getGraphByName(None, None, serialization_identity=serialization_identity)

    def getGraphByIdentity(self, identity):
        # TODO smart version that will search the identities table to
        # find whether such an identity exists and then dispatch to
        # identity relations based on that identity
        raise NotImplementedError('TODO')

    def _broken_getBySubject(self, subject, user):
        # this is completely broken since it doesn't recursively retrieve subgraphs where oblank > 1
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

        resp = list(self.session_execute(sql, args))
        return resp

    def getBySubject(self, subject, user):
        args = dict(uri=subject)
        sql = '''
with recursive subgraphs(/*triple_identity,*/ s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity, next_subgraph_identity) AS (
    SELECT /*sg.triple_identity,*/ sg.s, sg.s_blank, sg.p, sg.o,
           sg.o_lit, sg.datatype, sg.language,
           sg.o_blank, sg.subgraph_identity,
           sd.object_subgraph_identity as next_subgraph_identity
    FROM triples as sg
    LEFT OUTER JOIN subgraph_deduplication as sd on sg.subgraph_identity = sd.subject_subgraph_identity and sg.o_blank = sd.o_blank
    WHERE sg.s = :uri
    UNION ALL
    SELECT /*tsg.triple_identity,*/ tsg.s, tsg.s_blank, tsg.p, tsg.o,
           tsg.o_lit, tsg.datatype, tsg.language,
           tsg.o_blank, tsg.subgraph_identity,
           sd.object_subgraph_identity as next_subgraph_identity
    FROM subgraphs as sgs
    JOIN triples as tsg on
        (tsg.s is null or
         tsg.s = :uri
        ) and (
         tsg.subgraph_identity = sgs.next_subgraph_identity
         or (sgs.subgraph_identity = tsg.subgraph_identity and tsg.s_blank is not null and tsg.s_blank >= sgs.o_blank))
    LEFT OUTER JOIN subgraph_deduplication as sd on
         tsg.subgraph_identity = sd.subject_subgraph_identity and tsg.o_blank = sd.o_blank
)
select distinct * from subgraphs
'''
        # FIXME for some reason this hangs forever if there is no result? no looks like a wierd restart bug
        gen = self.session_execute(sql, args)
        resp = list(gen)
        return resp

    def getVerVarBySubject(self, subject):
        # get metadata for all sources that contain a subject
        args = dict(uri=subject)
        # FIXME we need a variant of the sources query that starts
        # from the triplesets query results for easier mapping
        old_source_sql = '''
with recursive id_parent(s, p) as (
select irs0.s, irs0.p from identity_relations as irs0 where irs0.o in
(
with starts as (
select named_embedded_identity from
triples as t
join identity_named_triples_ingest as inti on t.triple_identity = inti.triple_identity
where t.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' and t.s = :uri
)
select named_embedded_identity from starts
)
and irs0.p != 'hasEquivalent'
union all
select irs.s, irs.p from identity_relations as irs
join id_parent as ip on irs.o = ip.s
and irs.p != 'hasEquivalent'
)
select distinct ids.identity, ids.first_seen, t.*
from id_parent as idp
join identities as ids on ids.identity = idp.s
join identity_relations as irsf0 on irsf0.p = 'hasMetadataGraph' and irsf0.s = idp.s
join identity_relations as irsf1 on irsf1.p = 'hasNamedRecord' and irsf1.s = irsf0.o -- for this use case the named metadata record subset is sufficient
join identity_named_triples_ingest as inti on inti.named_embedded_identity = irsf1.o
join triples as t on t.triple_identity = inti.triple_identity
where ids.type in ('serialization', 'graph_combined_local_conventions')
'''
        # TODO next step is to also collect graph_bnode_identity for all triples as well we the named triples
        # we only need to go from the union of subgraph_identity to the the union of graph_bnode_identity
        # and check the intersection of those with the named graph parents i think
        triples_sql = '''
with recursive subgraphs(triple_identity, s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity, next_subgraph_identity) AS (
    SELECT sg.triple_identity, sg.s, sg.s_blank, sg.p, sg.o,
           sg.o_lit, sg.datatype, sg.language,
           sg.o_blank, sg.subgraph_identity,
           sd.object_subgraph_identity as next_subgraph_identity
    FROM triples as sg
    LEFT OUTER JOIN subgraph_deduplication as sd on sg.subgraph_identity = sd.subject_subgraph_identity and sg.o_blank = sd.o_blank
    WHERE sg.s = :uri
    UNION ALL
    SELECT tsg.triple_identity, tsg.s, tsg.s_blank, tsg.p, tsg.o,
           tsg.o_lit, tsg.datatype, tsg.language,
           tsg.o_blank, tsg.subgraph_identity,
           sd.object_subgraph_identity as next_subgraph_identity
    FROM subgraphs as sgs
    JOIN triples as tsg on
        (tsg.s is null or
         tsg.s = :uri
        ) and (
         tsg.subgraph_identity = sgs.next_subgraph_identity
         or (sgs.subgraph_identity = tsg.subgraph_identity and tsg.s_blank is not null and tsg.s_blank >= sgs.o_blank))
    LEFT OUTER JOIN subgraph_deduplication as sd on
         tsg.subgraph_identity = sd.subject_subgraph_identity and tsg.o_blank = sd.o_blank
)
select distinct * from subgraphs
order by subgraph_identity, o_blank, p
'''

        tripsets_sql = '''
select * from (
select t.triple_identity as ident, irs1.s, irs1.p --, ids.type
-- inti.named_embedded_identity, NULL as p
from triples as t
join identity_named_triples_ingest as inti on t.triple_identity = inti.triple_identity
join identity_relations as irs on irs.o = inti.named_embedded_identity
join identity_relations as irs1 on irs1.o = irs.s
join identities as ids on ids.identity = irs1.s
where
t.s = :uri
)
where p != 'hasMetadataGraph' -- amazingly this does NOT have the perf clif!
order by p, ident, s
'''

        ts_src_common = f'''
with recursive id_parent(s, p, o) as (
select irs0.s, irs0.p, irs0.o from identity_relations as irs0 where irs0.o in
(
with starts as (
-- FIXME fails for spec
{tripsets_sql}
)
select s from starts
)
and irs0.p != 'hasEquivalent'
union all
select irs.s, irs.p, ip.o from identity_relations as irs
join id_parent as ip on irs.o = ip.s
and irs.p != 'hasEquivalent'
)
'''
        ts_src_common2 = '''
from id_parent as idp
join identities as ids on ids.identity = idp.s
join identity_relations as irsf0 on irsf0.p = 'hasMetadataGraph' and irsf0.s = idp.s
'''
        ts_src_common3 = '''
where ids.type in ('serialization', 'graph_combined_local_conventions')
'''

        ts_to_source_sql = f'''{ts_src_common}
select distinct idp.o as gstart, ids.identity, ids.type, ids.first_seen
{ts_src_common2}
{ts_src_common3}
'''

        source_named_sql = f'''{ts_src_common}
select distinct ids.identity,
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity
{ts_src_common2}
join identity_relations as irsf1 on irsf1.p = 'hasNamedRecord' and irsf1.s = irsf0.o -- for this use case the named metadata record subset is sufficient
join identity_named_triples_ingest as inti on inti.named_embedded_identity = irsf1.o
join triples as t on t.triple_identity = inti.triple_identity
{ts_src_common3}
'''

        def f(g):
            from collections import namedtuple
            sigh = []
            for r in g:
                args = tuple(c.tobytes().hex() if isinstance(c, memoryview) else c for c in r)
                sigh.append(args)

            if not sigh:
                return []

            nt = namedtuple('rowthing', r._fields)
            out = [nt(*s) for s in sigh]
            return out

        source_named_resp = f(self.session_execute(source_named_sql, args))
        ts_to_source_resp = f(self.session_execute(ts_to_source_sql, args))
        tripsets_resp = f(self.session_execute(tripsets_sql, args))
        triples_resp = f(self.session_execute(triples_sql, args))
        return source_named_resp, ts_to_source_resp, tripsets_resp, triples_resp

    def getById(self, frag_pref, id, user):
        """ return all triples associated with an interlex id (curie suffix) """
        uri = f'http://uri.interlex.org/base/{frag_pref}_{id}'  # FIXME reference_host from db ...
        args = dict(uri=uri, prefix=frag_pref, id=id, p=str(ilxtr.hasExistingId))
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

        # FIXME TODO this needs to be rewritten to work with the history tables
        sql = '''
        WITH graph AS (
            SELECT s, s_blank, p, o, o_lit, datatype, language, o_blank, subgraph_identity
            FROM triples as t JOIN existing_iris as e
            ON s = iri
            WHERE ilx_prefix = :prefix AND ilx_id = :id
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
        UNION SELECT :uri, NULL, :p, iri, NULL, NULL, NULL, NULL, NULL FROM existing_iris WHERE ilx_prefix = :prefix AND ilx_id = :id;
        '''
        # FIXME serialization choices means that any and all ilx ids that are pulled out from here need
        # to have their existing ids pulled in as well, it is just easy to get the existing of the primary
        # in a single query here
        # FIXME is it worth considering not using base but instead using s_ilx p_ilx, and o_ilx since they they have known size?

        sql2 = f'''
        SELECT *
            FROM ({sql}) as sq
            LEFT JOIN existing_iris
            ON ilx_prefix = ilxPrefixFromIri(sq.o) AND ilx_id = ilxIdFromIri(sq.o)
            WHERE uri_host(sq.o) = reference_host();  -- OR TRUE; -- works but super slow
        '''

        sql3 = f'''
        WITH woo AS ({sql})
        SELECT * FROM woo JOIN ...
        '''


        if not hasattr(self.sql, 'getById'):
            self.sql.getById = sql

        resp = list(self.session_execute(self.sql.getById, args))
        return resp

    def getGraphFromSubjects(self, subjects, at_identity=None, expansion_rules=None):
        # TODO yeah ... at_identity is why we are still going to need something
        # closer to git for constructing theh total history for perspectives
        args = dict(subjects=tuple(subjects))
        sql = '''
select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity
-- sr.replica as subgraph_replica, sd.object_subgraph_identity as object_subgraph_identity, sd.object_replica as object_replica
from triples as t
where t.s in :subjects and t.triple_identity is not null

union

select
t.s, t.s_blank, t.p, t.o, t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity
from triples as ta
join triples as t on t.subgraph_identity = ta.subgraph_identity
where ta.s in :subjects
and ta.subgraph_identity is not null
and t.subgraph_identity is not null
'''
        return list(self.session_execute(sql, args))

    def generateOntologyFromSpec(self, spec):
        # TODO reduce roundtrips to 1 and deal with history/versions

        # 1. get latest head identity
        # 2. ...
        # 3. profit!

        #li = self.getLatestIdentityByName(spec)  # already done internally in getGraphByName
        spec_graph_rows = list(self.getGraphByName(spec))  # XXX TODO for now there should be no blanknodes in here
        if not spec_graph_rows:
            return

        pred = ilxtr['include-subject']  # FIXME TODO ilxr:includesSubject -> current ilx for includesTerm
        spred = str(pred)
        # TODO other config options if relevant
        subjects = [r.o for r in spec_graph_rows if r.p == spred]
        # TODO also pull dc title over and TODO maybe even insert it into the ontology metadata record itself
        graph_rows = self.getGraphFromSubjects(subjects)
        return graph_rows
        #breakpoint()
        #args = dict(name=spec)
        #return list(self.session_execute(sql, args))

    def getUnmappedByGroupUriPath(self, group, path, read_private, redirect=False):
        # XXX this should only be called via the api if the auth layer
        # has passed because the user matches or the user has been
        # granted at least the ability to view that groups scratch
        # space, that is the view role, and it is for all uris
        # TODO the most a single user can grant for another user
        # is view

        assert read_private  # read_private is included as a double sanity check

        resp = self.getByGroupUriPath(group, path)  # FIXME dump should not be returning for flask directly
        if resp:
            return resp

        args = dict(group=group, path=path)
        sql = ('SELECT uri FROM uris WHERE perspective = persFromGroupname(:group) '
               'AND uri_path = :path')

        gen = self.session_execute(sql, args)
        try:
            guri = next(gen)
            uri = guri.uri
        except StopIteration:
            return tuple()

        return self.getBySubject(f'http://{self.reference_host}/{group}/uris/{path}', group)

    def getByGroupUriPath(self, group, path, redirect=False):  # TODO bulk versions of these
        args = dict(group=group, path=path)
        sql = ('SELECT ilx_id FROM uri_mapping WHERE perspective = persFromGroupname(:group) '
               'AND uri_path = :path')
        # TODO handle the unmapped case (currently literally all of them)
        gen = self.session_execute(sql, args)
        try:
            guri = next(gen)
            ilx_prefix = guri.ilx_prefix
            ilx_id = guri.ilx_id
        except StopIteration:
            return tuple()
        # since group_id and uri_path are the primary key
        # each path will map to only 1 ilx_id
        # we also constrain group_id + ilx_id to be unique

        if redirect:
            return ilx_prefix, ilx_id
        else:
            return self.getById(group, ilx_prefix, ilx_id)

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

    def getTopLevelRdfTypes(self):
        sql = '''
SELECT distinct t.o
FROM triples AS t
WHERE t.s IS NOT NULL AND t.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' AND t.o IS NOT NULL
EXCEPT
SELECT distinct ta.o
FROM triples AS tn
JOIN triples AS ta ON ta.s = tn.s AND ta.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' AND ta.o IS NOT NULL
WHERE tn.s IS NOT NULL AND tn.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' AND tn.o = 'http://www.w3.org/2002/07/owl#NamedIndividual'
'''
        return list(self.session_execute(sql))

    def getObjectsForPredicates(self, iris, *predicates):
        if not iris:
            raise ValueError('iris should not be empty')

        args = dict(p=predicates, iris=tuple(iris))  # FIXME normalize here or there?
        sql = 'SELECT s, o_lit FROM triples WHERE p in :p AND s in :iris'
        for r in self.session_execute(sql, args):
            yield r.s, r.o_lit  # with multiple iris we have to keep track of the mapping

    def getLabels(self, user, iris):
        if not iris:
            raise ValueError('iris should not be empty')

        yield from self.getObjectsForPredicates(iris, rdfs.label)  # FIXME alts?

    def getDefinitions(self, user, *iris):
        # TODO aggregate/failover to defs from alternate sources where the ilx_id has an existing id
        # requires a different yielding strat
        #value_templates, params = makeParamsValues(iris)
        yield from self.getObjectsForPredicates(
            iris, definition, skos.definition,
            # fma.definition
            rdflib.URIRef('http://purl.org/sig/ont/fma/definition'),)

    def getByLabel(self, label, user):
        # TODO user mapping of lexical
        args = dict(p=rdfs.label, label=label.lower())
        #sql = f'SELECT s FROM triples WHERE p = :p AND o_lit ~~* :label'  # ~~* is LIKE case insensitive
        sql = 'SELECT DISTINCT s FROM triples WHERE s IS NOT NULL AND p = :p AND LOWER(o_lit) LIKE :label'
        # we can sort out the case sensitivity later if it is an issue
        results = [r.s for r in self.session_execute(sql, args)]
        if not results:
            # NOTE if ambiguation is done by a user, then they keep that mapping
            return False, None  # redlink? ambiguate
        elif len(results) == 1:
            return True, results[0]  # redirect
        else:
            _defs = {s: d for s, d in self.getDefinitions(user, *results)}
            defs = [(s, _defs[s]) if s in _defs else (s, '') for s in results]
            return False, defs  # disambiguate

    def getCurrentLabelExactIlx(self, *o_lits):
        args = dict(o_lits=tuple(o_lits))
        sql = 'SELECT distinct * FROM (SELECT prefix, id FROM current_interlex_labels_and_exacts WHERE o_lit in :o_lits)'
        return list(self.session_execute(sql, args))

    def getTriplesById(self, *triples_ids):
        # when using IN directly we don't have to convert to a list first
        # unlike in the unnest case
        yield from self.session_execute('SELECT * FROM triples WHERE id IN :triples_ids',
                                        dict(triples_ids=triples_ids))

    def tripleIdentity(self, *triples_ids):
        """ light wrapper around built in function """
        for (identity,) in self.session_execute('SELECT tripleIdentity(id)'
                                                'FROM unnest(ARRAY[:triples_ids]) '
                                                'WITH ORDINALITY id',
                                                dict(triples_ids=list(triples_ids))):
            yield identity

    def getTransitive(self, subjects, predicates, obj_to_sub=False, depth=None):
        # TODO need a way to indicate how much metadata to include
        args = dict(subjects=list(subjects), predicates=list(predicates), obj_to_sub=obj_to_sub, depth=-1 if depth is None else depth)
        sql = '''
with cp as (select * from connected_predicates_ilx(:subjects, :predicates, :obj_to_sub, :depth))
, need_lbls as (select distinct s as e from cp union select distinct p as e from cp union select distinct o as e from cp)
, out as (
select cp.s, cp.p, cp.o, null as o_lit, null as datatype, null as language, cp.ident from cp union
select distinct t.s, t.p, t.o, t.o_lit, t.datatype, t.language, t.triple_identity as ident
from triples as t join need_lbls as nl on t.s = nl.e and (t.p = 'http://www.w3.org/2000/01/rdf-schema#label'
        or t.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type')
)
select * from out
order by p, o, o_lit
'''
        return list(self.session_execute(sql, args, [bindparam('subjects', type_=ARRAY(uri)),
                                                     bindparam('predicates', type_=ARRAY(uri)),]))
