import re
from collections import defaultdict
import rdflib
from sqlalchemy import create_engine, inspect
from sqlalchemy.sql import text as sql_text
from pyontutils import combinators as cmb
from pyontutils.core import OntId, OntGraph
from pyontutils.utils_fast import chunk_list
from pyontutils.namespaces import ILX, ilxtr, oboInOwl, owl, rdf, rdfs
from pyontutils.namespaces import definition, replacedBy, makeURIs
from interlex import alt
from interlex import config
from interlex import exceptions as exc
from interlex.core import synonym_types, dbUri, makeParamsValues
from interlex.dump import Queries, MysqlExport
from interlex.load import TripleLoaderFactory, do_gc
from interlex.utils import log as _log
from interlex.namespaces import ilxr
from interlex.ingest import process_triple_seq, do_process_into_session

log = _log.getChild('sync')


# get interlex
class InterLexLoad:

    stype_lookup = synonym_types

    def __init__(self, db, do_cdes=False, debug=False, batchsize=20000):
        # batchsize tested at 20k, 40k, and 80k, 20k runs slightly faster than the other two
        # and does it with significantly less memory usage (< 1 gig)
        self._db = db
        self.batchsize = batchsize
        TripleLoader = TripleLoaderFactory(db.session)
        self.loader = TripleLoader('tgbugs', 'tgbugs', 'http://uri.interlex.org/base/ontologies/interlex')

        self.queries = Queries(self.loader.session)
        self.do_cdes = do_cdes
        self.debug = debug
        self.admin_engine = create_engine(dbUri(dbuser='interlex-admin'), echo=True)
        kwargs = {k: config.auth.get(f'alt-db-{k}')
                  for k in ('user', 'host', 'port', 'database')}
        if kwargs['database'] is None:
            msg = 'alt-db-database is None, did you remember to set one?'
            raise ValueError(msg)

        self.engine = create_engine(alt.dbUri(**kwargs), echo=True)
        dbconfig = None
        del(dbconfig)
        self.insp = inspect(self.engine)
        self.graph = None

    def setup(self):
        self.existing_ids()
        self.user_iris()
        self.make_triples()
        self.ids()

    @exc.bigError
    def local_load(self):
        loader = self.loader
        def lse(s, p, load_type='???'):
            # accepts two lists of equal length
            assert len(s) == len(p)
            n = len(p)
            log.debug(f'starting batch load for {load_type}')
            do_gc()  # pre/post is sufficient to stay stable, a bit of creep toward the end of a batch but it goes back down
            for i, (sql, params) in enumerate(zip(s, p)):
                loader.session.execute(sql_text(sql), params)
                loader.session.execute(sql_text(f'savepoint {load_type}'))
                msg = f'{((i + 1) / n) * 100:3.0f}% done with batched load of {load_type}'
                log.debug(msg)

            do_gc()

        # start sitting at around 10 gigs in pypy3 (oof)
        # now stays below 8 gigs in pypy3, and below about 1gig in postgres with 40k batch size, much better, 600mb at 20k
        lse(self.ilx_sql, self.ilx_params, 'interlex_ids')  # 3 gigs in postgres no batching
        lse(self.eid_sql, self.eid_params, 'existing_iris')  # 16.4 gigs in postgres with no batching
        lse(self.uid_sql, self.uid_params, 'uris')

        # FIXME this probably requires admin permissions
        vt, params = makeParamsValues(list(self.current.items()))
        #with self.admin_engine.connect() as conn:
            #conn.execute(sql_text(f"SELECT setval('interlex_ids_seq', {self.current}, TRUE)"))  # DANGERZONE
        with self.admin_engine.connect() as conn:  # calling UPDATE on this without the function requires admin (sensibly)
            conn.execute(sql_text(
                'INSERT INTO fragment_prefix_sequences (prefix, suffix_max) '
                f'VALUES {vt} ON CONFLICT (prefix) DO UPDATE '
                'SET suffix_max = EXCLUDED.suffix_max '
                'WHERE fragment_prefix_sequences.prefix = EXCLUDED.prefix'),
                         params)

        #lse([('INSERT INTO fragment_prefix_sequences (prefix, suffix_max) '
            #f'VALUES {vt} ON CONFLICT (prefix) DO UPDATE '
            #'SET suffix_max = EXCLUDED.suffix_max '
            #'WHERE fragment_prefix_sequences.prefix = EXCLUDED.prefix')], [params])

    @exc.bigError
    def local_load_part2(self):
        if self.graph is None:
            from pyontutils.namespaces import PREFIXES as uPREFIXES
            self.graph = OntGraph()
            self.graph.namespace_manager.populate_from(uPREFIXES)
            for t in self.triples:
                try:
                    self.graph.add(t)
                except AssertionError as e:
                    msg = f'bad type in {t}'
                    raise TypeError(msg) from e

        self.loader._graph = self.graph
        name = rdflib.URIRef('http://toms.ilx.dump/TODO')
        self.loader.Loader._bound_name = name
        #self.loader.expected_bound_name = name
        self.loader._serialization = repr((name, 'lol not a real serialization at all')).encode()  # self.triples  # FIXME TODO not everything has a serialization identity
        self.loader.name = name  # avoid name = None error, has to be set manually right now since we use TripleLoader directly
        expected_bound_name = name
        setup_failed = self.loader(expected_bound_name)

        if setup_failed is not None:
            raise exc.LoadError(setup_failed)

    @exc.bigError
    def remote_load(self):
        # FIXME there STILL should not be 5 gigs of memory in use at this point when we start :/
        self.loader.load()
        log.debug('Yay!')

    def load(self):
        do_process_into_session(self._db.session, process_triple_seq, self.triples,
                                commit=False, batchsize=self.batchsize, debug=True)
        self.local_load()
        #self.local_load_part2()
        #self.remote_load()

    def ids(self):
        with self.engine.connect() as conn:
            rows = conn.execute(sql_text('SELECT DISTINCT ilx, label FROM terms ORDER BY ilx ASC'))

        values = [(row.ilx[:3], row.ilx[4:], row.label) for row in rows]
        self.ilx_sql = []
        self.ilx_params = []
        for chunk in chunk_list(values, self.batchsize):
            vt, params = makeParamsValues(chunk)
            sql = 'INSERT INTO interlex_ids (prefix, id, original_label) VALUES ' + vt + ' ON CONFLICT DO NOTHING'  # FIXME BAD
            self.ilx_sql.append(sql)
            self.ilx_params.append(params)

        prefixes = set(v[0] for v in values)
        self.current = {p:int([v for v in values if v[0] == p][-1][1]) for p in prefixes}
        #self.current = int(values[-1][1].strip('0'))
        log.debug(self.current)

    def cull_bads(self, eternal_screaming, values, ind):
        verwat = defaultdict(list)
        for row in sorted(eternal_screaming, key=lambda r:r.version, reverse=True):
            #row[ind('ilx')][4:]
            pref, ilx = row.ilx[:3], row.ilx[4:]
            verwat[pref, ilx].append(row)

        vervals = list(verwat.values())

        ver_curies = defaultdict(lambda:[None, set()])
        for (pref, ilx), rows in verwat.items():
            for row in rows:
                iri = row.iri  # row[ind('iri')]
                curie = row.curie  # [ind('curie')]
                ver_curies[iri][0] = (pref, ilx)
                ver_curies[iri][1].add(curie)

        mult_curies = {k: v for k, v in ver_curies.items() if len(v[1]) > 1}

        maybe_mult = defaultdict(list)
        versions = defaultdict(list)
        for pref, ilx, iri, ver in sorted(values, key=lambda t: t[-1], reverse=True):
            versions[pref, ilx].append(ver)
            maybe_mult[iri].append((pref, ilx))

        multiple_versions = {k:v for k, v in versions.items() if len(set(v)) > 1}
        # if there are multiple iris they would be caught in the other steps
        # these will be the ones that have the same iri in multiple versions
        bad_versions = set((pref, ilx, nmv) for (pref, ilx), vs in multiple_versions.items() for nmv in sorted(vs)[:-1])

        any_mult = {k:v for k, v in maybe_mult.items() if len(v) > 1}

        dupe_report = {k:tuple(f'http://uri.interlex.org/base/{p}_{i}' for p, i in v)
                       for k, v in maybe_mult.items()
                       if len(set(v)) > 1}
        readable_report = {OntId(k):tuple(OntId(e) for e in v)
                           for k, v in dupe_report.items()}
        log.debug('obvious duplicate report')
        _ = [print(repr(k), '\t', *(f'{e!r}' for e in v))
             for k, v in sorted(readable_report.items())]

        dupes = tuple(dupe_report) + tuple(mult_curies)

        # dupes = [u for u, c in Counter(_[1] for _ in values).most_common() if c > 1]  # picked up non-unique ilx which is not what we wanted

        skips = []
        bads = []
        bads += [(p, a, b) for p, a, b, _ in values if b in dupes]
        # TODO one of these is incorrect can't quite figure out which, so skipping entirely for now
        for pref, id_, iri, version in values:  # FIXME
            if ' ' in iri:  # sigh, skip these for now since pguri doesn't seem to handled them
                bads.append((pref, id_, iri))
            elif 'neurolex.org/wiki' in iri:
                skips.append((pref, id_, iri))

        bads = sorted(bads, key=lambda ab:ab[1])
        # XXX reminder: values comes from start_values and already excludes self referential external ids
        _ins_values = [
            (pref, ilx, iri) for pref, ilx, iri, ver in values if
            (pref, ilx, iri) not in bads and
            (pref, ilx, iri) not in skips and
            (pref, ilx, ver) not in bad_versions]
        ins_values = [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' not in iri]
        user_iris = [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' in iri and 'org/base/' not in iri]
        # base are excluded because existing_iris only refer out HOWEVER
        # how do we deal with deprecated, I don't the we even had a process in place
        # for this when i was working on this before
        # FIXME TODO pretty much all the base_iris need to be inserted somewhere at least
        # i think they go in a deprecation table for speed or something? except that the
        # terms do exist, I guess one thing to note about the operations of interlex as
        # a whole is that merges are kind of made globally, except that the existing iris
        # table is technically per perspective ... ugh what a mess ... the basic rules
        # apply, in that the old interlex allowed duplicate labels, so there are deprecations
        # sometimes there will be for this iteration as well ... but the question of how to
        # to it needs significantly more though, so for how we are going to stick the info
        # in the triples table and LET THE QUERIER SORT EM OUT
        base_iris = [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' in iri and 'org/base/' in iri]
        replacedBys = [(  # this should be injective by construction all the violations should be in bads of one kind or another
            rdflib.URIRef(eid),
            replacedBy,
            rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),
            ) for pref, ilx, eid in base_iris]
        assert len(ins_values) + len(user_iris) + len(base_iris) == len(_ins_values)
        #ins_values += [(v[0], k) for k, v in mult_curies.items()]  # add curies back now fixed
        if self.debug:
            breakpoint()
        return ins_values, bads, skips, user_iris, replacedBys

    def existing_ids(self):
        insp, engine = self.insp, self.engine

        terms = [c['name'] for c in insp.get_columns('terms')]
        term_existing_ids = [c['name'] for c in insp.get_columns('term_existing_ids')]
        header = term_existing_ids + terms

        def ind(name):
            if name in header:
                return header.index(name)
            else:
                raise IndexError()

        with engine.connect() as conn:
            if self.do_cdes:
                query = conn.execute(
                    sql_text(
                        'SELECT * FROM term_existing_ids as teid '
                        'JOIN terms as t '
                        'ON t.id = teid.tid'))
            else:
                query = conn.execute(
                    sql_text(
                        'SELECT * FROM term_existing_ids as teid '
                        'JOIN terms as t '
                        'ON t.id = teid.tid WHERE t.type != "cde"'))

        #data = query.fetchall()
        #cdata = list(zip(*data))

        #def datal(head):
            #return cdata[header.index(head)]

        #values = [(row.ilx[4:], row.iri, row.version) for row in query if row.ilx not in row.iri]
        eternal_screaming = list(query)

        #start_values = [(row[ind('ilx')][:3], row[ind('ilx')][4:], row[ind('iri')], row[ind('version')])
                        #for row in eternal_screaming
                        #if row[ind('ilx')] not in row[ind('iri')]]
        start_values = [(row.ilx[:3], row.ilx[4:], row.iri, row.version)
                        for row in eternal_screaming
                        if row.ilx not in row.iri]

        values, bads, skips, user_iris, replacedBys = self.cull_bads(eternal_screaming, start_values, ind)
        if not self.debug:
            # major memory consumer
            # and it does seem that removing it saves quite a bit
            # along with not storing it with the other values
            start_values = None

        sql_base = 'INSERT INTO existing_iris (perspective, ilx_prefix, ilx_id, iri) VALUES '
        self.eid_sql = []
        self.eid_params = []
        for chunk in chunk_list(values, self.batchsize):
            values_template, params = makeParamsValues(chunk, constants=('persFromGroupname(:group)',))
            params['group'] = 'base'
            sql = sql_base + values_template + ' ON CONFLICT DO NOTHING'  # TODO return id? (on conflict ok here)
            self.eid_sql.append(sql)
            self.eid_params.append(params)

        self.replacedBys = replacedBys

        if self.debug:
            self.eid_raw = eternal_screaming
            self.eid_starts = start_values
            self.eid_values = values
            self.eid_bads = bads

        self.eid_skips = skips
        self.eid_user_iris = user_iris

        if self.debug:
            log.debug(bads)
        return sql, params

    def user_iris(self):
        if not hasattr(self, 'eid_user_iris'):
            self.existing_ids()

        bads = []

        seen_users = set()
        def iri_to_group_uripath(iri):
            if 'interlex.org' not in iri:
                raise ValueError(f'goofed {iri}')

            # FIXME do we really want this ... yes... because we don't want to
            # have to look inside uris to enforce mapping rules per user

            _, user_uris_path = iri.split('interlex.org/', 1)
            user, uris_path = user_uris_path.split('/', 1)
            if user not in seen_users:
                log.debug(user_uris_path)
                seen_users.add(user)

            if not uris_path.startswith('uris'):
                msg = f'not a user uris path {iri}'
                bads.append(msg)
                return None, None

            try:
                _, path = uris_path.split('/', 1)  # TODO in the actual impl this needs to be sanitized
            except ValueError:
                path = None
                bads.append(f'what is going on here!? {iri}')

            return user, path

        _values = [(ilx_prefix, ilx_id, *iri_to_group_uripath(iri))
                   for ilx_prefix, ilx_id, iri in self.eid_user_iris]

        if bads:
            raise ValueError('\n'.join(bads))

        persmap = self.queries.getGroupPers(*sorted(set(u for _, _, u, _ in _values)))
        # XXX if you encounter an error here it is probably because
        # new groups were used by convention in the ontology and
        # loaded into interlex as existing ids and we don't have them
        # listed here

        log.debug(persmap)
        values = [(ilx_prefix, ilx_id, persmap[g], uri_path)
                  for ilx_prefix, ilx_id, g, uri_path in _values]
        sql_uri = 'INSERT INTO uris (perspective, uri_path) VALUES '
        sql_uri_mapping = 'INSERT INTO uri_mapping (ilx_prefix, ilx_id, perspective, uri_path) VALUES '

        self.uid_sql = []
        self.uid_params = []
        ocdn = ' ON CONFLICT DO NOTHING'
        for chunk in chunk_list(values, self.batchsize):
            vt_uri, vt_uri_mapping, params = makeParamsValues(chunk, vsplit=((2, None), (0, None)))
            sql = (sql_uri + vt_uri + ocdn + ';' + sql_uri_mapping + vt_uri_mapping + ocdn)
            self.uid_sql.append(sql)
            self.uid_params.append(params)

    def make_triples(self):
        insp, engine = self.insp, self.engine
        #ilxq = ('SELECT * FROM term_existing_ids as teid '
                #'JOIN terms as t ON t.id = teid.tid '
                #'WHERE t.type != "cde"')
        header_object_properties = [d['name'] for d in insp.get_columns('term_relationships')]
        header_subClassOf = [d['name'] for d in insp.get_columns('term_superclasses')]
        header_terms = [d['name'] for d in insp.get_columns('terms')]
        queries = dict(
            terms = f'SELECT * from terms WHERE type != "cde"',
            synonyms = "SELECT * from term_synonyms WHERE literal != ''",  # FIXME these things have versions too :/
            subClassOf = 'SELECT * from term_superclasses',
            object_properties = "SELECT * from term_relationships WHERE withdrawn != '1'",  # FIXME also curation status
            annotation_properties = "SELECT * from term_annotations WHERE withdrawn != '1'",  # FIXME we are missing these?
            )
        if self.do_cdes:
            queries['terms'] = 'SELECT * FROM terms'  # FIXME TODO status ??? also deleted/deprecated dection ??? iirc i do that elsewhere ???
        else:
            queries['cde_ids'] = 'SELECT id, ilx FROM terms where type = "cde"'  # FIXME fde pde etc.

        with engine.connect() as conn:
            data = {name:conn.execute(sql_text(query)).fetchall()  # FIXME yeah this is gonna be big right?
                    for name, query in queries.items()}

        #breakpoint()  # XXX break here
        ilx_index = {}
        id_type = {}
        triples = [(rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),  # FIXME hardcoded structure
                    oboInOwl.hasDbXref, rdflib.URIRef(iri)) for pref, ilx, iri in self.eid_skips]  # FIXME broken for new fragment prefixes
        type_to_owl = MysqlExport.types

        # FIXME handle alternate fragment prefixes!
        def addToIndex(id, frag_pref, ilx, class_):
            if (frag_pref, ilx) not in ilx_index:
                ilx_index[frag_pref, ilx] = []
            ilx_index[frag_pref, ilx].append(id)
            if id not in id_type:
                id_type[id] = []
            id_type[id].append(class_)

        if not self.do_cdes:
            [addToIndex(row.id, row.ilx[:3], row.ilx[4:], owl.Class) for row in data['cde_ids']]

        def norm_obj(o_raw):
            o_strip = o_raw.strip()
            if o_strip != o_raw:
                msg = f'FIXME this needs to be handled more formally than a debug message ... leading or trailing whitespace: {o_strip!r} != {o_raw!r}'
                log.debug(msg)

            return o_strip

        triples.extend(self.replacedBys)
        #replaced_lu = {s: o for s, p, o in self.replacedBys}  # FIXME check injective
        #replaced = set(self.replacedBys)
        replaced = set(s for s, p, o in self.replacedBys)
        self.replacedBys = None  # a bit of cleanup foor memory hopefully
        obsReason, termsMerged = makeURIs('obsReason', 'termsMerged')
        deprecated = set()
        bads = []
        nodefs = []
        for row in data['terms']:
            #id, ilx_with_prefix, _, _, _, _, label, definition, comment, type_
            frag_pref = row.ilx[:3]
            ilx = row.ilx[4:]
            uri = rdflib.URIRef(f'http://uri.interlex.org/base/{frag_pref}_{ilx}')

            try:
                class_ = type_to_owl[row.type]
            except KeyError as e:
                bads.append(row)
                # fixed this particular case with
                # update terms set type = 'term' where id = 304434;
                continue

            # TODO consider interlex internal? ilxi.label or something?
            triples.append((uri, rdf.type, class_))
            triples.append((uri, rdfs.label, rdflib.Literal(row.label)))
            if row.definition and (normed_definition := norm_obj(row.definition)):  # if you can't see the invisible assume it is always there
                triples.append((uri, definition, rdflib.Literal(normed_definition)))  # FIXME ilxr.definition and ilxr.label ? or /base/ ?
            elif row.definition:
                log.debug(f'{uri} had a non-empty all whitespace definition')
            elif row.status == -1:  # deleted
                pass
            elif row.status == -2:  # deprecated
                pass  # many deprecated terms had their content zapped
            else:
                nodefs.append(uri)

            if row.status in (-1, -2):  # -1 deleted, -2 deprecated
                # deleted usually means that there was a flagrant
                # duplicate that was put in by accident by an
                # automated process deprecated also basically means
                # deleted and merged, there are almost no actual
                # deprecations
                deprecated.add(uri)
                triples.append((uri, owl.deprecated, rdflib.Literal(True)))
                if uri in replaced:
                    triples.append((uri, obsReason, termsMerged))

            # this is the wrong way to do these, have to hit the superless at the moment
            #if row.type == 'fde':
                #triples.append((uri, rdfs.subClassOf, ilxtr.federatedDataElement))
            #elif row.type == 'cde':
                #triples.append((uri, rdfs.subClassOf, ilxtr.commonDataElement))

            addToIndex(row.id, frag_pref, ilx, class_)

        log.debug(f'there were {len(nodefs)} entities missing a definition')

        # dbnr likely includes spam and out of scope? (i.e. we definitely load src to prevent issues also autocomplete)
        deprecated_but_not_replaced = deprecated - replaced  # FIXME there are nearly 1600 of these as of 2024-12-01
        replaced_but_still_live = replaced - deprecated
        versions = {k:v for k, v in ilx_index.items() if len(v) > 1}  # where did our dupes go!?
        tid_to_ilx = {v:k for k, vs in ilx_index.items() for v in vs}

        multi_type = {tid_to_ilx[id]:types for id, types in id_type.items()
                      if len(types) > 1}

        def baseUri(e):
            # FIXME this is wrong for fde cde pde
            frag_pref, ilx = tid_to_ilx[e]
            return rdflib.URIRef(f'http://uri.interlex.org/base/{frag_pref}_{ilx}')

        log.debug('synonyms ingest starting')
        synWTF = []
        synWTF_ids = []
        syn_annos = defaultdict(list)
        for row in data['synonyms']:
            synid, tid, literal, type, version, time = row  # FIXME there are definitely duplicates in here
            if not literal:
                synWTF.append(row)
            elif tid not in tid_to_ilx:
                synWTF_ids.append(row)
            else:
                # FIXME somehow possible to get tids that aren't in terms?
                t = baseUri(tid), ilxr.synonym, rdflib.Literal(literal)  # FIXME TODO whitespace cleanup
                # FIXME TODO ilxr.exactSynonym is needed in order to more sanely detect and enforce uniqueness beyond just labels
                triples.append(t)
                if type:  # yay for empty string! >_<
                    stype = self.stype_lookup[type]
                    syn_annos[t].append((ilxtr.synonymType, stype))

        # FIXME determine whether we add these or whether we return all
        # the rdfstar like things that come out of this and insert them
        # into a proper table, noting that it is really only possible to
        # use rdfstar and friends on the fully named subset of the graph

        # FIXME the min 3x increase in the number of triples is very bad here
        # prefer rdfstar via triple identity so that we don't wind up with
        # 3x the rows in our internal represenation
        # TODO ingest by another way
        #for t, stypes in syn_annos.items():
        #    if len(stypes) > 1:
        #        msg = f'multiple syn types {[s[-1] for s in stypes]} for {t}'
        #        log.debug(msg)

        #    triples.extend(cmb.annotation(t, *stypes).value)

        if synWTF_ids:
            # foreign keys kids
            log.warning(f'synonyms table non-existent tids:\n{synWTF_ids}')

        log.debug('object properties ingest starting')
        WTF = []
        for row in data['object_properties']:
            _, s_id, o_id, p_id, *rest = row
            ids_triple = s_id, p_id, o_id
            try:
                t = tuple(baseUri(e) for e in ids_triple)
                triples.append(t)
            except KeyError as e:
                WTF.append(row)

        re_https = re.compile('^https?://')
        def normalize_annotation_property_object(o_raw):
            o_strip = norm_obj(o_raw)
            if re.match(re_https, o_strip) and ' ' not in o_strip:
                o = rdflib.URIRef(o_strip)
                try:
                    o.n3()
                    return o
                except Exception as e:
                    # oof
                    # URIRef conversion failed: https://doi.org/10.1002/1097-0185(20010101)262:1<71::AID-AR1012>3.0.CO;2-A
                    msg = f'URIRef conversion failed: {o}'
                    log.debug(msg)
                    return rdflib.Literal(o_strip)
            else:
                return rdflib.Literal(o_strip)

        log.debug('annotation properties ingest starting')
        ap_annos = defaultdict(list)
        WTFa = []
        for row in data['annotation_properties']:  # oof knocks total triples to 12.5 mil
            _, s_id, p_id, o_value, comment, *rest = row
            o = normalize_annotation_property_object(o_value)
            try:
                t = baseUri(s_id), baseUri(p_id), o
                triples.append(t)
                if comment:
                    cstrp = norm_obj(comment)
                    if cstrp:
                        ap_annos[t].append((ilxtr.comment, rdflib.Literal(cstrp)))  # FIXME TODO predicate
            except KeyError as e:
                WTFa.append(row)

        # XXX definitely cannot do this, it explodes the actual number of triples by 3x
        # these need a dedicated table to make it tractable, also the combinator is extremely slow it seems
        # TODO ingest another way
        #for t, apos in ap_annos.items():  # FIXME see note on syn_annos above
        #    if len(apos) > 1:
        #        msg = f'multiple comments {[po[-1] for po in apos]} for {t} ???'
        #        log.debug(msg)

        #    triples.extend(cmb.annotation(t, *apos).value)

        log.debug('subClassOf ingest starting')
        WTF2 = []
        WTF3 = []
        for row in data['subClassOf']:
            _, s_id, o_id, *rest = row
            try:
                s, o = baseUri(s_id), baseUri(o_id)
            except KeyError as e:
                WTF2.append(row)
                continue

            # TODO for multi type properties we only need the overlap
            s_type = id_type[s_id][0]
            o_type = id_type[o_id][0]
            if s_type != o_type:
                WTF3.append(row)
                continue

            assert s_type == o_type, f'types do not match! {s_type} {o_type}'
            # FIXME XXX it was possible to insert subPropertyOf on Classes :/ and the errors were silent
            if s_type == owl.Class:
                p = rdfs.subClassOf
            else:
                p = rdfs.subPropertyOf
            t = s, p, o
            triples.append(t)

        #engine.execute()
        #breakpoint()
        self.triples = triples
        self.wat = bads, WTF, WTF2
        if self.debug and (bads or WTF or WTF2):
            log.debug(bads[:10])
            log.debug(WTF[:10])
            log.debug(WTF2[:10])
            breakpoint()
            raise ValueError('BADS HAVE ENTERED THE DATABASE AAAAAAAAAAAA')
        return triples
