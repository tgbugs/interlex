""" versions and variants """
from datetime import timezone
from collections import defaultdict
import rdflib
from pyontutils.core import OntGraph
from pyontutils.namespaces import rdf, dc, owl
from pyontutils.utils_fast import isoformat
from pyontutils.identity_bnode import toposort, IdentityBNode, idf, it as ibn_it
from interlex.dump import TripleExporter
from interlex.utils import log as _log

log = _log.getChild('vervar')
te = TripleExporter()


def process_vervar(s, snr, ttsr, tsr, trr, *args, debug=True):
    """ subject source_named tripset_to_source tripsets triples """
    # TODO missing the query that joints these to perspectives to say
    # which ones are variants etc. but since we don't have variants
    # yet either that is a first pass, we sort of have variants for
    # dns terms that are imported/redefined/used in obo ontologies

    dd_tindex = defaultdict(list)
    start_to_gclc = defaultdict(set)  # yes the same record can indeed appear in multiple resources, converse not true unless sha256 is broken ...
    gclc_first_seen = {}  # FIXME

    for tup in ttsr:
        start_to_gclc[tup.gstart].add(tup.identity)
        gclc_first_seen[tup.identity] = tup.first_seen

    dd = defaultdict(set)
    known_bstarts_ts = set()
    for i, m, t in tsr:
        dd[m].add((i, t))
        if t == 'hasBnodeGraph':
            known_bstarts_ts.add(i)

    vv = dict(dd)

    dd_siadj = defaultdict(list)
    sisigh = {}
    known_bstarts = set()
    for tr in trr:
        if tr.triple_identity is not None:
            dd_tindex[tr.triple_identity].append(tr)
            if tr.subgraph_identity is not None:
                # we now start from triple_identity due to potential
                # confiusion between cases like (s0 p0 id0) (s0 p1 id0)
                known_bstarts.add(tr.triple_identity)
                dd_siadj[tr.triple_identity].append(tr.subgraph_identity)

        if tr.subgraph_identity is not None:
            if tr.triple_identity is None:
                # can't append with triple identity because those are conn
                # triples and if a predicate changes then the triple changes
                # so we can't include conn triples here or versions can cross
                # pollute eachother
                dd_tindex[tr.subgraph_identity].append(tr)
            if tr.next_subgraph_identity is not None:
                dd_siadj[tr.subgraph_identity].append(tr.next_subgraph_identity)

    # siadj -> subgraph identity -> transitive subgraph identities
    # (include these other triples as well with these nested subgraph identities)
    # this has to be resolved after we have seen all triples using e.g. neurondm.orders
    if known_bstarts != known_bstarts_ts:
        breakpoint()

    assert known_bstarts == known_bstarts_ts, 'sigh'  # can't check this anymore because for any case where s is a uri they won't match
    siadj = [(k, v) for k, vs in dd_siadj.items() for v in vs]
    hrm = toposort(siadj, unmarked_key=lambda mv: 1)
    trans = defaultdict(list)
    for asdf in hrm:  # this only works because topo sort ensures nexts are already present
        if asdf in dd_siadj:
            nexts = dd_siadj[asdf]
            trans[asdf].extend(nexts)
            for n in nexts:
                if n in trans:
                    trans[asdf].extend(trans[n])

    sub_starts = {}
    for ks in known_bstarts:
        if ks in trans:
            sub_starts[ks] = trans[ks]

    dd = defaultdict(set)
    for i, st in vv.items():
        fst = frozenset(st)
        dd[fst].add(i)

    tindex = dict(dd_tindex)
    uniques = dict(dd)
    dd = defaultdict(list)
    done = set()
    for fst in uniques:
        u_starts = set()
        for start, stype in fst:
            dd[fst].extend(tindex[start])
            if stype == 'hasBnodeGraph' and start in sub_starts:
                # we do it this way to avoid multi-parent causing
                # repeatedly adding shared substructure
                u_starts.update(sub_starts[start])
                for sub_start in sub_starts[start]:
                    if sub_start in done:
                        break

        for us in u_starts:
            dd[fst].extend(tindex[us])

    if debug:
        debug_asm = dict(dd)
        nd = [sorted([r.triple_identity for r in rs if r.triple_identity]) for rs in debug_asm.values()]

    # vervar graphs
    vvgraphs = {}
    for fst, trows in dd.items():
        graph = OntGraph(bind_namespaces='none').populate_from_triples((te.triple(*r[1:-1], 0, r[-1], 0) for r in trows))
        vvgraphs[fst] = graph
        if debug:
            graph.debug()

    # from here we use uniques to do a second query to get first_seen or some other
    # timestamp for the various versions of a term, we already have the triples in trr
    # that can be used to reconstruct every possible version of the term including
    # transitive subgraphs

    # metadata graphs
    dd = defaultdict(list)
    for gid, *trow in snr:
        dd[gid].append(trow)

    metagraphs = {}
    for gid, trows in dd.items():
        graph = OntGraph(bind_namespaces='none').populate_from_triples((te.triple(*r) for r in trows))
        metagraphs[gid] = graph

    # unified graph (everything any resource ever included about a subject)
    ugraph = OntGraph(bind_namespaces='none').populate_from_triples((te.triple(*r[1:-1], 0, r[-1], 0) for r in trr))
    # make sure we get back what we put in
    rtugraph = OntGraph(bind_namespaces='none')
    [rtugraph.populate_from(vg) for vg in vvgraphs.values()]

    oops = set(ugraph) - set(rtugraph)
    if oops:
        breakpoint()

    assert not oops, oops

    # the frozensets that are they keys for uniques make links as follows
    # [metagraphs[meta_identity] for start_identity in uniques[triple_idents_frozenset] for meta_identity in start_to_gclc[start_identity]]
    # [vervar_graph for vervar_graph in vvgraphs[triple_idents_frozenset]]
    resp = {'type': 'vervar-record',
            'subject': s,
            'vervar_count': len(uniques),}
    versions = []
    for fst, sids in uniques.items():
        # XXX TODO we don't actually stored the bnode + named ids right now
        # but ideally we would have the exact identities we are working with
        # for the whole records here, that said, due to shared substructure
        # in some sources this often isn't possible to calculate in advance
        # however we could calculate and cache/record it somewhere ... the
        # named_condensed + bnode_condensed might be computable on the fly?
        vg = vvgraphs[fst]

        #_idg = IdentityBNode(vg, as_type=ibn_it['triple-seq'], id_method=idf['record-seq'])  # matches v3 behavior
        #_ids = IdentityBNode(rdflib.URIRef(s), id_method=idf['(s ((p o) ...))'], in_graph=vg)
        #_idga = IdentityBNode(vg, as_type=ibn_it['triple-seq'], id_method=idf['record-alt-seq'])
        #_idsa = IdentityBNode(rdflib.URIRef(s), id_method=idf['((s (p o)) ...)'], in_graph=vg)
        # FIXME notation of (s ((p o) ...)) is confusing because it isn't clear what happens with bnodes
        #_idg3 = IdentityBNode(vg, as_type=ibn_it['triple-seq'], id_method=idf['record-combined-seq'])
        _idg = IdentityBNode(vg, as_type=ibn_it['triple-seq'], id_method=idf['graph-combined'])
        _ids = IdentityBNode(rdflib.URIRef(s), id_method=idf['record-combined'], in_graph=vg)
        # FIXME TODO we shouldn't need to compute record-combined here because it should be pulled from irels once we update the query
        # and I can confirm that the record-combined entires in identities do match what we get here could compute here as debug check
        version = {
            # both identities are the -combined equivalent for their level
            'identity-graph': _idg.identity.hex(),  # use graph-combined because that is what ingest computes and stores
            'identity-record': _ids.identity.hex(),  # record-combined because it is the simplest route to id combined records and map to triples
            'triple_count': len(vg),
        }
        appears_in = []
        for sid in sids:
            if sid not in start_to_gclc:  # FIXME something is off here because specs are their own meta record ...
                msg = f'sigh {s} {sid.tobytes().hex() if isinstance(sid, memoryview) else sid}'
                log.warning(msg)
                continue
            for gid in sorted(start_to_gclc[sid], key=lambda m: gclc_first_seen[m]):
                if gid not in metagraphs:
                    # something is extremely wrong, usually bad data in irels and idents
                    # due to a bad checksumming commit or similar
                    msg = f'no metagraph known for gclc {gid} starting from {sid}'
                    log.critical(msg)
                    continue

                g = metagraphs[gid]
                fsm = isoformat(gclc_first_seen[gid].astimezone(timezone.utc))
                apin = {
                    'identity-gclc': gid,  # FIXME make sure it is actually gclc, need to adjust how we attach metadata
                    'first_seen': fsm,
                }
                types = list(g[:rdf.type:])
                _s, ty = types[0]
                apin['uri'] = _s
                apin['type'] = ty
                title = list(g[:dc.title:])
                if title: apin['title'] = title[0][1]
                vinfo = list(g[:owl.versionInfo:])
                if vinfo: apin['vinfo'] = vinfo[0][1]
                viri = list(g[:owl.versionIRI:])
                if viri: apin['viri'] = viri[0][1]
                appears_in.append(apin)

        if appears_in:
            version['appears_in'] = appears_in

        versions.append(version)

    if versions:
        versions = sorted(versions, key=lambda v: ('appears_in' in v and bool(v['appears_in']),
                                                    'appears_in' in v and v['appears_in'] and v['appears_in'][0]['first_seen']))
        resp['versions'] = versions

    return vv, uniques, metagraphs, ugraph, vvgraphs, resp


def get_latest_group_subject_hack(queries, group, subject_base):
    # get perspective head TODO maybe cache this at the cost of two roundtrips to the db on a miss?
    rci_ex = None
    graph_rows = queries.getRecordHeadGraphForGroupSubject(group, subject_base)
    if not graph_rows:
        # XXX this is a hacked workaround until we have proper history and perspective history and head tracking
        snr, ttsr, tsr, trr = queries.getVerVarBySubject(subject_base)  # FIXME more efficient single result query please
        if not trr:
            return None, None

        vv, uniques, metagraphs, ugraph, vvgraphs, resp = process_vervar(subject_base, snr, ttsr, tsr, trr)
        # XXX ignore vvgraphs that don't include s rdf:type also if there is not metagraph things are
        # complicated, so yes, we likely want a metagraph record but actually not strictly necessary because
        # if it is misisng it means that it was just entered, but yeah, we do want to know who originally put it
        # in and stuff, and now that I have some garbage data in the graph we need a way to separate those out

        if 'versions' in resp:
            # FIXME this whole approach is bad, and we should not be working from vervar for this
            # it is a temp hack, but we need a real solution based on perspective_heads

            # FIXME ah, ttsr is not being used to make the mapping because start to gclc is not exported
            #valid_n_or_b_graph_combined = set(v for vs in uniques.values() for v in vs)  # XXX this is the issue

            # we want the newest version but the oldest appears_in
            # for group then base (or curated or latest or whatever)
            newest_group = None
            newest_base = None
            newest_other = None
            for v in resp['versions']:
                rcid = v['identity-record']
                group_done, base_done, other_done = False, False, False
                if 'appears_in' in v:
                    for ai in v['appears_in'][::-1]:
                        # oldest last
                        if group_done and base_done and other_done:
                            break
                        if not group_done and group in ai['uri']:  # FIXME bad test
                            group_done = ai['first_seen'], rcid, group, ai['identity-gclc']
                        if not base_done and 'base' in ai['uri']:  # FIXME bad test
                            base_done = ai['first_seen'], rcid, 'base', ai['identity-gclc']
                        if not (group_done or base_done):
                            _other_group = ai['uri'].split('/', 4)[-2]
                            other_done = ai['first_seen'], rcid, _other_group, ai['identity-gclc']

                if group_done:
                    if newest_group is None:
                        newest_group = group_done
                    elif newest_group[0] < group_done[0]:
                        newest_group = group_done

                elif base_done:
                    if newest_base is None:
                        newest_base = base_done
                    elif newest_base[0] < base_done[0]:
                        newest_base = base_done

                elif other_done:
                    if newest_other is None:
                        newest_other = other_done
                    elif newest_other[0] < other_done[0]:
                        newest_other = other_done

            newest = newest_group if newest_group else (newest_base if newest_base else newest_other)
            if newest:
                # FIXME and here we see why we need a proper implementation
                # because this is nonsense
                gclc_to_start = {r.identity: r.gstart for r in ttsr}
                nfs, rci_ex, _g, ngclc = newest
                nstart = gclc_to_start[ngclc]
                fst = None
                for fst, u in uniques.items():
                    if nstart in u:
                        break
                if fst is None:
                    breakpoint()
                    raise ValueError('derp')
                graph_ex = vvgraphs[fst]
            else:
                graph_ex = OntGraph(bind_namespaces='none')
        else:
            graph_ex = OntGraph(bind_namespaces='none')

        rci_ex = bytes.fromhex(rci_ex)  # FIXME sigh
    else:
        # FIXME make it a single query
        rci_rows = queries.getRecordHeadForGroupSubject(group, subject_base)
        rci_ex = rci_rows[0].head_identity.tobytes()

        te = TripleExporter()
        graph_ex = OntGraph(bind_namespaces='none')
        # FIXME do predicates need to match as well? this part is super tricky
        for i, *r, f in graph_rows:
            graph_ex.add(te.triple(*r, None, f))

    return graph_ex, rci_ex
