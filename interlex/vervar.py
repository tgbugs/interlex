""" versions and variants """
from datetime import timezone
from collections import defaultdict
from pyontutils.core import OntGraph
from pyontutils.namespaces import rdf, dc, owl
from pyontutils.utils_fast import isoformat
from pyontutils.identity_bnode import toposort
from interlex.dump import TripleExporter
from interlex.utils import log as _log

log = _log.getChild('vervar')
te = TripleExporter()


def process_vervar(s, snr, ttsr, tsr, trr):
    """ subject source_named tripset_to_source tripsets triples """
    # TODO missing the query that joints these to perspectives to say
    # which ones are variants etc. but since we don't have variants
    # yet either that is a first pass, we sort of have variants for
    # dns terms that are imported/redefined/used in obo ontologies

    dd_tindex = defaultdict(list)
    start_to_meta = defaultdict(set)  # yes the same record can indeed appear in multiple resources, converse not true unless sha256 is broken ...
    meta_first_seen = {}

    for tup in ttsr:
        start_to_meta[tup.gstart].add(tup.identity)
        meta_first_seen[tup.identity] = tup.first_seen

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
            dd_tindex[tr.triple_identity].append(tr)  # obs there should only ever be one in this case, but for type uniformity we append
        elif tr.subgraph_identity is not None:
            dd_tindex[tr.subgraph_identity].append(tr)
            if tr.s_blank is None:
                known_bstarts.add(tr.subgraph_identity)  # these should match what appears in tsr where type is hasBnodeGraph
            if tr.next_subgraph_identity is not None:
                dd_siadj[tr.subgraph_identity].append(tr.next_subgraph_identity)
        else:
            breakpoint()
            raise NotImplementedError('sigh')

    # siadj -> subgraph identity -> transitive subgraph identities
    # (include these other triples as well with these nested subgraph identities)
    # this has to be resolved after we have seen all triples using e.g. neurondm.orders
    assert known_bstarts == known_bstarts_ts, 'sigh'
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

    uniques = dict(dd)
    dd = defaultdict(list)
    for fst in uniques:
        for start, stype in fst:
            dd[fst].extend(dd_tindex[start])
            if stype == 'hasBnodeGraph' and start in sub_starts:
                for sub_start in sub_starts[start]:
                    dd[fst].extend(dd_tindex[sub_start])

    # vervar graphs
    vvgraphs = {}
    for fst, trows in dd.items():
        graph = OntGraph().populate_from_triples((te.triple(*r[1:-1], 0, r[-1], 0) for r in trows))
        vvgraphs[fst] = graph

    # from here we use uniques to do a second query to get first_seen or some other
    # timestamp for the various versions of a term, we already have the triples in trr
    # that can be used to reconstruct every possible version of the term including
    # transitive subgraphs

    # metadata graphs
    dd = defaultdict(list)
    for mid, *trow in snr:
        dd[mid].append(trow)

    metagraphs = {}
    for mid, trows in dd.items():
        graph = OntGraph().populate_from_triples((te.triple(*r) for r in trows))
        metagraphs[mid] = graph

    # unified graph (everything any resource ever included about a subject)
    ugraph = OntGraph().populate_from_triples((te.triple(*r[1:-1], 0, r[-1], 0) for r in trr))

    # the frozensets that are they keys for uniques make links as follows
    # [metagraphs[meta_identity] for start_identity in uniques[triple_idents_frozenset] for meta_identity in start_to_meta[start_identity]]
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
        version = {
            'triple_count': len(vg),
            'appears_in': [],
        }
        for sid in sids:
            if sid not in start_to_meta:  # FIXME something is off here because specs are their own meta record ...
                msg = f'sigh {s} {sid.tobytes().hex() if isinstance(sid, memoryview) else sid}'
                log.warning(msg)
                continue
            for mid in sorted(start_to_meta[sid], key=lambda m: meta_first_seen[m]):
                g = metagraphs[mid]
                fsm = isoformat(meta_first_seen[mid].astimezone(timezone.utc))
                apin = {'first_seen': fsm}
                types = list(g[:rdf.type:])
                s, ty = types[0]
                apin['uri'] = s
                apin['type'] = ty
                title = list(g[:dc.title:])
                if title: apin['title'] = title[0][1]
                vinfo = list(g[:owl.versionInfo:])
                if vinfo: apin['vinfo'] = vinfo[0][1]
                viri = list(g[:owl.versionIRI:])
                if viri: apin['viri'] = viri[0][1]
                version['appears_in'].append(apin)

        versions.append(version)

    versions = sorted(versions, key=lambda v: ('appears_in' in v and bool(v['appears_in']),
                                                'appears_in' in v and v['appears_in'] and v['appears_in'][0]['first_seen']))
    resp['versions'] = versions

    return vv, uniques, metagraphs, ugraph, vvgraphs, resp
