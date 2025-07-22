import re
import math
from collections import defaultdict, Counter
from urllib.parse import urlparse, quote as url_quote, unquote as url_unquote
import rdflib
from sqlalchemy import create_engine, inspect
from sqlalchemy.sql import text as sql_text
from pyontutils import combinators as cmb
from pyontutils.core import OntId, OntGraph, OntMeta
from pyontutils.utils_fast import chunk_list, isoformat, utcnowtz
from pyontutils.namespaces import ILX, ilxtr, oboInOwl, owl, rdf, rdfs, dc
from pyontutils.namespaces import definition, replacedBy, makeURIs
from interlex import alt
from interlex import config
from interlex import exceptions as exc
from interlex.core import synonym_types, dbUri, makeParamsValues
from interlex.dump import Queries, MysqlExport
from interlex.load import TripleLoaderFactory, do_gc
from interlex.utils import log as _log
from interlex.config import existing_user_map
from interlex.namespaces import ilxr
from interlex.ingest import process_triple_seq, do_process_into_session

log = _log.getChild('sync')

ocdn = ' ON CONFLICT DO NOTHING'

def getpi(u):
    p_i = u.rsplit('/', 1)[-1]
    if '_' not in p_i:
        log.error((u, p_i))
        return (None, None)
    if p_i == '_':
        # FIXME BAD BAD BAD
        log.critical(u)
        return (None, None)

    try:
        p, i = p_i.split('_')
    except ValueError:
        log.critical(u)
        return (None, None)

    return p, i


def fix_laex(self, data, eid_duplicate_of, eid_values):
    # self for debug only

    type_to_owl = MysqlExport.types
    # we have to deal with the labels and synonyms before we can generate triples
    # FIXME TODO some of this should surely be fixed upstream, but not right now
    # FIXME TODO we need to know which of these if any are deprecated
    # a bunch of these are also just wrong because they somehow took the wrong field
    # when the correct name is in synonyms ... also it is using subClassOf when it should be partOf oof
    # consider these two of 12 cases ...
    # https://uri.olympiangods.org/base/ilx_0742095.html?links=internal
    # https://uri.olympiangods.org/base/ilx_0747061.html?links=internal
    label_disaster = defaultdict(list)
    deprecated = set()  # FIXME TODO
    deleted = set()
    derp_tid = {}
    pi_type = {}  # needed to deal with duplicates that are termsets i think
    pi_type_raw = {}
    pi_ouid = {}
    pi_lab = {}  # not downcased
    bads = []
    for row in data['terms']:
        pref = row.ilx[:3]
        ilx = row.ilx[4:]
        pi = pref, ilx
        derp_tid[row.id] = pi
        label_disaster[row.label.lower()].append(pi)
        pi_lab[pi] = row.label
        if row.status == -1:
            deleted.add(pi)  # review these because some were mistaken
        elif row.status == -2:  # deprecated ???
            deprecated.add(pi)

        # FIXME TODO pi_ouid is needed for personal data elements,
        # really these should all be merged into a single pde and the
        # group will be it, but we have to translate all the groups
        pi_ouid[pi] = row.orig_uid
        pi_type_raw[pi] = row.type
        try:
            pi_type[pi] = type_to_owl[row.type]
        except KeyError as e:
            bads.append(row)
            # troy_test_set not entirely sure what it should be
            continue

    pi_sco = {}  # there are no multi-parent cases at the moment
    scobad = []
    scobads = []
    for row in data['subClassOf']:
        if row.tid not in derp_tid:
            scobad.append(row)
            if row.superclass_tid not in derp_tid:
                scobads.append(row)
            continue
        elif row.superclass_tid not in derp_tid:
            scobads.append(row)
            continue

        pi = derp_tid[row.tid]
        scopi = derp_tid[row.superclass_tid]
        pi_sco[pi] = scopi

    hrm = dict(label_disaster)
    derp = sorted([(l, len(pis), sorted(pis)) for l, pis in hrm.items() if len(pis) > 1], key=lambda abc: (abc[1], abc[0], abc[2]), reverse=True)
    anypis = {pi: l for l, pis in hrm.items() for pi in pis}
    badpis = {pi: l for l, _, pis in derp for pi in pis}

    noc = {pi: (l, pi_type[pi]) for pi, l in badpis.items() if pi_type[pi] != owl.Class}

    _pisyn = defaultdict(list)
    for row in data['synonyms']:
        #synid, tid, literal, type, version, time = row  # FIXME there are definitely duplicates in here
        if row.tid not in derp_tid:
            log.error(f'sigh no term with tid {row.tid} {row.literal} {row.type}')
            continue
        pi = derp_tid[row.tid]
        _pisyn[pi].append(row.literal)

    pisyn = dict(_pisyn)  # candidates for replacement

    hrmsyn = {l: [(pi, (pisyn[pi] if pi in pisyn else None)) for pi in pis] for l, pis in hrm.items() if len(pis) > 1}

    pde_user = {}  # FIXME TODO

    # FIXME also need existing ids for this ...

    # cases where a label should be excluded, the original label can be retained
    # these are for terms merged cases (for example)
    exclude_pis = {}  # [pi] = reason

    #pido = {getpi(s): getpi(o) for s, p, o in duplicateOfs}
    pido = {a: b for a, b in eid_duplicate_of}
    pidonc = {k: v for k, v in pido.items() if v[0] != 'cde'}
    #pieid = {(p, i): getpi(e) for p, i, e in eid_values if 'uri.interlex.org' in e}  # empty

    _pieid = defaultdict(list)
    for p, i, e in eid_values:
        _pieid[(p, i)].append(e)
    pieid = dict(_pieid)

    already_duplicate = set(pido) & set(badpis)
    arhrm = {}
    adupes = set()
    for ar in already_duplicate:
        _rep = pido[ar]
        adupes.add(_rep)
        arhrm[ar] = (ar, anypis[ar]), (_rep, anypis[_rep])

    # TODO candidate rules
    # 2 and no syns on one perfer the one with syns, but always mark the duplicates with (duplicate) only on the higher, also check eid/rb
    # cde and ilx add something to cde to differentiate
    # many of the duplicate cdes are from NINDS vs ODC-SCI and so need subClassOf to differentiate these few cases

    # time for some rules
    cde_special_cases = {
        ('cde', '0100060'): 'Species (CDE)',
        ('cde', '0368502'): 'Species (VISION-SCI)',
        ('cde', '0102228'): 'Investigator (ODC-SCI)',
        ('cde', '0368503'): 'Investigator (VISION-SCI)',
        ('cde', '0369439'): 'Actuator type (PRECISE-TBI CCIM)',  # possibly misisng a reference to CDE:0369390

        ('cde', '0369968'): 'Barnes Maze test - pretest habituation handling time duration (minutes)',
        ('cde', '0369971'): 'Barnes Maze test - pretest habituation handling time duration (seconds)',

        ('cde', '0369917'): 'Craniotomy size value (animal)',  # ('cde', '0369935')

        ('cde', '0370006'): 'Imaging slice orientation type (3D)',  # ('cde', '0369775')

        ('cde', '0369906'): 'Neuroseverity score (NSS) - hind limb motor strength sub-score (left)',
        ('cde', '0369907'): 'Neuroseverity score (NSS) - hind limb motor strength sub-score (right)',

        ('cde', '0369391'): 'Test equipment manufacturer name (PRECISE-TBI CCIM)',  # possible version with ('cde', '0369427')

        ('cde', '0370001'): 'Value of brain region of interest type other (qc)',
    }
    ilx_special_cases = {
        # actually a pde
        ('ilx', '0739361'): pi_lab[('ilx', '0739361')] + f' (user {existing_user_map[pi_ouid[("ilx", "0739361")]][0]})',

        # http://terminologia-anatomica.org/en/Terms/View?sitemapItemId=100
        # TODO merge these probably despite the difference in the hierachy also can ingest TA98 hierarchy maybe?
        # for many of these TA98 cases we may move to merge them
        # two different latin terms that map to the same english term
        ('ilx', '0748106'): 'transverse (transversus) (TA98)',  # 26
        ('ilx', '0743450'): 'transverse (transversalis) (TA98)',  # 27

        # white substance
        #('ilx', '0741479'):
        ('ilx', '0747708'): 'white substance OF spinal cord (TA98) (duplicateOf ILX:0741479)',  # this one has more metadata though

        # subthalamus ... confusion in source
        #('ilx', '0742525'): 'subthalamus (ventral thalamus) (TA98)',  # has children
        ('ilx', '0747093'): 'subthalamus (A14.1.08.701) (TA98)',

        # venous plexus of cardiovascular system
        ('ilx', '0747213'): 'venous plexus (rete venosum) (TA98)',
        ('ilx', '0748123'): 'venous plexus (plexus venosus) (TA98)',

        #thoracic cavity of thorax ... confusion in source
        #('ilx', '0741602'):,  # has children
        ('ilx', '0741733'): 'thoracic cavity (A02.3.04.002) (TA98)',

        #thalamus of diencephalon of prosencephalon ... confusion in source
        ('ilx', '0743241'): 'thalamus (A14.1.08.601) (TA98)',
        #('ilx', '0748860'):,  # has children

        #tectopontine tract of white substance of tegmentum of midbrain
        #('ilx', '0743545'):,  # has children
        ('ilx', '0748305'): 'tectopontine tract (A14.1.06.219) (TA98)',

        # cuneiform tubercle ... confusion in source
        #('ilx', '0744151'):,
        ('ilx', '0748807'): 'cuneiform tubercle (A06.2.09.005) (TA98)',

        # corniculate tubercle ... confusion in source
        #('ilx', '0742514'):,
        ('ilx', '0747746'): 'corniculate tubercle (A06.2.09.004) (TA98)',

        # cusp OF valve
        ('ilx', '0742984'): 'cusp OF valve (cuspis) (TA98)',
        ('ilx', '0747460'): 'cusp OF valve (valvula) (TA98)',

    }
    ilx_label_special_cases = {
        'jejunal &amp; ileal plexuses (swannt)': ('ilx', '0740800'),
    }
    xdupes = set()
    not_xdupes_because_already_deduped = set()
    not_xdupes_because_not_min = set()
    not_actually_deprecated = set()
    repl = {}
    maybe_multi = {}
    rem_duplicate_of = []
    label_duplicate_of = [
        (('ilx', '0747708'), ('ilx', '0741479')),  # white substance (TA98)
    ]
    for pi, l_norm in badpis.items():
        if pi in ilx_special_cases:
            repl[pi] = ilx_special_cases[pi]
            continue

        p, i = pi
        # LOL PYTHON comprehensions now allowd to use loop variables >_<
        others = []
        for o in  hrm[l_norm]:
            if o != pi:
                others.append(o)

        # sometimes we have an even older replacement
        # sometimes the other replacement is newer
        nothers = []
        for o in others:
            if o in pido and pido[o] not in others and pido[o] != pi:
                nothers.append(pido[o])
                #log.info((others, o, pido[o]))

        others += nothers

        l = pi_lab[pi]
        maybe_better_rep = False
        if pi in arhrm:
            _, ((tp, ti), tl) = arhrm[pi]
            tilx = tp.upper() + ':' + ti
            #log.info((l, tl))
            # FIXME most of these aren't actually replacedBy
            # they are termsMerged and "please don't use this id anymore"
            # as in the identifier is deprecated, the class is not
            # maybe equvalentClass is more appropriate in those cases
            # but it adds noise, these are mostly for record keeping
            repl[pi] = l + f' (duplicateOf {tilx})'
            maybe_better_rep = True
            # do not continue here because we may have a more correct replacement
            # in which case the less correct replacement should also be replaced as well
        elif pi in deprecated:
            # this helps with maybe 14  # but 5 are still in conflict
            if pi[0] == 'cde' and l == 'leak':
                repl[pi] = f'cde leak CDE:{pi[1]} (deprecated)'
                continue
            else:
                maybe_multi[pi] = repl[pi] = l + ' (deprecated)'  # XXX FIXME HACK TEMP
                # let this fall through because there might be a label duplication we are expecting below
                # that was missing
        elif pi in deleted:
            # helps with maybe ... 2
            maybe_multi[pi] = repl[pi] = l + ' (deleted)'  # XXX FIXME HACK TEMP


        if pi in noc and noc[pi][-1] == ilxr.TermSet:
            if '(termset)' not in l_norm:
                repl[pi] = l + ' (TermSet)'
                continue

        if p == 'pde' or pi_type_raw == 'pde':
            # FIXME this should do replacedBy and converge pdes on the group
            # we will dedupe these later i think
            _pouid = pi_ouid[pi]
            if _pouid not in existing_user_map:  # 45505 looks like it was used for creating the cdes
                repl[pi] = l + f' (guid {_pouid})'
            else:
                ud = existing_user_map[_pouid]
                temp_group = ud[0]
                repl[pi] = l + f' (user {temp_group})'
            continue

        if p == 'cde':
            # TODO versions first
            if pi in cde_special_cases:
                # and let curation sort them out ALCSTO
                repl[pi] = cde_special_cases[pi]
                continue
            elif pi in pi_sco:
                scopi = pi_sco[pi]
                pl = anypis[scopi]
                if scopi == ('ilx', '0794760'):
                    repl[pi] = l + ' (NINDS-TBI)'
                    continue
                elif scopi == ('ilx', '0794909'):
                    repl[pi] = l + ' (TOPNT)'  # TOPNT is the group they want so better than TOP-NT I guess?
                    continue
                elif scopi == ('ilx', '0794941'):
                    #repl[pi] = l + ' (PRECISE-TBI CCIM)'
                    repl[pi] = l + ' (PRECISE-TBI)'
                    continue
                elif scopi == ('ilx', '0794911'):
                    #repl[pi] = l + ' (PRECISE-TBI Rotarod)'
                    repl[pi] = l + ' (PRECISE-TBI)'
                    continue
                elif scopi == ('ilx', '0794944'):
                    #repl[pi] = l + ' (PRECISE-TBI Study)'
                    repl[pi] = l + ' (PRECISE-TBI)'
                    continue
                elif scopi == ('ilx', '0793866'):
                    #repl[pi] = l + ' (PRECISE-TBI CDE)'
                    repl[pi] = l + ' (PRECISE-TBI)'
                    continue
                elif scopi == ('cde', '0102230'):
                    # FIXME why does this one use cde and the others ilx?
                    repl[pi] = l + ' (NDA-CDE)'
                    continue
                else:
                    log.info((scopi, pl))

        if l_norm in ilx_label_special_cases:
            op, oi = opi = ilx_label_special_cases[l_norm]
            label_duplicate_of.append((pi, opi))
            tilx = op.upper() + ':' + oi
            sighlx = p.upper() + ':' + i + ' '
            repl[pi] = l + f' {sighlx}(duplicateOf {tilx})'
            if maybe_better_rep:
                log.info('mbr hit')  # never hits
            continue

        if '(TA98)' not in l:
            eid = pieid[pi] if pi in pieid else 'no-eid'
            np_others = []
            for o in others:
                if o[0] != 'pde' and pi_type_raw[o] not in ('pde', 'TermSet'):
                    np_others.append(o)

            if len(np_others) == 1:
                opi = op, oi = np_others[0]
                if p == 'ilx' and p == op and i > oi:
                    if opi in pido and opi > pido[opi]:
                        ep, ei = epi = pido[opi]
                        tilx = ep.upper() + ':' + ei
                        sighlx = p.upper() + ':' + i + ' '
                        repl[pi] = l + f' {sighlx} (duplicateOf {tilx})'
                        label_duplicate_of.append((pi, epi))
                        not_xdupes_because_already_deduped.add(opi)
                        continue

                    # and opi not in deleted and opi not in deprecated:
                    if opi in deleted or opi in deprecated:
                        # FIXME still not right here because some of these _are_ deprecated
                        # or can't easily follow our reccomendations e.g. BICCN cases which
                        # have been published
                        log.debug(f'not actually deprecated {opi} {pi_lab[opi]}')
                        not_actually_deprecated.add(opi)

                    tilx = op.upper() + ':' + oi
                    repl[pi] = l + f' (duplicateOf {tilx})'  # FIXME TODO merge down and add to duplicateOfs i think?
                    label_duplicate_of.append((pi, opi))
                    if maybe_better_rep:
                        #log.info('mbr hit')  # all the hits
                        epi = pido[pi]
                        if epi != opi:
                            if epi < opi:
                                # epi was the correct mapping
                                if opi not in pido:  # seems ok ...
                                    log.warning(f'fixing {epi} < {opi}')
                                    label_duplicate_of.append((opi, epi))
                            else:
                                #log.debug((opi, pi, epi))
                                label_duplicate_of.append((epi, opi))
                                rem_duplicate_of.append((pi, epi))
                                # FIXME TODO need to resequence sqlgen because may of these are already prepped for insertion

                elif p == 'ilx' and p == op and i < oi:  # debug (issue was that the one to rename had synonyms)
                    xdupes.add(pi)
                    #log.info(f'{pi} expected to be non-duplicate for {l}')
                elif p == 'cde' and op == 'ilx':
                    repl[pi] = l + ' (CDE)'
                else:
                    nc_others = []
                    for o in np_others:
                        if o[0] != 'cde' and pi_type_raw[o] != 'cde':
                            nc_others.append(o)

                    if nc_others:
                        log.error(f'depdel issue {pi} {l} {nc_others}')

                continue
            elif len(np_others) == 2 and p == 'ilx':
                ao = sorted([(p, i) for p, i in np_others if p == 'ilx'], key=lambda pi: pi[1])
                #log.debug(f'aaaaaaaaaaa {l} {pi} {ao}')
                if ao:
                    opi = op, oi = ao[0]
                    if i != oi and i > oi and opi not in deleted and opi not in deprecated:
                        tilx = op.upper() + ':' + oi
                        sighlx = p.upper() + ':' + i + ' '
                        repl[pi] = l + f' {sighlx}(duplicateOf {tilx})'  # FIXME TODO merge down and add to duplicateOfs i think?
                        label_duplicate_of.append((pi, opi))
                        if pi in pido:
                            epi = pido[pi]
                            if epi != opi:
                                if epi <= opi:
                                    assert False, 'should not be happening in current data'
                                else:
                                    #log.debug(('sigh', opi, pi, epi))
                                    # seems like we don't need to add these ??
                                    #label_duplicate_of.append((epi, opi))
                                    #if (epi, opi) not in label_duplicate_of:
                                        # this might be added later but it also might not be added at all
                                        # so we give it a shot because 1 of 3 hits ... who knows why
                                        # possibly because the label just doesn't match at all
                                        # yeah it the one cse is where it is definitely not a label duplicate
                                        # and should not be deduplicated in that way so not doing this
                                        # and just removing the bad duplicate of from eid for now
                                        #log.debug((pi_lab[epi], pi_lab[opi]))
                                        #label_duplicate_of.append((epi, opi))

                                    rem_duplicate_of.append((pi, epi))
                                    not_xdupes_because_not_min.add(opi)

                        #log.debug(f'bbbbbbbbbbb {l} {pi} {ao}')
                    elif i < oi:
                        xdupes.add(pi)
                    else:
                        raise NotImplementedError('correctly')

                    continue

            else:
                if np_others:
                    if p != 'cde':
                        log.debug(f'wat {pi} {l} {np_others}')

        if pi in xdupes:
            log.error(f'in xdupes but somehow we got here? {pi} {l}')

        # FIXME some of these aren't hitting because the higher number has the synonyms?
        if pi not in pisyn:
            #log.warning(f'no alternative for {pi} {l} {eid} {others}')
            continue

        cands = pisyn[pi]
        # start rules
        if '(TA98)' in l:  # composition and bad ingest :/
            # hits about 1000
            if [o for o in others if o in ilx_special_cases] and l != 'white substance (TA98)':
                # should already be dealt with, but possibly not?
                continue
            candl = [c for c in cands if 'OF' in c]
            if len(candl) == 1:
                cand = candl[0]
                repl[pi] = cand + ' (TA98)'
            elif not candl:
                # presumably this is the actual parent class that is unqualified
                pass
            else:
                log.warning((pi, candl))

    PYTHON_SUCKS = True  # so much LOL PYTHON in here today
    if PYTHON_SUCKS:
        maybe_newsyns = {}
        dd = defaultdict(list)
        for pi, l in badpis.items():
            if pi in repl:
                maybe_newsyns[pi] = l
                l = repl[pi]

            dd[l.lower()].append(pi)

        re_hrm = dict(dd)
        re_hrmsyn = {l: [(pi, (pisyn[pi] if pi in pisyn else None)) for pi in pis] for l, pis in re_hrm.items() if len(pis) > 1}
        re_derp = sorted([(l, len(pis), sorted(pis)) for l, pis in re_hrm.items() if len(pis) > 1], key=lambda abc: (abc[1], abc[0], abc[2]), reverse=True)
        re_badpis = {pi: l for l, _, pis in re_derp for pi in pis}

    #[[pieid[o][0].split('=')[-1] for o in o] for l, _, o in re_derp if 'ta98' in l]

    for pi, l_norm in re_badpis.items():
        p, i = pi
        others = []
        for o in  re_hrm[l_norm]:
            if o != pi:
                others.append(o)

        if pi in repl:
            l = repl[pi]
        else:
            l = pi_lab[pi]

        if '(TA98)' in pi_lab[pi]:
            # at this point we'll deal with these later
            repl[pi] = f'{l.replace(" (TA98)", "")} ({pieid[pi][0].split("=")[-1]}) (FIXME-TODO) (TA98)'
            continue

        # versions i think
        if p == 'cde' and l_norm.startswith('rotor rod test') and len(others) == 1:
            repl.pop(pi)
            l = pi_lab[pi]
            if others[0][1] > i:
                repl[pi] = l + ' (v0)'
                continue

        if p == 'cde' and len(others) <= 2 and set(p for p, i in others) == {'ilx'}:
            remaining_others = []
            for o in others:
                if o not in xdupes and o not in repl and pi_type_raw[o] != 'pde':
                    remaining_others.append(o)
            if not remaining_others:
                repl[pi] = l + ' (CDE)'
                continue

            log.debug((pi, l_norm, remaining_others))

        if l.startswith('Aortic arch (duplicateOf'):
            sighlx = p.upper() + ':' + i
            repl[pi] = l.replace('(', f'{sighlx} (', 1)
            continue

        if p == 'pde' or pi_type_raw[pi] == 'pde':
            ao = sorted([(p, i) for p, i in others if p == 'pde' or pi_type_raw[p, i] == 'pde'], key=lambda pi: pi[1])
            if ao:
                op, oi = ao[0]
                if i != oi and i > oi:
                    tilx = op.upper() + ':' + oi
                    sighlx = p.upper() + ':' + i + ' ' if len(others) > 1 else ''
                    repl[pi] = l + f' {sighlx}(duplicateOf {tilx})'  # FIXME TODO merge down and add to replacedBys i think?
                    label_duplicate_of.append((pi, (op, oi)))
                    continue

    if PYTHON_SUCKS:
        dd = defaultdict(list)
        for pi, l in badpis.items():
            if pi in repl:
                maybe_newsyns[pi] = l
                l = repl[pi]

            dd[l.lower()].append(pi)

        re_hrm = dict(dd)
        re_hrmsyn = {l: [(pi, (pisyn[pi] if pi in pisyn else None)) for pi in pis] for l, pis in re_hrm.items() if len(pis) > 1}
        re_derp = sorted([(l, len(pis), sorted(pis)) for l, pis in re_hrm.items() if len(pis) > 1], key=lambda abc: (abc[1], abc[0], abc[2]), reverse=True)
        re_badpis = {pi: l for l, _, pis in re_derp for pi in pis}

    if len(label_duplicate_of) != len(set(label_duplicate_of)):
        log.error(f'sigh {len(label_duplicate_of)} != {len(set(label_duplicate_of))}')
        assert False, 'oops ldo'

    ldoo = [ref for d, ref in label_duplicate_of]
    x_but_no_dupes = (((xdupes - set(ldoo)) - adupes - not_xdupes_because_already_deduped) - not_xdupes_because_not_min)
    if x_but_no_dupes:
        _wat = sorted([badpis[x] for x in x_but_no_dupes])  # possibly replacedBy?
        _hrm = {badpis[x]: [((repl[pi], pi) if pi in repl else (None, pi)) for pi in hrm[badpis[x]]] for x in x_but_no_dupes}
        msg = f'expecting but missing a duplicate of ??? {_wat}'
        log.error(msg)

    ldor = [d for d, ref in label_duplicate_of]
    sldor = set(ldor)
    if len(ldor) != len(sldor):
        log.error(f'non-unique mappings {len(ldor)} != {len(sldor)}')
        #qq = [(a, b) for a, b in Counter(ldor).most_common() if b > 1]
    baddup = [(d, r) for d, r in label_duplicate_of if d[1] < r[1]]
    if baddup:
        log.error(f'bad duplicate direction {baddup}')

    actually_multi = {pi: v for pi, v in maybe_multi.items() if pi in repl and '(deprecated)' not in repl[pi] and '(deleted)' not in repl[pi]}
    not_multi = {pi: v for pi, v in maybe_multi.items() if pi not in repl or '(deprecated)' in repl[pi] or '(deleted)' in repl[pi]}
    #multimapped = sorted([r for r in repl.values() if '(deprecated)' in r and '(duplicateOf' in r])
    from pprint import pformat
    log.debug('\n' + pformat(sorted([(l, n, [(f'http://uri.olympiangods.org/base/{p}_{i}.html', (p, i)) for p, i in sorted(pis)]) for l, n, pis in re_derp]), width=240))
    nlabs = [v for v in repl.values()]
    assert len(nlabs) == len(set(nlabs))
    return repl, label_duplicate_of, maybe_newsyns, rem_duplicate_of


# get interlex
class InterLexLoad:

    stype_lookup = synonym_types

    def __init__(self, db, do_cdes=False, skip_trips=False, debug=False, echo=False, batchsize=20000):
        # batchsize tested at 20k, 40k, and 80k, 20k runs slightly faster than the other two
        # and does it with significantly less memory usage (< 1 gig)
        self._db = db
        self.batchsize = batchsize
        TripleLoader = TripleLoaderFactory(db.session)
        self.loader = TripleLoader('tgbugs', 'tgbugs', 'http://uri.interlex.org/base/ontologies/interlex')

        self.queries = Queries(self.loader.session)
        self.do_cdes = do_cdes
        self.skip_trips = skip_trips
        self.debug = debug
        eurl = db.session.connection().engine.url
        self.admin_engine = create_engine(dbUri(dbuser='interlex-admin', host=eurl.host, port=eurl.port, database=eurl.database), echo=echo)
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
        self._sync_start = utcnowtz()
        self._get_trip_data()
        self.existing_ids()
        self.user_iris()
        self._sync_end = utcnowtz()
        self.make_triples()
        self.ids()  # this runs at the end to ensure we always get latest though that is not how ops should work
        self.make_metadata()
        #self.engine.dispose()  # doesn't make any meaningful difference in memory usage

    def make_metadata(self):
        # FIXME TODO need to decide on the metadata class for this and the uri we are going to use
        # also need to make sure that we have a way to prevent exceedingly large ontology files from
        # being reserialized if they weren't in the first place, but may way to use our nt dump code
        _source = self.engine.url
        _max_frags = self.current
        _total_triples = len(self._triples)
        _sync_start = isoformat(self._sync_start)
        _sync_end = isoformat(self._sync_end)  # processing doesn't count, we want the time window for sql queries
        _some_datetime = _sync_end
        _nowish_epoch = math.floor(self._sync_end.timestamp())
        _cdes = 'with cdes' if self.do_cdes else 'without cdes'

        s = rdflib.URIRef('http://uri.interlex.org/base/ontologies/sync')  # FIXME need better alternative
        sv = rdflib.URIRef(s + f'/version/{_nowish_epoch}/sync')

        asdf = (
            (rdf.type, owl.Ontology),
            #(rdf.type, ilxtr.OntologySync),
            #(rdfs.comment, rdflib.Literal(f'source {_source} max ilx {_max_ilx} total first pass triples {_total_triples}')),
            (ilxtr['sync-start'], rdflib.Literal(_sync_start)),
            (ilxtr['sync-end'], rdflib.Literal(_sync_end)),
            (ilxtr['sync-source'], rdflib.Literal(_source)),
            #(ilxtr['sync-max-fragpref'], rdflib.Literal(_max_ilx)),
            (ilxtr['sync-triple-count'], rdflib.Literal(_total_triples)),
            #(ilxtr['sync-git-commit'], rdflib.Literal()),
            #(ilxtr.datetime, rdflib.Literal(f'{_some_datetime}')),
            (ilxtr.epoch, rdflib.Literal(_nowish_epoch)),
            (dc.title, rdflib.Literal(f'interlex sync for {_sync_end} {_cdes}')),
            (owl.versionInfo, rdflib.Literal(_sync_end)),
            (owl.versionIRI, sv),
        )
        triples = []
        for p, o in asdf:
            triples.append((s, p, o))
        for frag, val in _max_frags.items():
            p = ilxtr[f'sync-max-{frag}']
            o = rdflib.Literal(val)
            triples.append((s, p, o))

        # FIXME also need to make sure that these are entered as metadata correctly in the call to load
        self._meta_triples = triples
        _metagraph = OntGraph()
        _metagraph.populate_from_triples(triples)
        # at the moment ingest ignores meta curies so there won't be a
        # mismatch between meta curies and triples curies
        _metagraph.namespace_manager.bind('ilxtr', ilxtr)
        class OntMetaL(OntMeta):
            def __init__(self):
                self._identifier = s
                self._graph = _metagraph

        sigh = OntMetaL()
        self._mntf = sigh

    def delete_existing(self, conn):
        # this is reasonably safe because we do retain the relations in triples
        # as well since that is how we reconstruct the history
        sql = '''
delete from existing_iris as ex
using
fragment_prefix_sequences as fps where
ex.ilx_prefix != 'tmp' and fps.prefix = ex.ilx_prefix and ex.ilx_id <= LPAD(cast(fps.suffix_max AS text), fps.current_pad, '0');

delete from existing_internal as ex
using
fragment_prefix_sequences as fps where
ex.ilx_prefix != 'tmp' and fps.prefix = ex.ilx_prefix and ex.ilx_id <= LPAD(cast(fps.suffix_max AS text), fps.current_pad, '0');

delete from uri_mapping as ex
using
fragment_prefix_sequences as fps where
ex.ilx_prefix != 'tmp' and fps.prefix = ex.ilx_prefix and ex.ilx_id <= LPAD(cast(fps.suffix_max AS text), fps.current_pad, '0');

delete from current_interlex_labels_and_exacts as ex
using
fragment_prefix_sequences as fps where
ex.prefix != 'tmp' and fps.prefix = ex.prefix and ex.id <= LPAD(cast(fps.suffix_max AS text), fps.current_pad, '0');
'''
        conn.execute(sql_text(sql))
        conn.execute(sql_text(f'savepoint delete_existing'))

    @exc.bigError
    def local_load(self, commit=True):
        def lse(conn, s, p, load_type='???'):
            # accepts two lists of equal length
            assert len(s) == len(p)
            n = len(p)
            log.debug(f'starting batch load for {load_type}')
            do_gc()  # pre/post is sufficient to stay stable, a bit of creep toward the end of a batch but it goes back down
            for i, (sql, params) in enumerate(zip(s, p)):
                conn.execute(sql_text(sql), params)
                conn.execute(sql_text(f'savepoint {load_type}'))
                msg = f'{((i + 1) / n) * 100:3.0f}% done with batched load of {load_type}'
                log.debug(msg)

            do_gc()

        vt_current, params_current = makeParamsValues(list(self.current.items()))
        # start sitting at around 10 gigs in pypy3 (oof)
        # now stays below 8 gigs in pypy3, and below about 1gig in postgres with 40k batch size, much better, 600mb at 20k
        with self.admin_engine.connect() as conn:
            # while only delete_existing and update current require the admin connection,
            # since we are deleting the contents of existing tables we want it all in the
            # same transaction, which means that sync will effectively parts of the database
            # for the duration, however since this is only intended for the initial migration
            # and possibly subsequent maintenance periods it is ok for now because we ensure
            # that any other operations happen on consistent state
            self.delete_existing(conn)
            lse(conn, self.ilx_sql, self.ilx_params, 'interlex_ids')  # 3 gigs in postgres no batching
            lse(conn, self.label_exact_sql, self.label_exact_params, 'label_exact')
            lse(conn, self.eid_sql, self.eid_params, 'existing_iris')  # 16.4 gigs in postgres with no batching
            lse(conn, self.int_eid_sql, self.int_eid_params, 'existing_internal')
            lse(conn, self.uid_sql, self.uid_params, 'uris')

        # FIXME this probably requires admin permissions
            #conn.execute(sql_text(f"SELECT setval('interlex_ids_seq', {self.current}, TRUE)"))  # DANGERZONE
            # calling UPDATE on this without the function requires admin (sensibly)
            conn.execute(sql_text(
                'INSERT INTO fragment_prefix_sequences (prefix, suffix_max) '
                f'VALUES {vt_current} ON CONFLICT (prefix) DO UPDATE '
                'SET suffix_max = EXCLUDED.suffix_max '
                'WHERE fragment_prefix_sequences.prefix = EXCLUDED.prefix'),
                         params_current)
            if commit:
                conn.commit()
            else:
                breakpoint()
                pass

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
        # FIXME we need to insure that the interlex id seq is present before triples go in because
        # we want to make sure that only ids that have been minted can be inserted into the triples
        # table ... might need a trigger for that one though
        serialization_identity = None
        metadata_to_fetch = self._mntf  # FIXME TODO populate from self._meta_triples
        metadata_not_to_fetch = None
        local_conventions = None

        if self.skip_trips:
            log.info('skipping triple ingest')
        else:
            # sometimes the triples haven't changed and we need to fix something downstream
            triples = self._meta_triples + self._triples
            do_process_into_session(self._db.session, process_triple_seq,
                                    triples,
                                    serialization_identity,
                                    metadata_to_fetch,
                                    metadata_not_to_fetch,
                                    local_conventions,
                                    commit=True, batchsize=self.batchsize, debug=True)

        self.local_load()
        #self.local_load_part2()
        #self.remote_load()

    def ids(self):
        with self.engine.connect() as conn:
            rows = conn.execute(sql_text('SELECT DISTINCT ilx, label FROM terms ORDER BY ilx ASC'))

        values = [(row.ilx[:3], row.ilx[4:], row.label) for row in rows]
        bads = [v for v in values if v[2] != v[2].strip() or not v[2].strip()]
        if bads:
            log.warning(bads)
            values = [(v[0], v[1], v[2].strip()) for v in values]
            values = [v for v in values if v[2]]

        fixed_values = []
        for p, i, l in values:
            # FIXME l may not be normalized and thus may not match what is in triples
            if (p, i) in self.repl_label:
                fixed_values.append((p, i, self.repl_label[(p, i)]))
            else:
                fixed_values.append((p, i, l))

        values = fixed_values

        self.ilx_sql = []
        self.ilx_params = []
        self.label_exact_sql = []
        self.label_exact_params = []
        for chunk in chunk_list(values, self.batchsize):
            vt, params = makeParamsValues(chunk)
            sql = ('INSERT INTO interlex_ids (prefix, id, original_label) VALUES ' + vt +
                   ' ON CONFLICT (prefix, id) DO UPDATE SET original_label = EXCLUDED.original_label')
            self.ilx_sql.append(sql)
            self.ilx_params.append(params)
            lvt = vt.replace(')', ', :pred)')
            lsql = 'INSERT INTO current_interlex_labels_and_exacts (prefix, id, o_lit, p) VALUES ' + lvt # can't ocdn on this one
            self.label_exact_sql.append(lsql)
            self.label_exact_params.append({**params, 'pred': 'label'})

        prefixes = set(v[0] for v in values)
        self.current = {p:int([v for v in values if v[0] == p][-1][1]) for p in prefixes}
        #self.current = int(values[-1][1].strip('0'))
        log.info(self.current)

    def cull_bads(self, eternal_screaming, values, ind):
        verwat = defaultdict(list)
        for row in sorted(eternal_screaming, key=lambda r:r.version, reverse=True):
            #row[ind('ilx')][4:]
            pref, ilx = row.ilx[:3], row.ilx[4:]
            verwat[pref, ilx].append(row)

        vervals = list(verwat.values())

        dexr = set()
        duplicate_ex_rec = defaultdict(list)  # catches multiple rows with identical curies in addition to multiple curies
        ver_curies = defaultdict(lambda:[None, set()])
        for (pref, ilx), rows in verwat.items():
            for row in rows:
                iri = row.iri  # row[ind('iri')]
                curie = row.curie  # [ind('curie')]
                if (pref, ilx, iri, row.version) in dexr:
                    duplicate_ex_rec[(pref, ilx, iri, row.version)].append(row)
                else:
                    dexr.add((pref, ilx, iri, row.version))
                ver_curies[iri][0] = (pref, ilx)
                ver_curies[iri][1].add(curie)

        mult_curies = {k: v for k, v in ver_curies.items() if len(v[1]) > 1}

        deprecated = set()
        deleted = set()
        for row in self._data['terms']:
            if row.status == -1:
                pi = tuple(row.ilx.split('_'))
                deleted.add(pi)  # review these because some were mistaken
            elif row.status == -2:  # deprecated ???
                pi = tuple(row.ilx.split('_'))
                deprecated.add(pi)

        maybe_mult = defaultdict(list)
        versions = defaultdict(list)
        for pref, ilx, iri, ver in sorted(values, key=lambda t: t[-1], reverse=True):
            versions[pref, ilx].append(ver)
            pi = pref, ilx
            v = ('dep', pi) if pi in deprecated else (('del', pi) if pi in deleted else ('aok', pi))
            maybe_mult[iri].append(v)

        multiple_versions = {k:v for k, v in versions.items() if len(set(v)) > 1}
        # if there are multiple iris they would be caught in the other steps
        # these will be the ones that have the same iri in multiple versions
        bad_versions = set((pref, ilx, nmv) for (pref, ilx), vs in multiple_versions.items() for nmv in sorted(vs)[:-1])

        any_mult = {k:tuple(sorted(v)) for k, v in maybe_mult.items() if len(v) > 1}

        dupe_report = {k:tuple((status, f'http://uri.interlex.org/base/{p}_{i}') for status, (p, i) in sorted(v))
                       for k, v in maybe_mult.items()
                       if len(set(v)) > 1}
        readable_report = {OntId(k):tuple((s, OntId(e)) for s, e in v)
                           for k, v in dupe_report.items()}
        log.debug('obvious duplicate report')
        _ = [print(repr(k), '\t', *(f'{e!r}' for e in v))
             for k, v in sorted(readable_report.items())]

        dupes = tuple(dupe_report) + tuple(mult_curies)

        dupe_depdel = set()
        eid_duplicate_of = []
        _eiddo_done = set()
        already_replaced = (  # FIXME ideally not hardcode this ...
            # these are actually already replaced
            ('ilx', '0793234'),  # Interganglionic branch of inferior cervical ganglion to middle cervical ganglion -> ILX:0738290
            ('ilx', '0793233'),  # Interganglionic branch of inferior cervical ganglion to first thoracic ganglion -> ILX:0738291
            # these I'm manually forcing here
            ('ilx', '0741726'),  # frontal notch (TA98)
            ('ilx', '0741680'),  # median sacral crest (TA98)
            ('ilx', '0739010'),  # long qt syndrome XXX this one has way more info so def need to make sure to merge it back
            ('ilx', '0108304'),  # overlay type
        )
        self.ignore_depdel = (
            ('ilx', '0106349'),  # long qt syndrome
            ('ilx', '0108300'),  # overlay planes
            ('ilx', '0738373'),  # Internal branch of superior laryngeal nerve XXX incorrect deprecation procedure
        )
        merge_label_priority = (  # in the event that newer takes priority over older
            ('ilx', '0739010'),  # long qt syndrome
            ('ilx', '0108304'),  # overlay type
            ('ilx', '0793561'),  # internal branch of superior laryngeal nerve
        )
        manual_no_eid = (  # better not to guess on these where they are already double mapped and deduped
            # if deprecated/replaced terms retain an existing iri we will port them over later
            ('ilx', '0739010', 'http://uri.neuinfo.org/nif/nifstd/oen_0001063'),  # long qt syndrome
            ('ilx', '0108304', 'http://uri.interlex.org/dicom/uris/terms/60xx_0040'),  # overlay type
            ('ilx', '0108304', 'http://uri.neuinfo.org/nif/nifstd/nlx_150436'),
            ('ilx', '0793234', 'http://purl.org/sig/ont/fma/fma6942'),  # Interganglionic branch of inferior cervical ganglion to middle cervical ganglion -> ILX:0738290
            ('ilx', '0793233', 'http://purl.org/sig/ont/fma/fma6944'),  # Interganglionic branch of inferior cervical ganglion to first thoracic ganglion -> ILX:0738291
            ('ilx', '0741726', 'https://taviewer.openanatomy.org/?id=A02.1.03.010'),  # frontal notch (TA98)
            ('ilx', '0741680', 'https://taviewer.openanatomy.org/?id=A02.2.05.014'),  # median sacral crest (TA98)
        )
        flip = ((('ilx', '0738373'), ('ilx', '0793561')),)
        for iri, _stat_pis in any_mult.items():
            stat_pis = tuple(sorted(set(_stat_pis)))
            if len(stat_pis) == 1:  # version mult
                continue
            ref = None
            _dupes = []
            for status, (p, i) in stat_pis:
                pi = p, i
                if status in ('dep', 'del') and pi not in self.ignore_depdel:
                    dupe_depdel.add((p, i, iri))
                    _dupes.append(pi)
                elif status == 'aok':
                    if ref is None:
                        ref = pi
                    elif pi in already_replaced:
                        continue
                    else:
                        rp, ri = ref
                        ru = f'http://uri.olympiangods.org/base/{rp}_{ri}.html'
                        u = f'http://uri.olympiangods.org/base/{p}_{i}.html'
                        log.error(f'conflict {iri} {ref} {pi} {ru} {u} {stat_pis}')
                        ref = None

            if stat_pis in _eiddo_done:
                continue

            _eiddo_done.add(stat_pis)
            if ref is not None:
                for d in _dupes:
                    eid_duplicate_of.append((d, ref))

        # dupes = [u for u, c in Counter(_[1] for _ in values).most_common() if c > 1]  # picked up non-unique ilx which is not what we wanted

        #ok_by_other_skip = set(iri for p, i, iri in dupe_depdel)
        #grrr = set((p, i) for p, i, iri in dupe_depdel)

        skips = []
        bads = []
        #bads += [(p, a, b) for p, a, b, _ in values if (b in dupes and b not in ok_by_other_skip) or (p, a) in grrr]
        #bads += [(p, i, r) for p, i, r, v in duplicate_ex_rec]  # wierd that pi is distinct here ???  XXX FIXME there is no way to skip this they are just straight duplicates right now
        # TODO one of these is incorrect can't quite figure out which, so skipping entirely for now
        fixes = {}
        for pref, id_, iri, version in values:  # FIXME
            if ' ' in iri:  # sigh, skip these for now since pguri doesn't seem to handled them
                if 'TOPNT' in iri:
                    if '[' in iri:
                        fixes[iri] = iri.replace(' ', '%20').replace('[', url_quote('[')).replace(']', url_quote(']'))
                    else:
                        fixes[iri] = iri.replace(' ', '_').replace('__', '_')
                elif 'SNOMEDCT' in iri:
                    fixes[iri] = iri.replace(' ', '')
                else:
                    bads.append((pref, id_, iri))
            elif (pref, id_, iri) in dupe_depdel:
                skips.append((pref, id_, iri))
            elif 'neurolex.org/wiki' in iri:
                skips.append((pref, id_, iri))

        bads = sorted(bads, key=lambda ab:ab[1])
        # XXX reminder: values comes from start_values and already excludes self referential external ids
        sbads, sskips, sbad_versions = set(bads), set(skips), set(bad_versions)
        _ins_values = [
            (pref, ilx, (fixes[iri] if iri in fixes else iri)) for pref, ilx, iri, ver in values if
            (pref, ilx, iri) not in sbads and
            (pref, ilx, iri) not in sskips and
            (pref, ilx, ver) not in sbad_versions and
            (pref, ilx, iri) not in manual_no_eid
            #(pref, ilx, iri, ver) not in duplicate_ex_rec
        ]

        sigh = set(a for a, b in Counter(_ins_values).most_common() if b > 1)

        _a = set(_ins_values)
        _b = set([(p, i, r) for p, i, r, v in duplicate_ex_rec])
        _a & _b == _b
        sigh == _b
        self_ref = _b - sigh
        assert not [(p, i, r) for p, i, r in self_ref if r != f'http://uri.interlex.org/base/{p}_{i}']
        _i = set(r for p, i, r in _ins_values)
        _s = set(r for p, i, r in skips)
        hrm = _s - _i
        rtm = [h for h in hrm if 'neurolex' not in h]
        assert not rtm, 'removed too much'
        # we are ok to clean up _ins_values to remove duplicates at this point
        _ins_values = sorted(set(_ins_values))

        def morefix(p, i, iri):
            if iri.endswith(';'):  # yes fix it in the source but
                out = iri[:-1]
                log.debug((p, i, iri, out))
            elif iri.startswith('https://scicrunch.org'):
                out = 'http' + iri[5:]
                if 'RRID:' in out:
                    out = out.replace('RRID:', '')

                log.debug((p, i, iri, out))
            else:
                out = iri.replace(
                    'https://ncimeta.nci.nih.gov/ncimbrowser/ConceptReport.jsp?dictionary=NCI%20Metathesaurus&code=',
                    'https://evsexplore.semantics.cancer.gov/evsexplore/concept/ncim/',)

            return out

        _ins_values = [(p, i, morefix(p, i, r)) for p, i, r in _ins_values]
        skips = [(p, i, morefix(p, i, r)) for p, i, r in skips]

        # however we have a non-injective problem still
        dd = defaultdict(list)
        for p, i, r in _ins_values:
            dd[r].append((p, i))
        ohno_v = {r:pis for r, pis in dd.items() if len(pis) > 1}
        if ohno_v:
            assert False, 'non-injective'

        ins_values = []  # [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' not in iri]
        for pref, ilx, iri in _ins_values:
            if 'interlex.org' not in iri:
                ins_values.append((pref, ilx, iri))

        user_iris = []  # [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' in iri and 'org/base/' not in iri]
        for pref, ilx, iri in _ins_values:
            if 'interlex.org' in iri and 'org/base/' not in iri:
                user_iris.append((pref, ilx, iri))

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
        base_iris = [] #  [(pref, ilx, iri) for pref, ilx, iri in _ins_values if 'interlex.org' in iri and 'org/base/' in iri]
        for pref, ilx, iri in _ins_values:
            if 'interlex.org' in iri and 'org/base/' in iri:
                base_iris.append((pref, ilx, iri))
        # FIXME replacedBys non-unique
        # FIXME these aren't actually replacedBys they are duplicateOfs because rb implies an old in time relaced by new in time
        # however some of them actually _are_ replacedBys as in the case of cdes
        #replacedBys = [(  # this should be injective by construction all the violations should be in bads of one kind or another
        #    rdflib.URIRef(eid),
        #    replacedBy,
        #    rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),
        #    ) for pref, ilx, eid in base_iris]

        more_eid_duplicate_of = [((pref, ilx), getpi(eid)) if (getpi(eid), (pref, ilx)) in flip else (getpi(eid), (pref, ilx))
                                 for pref, ilx, eid in base_iris if pref != 'cde'
                                 and getpi(eid) not in already_replaced]
        sedo = set(eid_duplicate_of)
        smedo = set(more_eid_duplicate_of)
        redundant = smedo & sedo

        eid_duplicate_of = eid_duplicate_of + more_eid_duplicate_of
        sedo = set(eid_duplicate_of)
        if len(eid_duplicate_of) != len(sedo):
            qq = [(a, b) for a, b in Counter(eid_duplicate_of).most_common() if b > 1]
            if set([a for a, b in qq]) != redundant:
                assert False, 'derp'
                # this is because these have more than one existing iri in common ?
                log.error('eid_duplicate_of has non-unique values')

        for (ap, ai), (bp, bi) in eid_duplicate_of:
            if ai <= bi:
                # long qt syndrome and overlay planes vs overlay type
                # lqts should switch direction and planes and type should be merged but type gets label priority
                log.error(f'wrong replace direction {ap} {ai} <= {bp} {bi}')

        # at this point it is safe to clean up eiddo
        eid_duplicate_of = sorted(sedo)

        sa = [a for a, b in sedo]
        if len(set(sa)) != len(sa):
            qq = [(a, b) for a, b in Counter(sa).most_common() if b > 1]
            log.error('duplicate duplicate mappings for some terms!')

        # these are the real replacedBy cases
        eid_replaced_by = [(getpi(eid), (pref, ilx)) for pref, ilx, eid in base_iris if pref == 'cde']
        serb = set(eid_replaced_by)
        if len(serb) != len(eid_replaced_by):
            qq = [(a, b) for a, b in Counter(eid_replaced_by).most_common() if b > 1]
            log.error('eid_replaced_by has non-unique values')

        sarb = [a for a, b in sedo]
        if len(set(sarb)) != len(sarb):
            qq = [(a, b) for a, b in Counter(sarb).most_common() if b > 1]
            log.error('duplicate replacedBy mappings for some terms!')

        assert len(ins_values) + len(user_iris) + len(base_iris) == len(_ins_values)

        #ins_values += [(v[0], k) for k, v in mult_curies.items()]  # add curies back now fixed
        if self.debug:
            breakpoint()
        return ins_values, bads, skips, user_iris, eid_replaced_by, eid_duplicate_of

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

        values, bads, skips, user_iris, eid_replaced_by, eid_duplicate_of = self.cull_bads(eternal_screaming, start_values, ind)

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
            sql = sql_base + values_template + ocdn  # TODO return id? (on conflict ok here)
            self.eid_sql.append(sql)
            self.eid_params.append(params)

        self.eid_replaced_by = eid_replaced_by
        self.eid_duplicate_of = eid_duplicate_of

        if self.debug or True:  # needed for label/syn dedue
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

        self.uri_mapping_values = _values  # need for triples for history

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
        for chunk in chunk_list(values, self.batchsize):
            vt_uri, vt_uri_mapping, params = makeParamsValues(chunk, vsplit=((2, None), (0, None)))
            sql = (sql_uri + vt_uri + ocdn + ';' + sql_uri_mapping + vt_uri_mapping + ocdn)
            self.uid_sql.append(sql)
            self.uid_params.append(params)

    def _get_trip_data(self):
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

        self._data = data

    def make_triples(self):
        data = self._data
        #breakpoint()  # XXX break here
        ilx_index = {}
        id_type = {}
        triples = [(rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),  # FIXME hardcoded structure
                    oboInOwl.hasDbXref, rdflib.URIRef(iri)) for pref, ilx, iri in self.eid_skips]  # FIXME broken for new fragment prefixes

        # fill values that have gone in other tables here as well because
        # we want to reuse the triple table history to track these and the
        # sql tables to enforce consistency at any given moment
        # these are mediated by special predicates

        # FIXME special predicates should probably switch over to use uilx.org ids for space reasons for now
        # ilx ids           ilxtr:origLabel        # only in cases where we had to change rdfs:label
        # existing iris     ilxtr:hasExternalId    # goes on the main ilx term because it is part of the history of that term
        # existing internal replacedBy: or ilxtr:duplicateOf  # goes on the replaced term because it tracks history of the replaced
        # user iris         ilxtr:hasIlxId         # FIXME pred, goes from user uri to ilx term since it is for history tracking of the user uri
        # labels and exacts ilxtr:hasExactSynonym  # FIXME pred, we only set label right now, will have an exact promotion party later

        # point of interest here is that the uri mapping values here are present for history
        # but despite sharing a subject with a user uri, do not share a perspective, because
        # that mapping is controlled by interlex, it can only be changed by the user if they
        # also update it, and they may not define the mapping in the source file that defines
        # those user iris
        triples.extend([
            (rdflib.URIRef(f'http://uri.interlex.org/{g}/uris/{uri_path}'),
             ilxtr.hasIlxId,
             rdflib.URIRef(f'http://uri.interlex.org/base/{p}_{i}'))
            for p, i, g, uri_path in self.uri_mapping_values])
        triples.extend([
            (rdflib.URIRef(f'http://uri.interlex.org/base/{p}_{i}'),
             ilxtr.hasExternalId,
             rdflib.URIRef(r))
            for p, i, r in self.eid_values])

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

        def norm_obj(context, o_raw):
            o_strip = o_raw.strip()
            if o_strip != o_raw:
                msg = ('FIXME this needs to be handled more formally than a debug message ... '
                       f'leading or trailing whitespace in {context}: {o_strip!r} != {o_raw!r}')
                log.debug(msg)

            if not o_strip:
                msg = f'empty value for {context}'
                log.debug(msg)
                return None

            return o_strip


        repl_label, label_duplicate_of, maybe_newsyns, rem_duplicate_of = fix_laex(self, data, self.eid_duplicate_of, self.eid_values)

        duplicate_ofs = sorted(((set(self.eid_duplicate_of) | set(label_duplicate_of)) - set(rem_duplicate_of)))

        dor = [d for d, ref in duplicate_ofs]
        sdor = set(dor)
        if len(dor) != len(sdor):
            log.error(f'non-unique mappings {len(dor)} != {len(sdor)}')
            qq = [(a, b) for a, b in Counter(dor).most_common() if b > 1]
            zz = [a for a, b in qq]
            ouch = [((d, r),
                     pi_lab[d], pi_lab[r],
                     (d, r) in self.eid_duplicate_of, (d, r) in label_duplicate_of)
                    for d, r in duplicate_ofs if d in zz]

        baddup = [(d, r) for d, r in duplicate_ofs if d[1] < r[1]]
        if baddup:
            log.error(f'bad duplicate direction {baddup}')

        replacedBys = [(
            rdflib.URIRef(f'http://uri.interlex.org/base/{epref}_{eilx}'),
            replacedBy,
            rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),
            ) for (epref, eilx), (pref, ilx) in self.eid_replaced_by]

        duplicateOfs = [(
            rdflib.URIRef(f'http://uri.interlex.org/base/{epref}_{eilx}'),
            ilxtr.duplicateOf,  # FIXME predicate
            rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),
            ) for (epref, eilx), (pref, ilx) in duplicate_ofs]

        replaced = set(s for s, p, o in replacedBys)
        duplicates = set(s for s, p, o in duplicateOfs)

        sql_base = 'INSERT INTO existing_internal (ex_ilx_prefix, ex_ilx_id, ilx_prefix, ilx_id) VALUES '
        self.int_eid_sql = []
        self.int_eid_params = []
        for chunk in chunk_list([(*a, *b) for a, b in duplicate_ofs + self.eid_replaced_by], self.batchsize):
            values_template, params = makeParamsValues(chunk)
            params['group'] = 'base'
            sql = sql_base + values_template + ' ON CONFLICT DO NOTHING'  # TODO return id? (on conflict ok here)
            self.int_eid_sql.append(sql)
            self.int_eid_params.append(params)

        self.repl_label = repl_label

        duplicateOfs = [(
            rdflib.URIRef(f'http://uri.interlex.org/base/{epref}_{eilx}'),
            ilxtr.duplicateOf,  # FIXME predicate
            rdflib.URIRef(f'http://uri.interlex.org/base/{pref}_{ilx}'),
            ) for (epref, eilx), (pref, ilx) in label_duplicate_of]

        #self.duplicateOfs
        #sdos, ssdos = set(duplicateOfs), set(self.duplicateOfs)
        #double_dupes = sdos & ssdos
        #_dofs = sorted(sdos | ssdos)
        triples.extend(duplicateOfs)
        triples.extend(replacedBys)  # FIXME uh ... why were these inserted ???
        #replaced_lu = {s: o for s, p, o in self.replacedBys}  # FIXME check injective
        #replaced = set(self.replacedBys)
        #self.replacedBys = None  # a bit of cleanup foor memory hopefully

        obsReason, termsMerged = makeURIs('obsReason', 'termsMerged')
        deprecated = set()
        bads = []
        nolabs = []
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

            if (frag_pref, ilx) in repl_label:
                label = repl_label[frag_pref, ilx]
                # TODO maybe_newsyns
                syn = maybe_newsyns[frag_pref, ilx]
                triples.append((uri, ilxtr.origLabel, rdflib.Literal(norm_obj(uri, syn))))
            else:
                label = row.label

            if label and (normed_label := norm_obj(uri, label)):
                triples.append((uri, rdfs.label, rdflib.Literal(normed_label)))
            else:
                nolabs.append(uri)

            if row.definition and (normed_definition := norm_obj(uri, row.definition)):  # if you can't see the invisible assume it is always there
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
                if (frag_pref, ilx) not in self.ignore_depdel:
                    deprecated.add(uri)
                    triples.append((uri, owl.deprecated, rdflib.Literal(True)))

            if uri in duplicates or uri in replaced:  # invert the logic
                # FIXME these really aren't deprecations in the owl sense, they
                # are "don't use this identifier" the concept is still valid it
                # is just that the name is not
                if uri in duplicates:
                    triples.append((uri, obsReason, termsMerged))
                else:
                    triples.append((uri, obsReason, ilxtr.idMigration))

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
        syn_annos = defaultdict(set)
        done_sy = set()
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
                if t not in done_sy:
                    done_sy.add(t)
                    triples.append(t)

                if type:  # yay for empty string! >_<
                    stype = self.stype_lookup[type]
                    at = (ilxtr.synonymType, stype)
                    syn_annos[t].add(at)

        done_sy = None
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
        done_op = set()
        for row in data['object_properties']:
            _, s_id, o_id, p_id, *rest = row
            ids_triple = s_id, p_id, o_id
            try:
                t = tuple(baseUri(e) for e in ids_triple)
                if t in done_op:
                    continue
                done_op.add(t)
                triples.append(t)
            except KeyError as e:
                WTF.append(row)

        done_op = None

        re_https = re.compile('^https?://')
        def normalize_annotation_property_object(context, o_raw):
            o_strip = norm_obj(context, o_raw)
            if re.match(re_https, o_strip):
                _oin = o_strip
                if ' ' in o_strip:
                    if 'FMAID: ' in o_strip:
                        o_strip = o_strip.replace(' ', '')
                    elif 'NCBITaxon: ' in o_strip:
                        o_strip = o_strip.replace(' ', '')
                    elif 'PATO 'in o_strip:
                        o_strip = o_strip.replace(' ', ':')
                    else:
                        log.warning(o_strip)
                        return rdflib.Literal(o_strip)

                if o_strip.startswith('https://scicrunch.org'):  # apparently these aren't in annotation properties somehow ?? must be existing ids
                    o_strip = 'http' + o_strip[5:]
                    if 'RRID:' in o_strip:
                        o_strip = o_strip.replace('RRID:', '')

                elif o_strip.startswith('https://en.wikipedia.org'):
                    o_strip = 'http' + o_strip[5:]

                o_strip = url_quote(url_unquote(o_strip), safe='/&?=+:.,!*@#$();\'')
                if o_strip != _oin:
                    log.info(f'normalized {_oin} -> {o_strip}')

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
        done_ap = set()
        for row in data['annotation_properties']:  # oof knocks total triples to 12.5 mil
            _, s_id, p_id, o_value, comment, *rest = row
            try:
                s = baseUri(s_id)
                o = normalize_annotation_property_object(s, o_value)
                t = s, baseUri(p_id), o
                if t in done_ap:
                    continue
                done_ap.add(t)
                triples.append(t)
                if comment:
                    cstrp = norm_obj(s, comment)
                    if cstrp:
                        ap_annos[t].append((ilxtr.comment, rdflib.Literal(cstrp)))  # FIXME TODO predicate
            except KeyError as e:
                WTFa.append(row)

        done_ap = None
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
        done_sc = set()
        for row in data['subClassOf']:
            _, s_id, o_id, *rest = row
            if (s_id, o_id) in done_sc:
                continue
            done_sc.add((s_id, o_id))
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

        done_sc = None
        #engine.execute()
        #breakpoint()

        _uris = set(e for t in triples for e in t if isinstance(e, rdflib.URIRef))
        _paths = defaultdict(list)
        _schemes = defaultdict(set)
        _colms = defaultdict(list)
        ms = 'en.wikipedia.org', 'scicrunch.org'
        # normalize wiki https -> http to match the vast majority of what we have
        # normalize scr -> http and without the RRID:
        for u in _uris:
            up = urlparse(u)
            _schemes[up.netloc].add(up.scheme)
            if up.netloc in ms:
                _colms[up.netloc].append(u)

            _rest = u.split('/', 3)[-1]
            _paths[_rest].append(u)

        _http = {h: s for h, s in _schemes.items() if 'http' in s and 'https' not in s}
        _https = {h: s for h, s in _schemes.items() if 'https' in s and 'http' not in s}
        _multi_scheme = {h:ss for h, ss in _schemes.items() if len(ss) > 1}
        _both = _multi_scheme
        if _both:
            log.warning(_both)

        _multi_path = {p: us for p, us in _paths.items() if len(us) > 1}
        if _multi_path:
            log.warning(_multi_path)

        #_percent_path = {p: us for p, us in _paths.items() if '%' in p}
        #_unpaths = {url_unquote(p): [url_unquote(u) for u in us] for p, us in _paths.items()}
        # oooh http vs https ... gonna have to deal with that ... nowish
        # at least for stuff that is coming from us, might need a record
        # but we have to normalize somewhere, maybe can can record domains
        # where we have seen https? that seems tractable?
        safe = '/&?=+:.,!*@#$();\''  # uriparser ; is safe in
        unsafe = '<>{}[] ^|'  # + unicode (and technically %) don't want to double escape
        #wat = [rdflib.URIRef(u) for us in _unpaths.values() for u in us if ' ' not  in u]  # umls is really bad for this
        #_badpaths = {p: us for p, us in _unpaths.items() if url_quote(p, safe='/&?=+:.,!*@#$();\'') != p}  # FIXME ; in uri at end is 99% a mistake
        #_sigh = {p: us for p, us in _unpaths.items() if ';' in p}  # oh boy
        #_wat = {p: us for p, us in _unpaths.items() if 'uri.interlex.org' in us[0] and not p.split('/', 1)[0].isalpha()}
        # the number of badpaths is small enough now that we've switched out the umls iris that have spaces
        _final_check = {p: us for p, us in _paths.items() if '%' not in p and url_quote(p, safe='/&?=+:.,!*@#$();\'') != p}
        if _final_check:
            log.warning(_final_check)

        # TODO have to find common denominator between uriparser and rdflib ...
        # also unfortunately we cannot deviate from the stored form for external
        # ontologies unless we add a normalization pass, but that can break
        # when there are escaped and unescaped variants of uri in the same file
        # as in, I'd really rather have a situation where different seriazations
        # can converge on the same gclc because we enforce normalization to a form
        # without any replicas because it makes everything vastly simpler, but
        # it means we can't reproduce the original set of triples and bnode structure
        # which would be ok if we just store the raw inputs

        # the policy is as follows
        # interlex does not escape or unescape uris during processing
        # the only charachters that must be escaped are those that cause
        # uripraser or rdflib to fail/warn (uriparser is the superset)
        # the most obvious set for these are unicode chars
        # and <>{}[] ^| though there may be others as well

        self._triples = triples
        self.wat = bads, WTF, WTF2
        if self.debug and (bads or WTF or WTF2):
            log.debug(bads[:10])
            log.debug(WTF[:10])
            log.debug(WTF2[:10])
            breakpoint()
            raise ValueError('BADS HAVE ENTERED THE DATABASE AAAAAAAAAAAA')
        return triples
