"""
load directly to db from a uri
run as a shell script in a subprocess to avoid lxml memory leak issues >_<
"""

import gc
import os
import sys
import signal
import shutil
import base64
import pathlib
import tempfile
import subprocess
from collections import defaultdict, Counter
from itertools import chain
from urllib.parse import urlparse
import idlib
import rdflib
import requests
from rdflib.exceptions import ParserError as ParseError
from rdflib.plugins.parsers import ntriples as nt
from sqlalchemy.sql import text as sql_text
from ttlser.serializers import natsort
from pyontutils.core import OntGraph, OntResIri
from pyontutils.utils_fast import chunk_list
from pyontutils.namespaces import owl
from pyontutils.identity_bnode import IdentityBNode, toposort, idf, it as ibn_it, split_named_bnode
from . import exceptions as exc
from .core import getScopedSession, makeParamsValues
from .dump import Queries, TripleExporter
from .utils import log

try:
    from desc.prof import profile_me
except ModuleNotFoundError as e:
    def profile_me(f):
        return f

log = log.getChild('ingest')


# ocdn is used extensively at the moment because it uses less memory
# to try to insert and fail than it does to compute collective identities
# in advance and only insert if the identity is not already present
# we insert the serialization identity last because that can be used
# as a way to detect whether something has already been ingested
# most of the time this approach is safe because the process just needs
# the record to be present in the database and a conflict is not a
# problem, HOWEVER if there is a bug in the unique constraints on a
# table then this will mask the issue, ANOTHER area that is a risk
# is if the identity function changes, inducing silent conflicts
ocdn = 'ON CONFLICT DO NOTHING'

_batchsize = 20000  # good enough, could profile more to tune better


class BCTX:
    def get(self, nid, default=None):
        return nid


bctx = BCTX()


class GenNTParser(nt.W3CNTriplesParser):

    def gen(self, f, bnode_context=None, skolemize=False):
        if not hasattr(f, "read"):
            raise ParseError("Item to parse must be a file-like object.")

        if not hasattr(f, "encoding") and not hasattr(f, "charbuffer"):
            # someone still using a bytestream here?
            f = codecs.getreader("utf-8")(f)

        bnode_context = bctx
        self.file = f
        self.buffer = ""
        while True:
            self.line = self.readline()
            if self.line is None:
                break
            try:
                yield self.parseline(bnode_context=bnode_context)
            except ParseError:
                raise ParseError("Invalid line: {}".format(self.line))

    def parseline(self, bnode_context=None):
        self.eat(nt.r_wspace)
        if (not self.line) or self.line.startswith("#"):
            return  # The line is empty or a comment

        subject = self.subject(bnode_context)
        self.eat(nt.r_wspaces)

        predicate = self.predicate()
        self.eat(nt.r_wspaces)

        object_ = self.object(bnode_context)
        self.eat(nt.r_tail)

        if self.line:
            raise ParseError("Trailing garbage: {}".format(self.line))

        return subject, predicate, object_


def gent(path):
    gnt = GenNTParser()
    with open(path, 'rt') as f:
        yield from gnt.gen(f)


def bnode_last(e):
    # https://stackoverflow.com/a/29563948
    # https://en.wikipedia.org/wiki/Private_Use_Areas
    return '\uf8ff' if isinstance(e, rdflib.BNode) else e


def sortkey(triple):
    s, p, o = triple
    s = bnode_last(s)
    o = bnode_last(o)
    return p, o, s


def normalize(cmax, t, existing, sgid, replica):#, subgraph_and_integer, subgraph_object_dupes):
    for i, e in enumerate(t):
        if isinstance(e, rdflib.BNode):
            if e not in existing:
                cmax += 1
                existing[e] = cmax
                #if e in subgraph_and_integer:
                    #subgraph_object_dupes[e, sgid] = replica, cmax
                #else:
                    #subgraph_and_integer[e] = sgid, replica, cmax

            yield existing[e]
        else:
            yield e

    yield cmax


def normgraph(head_subject, subgraph, sgid, replica, subject_condensed_idents, secondaries):#, subgraph_integer, subgraph_object_dupes):
    """ replace the bnodes with local integers inside the graph """
    _osg = subgraph
    try:
        g = OntGraph(bind_namespaces='none').populate_from_triples((((bnNone if s is None else s), p, o) for s, p, o in subgraph))
    except Exception as e:
        breakpoint()
        raise e

    subgraph = list(g.subject_triples(head_subject))  # FIXME isn't this redundant ????

    cmax = 0

    #if head_subject in subgraph_and_integer:
    #    # we hit this because there are cases where nodes can
    #    # be in connected heads and free heads but also where
    #    # they can be a free head AND somewhere down a
    #    # connected graph as well
    #    e_sgid, e_replica, e_cmax = subgraph_and_integer[head_subject]
    #    assert e_cmax != 0, 'THERE CAN BE ONLY ONE'
    #    subgraph_object_dupes[head_subject, e_sgid] = e_replica, e_cmax

    #subgraph_and_integer[head_subject] = sgid, replica, cmax
    existing = {head_subject:0}  # FIXME the head of a list is arbitrary :/
    normalized = []
    for trip in sorted(subgraph, key=sortkey):
        s, p, o = trip
        if o == head_subject:
            if not isinstance(o, rdflib.BNode):
                #printD(tc.red('Yep working'), trip, o)
                continue  # this has already been entered as part of data_unnamed
            else:
                # this branch happens e.g. if the subgraph is malformed
                # and e.g. contains other bits of graph that e.g. have
                # head_subject in the object position because they are
                # from the raw subgraph_mappings that are used for debug
                # this particular example is avoided above via subject_triples
                breakpoint()
                raise TypeError('This should never happen!')

        *ntrip, cmax = normalize(cmax, trip, existing, sgid, replica)#, subgraph_and_integer)

        o_scid, o_replica = None, None
        if isinstance(o, rdflib.BNode):
            o_scid = subject_condensed_idents[o]  # o has to be in already due to toposort
            if o_scid in secondaries:
                o_replica = secondaries[o_scid]

        normalized.append((*ntrip, o_scid, o_replica))  # XXX o_ind sould always be zero in these cases

    return tuple(normalized)




# TODO will need api key verification etc.
# or we might only allow this to run in the first place if the user has permissions


def do_loader(loader, n, ebn, commit=False):
    check_failed = loader.check(n)
    if check_failed:
        # me wondering how tasks.base_ffi every succeeds ...
        # answer: we never raise on check_failed >_< DERP
        raise exc.LoadError(check_failed)

    setup_failed = loader(ebn)
    if setup_failed:
        raise exc.LoadError(setup_failed)

    out = loader.load(commit=commit)
    return out


# TODO into OntGraph or OntMetaIri

def _metadata_embedded(mg):
    if not _dangling(mg):
        return _metadata_truncated_embedded(mg)

def _metadata_condensed(mg):
    if not _dangling(mg):
        return _metadata_truncated_condensed(mg)

def _dangling(mg):
    # dangling means in objects but not in subjects
    return (set(o for o in mg.objects(unique=True) if isinstance(o, rdflib.BNode))
            - set(s for s in mg.subjects(unique=True) if isinstance(s, rdflib.BNode)))

def _metadata_truncated_embedded(mg):
    mgi = mg.identity()
    return mgi._if_cache[mg, mg.boundIdentifier, idf['(s ((p o) ...))']]

def _metadata_truncated_condensed(mg):
    mgi = mg.identity()
    return mgi._if_cache[mg, mg.boundIdentifier, idf['((p o) ...)']]

def figure_out_reference_name(
        name,
        bound_name=None,
        bound_version_name=None,
        metadata_graph=None,
        metadata_truncated_embedded=None,
        metadata_truncated_condensed=None,
        metadata_embedded=None,
        metadata_condensed=None,
        serialization=None,
        user_provided_reference_name=None,):
    # if we have never seen the file before and it contains no
    # metadata section then all we are going to have is a name
    # but that is our last resort

    prefix = 'http://uri.interlex.org/base/ontologies/dns/'

    if bound_name:
        if bound_version_name:
            pass

        if isinstance(bound_name, rdflib.BNode):
            pass

        if name == bound_name:
            pass
        else:
            pass

        return

    if bound_version_name:
        # bvn only defined if there is also a verion name
        raise ValueError('this is impossible what have you done')
    if metadata_truncated_embedded:
        session.execute
        pass
    if serialization:
        pass

    url = urlparse(name)
    if url.scheme == 'file':
        # FIXME pretty sure this case should go to the upload endpoint right?
        msg = ('user must provide reference name if there is no '
               f'metadata for a local file system sourced ontology {name}')
        raise ValueError(msg)

    reference_name = rdflib.URIRef(f'{prefix}{url.netloc}{url.path}')

    return reference_name


def get_paths(path):
    stem = path.stem
    name = path.name
    suffixes = ''.join(path.suffixes)
    pnames = (
        f'{name}.size-bytes',
        f'{name}.sha256',
        f'{stem}.count',
        f'{stem}-named.count',
        f'{stem}-bnode.count',
        f'{stem}-term.count',
        f'{stem}-link.count',
        f'{stem}-conn.count',
        f'{stem}.ntriples',
        f'{stem}-name.ntriples',
        f'{stem}-term.ntriples',
        f'{stem}-link.ntriples',
        f'{stem}-conn.ntriples',
        #f'{stem}-dang',
        f'{stem}-ncnt',
        f'{stem}-term-bscnt',
        f'{stem}-link-bscnt',
        f'{stem}-link-bocnt',
        f'{stem}-conn-bocnt',
        f'{stem}-conn-nscnt',
        'edges',
        'raw-sord',
    )
    parent = path.parent
    return tuple(parent / n for n in pnames)


def run_cmd(argv, cwd, logfile):
    with open(logfile, 'at') as logfd:
        try:
            p1 = subprocess.Popen(
                argv,
                cwd=cwd,
                stderr=subprocess.STDOUT, stdout=logfd)
            out1 = p1.communicate()
            if p1.returncode != 0:
                raise exc.SubprocessException(f'oops retr return code was {p1.returncode}')
        except KeyboardInterrupt as e:
            p1.send_signal(signal.SIGINT)
            raise e


def ilxbin(subpath):
    # FIXME TODO :/
    # we may need to translate these to python because finding locations of non-python files
    # from python is a non-specified nightmare
    up = (pathlib.Path('~/git/interlex/bin/') / subpath).expanduser()
    return up.as_posix()

cmd_sh = shutil.which('sh')
cmd_curl = shutil.which('curl')
def curl_url(iri, path, logfile):
    argv = [cmd_curl, '--location', '-o', path.as_posix(), iri]
    # can fail (duh)
    cwd = path.parent.as_posix()
    run_cmd(argv, cwd, logfile)


def path_to_ntriples_and_xz(path, rapper_input_type, logfile):
    argv = [cmd_sh, ilxbin('make-ntriples-xz.sh'), path.as_posix(), rapper_input_type]
    # can also fail
    cwd = path.parent.as_posix()
    run_cmd(argv, cwd, logfile)


def make_subsets(path, logfile):
    argv = [cmd_sh, ilxbin('make-subsets.sh'), path.as_posix()]
    cwd = path.parent.as_posix()
    run_cmd(argv, cwd, logfile)


def process_edges(path_edges, raw=False):
    with open(path_edges, 'rt') as f:
        edges = [l.split() for l in f.read().split('\n') if l]

    # silly and somewhat wasteful, but whatever it recovers the original
    # order in the file which may help reduce total memory usage later
    # by reducing the average number if intervening triples until we
    # get to the end
    fs = {}
    for i, e in enumerate(edges):
        for j, v in enumerate(e):
            fs[v] = i, j

    def unmarked_key(v):
        return fs[v]

    eord = toposort(edges, unmarked_key=unmarked_key)

    if raw:
        return eord
    else:
        return [rdflib.BNode(e[2:]) for e in eord]


def shellout(iri, path, rapper_input_type, logfile, only_local=False):
    if not only_local:
        curl_url(iri, path, logfile)
        path_to_ntriples_and_xz(path, rapper_input_type, logfile)

    make_subsets(path, logfile)
    return sort_ntriples_files(path)


def sort_ntriples_files(path):
    # it is WAY faster and more memory efficient to
    # topo sort the lines at this stage and rewrite
    # which avoids memory bloading of the waiting_ lists

    _paths = get_paths(path)
    term, link, conn = _paths[10:13]
    edges = _paths[-2]
    raw_sord_path = _paths[-1]
    raw_sord = process_edges(edges, raw=True)
    ls = len(raw_sord)
    lsp1 = ls + 1
    index = {k:i for i, k in enumerate(raw_sord)}

    # FIXME it seems like this might be too inefficient for somthing like pr
    # the memory usage is still low but ... actually it might just be computing
    # sord that is so slow
    _es = ''
    def kterm(l):
        bnode, _ = l.split(' ', 1)
        if bnode in index:
            return index[bnode], _es
        else:
            return lsp1, natsort(bnode)

    def klink(l):
        sbnode, _ = l.split(' ', 1)
        _, obnode, _ = l.rsplit(' ', 2)
        # putting obnode first nearly doubles the time it takes to
        # complete likely caused by vastly increasing the number of
        # appends to and pops from waiting_link
        return index[sbnode], index[obnode]

    def kconn(l):
        _, bnode, _ = l.rsplit(' ', 2)
        if bnode in index:
            return index[bnode], _es
        else:
            return lsp1, natsort(bnode)  # sort by bnode allows coordination with term

    for _path, key in ((term, kterm),
                       (link, klink),
                       (conn, kconn)):
        with open(_path, 'rt') as f:
            lines = f.read().split('\n')[:-1]
        slines = sorted(lines, key=key)
        with open(_path, 'wt') as f:
            f.write('\n'.join(slines))

    with open(raw_sord_path, 'wt') as f:
        f.write('\n'.join(raw_sord))

    return raw_sord

    #with open(term, 'rt') as f:
    #    tlines = f.read().split('\n')[:-1]
    #stlines = sorted(tlines, key=kterm)

    #with open(link, 'rt') as f:
    #    llines = f.read().split('\n')[:-1]
    #sllines = sorted(llines, key=klink)

    #with open(conn, 'rt') as f:
    #    clines = f.read().split('\n')[:-1]
    #sclines = sorted(clines, key=kconn)


_hbn = IdentityBNode('')
def oid(*args, separator=False, **kwargs):
    # default to separator=False to avoid crazy
    return _hbn.ordered_identity(*args, separator=separator, **kwargs)


def sid(things, separator=False):
    return oid(*sorted(things), separator=separator)


def named_counts_from_path(path):
    with open(path, 'rt') as f:
        data = f.read()

    out = {}
    for l in data.split('\n'):
        if not l:
            continue
        strcount, n3uri = [f.strip() for f in l.split()]
        count = int(strcount)
        uri = n3uri[1:-1]
        subject = rdflib.URIRef(nt.uriquote(nt.unquote(uri)))
        out[subject] = count

    return out


def bnode_counts_from_path(path):
    with open(path, 'rt') as f:
        data = f.read()

    out = {}
    for l in data.split('\n'):
        if not l:
            continue
        strcount, sbnode = [f.strip() for f in l.split()]
        count = int(strcount)
        ent = rdflib.BNode(sbnode[2:])
        out[ent] = count

    return out


def getstr(path):
    with open(path, 'rt') as f:
        str_value = f.read().split()[0].strip()

    return str_value


def mkgen(seq):
    # for when the consumer needs the sequence not to restart from
    # zero every time
    yield from seq


def process_triple_seq(triple_seq, serialization_identity=None,
                       metadata_to_fetch=None, metadata_not_to_fetch=None,
                       local_conventions=None,
                       batchsize=None, force=False, debug=False, dout=None):
    # triples_seq should not be a generator because we need to traverse it multiple times ...
    # imagine you go them from somewhere else
    if dout is None:
        dout = {}

    # our natsort is safe because it doesn't ignore leading zeros and thus identically equal values sort as expected
    def kname(t):
        return tuple(natsort(e) for e in t)

    def kterm(t):
        if t[0] in index:
            return index[t[0]], _es
        else:
            return lsp1, natsort(t[0])

    def klink(t):
        return index[t[0]], index[t[2]]

    def kconn(t):
        if t[2] in index:
            return index[t[2]], _es
        else:
            return lsp1, natsort(t[2])

    triple_count = len(triple_seq)

    if isinstance(triple_seq, OntGraph):
        if local_conventions is None:
            local_conventions = triple_seq.namespace_manager

    if local_conventions is not None:
        local_conventions_count = len(list(local_conventions))
        yield from process_local_conventions(local_conventions, local_conventions_count, dout=dout)
        local_conventions_identity = dout['local_conventions_identity']
        record_count = local_conventions_count + triple_count
    else:
        local_conventions_identity = None
        # rc only used if si is not None since lci None skips gclc
        record_count = triple_count

    if serialization_identity is not None:
        yield from process_serialization(serialization_identity, record_count)
        yield from process_name_metadata(serialization_identity, metadata_to_fetch, metadata_not_to_fetch)
        yield None, None

    g_name = sorted([(s, p, o) for s, p, o in triple_seq if not isinstance(s, rdflib.BNode) and not isinstance(o, rdflib.BNode)], key=kname)
    named_counts = dict(Counter([s for s, p, o in g_name]))
    yield from process_named(named_counts, g_name, batchsize=batchsize, dout=dout, debug=debug)

    g_node =  [(s, p, o) for s, p, o in triple_seq if     isinstance(s, rdflib.BNode) or      isinstance(o, rdflib.BNode)]
    _g_link = [(s, p, o) for s, p, o in g_node     if     isinstance(s, rdflib.BNode) and     isinstance(o, rdflib.BNode)]
    edges = [(s, o) for s, p, o in _g_link]
    sord = toposort(edges)
    lsp1 = len(sord) + 1
    index = {k:i for i, k in enumerate(sord)}
    _es = ''

    g_term = sorted([(s, p, o) for s, p, o in g_node if     isinstance(s, rdflib.BNode) and not isinstance(o, rdflib.BNode)], key=kterm)
    g_link = sorted(_g_link, key=klink)
    g_conn = sorted([(s, p, o) for s, p, o in g_node if not isinstance(s, rdflib.BNode) and     isinstance(o, rdflib.BNode)], key=kconn)

    # FIXME TODO we could probably do this all in a single pass over tripleseq
    bnode_term_subject_counts = dict(Counter([s for s, p, o in g_term]))
    bnode_link_subject_counts = dict(Counter([s for s, p, o in g_link]))
    bnode_link_object_counts =  dict(Counter([o for s, p, o in g_link]))
    bnode_conn_object_counts =  dict(Counter([o for s, p, o in g_conn]))
    named_conn_subject_counts = dict(Counter([s for s, p, o in g_conn]))
    dangle = (set(bnode_link_object_counts) | set(bnode_conn_object_counts)) - (set(bnode_link_subject_counts) | set(bnode_term_subject_counts))
    yield from process_bnode(
        bnode_term_subject_counts,
        bnode_link_subject_counts,
        bnode_link_object_counts,
        bnode_conn_object_counts,
        named_conn_subject_counts,
        sord, dangle, mkgen(g_term), mkgen(g_link), mkgen(g_conn), batchsize=batchsize, dout=dout)

    graph_named_identity = dout['graph_named_identity']
    graph_bnode_identity = dout['graph_bnode_identity']

    yield from process_post(
        graph_bnode_identity, graph_named_identity, triple_count,
        local_conventions_identity,
        serialization_identity,
        record_count,
        dout=dout)
    yield None, None


def already_in(session, serialization_identity, identity_function_version=3):
    sql = "SELECT o FROM identity_relations WHERE s = :si AND p = 'parsedTo'"
    rows = list(session.execute(sql_text(sql), params={'si': serialization_identity}))
    if rows:
        return rows[0][0]


def process_prepared(path, serialization_identity, metadata_to_fetch, metadata_not_to_fetch,
                     local_conventions, raw_sord=None,
                     batchsize=None, force=False, debug=False, dout=None):
    # FIXME TODO need the metadata identity and stuff
    if batchsize is None:
        batchsize = _batchsize

    (size_bytes,
     checksum_sha256,
     path_triple_count,
     path_triple_count_named,
     path_triple_count_bnode,
     path_triple_count_term,
     path_triple_count_link,
     path_triple_count_conn,
     nt,
     name,
     term,
     link,
     conn,
     #dang,
     ncnt,
     term_bscnt,
     link_bscnt,
     link_bocnt,
     conn_bocnt,
     conn_nscnt,
     edges,
     raw_sord_path,
     ) = get_paths(path)

    str_triple_count = getstr(path_triple_count)
    triple_count = int(str_triple_count)

    str_triple_count_named = getstr(path_triple_count_named)
    triple_count_named = int(str_triple_count_named)

    str_triple_count_bnode = getstr(path_triple_count_bnode)
    triple_count_bnode = int(str_triple_count_bnode)

    str_triple_count_term = getstr(path_triple_count_term)
    triple_count_term = int(str_triple_count_term)

    str_triple_count_link = getstr(path_triple_count_link)
    triple_count_link = int(str_triple_count_link)

    str_triple_count_conn = getstr(path_triple_count_conn)
    triple_count_conn = int(str_triple_count_conn)

    _tc_b = triple_count_term + triple_count_link + triple_count_conn
    assert _tc_b == triple_count_bnode, f'{_tc_b} != {triple_count_bnode}'
    _tc_nb = triple_count_named + triple_count_bnode
    assert _tc_nb == triple_count, f'{_tc_nb} != {triple_count}'

    local_conventions_count = len(list(local_conventions))
    record_count = local_conventions_count + triple_count

    yield from process_serialization(serialization_identity, record_count)
    yield from process_name_metadata(serialization_identity, metadata_to_fetch, metadata_not_to_fetch)
    yield None, None

    if dout is None:
        dout = {}

    yield from process_local_conventions(local_conventions, local_conventions_count, dout=dout)

    named_counts = named_counts_from_path(ncnt)
    g_name = gent(name)
    yield from process_named(named_counts, g_name, batchsize=batchsize, dout=dout, debug=debug)

    bnode_term_subject_counts = bnode_counts_from_path(term_bscnt)
    bnode_link_subject_counts = bnode_counts_from_path(link_bscnt)
    bnode_link_object_counts = bnode_counts_from_path(link_bocnt)
    bnode_conn_object_counts = bnode_counts_from_path(conn_bocnt)
    named_conn_subject_counts = named_counts_from_path(conn_nscnt)
    dangle = (set(bnode_link_object_counts) | set(bnode_conn_object_counts)) - (set(bnode_link_subject_counts) | set(bnode_term_subject_counts))
    if raw_sord is None:
        sord = process_edges(edges)
    else:
        sord = [rdflib.BNode(e[2:]) for e in raw_sord]
        raw_sord = None

    g_term = gent(term)
    g_link = gent(link)
    g_conn = gent(conn)
    yield from process_bnode(
        bnode_term_subject_counts,
        bnode_link_subject_counts,
        bnode_link_object_counts,
        bnode_conn_object_counts,
        named_conn_subject_counts,
        sord, dangle, g_term, g_link, g_conn, batchsize=batchsize, dout=dout, debug=debug)

    assert triple_count_named == dout['named_count'], f'{triple_count_named} != {dout["named_count"]}'
    assert triple_count_bnode == dout['bnode_count'], f'{triple_count_bnode} != {dout["bnode_count"]}'

    triple_count_internal = dout['named_count'] + dout['bnode_count']
    assert triple_count == triple_count_internal, f'derp {triple_count} != {triple_count_internal}'

    graph_named_identity = dout['graph_named_identity']
    graph_bnode_identity = dout['graph_bnode_identity']
    # yes, we want graph_combined_identity to include the null
    # identity either of these if it was indeed empty so that you
    # can't mistake one or the other for the combination with the
    # empty graph of the other
    local_conventions_identity = dout['local_conventions_identity']
    yield from process_post(graph_bnode_identity, graph_named_identity, triple_count_internal,
                            local_conventions_identity, serialization_identity, record_count,
                            dout=dout)
    yield None, None


def process_serialization(serialization_identity, record_count):
    idents = (('serialization', serialization_identity, record_count),)
    # FIXME inserting serialization needs OCDN here because the actual insert workflow
    # that checks whether parsesTo has been set runs outside this, and we need this to
    # succeed unconditionally in cases where a previous load might have failed
    # (also because we can't do any error handling that is specific to a given insert)
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 7 */', idents, ocdn)


def process_name_metadata(serialization_identity, metadata_to_fetch, metadata_not_to_fetch):
    log.debug('start names and metadata')
    # name + resolution chain
    # bound name
    # reference name if provided (TODO)
    # idents
    # metadata embedded identity
    # metadata condensed identity
    # irels
    # ser -> me

    # FIXME we want more than just name -> identity
    # we need the date, we can flattenthe dereference chain for now
    # we can store the distance from the identity in the resolution chain

    # bound name can dereference vs can't dereference
    idents = []
    irels = []
    name_rows = []
    name_to_idents = []
    for metadata in (metadata_not_to_fetch, metadata_to_fetch):
        if metadata is None:
            continue

        name = metadata.identifier
        _http_resp = metadata.progenitor(type='stream-http')
        http_resps = _http_resp.history + [_http_resp]
        http_headers = [r.headers for r in http_resps]

        names = [resp.url for resp in http_resps]
        # FIXME TODO consider whether we want to differentiate the type for
        # the name that was the input name
        name_rows.extend(names)
        name_to_idents.extend([(name, serialization_identity, 'pointer') for name in names])

        bound_name = metadata.identifier_bound
        if bound_name:
            name_rows.append(bound_name)
            name_to_idents.append((bound_name, serialization_identity, 'bound'))

        bound_version_name = metadata.identifier_version
        if bound_version_name:
            name_rows.append(bound_version_name)
            name_to_idents.append((bound_version_name, serialization_identity, 'bound_version'))

        if name != bound_name and name != bound_version_name:
            if bound_name in names:
                print('todo bn in names')
                pass

            if bound_version_name in names:
                print('todo bvn in names')
                pass

            #breakpoint()
            # TODO try to resolve the bound name and see where it goes, if it resolves
            pass

        # trunc first because non-trunc is impossible at this point if dangling
        mg = metadata.graph
        # we are not using graph_combined for this
        # also, metadata_graph is needed in cases where we have non-truncated multi-parent
        # but that can usually only be calculated from the full graph, so a separate phase
        _if_cache = IdentityBNode._if_cache
        metadata_graph = IdentityBNode(mg, as_type=ibn_it['triple-seq'], id_method=idf['record-seq'])
        metadata_embedded = _if_cache[mg, bound_name, idf['embedded']]
        metadata_condensed = _if_cache[mg, bound_name, idf['condensed']]
        metadata_combined = IdentityBNode(mg, as_type=ibn_it['triple-seq'], id_method=idf['graph-combined'])
        # if there are no bnodes then metadata_named = oid(metadata_embedded)
        metadata_named = _if_cache[(mg, 'named'), idf['record-seq']]  # thi is invar to trunc
        metadata_bnode = _if_cache[(mg, 'bnode'), idf['record-seq']]
        metadata_named_embedded = _if_cache[(mg, 'named'), bound_name, idf['embedded']]
        metadata_named_condensed = _if_cache[(mg, 'named'), bound_name, idf['condensed']]
        # mbc is what is used as the subgraph identifier, but mbe is used in metadata_bnode
        # mbc should also show up in identity relations during the later load if non-trunc
        mbc_key = (mg, 'bnode'), bound_name, idf['condensed']
        metadata_bnode_condensed = (_if_cache[mbc_key]
                                    if mbc_key in _if_cache else
                                    _hbn.null_identity)
        record_count = len(mg)
        named, bnode = split_named_bnode(mg)  # sigh, but metadata is small so ok
        named_record_count = len(named)
        bnode_record_count = len(bnode)

        truncated = _dangling(mg)
        if truncated:  # metadata_embedded is None:
            _type = 'truncated_metadata'
            #embedded = metadata_truncated_embedded
            #condensed = metadata_truncated_condensed
        else:
            _type = 'metadata'

        graph = metadata_graph.identity
        embedded = metadata_embedded
        condensed = metadata_condensed

        combined = metadata_combined.identity
        named = metadata_named
        bnode = metadata_bnode
        named_embedded = metadata_named_embedded
        # FIXME we need conn free seq in here too, but I'm not sure
        # what that is called in the identity function right now?
        # record-seq i think? all the others are still useful for
        # other use cases but we need conn free seq for consistency?
        named_condensed = metadata_named_condensed
        bnode_condensed = metadata_bnode_condensed

        idents.extend((
            (f'{_type}_graph', graph, record_count),
            (f'{_type}_graph_combined', combined, record_count),
            # FIXME this isn't quite right ... conn free seq needs to be in here

            ('embedded', embedded, record_count),
            ('condensed', condensed, record_count),

            ('named_embedded_seq', named, named_record_count),
            ('named_embedded', named_embedded, named_record_count),
            ('named_condensed', named_condensed, named_record_count),

            ('bnode_conn_free_seq', bnode, bnode_record_count),
            ('bnode_condensed', bnode_condensed, bnode_record_count),
        ))

        irels.extend(
            ((serialization_identity, 'hasMetadataGraph', graph),
             (serialization_identity, 'hasMetadataGraph', combined),
             (graph, 'hasEquivalent', combined),

             (graph, 'hasMetadataRecord', embedded),
             (embedded, 'hasCondensed', condensed),

             (combined, 'hasNamedGraph', named),
             (combined, 'hasBnodeGraph', bnode),
             (named, 'hasNamedRecord', named_embedded),
             (named_embedded, 'hasCondensed', named_condensed),
             (bnode, 'hasBnodeRecord', bnode_condensed),  # XXX might miss free but dedupe should cover it?
             # FIXME if this is not truncated then bnode_condensed
             # will be a subgraph identity, if it is truncated then
             # we have map metadata_graph_combined to truncated_metadata_graph_combined
             # i think going via bound name will work

             ))

    yield prepare_batch('INSERT INTO names (name) VALUES', [(n,) for n in name_rows], ocdn)
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 8 */',
                        idents,
                        ocdn,)
    yield prepare_batch('INSERT INTO name_to_identity (name, identity, type) VALUES', name_to_idents, ocdn)
    yield prepare_batch('INSERT INTO identity_relations (s, p, o) VALUES', irels, ocdn)


def process_local_conventions(local_conventions, local_conventions_count, dout=None):
    local_conventions_identity = IdentityBNode(local_conventions, as_type=ibn_it['pair-seq']).identity
    dout['local_conventions_identity'] = local_conventions_identity
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 1 */',
                        (('local_conventions', local_conventions_identity, local_conventions_count),),
                        ocdn,)
    yield prepare_batch('INSERT INTO curies (local_conventions_identity, curie_prefix, iri_namespace) VALUES',
                        [(p, str(n)) for p, n in local_conventions],
                        ocdn,
                        constant_dict={'si': local_conventions_identity})


def process_post(
        graph_bnode_identity,
        graph_named_identity,
        triple_count,
        local_conventions_identity=None,
        serialization_identity=None,
        record_count=None,
        dout=None,):

    if dout is None:
        dout = {}

    graph_combined_identity = oid(graph_named_identity, graph_bnode_identity)
    dout['graph_combined_identity'] = graph_combined_identity
    idents = (('graph_combined', graph_combined_identity, triple_count),)
    irels = ((graph_combined_identity, 'hasNamedGraph', graph_named_identity),
             (graph_combined_identity, 'hasBnodeGraph', graph_bnode_identity),)

    if local_conventions_identity is not None:
        graph_combined_local_conventions_identity = oid(local_conventions_identity, graph_combined_identity)  # yes the order is confusing but lc first
        dout['graph_combined_local_conventions_identity'] = graph_combined_local_conventions_identity
        idents += (('graph_combined_local_conventions', graph_combined_local_conventions_identity, record_count),)
        irels += ((graph_combined_local_conventions_identity, 'hasGraph', graph_combined_identity),
                  (graph_combined_local_conventions_identity, 'hasLocalConventions', local_conventions_identity),)

    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 2 */', idents, ocdn)
    yield prepare_batch('INSERT INTO identity_relations (s, p, o) VALUES', irels, ocdn)

    if serialization_identity is not None:
        # serialization should be inserted last and separately
        # irels in particular need to be separate to detect if
        # the identity function changed (by accident)
        # XXX NOTE this makes the actual indicator that an insertion process has finished
        # the presence of the parsedTo record in irels, and serialization_identity can go in earlier if we want (TODO)
        # e.g. to use the database to prevent multiple load attems
        irels = ((serialization_identity, 'parsedTo', graph_combined_local_conventions_identity),)
        yield prepare_batch('INSERT INTO identity_relations (s, p, o) VALUES', irels)


def process_bnode(
        term_bnode_subject_counts,
        link_bnode_subject_counts,
        link_bnode_object_counts,
        conn_bnode_object_counts,
        conn_named_subject_counts,
        sord, dangle, g_term, g_link, g_conn, batchsize=None, dout=None, debug=False):

    if batchsize is None:
        batchsize = _batchsize

    log.debug('start process_bnode')

    # TODO dangling i think

    total = sum([v for counts in (term_bnode_subject_counts, link_bnode_subject_counts, conn_named_subject_counts) for v in counts.values()])

    def total_object_count(o):
        return ((link_bnode_object_counts[o] if o in link_bnode_object_counts else 0) +
                (conn_bnode_object_counts[o] if o in conn_bnode_object_counts else 0))

    def total_subject_count(s):
        return ((term_bnode_subject_counts[s] if s in term_bnode_subject_counts else 0) +
                (link_bnode_subject_counts[s] if s in link_bnode_subject_counts else 0))

    def total_count(e):
        # FIXME this can be off by 1 if there is a cycle length 1 self reference, but all cycles should be kicked out before we get here
        return total_subject_count(e) + total_object_count(e)

    term_seen_s = defaultdict(lambda: 0)
    link_seen_s = defaultdict(lambda: 0)
    link_seen_o = defaultdict(lambda: 0)
    conn_seen_o = defaultdict(lambda: 0)
    conn_seen_s = defaultdict(lambda: 0)
    # hold out of order subjects, under the assumption that rapper will produce a nearly topo order
    waiting_term = defaultdict(list)  # FIXME even with sorted ntriples inputs I'm still seeing the spike here at the start !??
    waiting_link = defaultdict(list)
    waiting_conn = defaultdict(list)
    transitive_trips = defaultdict(list)
    pair_idents = {}
    subject_idents = defaultdict(list)
    subject_condensed_idents = {}
    condensed_counts = defaultdict(lambda: -1)
    accum_embedded = []  # this is for the graph bnode identity
    accum_condensed = set() # this is for the irels table, slightly different from accum condensed

    batch_term_uri_rows = []
    batch_term_lit_rows = []
    batch_link_rows = []
    batch_conn_rows = []
    batch_idents = []

    secondaries = {}
    replica_helper = set()
    dedupe_helper = set()

    # FIXME counts is only subject counts right now, we actually do
    # need the object counts (multi-parent detection) to know when to
    # pop a subject from transitive trips i think? yes for sure
    #breakpoint()

    # TODO process dangles up here

    for _s in sorted(term_bnode_subject_counts, key=natsort):
        # make sure that we run cases where term -> conn directly
        # we put them all at the end given that we don't know where
        # they actually occur in the graph, so we may end up carrying
        # them for quite a while since we don't know where they fit
        # in sord, the cost is that in order to insert them into
        # sord we would probably have to iterate over sord multiple times
        # so the cost is in memory used for waiting_term essentially
        # unless we could somehow sort the no-link cases to the end
        # of term.ntriples during preprocessing or insert them sanely
        # into edges, which might be possible from conn ... but then
        # we are still missing free terminal cases and this doesn't
        # help reorder term anyway so the memory usage issue remains
        if _s not in link_bnode_object_counts and _s not in link_bnode_subject_counts:
            sord.append(_s)

    def make_subgraph_rows(s, scid, replica):
        nonlocal counter_row
        if s not in transitive_trips:
            breakpoint()

        subgraph = transitive_trips.pop(s)
        batch_idents.append((scid, len(subgraph)))
        accum_condensed.add(scid)
        ng = normgraph(s, subgraph, scid, replica, subject_condensed_idents, secondaries)
        for n_s, _n_p, n_o, o_scid, o_replica in ng:#, subgraph_integer, subgraph_object_dupes):
            n_p = str(_n_p)
            rows = None
            if isinstance(n_s, rdflib.URIRef):
                n_s = str(n_s)
                rows = batch_conn_rows

            if n_s == 0:
                if rows is None:
                    rhr = (None, n_s, n_p, scid, replica)
                else:
                    rhr = (n_s, None, n_p, scid, replica)

                # replica_helper must be a set because if a value is present as a subject in multiple
                # triples then the rh will be generated multiple times
                replica_helper.add(rhr)

            if o_scid:
                # same for dedupe helper, the value will be generated multiple times
                dedupe_helper.add((scid, replica, n_o, o_scid, o_replica))

            if isinstance(n_o, int):
                row = n_s, n_p, n_o, scid
                if rows is None:
                    rows = batch_link_rows

            elif isinstance(n_o, rdflib.Literal):
                row = n_s, n_p, str(n_o), str_None(n_o.datatype), str_None(n_o.language), scid
                if rows is None:
                    rows = batch_term_lit_rows

            else:
                row = n_s, n_p, str(n_o), scid
                if rows is None:
                    rows = batch_term_uri_rows

            rows.append(row)
            counter_row += 1

    counter_row = 0
    counter_batch = 0 
    lsm1 = len(sord) - 1
    last_batch = 0
    for i, subject in enumerate(sord):
        if len(waiting_conn) > 100:
            breakpoint()

        if len(waiting_link) > 100:
            breakpoint()

        if len(waiting_term) > 100:
            breakpoint()

        if False and debug:
            msg = (f'{i: >6} {counter_batch: >6} {len(accum_embedded): >6} {len(accum_condensed): >6} '
                   # FIXME somehow these ramp super high and then count down to zero ???
                   # maybe i should toposort all the files first ...
                   f'{len(waiting_term): >6} '
                   f'{len(waiting_link): >6} '
                   f'{len(waiting_conn): >6} '
                   f'{len(transitive_trips): >6} '  # FIXME this is the last one that seems to accumulate lots values?
                   )
            log.debug(msg)
        min_expected_count = total_subject_count(subject)
        expected_count = min_expected_count + (conn_bnode_object_counts[subject] if subject in conn_bnode_object_counts else 0)
        actual_count = 0
        _debug_actual = []
        if subject in term_bnode_subject_counts:  # and term_bnode_subject_counts[subject] < term_seen_s[subject]:
            #if term_peek is not None:
                #gen_term = chain((term_peek,), g_term)
            #else:
                #gen_term = g_term

            if subject in waiting_term:
                gen_term = chain(waiting_term.pop(subject), g_term)
            else:
                gen_term = g_term

            for tt in gen_term:  # these come in sorted (with some strong assumptions about implicit bnode ordering XXX which may be wrong)
                ts, tp, to = tt
                if ts != subject:
                    waiting_term[ts].append(tt)
                    continue

                counter_batch += 1
                actual_count += 1
                _debug_actual.append(tt)
                term_seen_s[ts] += 1
                transitive_trips[ts].append(tt)
                t_pair_identity = IdentityBNode((tp, to), as_type=ibn_it['(p o)']).identity
                subject_idents[ts].append(t_pair_identity)
                if term_seen_s[ts] == term_bnode_subject_counts[ts]:
                    if term_seen_s[ts] == total_subject_count(ts):
                        tscid = subject_condensed_idents[ts] = sid(subject_idents.pop(ts))
                        condensed_counts[tscid] += 1
                        treplica = condensed_counts[tscid]
                        tstoc = total_object_count(ts)
                        if tstoc > 1 or tstoc == 0:
                            accum_embedded.append(tscid)
                            make_subgraph_rows(ts, tscid, treplica)

                        secondaries[tscid] = treplica  # we don't know if we will need this because it depends on the hash

                    break

        if subject in link_bnode_subject_counts:
            if subject in waiting_link:
                gen_link = chain(waiting_link.pop(subject), g_link)
            else:
                gen_link = g_link

            #can_break = False
            for t in gen_link:
                #if can_break and t[0] != s:
                    #waiting[t[0]].append(t)
                    #break

                s, p, o = t
                if s != subject:
                    waiting_link[s].append(t)
                    continue

                counter_batch += 1
                actual_count += 1
                _debug_actual.append(t)
                link_seen_s[s] += 1
                link_seen_o[o] += 1
                transitive_trips[s].append(t)
                #if s == subject:
                    #can_break = True

                # accumulate objects
                if o in transitive_trips:  # this will only be an transitive trips if it is single parent at this point
                    transitive_trips[s].extend(transitive_trips.pop(o))
                #else:  # secondary case
                    # TODO dedupes
                    #breakpoint()
                    #'TODO'

                if o not in subject_condensed_idents:
                    breakpoint()
                    raise ValueError('should never get here')
                    #assert term_seen_s[o] < term_scounts[o]  # FIXME dangle might violate our assumptions here
                    ## we know that all link trips with o as a subject have
                    ## to already be done due to topo, so the remaining ones
                    ## must be in terminals so we are guranteed to hit the
                    ## subject when we go through terminals
                    #if ocounts[o] > 1:
                    #    tidents = done_term[o]
                    #else:
                    #    tidents = done_term.pop(o)

                    #tident = sid(tidents)

                    #subject_embedded_idents[o] = tident

                # we can't pop these ever because there might be a replica
                #if link_seen_o[o] + conn_seen_o[o] == total_object_count(o):
                #    oident = subject_condensed_idents.pop(o)
                #    # XXX there are some other things we should be doing in here ???
                #    # like creating the subgraph record rows ??? but there are multiple points where this condition
                #    # could first become true in the code, though only one of them will be hit by any given object
                #else:
                #    oident = subject_condensed_idents[o]

                #elif link_seen_o[o] == link_bnode_object_counts[o]:

                pair_identity = oid(oid(p.encode()), subject_condensed_idents[o])
                subject_idents[s].append(pair_identity)
                # FIXME I think we only need to accumulate the subject
                # idents in a list, no need for defaultdict lookup since
                # thing are already sorted and we reorder the triples

                if link_seen_s[s] == link_bnode_subject_counts[s]:
                    scid = subject_condensed_idents[s] = sid(subject_idents.pop(s))
                    condensed_counts[scid] += 1
                    replica = condensed_counts[scid]
                    stoc = total_object_count(s)
                    if stoc > 1 or stoc == 0:
                        accum_embedded.append(scid)
                        make_subgraph_rows(s, scid, replica)

                    secondaries[scid] = replica  # we don't know if we will need this because it depends on the hash
                    break

        if subject in conn_bnode_object_counts:
            if subject in waiting_conn:
                gen_conn = chain(waiting_conn.pop(subject), g_conn)
            else:
                gen_conn = g_conn

            for ct in gen_conn:
                cs, cp, co = ct
                if co != subject:
                    waiting_conn[co].append(ct)
                    continue

                counter_batch += 1
                actual_count += 1
                _debug_actual.append(ct)
                conn_seen_s[cs] += 1
                conn_seen_o[co] += 1
                transitive_trips[cs].append(ct)
                if co in transitive_trips:
                    # this will only be an transitive trips if o is single parent and the transitive set
                    # will only include trips that are not transitively part of a multi-parent subgraph
                    transitive_trips[cs].extend(transitive_trips.pop(co))

                if co not in subject_condensed_idents:
                    breakpoint()

                pair_identity = oid(oid(cp.encode()), subject_condensed_idents[co])
                subject_idents[cs].append(pair_identity)

                if conn_seen_s[cs] == conn_named_subject_counts[cs]:
                    # subject_embedded_idents[cs]
                    cscid = subject_condensed_idents[cs] = sid(subject_idents.pop(cs))
                    condensed_counts[cscid] += 1
                    creplica = condensed_counts[cscid]
                    cseid = oid(oid(cs.encode()), cscid)
                    accum_embedded.append(cseid)  # FIXME may want to differentiate these from bnode only
                    make_subgraph_rows(cs, cscid, creplica)

                if conn_seen_o[co] == conn_bnode_object_counts[co]:
                    break

            # not needed for conn, because we just need to fill in the subgraph
            #if o in transitive_trips:  # might not be in if dangle
            #    # FIXME TODO 
            #    if ocounts[o] > 1:
            #        ott = transitive_trips[o]
            #    else:
            #        ott = transitive_trips.pop(o)

            #    transitive_trips[s].extend(ott)
        if actual_count < min_expected_count:
            # derp
            breakpoint()
            raise ValueError('implementer really messed up')

        if actual_count != expected_count:
            breakpoint()
            raise ValueError('implementer messed up')

        if counter_row > batchsize or i == lsm1:
            if i == lsm1:
                assert conn_bnode_object_counts == dict(conn_seen_o)

            yield from prepare_batch_bnode(
                batch_term_uri_rows,
                batch_term_lit_rows,
                batch_link_rows,
                batch_conn_rows,
                batch_idents,)

            if i != lsm1:
                yield None, None

            last_batch = i
            batch_term_uri_rows = []
            batch_term_lit_rows = []
            batch_link_rows = []
            batch_conn_rows = []
            batch_idents = []
            counter_row = counter_row - batchsize

    assert total == counter_batch
    graph_bnode_identity = sid(accum_embedded)
    #irels = [(graph_bnode_identity, e) for e in accum_condensed]  # if we screwed this up the database will catch it because they wont be in idents
    irels = [(e,) for e in accum_condensed]
    log.debug('done process_bnode triples')
    #replicas = [(graph_bnode_identity, *r) for r in replica_helper]
    #dedupes = [(graph_bnode_identity, *d) for d in dedupe_helper]
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 3 */',
                        ((graph_bnode_identity, total),), ocdn,
                        constant_dict={'nt': 'bnode_conn_free_seq'})

    if irels:
        for chunk in chunk_list(irels, batchsize):
            yield prepare_batch('INSERT INTO identity_relations (p, s, o) VALUES', chunk, ocdn,
                                constant_dict={'p': 'hasBnodeRecord', 's': graph_bnode_identity})

    if replica_helper:
        for chunk in chunk_list(list(replica_helper), batchsize):
            yield prepare_batch(('INSERT INTO subgraph_replicas (graph_bnode_identity, '
                                's, s_blank, p, subgraph_identity, replica) VALUES'),
                                chunk, ocdn,
                                constant_dict={'graph_bnode_identity': graph_bnode_identity})

    if dedupe_helper:
        for chunk in chunk_list(list(dedupe_helper), batchsize):
            yield prepare_batch(('INSERT INTO subgraph_deduplication (graph_bnode_identity, '
                                'subject_subgraph_identity, subject_replica, o_blank, '
                                'object_subgraph_identity, object_replica) VALUES'),
                                chunk, ocdn,
                                constant_dict={'graph_bnode_identity': graph_bnode_identity})

    dout['bnode_count'] = counter_batch
    dout['graph_bnode_identity'] = graph_bnode_identity
    yield None, None
    log.debug('done process_bnode')


def process_conn(scounts, ocounts, sseen, oseen, gen, transitive_trips, ):
    pass


def do_batch_insert_identity_relations(identity_relations):
    breakpoint()


def str_None(thing):
    return thing if thing is None else str(thing)


def prepare_batch(sql, values, suffix='', constant_dict=None):
    if constant_dict:
        constants = tuple(f':{n}' for n in constant_dict)
    else:
        constants = tuple()

    values_template, params = makeParamsValues(values, constants=constants)
    if constant_dict:
        params.update(constant_dict)

    return sql_text(' '.join((sql, values_template, suffix))), params


def prepare_batch_named(uri_rows, lit_rows, batch_idents, batch_idni):
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 4 */', batch_idents, ocdn, constant_dict={'nt': 'named_embedded'})
    if uri_rows:
        yield prepare_batch('INSERT INTO triples (s, p, o, triple_identity) VALUES', uri_rows, ocdn)
    if lit_rows:
        yield prepare_batch('INSERT INTO triples (s, p, o_lit, datatype, language, triple_identity) VALUES', lit_rows, ocdn)

    yield prepare_batch('INSERT INTO identity_named_triples_ingest (named_embedded_identity, triple_identity) VALUES', batch_idni, ocdn)


def prepare_batch_bnode(batch_term_uri_rows,
                        batch_term_lit_rows,
                        batch_link_rows,
                        batch_conn_rows,
                        batch_idents,):
    if not batch_idents:
        breakpoint()

    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 5 */', batch_idents, ocdn, constant_dict={'nt': 'bnode_condensed'})
    if batch_term_uri_rows:
        yield prepare_batch('INSERT INTO triples (s_blank, p, o, subgraph_identity) VALUES', batch_term_uri_rows, ocdn)
    if batch_term_lit_rows:
        yield prepare_batch('INSERT INTO triples (s_blank, p, o_lit, datatype, language, subgraph_identity) VALUES', batch_term_lit_rows, ocdn)
    if batch_link_rows:
        yield prepare_batch('INSERT INTO triples (s_blank, p, o_blank, subgraph_identity) VALUES', batch_link_rows, ocdn)
    if batch_conn_rows:
        yield prepare_batch('INSERT INTO triples (s, p, o_blank, subgraph_identity) VALUES', batch_conn_rows, ocdn)


def process_named(counts, gen, batchsize=None, dout=None, debug=False):
    if batchsize is None:
        batchsize = _batchsize

    log.debug('start process_named')

    def condense_and_make_named_rows():
        nonlocal batch_after_this_subject
        nonlocal batch_uri_rows
        nonlocal batch_lit_rows
        nonlocal batch_idents
        nonlocal batch_idni

        # XXX having subject count for these would actually help because
        # then we would know if we should go over batch size
        subject_condensed_identity = sid(accum_pair)
        subject_embedded_identity = oid(oid(s.encode()), subject_condensed_identity)
        accum_embedded.append(subject_embedded_identity)
        batch_idents.append((subject_embedded_identity, this_subject_count))
        batch_idni.extend([(subject_embedded_identity, tid) for tid in accum_trip])
        if batch_after_this_subject:
            # note that a subject could start the batchsize -1th triple
            # and then contain more than batchsize triples, if that happens
            # it could induce a stall, which is another reason to compute
            # counts for all subjects
            yield from prepare_batch_named(batch_uri_rows, batch_lit_rows, batch_idents, batch_idni)
            #if tm1 > i > batchsize:
                # don't signal to commit on first and last batch (but why not ??? we want to after all triples go in)
            yield None, None  # signal to comit if commit=True
            batch_after_this_subject = False
            batch_uri_rows = []
            batch_lit_rows = []
            batch_idents = []
            batch_idni = []

    s = None
    expected_count = None
    accum_embedded = []  # needed to get the fully named identity
    accum_pair = []
    accum_trip = []
    batch_uri_rows = []
    batch_lit_rows = []
    batch_idents = []
    batch_idni = []
    batch_after_this_subject = False
    this_subject_count = None
    total = sum(counts.values())
    tm1 = total -1
    for i, t in enumerate(gen):
        if t[0] != s:
            # finish processing the previous loop before setting anything for this one
            if this_subject_count != expected_count:
                breakpoint()
                # if you hit this it might be because your input is not sorted correctly
                # apparently FMA actually duplicates and conflates these as well despite
                # having different labels fma0323167 fma323167 the FMAID stripped the leading
                # zero (extra oof)
                msg = f'actual != expected {this_subject_count} {expected_count} for {t[0]} != {s}'
                raise ValueError(msg)

            if s is not None:
                if len(accum_pair) != len(accum_trip) != expected_count:
                    breakpoint()
                    raise ValueError('wat')

                yield from condense_and_make_named_rows()

            this_subject_count = 0
            expected_count = counts[t[0]]
            accum_pair = []
            accum_trip = []

            if 0 <= (i + expected_count) % batchsize < expected_count:
                # strictly less than expected count works because if the previous hit exactly on batchsize it will have run
                batch_after_this_subject = True

        if i == tm1:
            # last batch will almost always be less than batchsize
            # or first batch for files less than batchsize
            batch_after_this_subject = True
            try:
                oops = next(gen)
                msg = f'should have been done but {oops}'
                raise ValueError(msg)
            except StopIteration:
                pass
            except TypeError as e:
                # FIXME this is a dumb way to handle this, but it is mostly for debug during devel
                if isinstance(gen, list) or isinstance(gen, tuple):
                    assert len(gen) == total
                else:
                    raise e

        this_subject_count += 1
        s, p, o = t
        pair_identity = IdentityBNode((p, o), as_type=ibn_it['(p o)'])
        triple_identity = IdentityBNode(t, as_type=ibn_it['(s p o)'], id_method=idf['(s (p o))'])
        accum_trip.append(triple_identity.identity)
        accum_pair.append(pair_identity.identity)
        if isinstance(o, rdflib.Literal):
            row = str(s), str(p), str(o), str_None(o.datatype), str_None(o.language), triple_identity.identity  # FIXME TODO fixes
            batch_lit_rows.append(row)
        else:
            row = str(s), str(p), str(o), triple_identity.identity
            batch_uri_rows.append(row)

    if s is not None:  # named can be empty
        yield from condense_and_make_named_rows()

    if batch_idents:
        breakpoint()

    assert not batch_idents
    assert s is None or total == i + 1
    # XXX the other way we could do this is to store subject_identities
    # across process_name -> process_conn for those that are in process conn
    # which is going to be pretty much all of them so no need to try to
    # be efficient about it ...
    graph_named_identity = sid(accum_embedded)  # FIXME TODO consider inserting serialization hasPart graph_named_identity as temp for recovery?
    irels = [(e,) for e in accum_embedded]
    yield prepare_batch('INSERT INTO identities (type, identity, record_count) VALUES /* 6 */',
                        ((graph_named_identity, total),), ocdn,
                        constant_dict={'nt': 'named_embedded_seq'})

    # FIXME pr hits missing identities here somehow possibly an off by one error at the end of the loop?
    for chunk in chunk_list(irels, batchsize):
        yield prepare_batch('INSERT INTO identity_relations (p, s, o) VALUES', chunk, ocdn,
                            constant_dict={'p': 'hasNamedRecord', 's': graph_named_identity})

    if s is None:
        dout['named_count'] = 0
    else:
        dout['named_count'] = i + 1

    dout['graph_named_identity'] = graph_named_identity
    yield None, None


def do_process_into_session(session, process, *args, commit=False, batchsize=None, debug=False,
                            force=False, dout=None):
    if batchsize is None:
        batchsize = _batchsize
    try:
        stashed_error = []
        for i, (sql, params) in enumerate(process(*args, batchsize=batchsize, debug=debug, dout=dout)):

            if sql is None and params is None:
                if commit:
                    session.commit()
                elif not debug:
                    session.execute(sql_text(f'savepoint sp{i}'))
                    log.debug(f'last savepoint sp{i}')

            else:
                if stashed_error:
                    breakpoint()
                    # FIXME I'm sure this will pass some things that should fail
                    msg = f'failure only allowed on final {i} > {stashed_error[0][0]}'
                    raise ValueError(msg) from stashed_error[0][1]

                try:
                    # one major advantage of yielding all the sql to be executed is that there is a single
                    # point that controls all sql execution, that alone kind of makes yielding worth it
                    session.execute(sql, params=params)
                except Exception as e:
                    if force:
                        log.exception(e)
                        stashed_error.append((i, e))
                        continue
                    else:
                        raise e

                if debug and not commit:
                    session.execute(sql_text(f'savepoint sp{i}'))
                    log.debug(f'last savepoint sp{i}')

            session.flush()

    except BaseException as e:
        session.rollback()
        raise e
    finally:
        session.close()


#@profile_me(sort='cumtime')
def ingest_uri(uri_string, user, commit=False, batchsize=None, debug=False, force=False):
    # FIXME TODO something with user yeah?
    if batchsize is None:
        batchsize = _batchsize

    # XXX query_cache_size is THE major memory hog when doing batch inserts
    # in an uberon load the default limit of 500 entires will use on the order
    # of an additional 5 gigs of memory for nothing since all the cached content
    # is unique and mostly params, the issue is so bad in fact that I'm considering
    # changing our defaults to avoid memory issues
    session = getScopedSession(echo=False, query_cache_size=0)
    q = Queries(session)
    iri = rdflib.URIRef(uri_string)
    url = urlparse(iri)
    # FIXME need to populate reference names
    # FIXME read the file header

    # FIXME the logic for arriving at the correct reference name requires knowing
    # the name, the bound name
    ori = OntResIri(iri)
    metadata = ori.metadata()

    # XXX XXX XXX preamble
    metadata.graph
    bound_version_name = metadata.identifier_version

    if bound_version_name is not None:
        metadata_version = metadata.__class__(bound_version_name)
        try:
            metadata_version.graph
            metadata_to_fetch = metadata_version
            metadata_not_to_fetch = metadata
        except requests.exceptions.HTTPError:
            metadata_to_fetch = metadata
            metadata_not_to_fetch = None

    else:
        metadata_to_fetch = metadata
        metadata_not_to_fetch = None

    name_to_fetch = metadata_to_fetch.identifier_actionable
    base = pathlib.Path(tempfile.tempdir) / 'interlex-load'
    if not base.exists():
        base.mkdir(exist_ok=True)

    url_ntf = urlparse(name_to_fetch)
    etag = metadata_to_fetch.headers['etag']  # we can't trust etags not to be malformed so b64 them before sticking them on the fs
    betag = base64.urlsafe_b64encode(etag.encode())[:-2].decode()
    #etag = _etag[(2 if _etag.startswith('W/') else 0):].strip('"')
    working_path = base / url_ntf.netloc / url.path[1:] / betag
    #working_path = pathlib.Path(tempfile.mkdtemp(dir=base))  # unfriendly because of repeated fetches
    if not working_path.exists():
        working_path.mkdir(parents=True, exist_ok=True)

    path = working_path / pathlib.PurePath(url.path).name
    logfile = working_path / 'sysout.log'
    rapper_input_type = metadata_to_fetch.rapper_input_type()
    if rapper_input_type is None:
        orif = OntResIri(metadata_to_fetch.iri)
        orif.graph_next(compute_identity=True)
        serialization_identity = orif._identity
        sha256hex = serialization_identity.hex()
        process_fun = process_triple_seq
        process_args = (orif.graph, serialization_identity,
                        metadata_to_fetch, metadata_not_to_fetch)

    else:
        msg = f'ingesting {name_to_fetch} to {path} as {rapper_input_type}'
        log.debug(msg)
        (_, checksum_sha256, *_, raw_sord_path) = get_paths(path)
        if not (working_path / 'edges').exists() or force:
            only_local = (working_path / 'edges').exists() and force
            log.debug(f'{name_to_fetch} starting shellout with only_local {only_local}')
            raw_sord = shellout(name_to_fetch, path, rapper_input_type, logfile, only_local=only_local)
            # FIXME may want to write raw_sord to disk given the time it can take
        else:
            with open(raw_sord_path, 'rt') as f:
                # since we write this from python instead of e.g. grep
                # there is no trailing newline to discard so no [:-1]
                raw_sord = f.read().split('\n')

        sha256hex = getstr(checksum_sha256)
        serialization_identity = bytes.fromhex(sha256hex)
        process_fun = process_prepared
        process_args = (path, serialization_identity,
                        metadata_to_fetch, metadata_not_to_fetch,
                        metadata_to_fetch.graph.namespace_manager, raw_sord)

    dout = {}
    def post_check():
        dout
        IdentityBNode._if_cache = {}
        if debug and dout['named_count'] + dout['bnode_count'] < 1_000_000:
            ori = OntResIri(metadata_to_fetch.iri)
            orid = ori.graph.identity()  # FIXME for small only obviously
            oridc = IdentityBNode(ori.graph, as_type=ibn_it['graph-combined-and-local-conventions'])

            mr = [(k, oridc._if_cache[k]) for k in oridc._if_cache if idf['multi-record'] in k][-2:]
            rs = [(k, oridc._if_cache[k]) for k in oridc._if_cache if idf['record-seq'] in k][-2:]

            if dout:
                # named ok
                if rs[0][-1] != dout['graph_named_identity']:
                    breakpoint()

                assert rs[0][-1] == dout['graph_named_identity'], 'urg'

                # bnode does not match for some reason tbd
                # pretty sure it is because ibn is still using
                # condensed to calculate for connected instead of embedding
                # the subject ids ...
                # XXX NOPE it was a super stupid bug where i had s instead of cs
                # thankfully my testcase had term/conn only with no link
                if rs[1][-1] != dout['graph_bnode_identity']:
                    breakpoint()

                assert rs[1][-1] == dout['graph_bnode_identity'], 'urg'

            # lcid at least matches :/
            lcid = oridc._if_cache[[k for k in oridc._if_cache if idf['local-conventions'] in k][0]].hex()
            if parsedTo is not None and oridc.identity != parsedTo.tobytes():
                breakpoint()


        IdentityBNode._if_cache = {}

        te = TripleExporter()
        out_graph = OntGraph(bind_namespaces='none')
        # potential memory issues with having two copies of the same graph around
        local_convention_rows = q.getCuriesByBoundName(iri)
        # FIXME these two queries need to be run together
        # because it could happen that the latest identity
        # could change between the two calls causing reconstruction
        # to fail, another solution is to get the latest identity
        # and then use it to retrieve both parts
        graph_rows = q.getGraphByBoundName(iri)  # FIXME this deadlocks too, wtf is going on here
        # FIXME somehow we are hitting idle in transaction blowing through 100% cpu usage
        # how am I deadlocking myself so much on this it is nutso ...
        if not graph_rows:
            breakpoint()

        curies = {p: n for p, n in local_convention_rows}
        out_graph.namespace_manager.populate_from(curies)
        @profile_me
        def herpderp():
            _ = [out_graph.add(te.triple(*r)) for r in graph_rows]  # FIXME this is insanely slow ??? why ???
        log.debug('begin populate outgraph')
        out_graph.namespace_manager.populate_from()
        herpderp()
        log.debug('end populate outgraph')
        redout = {}
        regen = list(process_triple_seq(out_graph, dout=redout))

        if dout['graph_combined_identity'] != redout['graph_combined_identity']:
            breakpoint()

        assert dout['graph_combined_identity'] == redout['graph_combined_identity']

        if (dout['graph_combined_local_conventions_identity'] !=
            redout['graph_combined_local_conventions_identity']):
            breakpoint()

        assert (dout['graph_combined_local_conventions_identity'] ==
                redout['graph_combined_local_conventions_identity'])

    ### end post_check

    ifv = _hbn.version
    parsedTo = already_in(session, serialization_identity, ifv)
    if parsedTo:
        msg = f'{name_to_fetch} -> {sha256hex} parsedTo {parsedTo.hex()} with identity function version {ifv}'
        log.info(msg)
        if not force:
            return

    do_process_into_session(session, process_fun, *process_args,
                            commit=commit, batchsize=batchsize, debug=debug, force=force, dout=dout)

        # TODO need to clean up shellout and stash the xz somewhere,
        # especially if we are using a ramdisk, because the in-process
        # files take up lots of space, starting with the .ntriples files
        # might be enough, but also, these files xz down to teeny tiny sizes
        # as in small enough to put as blobs into the database if we wanted
        # not that that is a good idea, but we could, they are small enough

    #reference_name = figure_out_reference_name(  # TODO
        #name=name,
        #bound_name=bound_name,
        #bound_version_name=bound_version_name,
        #user_provided_reference_name=None,)

    # TODO figure out when and how we use reference names because for
    # general ingest we don't need them, external source are identified
    # and their various components tracked implicitly there are one or
    # more perspectives that they might belong to but that kind of
    # doesn't matter right now?
    reference_name = rdflib.URIRef(f'http://uri.interlex.org/base/ontologies/dns/{url.netloc}{url.path}')
    post_check()


def main():
    user = sys.argv[1]
    uri = sys.argv[2]
    commit = '--commit' in sys.argv
    force = '--force' in sys.argv
    debug = '--debug' in sys.argv
    ingest_uri(uri, user, commit=commit, force=force, debug=debug)


if __name__ == '__main__':
    main()
