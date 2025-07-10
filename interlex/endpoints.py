import os
import re
import json
import base64
import random
import secrets
from time import time, sleep
from datetime import timedelta, timezone
from functools import wraps
from urllib.parse import urlparse, quote as url_quote
import requests
import sqlalchemy as sa
import flask_login as fl
from flask import request, redirect, url_for, abort, Response, session as fsession
from rdflib import URIRef  # FIXME grrrr
from htmlfn import atag, btag, h2tag, htmldoc
from htmlfn import table_style, render_table, redlink_style
from pyontutils.core import OntGraph, makeGraph, populateFromJsonLd
from pyontutils.utils_fast import TermColors as tc, isoformat
from pyontutils.namespaces import makePrefixes, definition, rdf, rdfs, owl, dc, ilxtr
from sqlalchemy.sql import text as sql_text
import idlib
from interlex import auth as iauth
from interlex import tasks
from interlex import config
from interlex import exceptions as exc
from interlex.auth import Auth, gen_key
from interlex.core import diffCuries, makeParamsValues, default_prefixes, from_title_subjects_ontspec
from interlex.dump import TripleExporter, Queries
from interlex.load import FileFromIRIFactory, FileFromPostFactory, TripleLoaderFactory, BasicDBFactory, UnsafeBasicDBFactory
from interlex.utils import log as _log
from interlex.config import ilx_pattern  # FIXME pull from database probably
from interlex.ingest import ingest_ontspec
from interlex.dbstuff import Stuff
from interlex.vervar import process_vervar
from interlex.render import TripleRender  # FIXME need to move the location of this
from interlex.notifications import send_message, get_smtp_spec, msg_email_verify, msg_user_recover, msg_user_recover_alt

log = _log.getChild('endpoints')
log_ver = _log.getChild('verification')

ctaj = {'Content-Type': 'application/json'}
_param_popup = 'aspopup'

tripleRender = TripleRender()

_email_mock = False
_email_mock_tokens = {}

_orcid_mock = False
_orcid_mock_codes = {}

_reset_mock = False
_reset_mock_tokens = {}


def getBasicDB(self, group, request):
    #log.debug(f'{group}\n{request.method}\n{request.url}\n{request.headers}')

    expired_token = False
    try:
        # FIXME pretty sure this isn't quite right
        # XXX yeah, auth_group is the wrong way to do this
        # we have to check user persmissions in the group during
        # authenticate_request
        auth_group, auth_user, scope, auth_token, read_private = self.auth.authenticate_request(request)
    except self.auth.ExpiredTokenError:
        # FIXME are the cases where we want to redirect to login?
        expired_token = True
    except (self.auth.MissingTokenError, self.auth.InvalidScopeError, self.auth.HasNotCompletedVerificationError) as e:
        # it is ok to return a 401 for missing token because it is returned for
        # particular methods or well known endpoints, never for scratch space
        # urls, also ok for invalid scope because the result doesn't check whether
        # the target group exists, only that it does not match
        abort(401, {'message': e.extra_info})
    except (self.auth.MalformedRequestHeader, self.auth.MangledTokenError) as e:
        abort(400, {'message': e.extra_info})
    except self.auth.AuthError as e:
        log.exception(e)
        abort(400, {'message': 'something went wrong on your end'})

    expired_token = expired_token or (
        fl.current_user is not None and
        not fl.current_user.is_authenticated and
        hasattr(fl.current_user, 'via_auth') and
        fl.current_user.via_auth == 'orcid')

    if expired_token:
        if '_via_auth' in fsession and fsession['_via_auth'] == 'orcid':
            abort(401, {'message': 'orcid login expired, please login again'})
        else:
            newtokl = url_for('Priv /<group>/priv/api-token-new')
            abort(401, {'message': (
                'Your token has expired, please get a '
                f'new one at {newtokl}')})

    if request.method in ('HEAD', 'GET', 'OPTIONS'):
        # FIXME there are some pages we need to reject at this point?
        db = self.getBasicInfoReadOnly(group, auth_user)

    else:
        #if auth_token:
        #    if auth_group != group:
        #        return f'This token is not valid for group {group}', 401

        #    if not auth_user:  # this should be impossible ...
        #        if group == 'api':  # should this be hardcoded? probably
        #            return 'FIXME what do we want to do here?', 401
        #        else:
        #            # not 403 because this way we are ignorant by default
        #            # we dont' have to wonder whether the url they were
        #            # looking for was private or not (most shouldn't be)
        #            abort(404)

        db = self.getBasicInfo(group, auth_user)

    return db, auth_user, read_private

pass_db = False  # new permissions model means we don't need this anymore
def basic(function):
    @wraps(function)
    def basic_checks(self, *args, **kwargs):
        try:
            group = kwargs['group']  # FIXME really group
        except KeyError as e:
            # note for those who encounter this error when trying to call one
            # view function from inside another: flask passes **req.view_args
            # to self.view_functions[rule.endpoint] so you need to construct
            # the kwarg dictionary accordingly
            raise KeyError('remember that basic needs kwargs not args!') from e

        if 'db' not in kwargs:  # being called via super() probably
            maybe_db, _, read_private = getBasicDB(self, group, request)
            if not isinstance(maybe_db, BasicDBFactory):
                if maybe_db is None:
                    abort(404)
                else:
                    return maybe_db
            else:
                db = maybe_db

            if pass_db:
                kwargs['db'] = db

            if 'read_private' in kwargs:
                breakpoint()
                kwargs['read_private'] = read_private

        return function(self, *args, **kwargs)

    return basic_checks


def basic0(function):
    """ only use this u/priv because it only exists to abort if anything other
        than an orcid only token is set """
    @wraps(function)
    def basic0_checks(self, *args, **kwargs):
        group = None
        _, _, read_private = getBasicDB(self, group, request)
        return function(self, *args, **kwargs)

    return basic0_checks


def basic2(function):
    @wraps(function)
    def basic2_checks(self, *args, **kwargs):
        if 'db' not in kwargs:  # being called via super() probably
            group = kwargs['group']
            maybe_db, auth_user, read_private = getBasicDB(self, group, request)
            if not isinstance(maybe_db, BasicDBFactory):
                if maybe_db is None:
                    abort(404)
                else:
                    return maybe_db
            else:
                db = maybe_db

            if pass_db:
                kwargs['db'] = db

            if 'read_private' in kwargs:
                breakpoint()
                kwargs['read_private'] = read_private

            if 'other_group' in kwargs:
                other_group = kwargs['other_group']
            elif 'other_group_diff' in kwargs:
                other_group = kwargs['other_group_diff']

            db2 = self.getBasicInfoReadOnly(other_group, auth_user)
            if db2 is None:
                abort(404)

            db.other = db2

        elif hasattr(kwargs['db'], 'other'):
            pass  # its ok, this is probably being called by another wrapped function 

        else:
            log.error('a database was provided as a kwarg '
                      'that did not have other already bound\n'
                      f'{request.url}')
            abort(404)

        return function(self, *args, **kwargs)

    return basic2_checks


def check_reiri(reiri):
    # seems like I'm not the only one https://github.com/lingthio/Flask-User/issues/119#issuecomment-610237001
    reurl = urlparse(reiri)
    if reurl.netloc in config.redirect_allow_hosts:
        return reiri
    elif reurl.scheme != request.scheme or reurl.netloc != request.host:  # FIXME uri.interlex.org vs interlex.org
        log.info(f'possibly malicious redirect? {reiri}')
    else:
        return reiri


def _rp_schema():
    schema = {'type': 'object',
     'required': ['code'],
     'properties': {
         'code': {'type': 'integer'},
         'orcid_meta': {  # not present when user has not associated an orcid yet
             'type': 'object',
             'required': ['orcid'],
             'properties': {
                 'orcid': {'type': 'string'},
                 'name': {'type': 'string'},  # not present from login only orcid-new atm
             }},
         'grouname': {'type': 'string'},  # not present when user only has orcid
         'redirect': {'type': 'string'},
         'settings_url': {'type': 'string'},  # XXX deprecated, use redirect instead
     },}
    s = json.dumps(schema, indent=2)
    return s


def return_page(html=None, data={}, status=200):
    #TODO the window.close at line 231 can be customised to account for the status code invoked when calling
    # this function, so that if we want to display an error it can leave the popup opened.
    # not urgent imho, since we are also giving the possibility to inject the entire html and return that.
    if html is not None:
        return html
    else:
        data['code'] = status
        data['status'] = status
        response_json = json.dumps(data)
        return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex Login / Registration</title></head>
<body>
<h1>InterLex Login / Registration</h1>
<script type="module">
    function parseCookies() {{
        return document.cookie
        .split('; ')
        .filter(Boolean)
        .reduce((acc, cookie) => {{
            const [name, ...rest] = cookie.split('=');
            acc[decodeURIComponent(name)] = decodeURIComponent(rest.join('='));
            return acc;
        }}, {{}});
    }}

    const response = {response_json};
    const cookies = parseCookies();
    response['cookies'] = JSON.stringify(cookies);
    if (window.opener !== null && window.opener !== undefined) {{
        window.opener.postMessage(response, "*");
    }} else {{
        parent.postMessage(response, "*");
    }};
    window.close();
</script>
</body>
</html>'''


class EndBase:

    def __init__(self, db, rules_req_auth):
        self.db = db
        self.session = self.db.session
        self.queries = Queries(self.session)
        self.auth = Auth(self.session, rules_req_auth)
        #self.FileFromIRI = FileFromIRIFactory(self.session)  # FIXME I think these go in tasks
        #self.FileFromPost = FileFromPostFactory(self.session)  # FIXME I think these go in tasks
        self.BasicDB = BasicDBFactory(self.session)
        self.UnsafeBasicDB = UnsafeBasicDBFactory(self.session)

    def get_func(self, nodes, mapping=None):
        #ilx_get = ilx_pattern + '.<extension>'  # FIXME TODO where did we need this again?
        if mapping is None:
            mapping = {}

        for node in nodes[::-1]:
            if node in mapping:
                return mapping[node]
        else:
            breakpoint()
            raise KeyError(f'could not find any value for {nodes}')

    @property
    def reference_host(self):
        return self.queries.reference_host

    def session_execute(self, sql, params=None):
        return self.session.execute(sql_text(sql), params=params)

    def getBasicInfo(self, group, auth_user):
        try:
            return self.BasicDB(group, auth_user, read_only=False)
        except exc.NotGroup:
            return None

    def getBasicInfoReadOnly(self, group, auth_user):
        """ Read only access means that any identifiers that are provisional
            cannot be seen by people who do not have edit acces. This is intention,
            and is an attempt to allow editors to work in their own space without
            risking 'identifier escape' """
        # this code is intentionally reproduced so that the function name
        # stands out to the (human) reader
        try:
            # we keep the user for provenance and auditing purposes
            return self.UnsafeBasicDB(group, auth_user, read_only=True)
        except exc.NotGroup:
            log.debug(f'not group? {group}')
            return None



class Endpoints(EndBase):

    def get_func(self, nodes):
        mapping = {
            'group_': self.group_,
            'ilx': self.ilx,
            'other': self.other,
            '*versions': self.versions,
            #'*versions_': self.versions,
            '<record_combined_identity>': self.get_version,

            #ilx_get: self.ilx_get,
            '*ilx_get': self.ilx,

            'dns': self.dns,

            'lexical': self.lexical,
            'readable': self.readable,
            'uris': self.uris,
            'curies_': self.curies_,
            'curies': self.curies,

            # FIXME how to deal with own/other for ontologies/uris ?
            # FIXME ontologies are weird with need to be here ...
            # but either you duplicate functions or you duplicate diff and own classes
            '*ontologies': self.ontologies_,  # Endpoints only
            'ontologies': self.ontologies,
            'version': self.ontologies_version,  # FIXME collision prone?
            '*dns_version': self.ontologies_dns_version,

            '*ont_ilx_pattern': self.ontologies_ilx,
            '*ont_ilx_get': self.ontologies_ilx,
            '*dns_ont': self.ontologies_dns,
            '*uris_ont': self.ontologies_uris,

            'spec': self.ontologies_spec,
            'spec.<extension>': self.ontologies_spec,
            '*spec': self.ontologies_ilx_spec,
            '*spec.<extension>': self.ontologies_ilx_spec,

            '*<path:uris_ont_path>': self.ontologies_uris,
            '*uris_version': self.ontologies_uris_version,

            'contributions_': self.contributions_,
            'contributions': self.contributions,
            '*contributions_ont': self.ontologies_contributions,

            'prov': self.prov,

            'query_transitive': self.query_transitive,

            'mapped': self.mapped,
        }
        return super().get_func(nodes, mapping)

    def getGroupCuries(self, group, epoch_verstr=None,
                       default=default_prefixes):
        PREFIXES = self.queries.getGroupCuries(group, epoch_verstr)
        currentHost = request.headers['Host']
        PREFIXES = {cp:ip.replace('uri.interlex.org', currentHost) if config.debug else ip
                    # TODO app.debug should probably be switched out for something configurable
                    for cp, ip in PREFIXES.items()}
        if not PREFIXES:  # we get the base elsewhere
            PREFIXES = default
        #log.debug(PREFIXES)
        graph = makeGraph(group + '_curies_helper', prefixes=PREFIXES if PREFIXES else default_prefixes).g
        return PREFIXES, graph

    def build_reference_name(self, group, path):
        # need this for testing, in an ideal world we read from headers
        return os.path.join(f'https://{self.reference_host}', group, path)

    @staticmethod
    def iriFromPrefix(prefix, *ordered_prefix_sets):
        for PREFIXES in ordered_prefix_sets:
            try:
                return PREFIXES[prefix]  # redirect(iri, 302)
            except KeyError:
                pass
        else:
            return f'Unknown prefix {prefix}', 404

    def mapped(self, group):
        # see the alt implementation of external/mapped for use case
        return request.path, 501

    rx_pref = re.compile('^(ilx|cde|fde|pde)_')  # TODO configure
    def isIlxIri(self, iri):
        # FIXME the is a horrible way to define valid uri structure
        scheme, rest = iri.split('://', 1)
        prefix, maybe_ilx = rest.rsplit('/', 1)
        if (prefix.startswith(self.reference_host) and
            re.match(self.rx_pref, maybe_ilx)):  # TODO allow configurable prefix here
            _, group, _ = (prefix + '/').split('/', 2)  # at trailing in case group was terminal
            frag_pref, id = maybe_ilx.split('_')
            return group, frag_pref, id

    def _even_more_basic(self, group, frag_pref, id, db):
        # FIXME multiple fragment prefixes makes for a FUN TIME
        # do we have separate tables for each fragment? seems bad
        # or do we add a frag_pref = :frag_pref and then have to deal
        # with creating a new primary sequence whenever we create a new
        # fragment prefix? ... SIGH
        if group != 'base' and group != 'latest':
            sql = 'SELECT id FROM interlex_ids WHERE id = :id'
            try:
                res = next(self.session_execute(sql, dict(id=id)))
                id = res.id
                #log.debug((id, db.group_id))
            except StopIteration:
                abort(404)

        try:
            _, _, func = tripleRender.check(request)
        except exc.UnsupportedType as e:
            abort(e.code, {'message': e.message})

    @basic
    def group_(self, group, db=None):
        '''overview page for group (user/org)'''
        dbstuff = Stuff(self.session)
        resp = dbstuff.getUserOverview(group)
        if resp:
            row = resp[0]
            stuff = {
                'groupname': row.groupname,
                'fullname': row.name,  # 'Place Holder' # lol
                'orcid': row.orcid,
                'group_created_datetime': isoformat(row.created_datetime.astimezone(timezone.utc)),
            }
            if row.member_of:
                stuff['member_of'] = row.member_of

            if row.edrev_of:
                stuff['edrev_of'] = row.edrev_of

            return json.dumps(stuff), 200, ctaj

        abort(404)

    def _ilx_impl(self, group, frag_pref, id, func):
        PREFIXES, graph = self.getGroupCuries(group)
        resp = self.queries.getById(frag_pref, id, group)
        #log.debug(resp)
        # TODO formatting rules for subject and objects
        object_to_existing = self.queries.getResponseExisting(resp, type='o')

        te = TripleExporter()
        _ = [graph.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

        # TODO list users with variants from base and/org curated
        # we need an 'uncurated not latest' or do we?
        if group == 'base':
            _pref = frag_pref.upper() # FIXME TODO frag_pref -> curie using getGroupCuries
            title = f'{_pref}:{id}'
        else:
            title = f'ilx.{group}:{frag_pref}_{id}'

        if func == tripleRender.ttl_html:  # FIXME hackish?
            # FIXME getting additional content from the db based on file type
            # leads to breakdown of separation of concerns due to statefulness
            # slow but probably worth it for enhancing readability
            iris = set(e for t in graph for e in t if isinstance(e, URIRef))
            labels = {URIRef(s):label for s, label in self.queries.getLabels(group, iris)}
        else:
            labels = None

        return graph, object_to_existing, title, labels

    # TODO PATCH
    @basic
    def ilx(self, group, frag_pref_id, extension=None, db=None):
        return self._ilx(group, frag_pref_id, extension=extension)

    def _ilx(self, group, frag_pref_id, extension=None, db=None):
        frag_pref, id = frag_pref_id.split('_')
        # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}
        # TODO better to accept just modified jsonld
        if request.method == 'PATCH':
            # accepts jsonld or ttl coming back, but it must be well formed
            # and must have the reference to the previous identity
            jld = request.json
            ont = [o for o in jld['@graph'] if o['@type'] == 'owl:Ontology'][0]
            pred = 'isAbout' if 'isAbout' in ont else 'http://purl.obolibrary.org/obo/IAO_0000136'  # FIXME curies and context ...
            bound_frag_pref_id = ont[pred]['@id'].rsplit('/')[-1]
            if bound_frag_pref_id != frag_pref_id:
                abort(422, f'wrong id: {bound_frag_pref_id} != frag_pref_id')

            # steps:
            # 0. extract identity from ont
            # 0. somewhere in here drop version related info to get something more invariant
            # 0. use identity to retrieve what we sent (or the modifiable part of what we sent?)
            # 0. compute the identity of what we received (or maybe just the modifiable record?)
            # 0. make sure that what has changed is part of the ilx record they can modify
            # 0. ingest the new version, update perspective head
            # 0. return the full new record with the newly computed identity to track further changes
            graph = OntGraph()
            graph.namespace_manager.populate_from(jld['@context'])  # FIXME complex contexts
            populateFromJsonLd(graph, jld)
            abort(501)

        else:
            func = self._even_more_basic(group, frag_pref, id, db)
            graph, object_to_existing, title, labels = self._ilx_impl(group, frag_pref, id, func)
            return tripleRender(request, graph, group, frag_pref, id,
                                object_to_existing, title, labels=labels)

    @basic
    def ilx_get(self, group, frag_pref_id, extension, db=None):
        raise NotImplementedError('use ilx directly ')
        # TODO these are not cool uris
        # TODO move this lookup to config?
        return self._ilx(group=group, frag_pref_id=frag_pref_id, extension=extension)
        #return tripleRender(request, g, group, id, object_to_existing, title)

    @basic
    def other(self, group, frag_pref_id, epoch_verstr_id=None, db=None):
        abort(501, 'TODO')

    @basic
    def versions(self, group, frag_pref_id, epoch_verstr_id=None, db=None):
        uri = f'http://uri.interlex.org/base/{frag_pref_id}'
        snr, ttsr, tsr, trr = self.queries.getVerVarBySubject(uri)
        vv, uniques, metagraphs, ugraph, vvgraphs, resp = process_vervar(uri, snr, ttsr, tsr, trr)
        return json.dumps(resp), 200, ctaj

    @basic
    def get_version(self, group, frag_pref_id, record_combined_identity):
        # FIXME TODO variant with no deps on frag pref just return whatever is at the id
        uri = f'http://uri.interlex.org/base/{frag_pref_id}'
        # FIXME TODO use the new better query
        snr, ttsr, tsr, trr = self.queries.getVerVarBySubject(uri)
        vv, uniques, metagraphs, ugraph, vvgraphs, resp = process_vervar(uri, snr, ttsr, tsr, trr)
        # FIXME obviously bad
        fst = None
        for fst, u in uniques.items():
            if 'versions' in u:
                if u['versions']['identity-record'] == record_combined_identity:
                    break

        vg = vvgraphs[fst]
        title = f'version graph for {uri} at {record_combined_identity}'
        resp = tripleRender(request, vg, group, None, None,
                            tuple(), title, redirect=False, simple=True)
        return resp

    @basic
    def dns(self, group, dns_host, dns_path, extension=None):
        # FIXME TODO perspective head
        subject = f'http://{dns_host}/{dns_path}'
        # FIXME do we want ot use original source curies in this case?
        #curies = {p: n for p, n in self.queries.getCuriesByName(spec_uri)}
        curies = self.queries.getGroupCuries(group)
        resp = self.queries.getBySubject(subject, group)
        graph = OntGraph(bind_namespaces='none')
        graph.namespace_manager.populate_from(curies)
        te = TripleExporter()
        for r in resp:
            graph.add(te.triple(*r[:-1], None, r[-1]))

        title = f'graph for {subject}'
        return tripleRender(request, graph, group, None, None, tuple(),
                            title, redirect=False, simple=True)

    @basic
    def lexical(self, group, label, db=None):
        # TODO FIXME consider normalization in cases where there is not an exact match?
        # like with my request to n2t, check for exact, then normalize
        do_redirect, identifier_or_defs = self.queries.getByLabel(label, group)
        if do_redirect:
            if self.reference_host not in identifier_or_defs:
                # FIXME temporary workaround for finding a uri that goes elsewhere
                curie, _code = self.curies(
                    prefix_iri_curie=identifier_or_defs, group=request.view_args['group'])
                to_curie = url_for('Endpoints.curies /<group>/curies/<prefix_iri_curie>',
                                   group=group, prefix_iri_curie=curie)
                to_curie +=  '?local=true'
                return redirect(to_curie, code=302)
            else:
                # FIXME devel hack
                identifier = identifier_or_defs.replace(self.reference_host, request.host)
                return redirect(identifier, code=302)
        elif not identifier_or_defs:
            # FIXME this does not route to uri.interlex.org (probably)?
            title = f'{label} (ambiguation)'
            ambiguate = f'https://interlex.org/ambiguation/{label}'
            body = (f'<a href="{ambiguate}" class="redlink">{label}</a> is undefined.')
            return htmldoc(body,
                           title=title,
                           styles=(redlink_style,)), 404
        else:
            PREFIXES, g = self.getGroupCuries(group)
            defs = [(atag(s, g.qname(s)), d) for s, d in identifier_or_defs]
            title = f'{label} (disambiguation)'  # mirror wiki
            # TODO resolve existing_iri mappings so they don't show up here
            # also always resolve to the interlex page for a term not external

            content = render_table(defs, 'Identifier', atag(definition, 'definition:'))
            return htmldoc(h2tag(f'{label} (disambiguation)'),
                           content, title=title, styles=(table_style,))

            # TODO rdf version of the disambiguation page
            try:
                _, _, func = tripleRender.check(request)
            except exc.UnsupportedType as e:
                abort(e.code, {'message': e.message})

            object_to_existing = []
            te = TripleExporter()
            for iri in iri, _ in identifiers_or_defs:
                resp = self.queries.getBySubject(iri, group)
                _ = [g.g.add(te.triple(*r[:-1], None, r[-1])) for r in resp]
                object_to_existing += self.queries.getResponseExisting(resp, type='o')


    # TODO PATCH only admin can change the community readable mappings just like community curies
    @basic
    def readable(self, group, word, db=None):
        return request.path

    @basic
    def contributions_(self, group, db=None):
        # without at type lands at the additions and deletions page
        return 'TODO identity for group contribs directly to interlex', 501

    @basic
    def contributions(self, *args, **kwargs):
        return 'TODO slicing on contribs ? or use versions?', 501

    # TODO POST ?private if private PUT (to change mapping) PATCH like readable
    @basic
    def uris(self, group, uri_path, db=None, read_private=False):
        # owl:Class, owl:*Property
        # owl:Ontology
        # /<group>/ontologies/obo/uberon.owl << this way
        # /<group>/uris/obo/uberon.owl << no mapping to ontologies here
        title = f'uris.{group}:{uri_path}'
        PREFIXES, graph = self.getGroupCuries(group)
        if read_private:
            resp = self.queries.getUnmappedByGroupUriPath(group, uri_path, read_private, redirect=False)
        else:
            resp = self.queries.getByGroupUriPath(group, uri_path, redirect=False)

        if not resp:
            iri = request.url
            suggestions = ''  # TODO this requires them to have uploaded or we guess the suffix
            # FIXME content type :/
            return htmldoc(f'404 error. <b>{group} {uri_path}</b> has not been mapped to an InterLex id!\n{suggestions}',
                            title='404 ' + title), 404

        else:
            object_to_existing = self.queries.getResponseExisting(resp, type='o')

            te = TripleExporter()
            _ = [graph.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

            return tripleRender(request, graph, group, frag_pref, id, object_to_existing)

    # TODO POST PUT PATCH
    # just overload post? don't allow changing? hrm?!?!
    @basic
    def curies_(self, group, db=None):
        # TODO auth
        # TODO DELETE yes, sometimes you make a typo when the system is this easy to use
        # and you need to fix it ...
        if request.method == 'POST':
            PREFIXES, g = self.getGroupCuries(group, default={})
            # FIXME enforce rdf rdfs and owl? or only no empty?
            if request.json is None:
                return 'No curies were sent\n', 400
            newPrefixes = request.json

            ok, to_add, existing, message = diffCuries(PREFIXES, newPrefixes)
            # FIXME this is not inside a transaction so it could fail!!!!
            if not ok:
                abort(409, {'message': message})
            elif not to_add:
                return 'No new curies were added.', 409  # FIXME

            dbstuff = Stuff(self.session)
            try:
                resp = dbstuff.insert_curies(group, to_add)
                self.session.commit()
                return message, 201
            except sa.exc.IntegrityError as e:
                self.session.rollback()
                return f'Curie exists\n{e.orig.pgerror}', 409  # conflict
                return f'Curie exists\n{e.args[0]}', 409  # conflict
        else:
            PREFIXES, g = self.getGroupCuries(group)

        return json.dumps(PREFIXES), 200, ctaj

    # TODO POST PATCH PUT
    @basic
    def curies(self, group, prefix_iri_curie, extension=None, db=None):
        # FIXME confusion between group (aka group) and logged in group :/
        #log.debug(prefix_iri_curie)
        PREFIXES, graph = self.getGroupCuries(group)
        frag_pref = None
        if prefix_iri_curie.startswith('http') or prefix_iri_curie.startswith('file'):  # TODO decide about urlencoding
            iri = prefix_iri_curie
            try:
                curie = graph.namespace_manager.qname(iri)
                return curie, 200
            except KeyError:
                return f'Unknown iri {iri}', 404

        elif ':' in prefix_iri_curie:
            curie = prefix_iri_curie
            prefix, suffix = curie.split(':', 1)
            if prefix == 'ILX':  # TODO more matches?
                frag_pref = 'ilx'
                id = suffix
            else:
                id = None

            namespace = graph.namespace_manager.store.namespace(prefix)  # FIXME ...
            if namespace is None:
                return f'Unknown prefix {prefix}', 404

            iri = namespace + suffix

            maybe_ilx = self.isIlxIri(iri)
            if not suffix and maybe_ilx:
                group, frag_pref, id = maybe_ilx
                # overwrite user here because there are (admittedly strange)
                # cases where someone will have a curie that points to another
                # user's namespace, and we already controlled for the requesting user
                # when we asked for their curies
                # TODO FIXME consider how this interacts with whether the user has
                # set to have all the common curies point to their own space
                # TODO failover behavior for curies is needed for the full consideration

            if 'local' in request.args and request.args['local'].lower() == 'true':
                if id is None:
                    sql = ('SELECT ilx_prefix, ilx_id FROM existing_iris AS e WHERE e.iri = :iri '
                           'AND (e.perspective = persFromGroupname(:group) OR e.perspective = 0)')  # base vs curated
                    args = dict(iri=iri, group=group)
                    try:
                        resp = next(self.session_execute(sql, args))
                        frag_pref = resp.ilx_prefix
                        id = resp.ilx_id
                    except AttributeError as e:
                        breakpoint()
                        raise e
                    except StopIteration:
                        # FIXME this breaks the semantics, but it seems to be the only
                        # current way to get the local interlex content view of unmapped
                        # terms, which we do need a solution for, even if the plan is to
                        # force all terms to be mapped
                        try:
                            _, _, func = tripleRender.check(request)
                        except exc.UnsupportedType as e:
                            abort(e.code, {'message': e.message})

                        resp = self.queries.getBySubject(iri, group)  # FIXME shouldn't we not be using self.queries for this?
                        te = TripleExporter()
                        _ = [graph.add(te.triple(*r[:-1], None, r[-1])) for r in resp]
                        object_to_existing = self.queries.getResponseExisting(resp, type='o')
                        # FIXME we need to abstract TripleRender to work with any ontology name
                        # FIXME we probably need a uri.interlex.org/base/iri/purl.obolibrary.org/obo/ trick ...
                        # as a way to resolve to local content ...
                        # this is the much better solution here

                        if func == tripleRender.ttl_html:  # FIXME hackish?
                            # FIXME getting additional content from the db based on file type
                            # leads to breakdown of separation of concerns due to statefulness
                            # slow but probably worth it for enhancing readability
                            iris = set(e for t in graph for e in t if isinstance(e, URIRef))
                            if not iris:
                                abort(404)
                            labels = {URIRef(s):label for s, label in self.queries.getLabels(group, iris)}
                        else:
                            labels = None

                        id = 'None-FIXMETODO'
                        frag_pref = 'nil'
                        title = 'InterLex local ' + curie
                        return tripleRender(request, graph, group, frag_pref, id,
                                            object_to_existing, title, labels=labels)
                        abort(404)
                        pass

                if extension is not None:
                    url = url_for(f'Endpoints.ilx_get /<group>/{ilx_pattern}.<extension>',
                                  group=group, frag_pref_id=frag_pref + '_' + id, extension=extension)
                else:
                    url = url_for(f'Endpoints.ilx /<group>/{ilx_pattern}',
                                  group=group, frag_pref_id=frag_pref + '_' + id)

                return redirect(url, code=302)

                #return redirect('https://curies.interlex.org/' + curie, code=302)  # TODO abstract
            return redirect(iri, code=302)
        else:
            prefix = prefix_iri_curie
            if prefix not in PREFIXES:
                # TODO query for user failover preferences
                bPREFIXES, g = self.getGroupCuries('base')  # FIXME vs curated
                ordered_prefix_sets = bPREFIXES,
            else:
                ordered_prefix_sets = PREFIXES,

            return self.iriFromPrefix(prefix, *ordered_prefix_sets)

    @basic
    def prov(self, *args, **kwargs):
        """ Return all the identities that an org/user has uploaded
            Show users their personal uploads and then their groups.
            Show groups all uploads with the user who did it
        """
        # in html
        # reference_name, bound_name, identity, date, triple_count, parts
        # if org: uploading_user
        # if user: contribs per group
        return 'TODO\n', 501

    @basic
    def query_transitive(self, group, start, predicate):
        nm = OntGraph(bind_namespaces='none').namespace_manager
        nm.populate_from(self.queries.getGroupCuries(group))  # FIXME
        errors = []
        try:
            s = nm.expand_curie(start)
        except ValueError:
            errors.append(f'unknown curie prefix for start {start}')

        try:
            p = nm.expand_curie(predicate)
        except ValueError:
            errors.append(f'unknown curie prefix for predicate {predicate}')

        if errors:
            msg = '\n'.join(errors)
            # TODO likely need a json variant for this
            abort(422, msg)

        depth = (
            int(request.args['depth'])
            if 'depth' in request.args and (request.args['depth'].isdigit() or request.args['depth'] == '-1')
            else -1)
        obj_to_sub = 'obj-to-sub' in request.args and request.args['obj-to-sub'].lower() == 'true'
        tt = self.queries.getTransitive([s], [p], obj_to_sub=obj_to_sub, depth=depth)
        te = TripleExporter()
        graph = OntGraph()
        for r in tt:
            t = te.triple(r.s, None, r.p, r.o, r.o_lit, r.datatype, r.language)
            graph.add(t)

        object_to_existing = None
        so_or_os = 'subject to object'
        title = f'transitive closure from {start} under {predicate} going {so_or_os} to depth {depth}'
        resp = tripleRender(request, graph, group, None, None,
                            tuple(), title, redirect=False, simple=True)
        return resp

    @basic
    def ontologies_(self, group, db=None):
        """ The terminal ontologies query does go on endpoints """
        dbstuff = Stuff(self.session)
        resp = dbstuff.getGroupOntologies(group)
        if group == 'base':
            # FIXME see if this makes sense
            resp = dbstuff.getFreeOntologies()
            onts = [
                {'uri': row.name,
                 'first_seen': isoformat(row.first_seen.astimezone(timezone.utc))}
                for row in resp]
            return json.dumps(onts), 200, ctaj

        else:
            # FIXME this section should be moved to queries or something like that
            resp = dbstuff.getGroupOntologies(group)
            specs = [r.spec for r in resp]
            # assert not [r for r in resp if r.spec_head_identity != r.identity]
            triple_rows = [list(self.queries.getGraphByName(spec)) for spec in specs]  # FIXME TODO getGraphByIdentity
            te = TripleExporter()
            graphs = [OntGraph().populate_from_triples((te.triple(*r) for r in trows)) for trows in triple_rows]
            onts = []
            for srow, graph in zip(resp, graphs):
                ont = {'uri': srow.spec,
                 'first_seen': isoformat(srow.first_seen.astimezone(timezone.utc)),  # identity first seen, isn't actually last modified because might revert to old identity that has been seen previously
                 }
                for s, o in graph[:dc.title:]:
                    ont['title'] = str(o)

                ont['entity_count'] = len(list(graph[:ilxtr['include-subject']:]))

                onts.append(ont)

            return json.dumps(onts), 200, ctaj

        # TODO
        return json.dumps('your list sir'), 501

    @basic
    def ontologies_ilx(self, group, frag_pref_id, extension=None, db=None):
        # FIXME termset
        # FIXME TODO i think this dispatch is just wrong? should be on ontologies?
        return self._ilx(group=group, frag_pref_id=frag_pref_id, extension=extension)

    @basic
    def ontologies(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_version(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_dns(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_dns_version(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_uris(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_uris_version(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_contributions(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_spec(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_ilx_spec(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')


def _sigh_insert_orcid_meta(session, orcid_meta, user=None):
    # FIXME are new access tokens generated every single time we request that a user log in?
    # FIXME also the id_token for openid seems like something that could be used to invalidate orcid sessions
    # FIXME do we need to store access tokens for every single login we receive i.e. from different computers
    dbstuff = Stuff(session)
    kls = idlib.systems.orcid.OrcidSandbox if config.orcid_sandbox else idlib.Orcid
    orcid = kls._id_class(prefix='orcid', suffix=orcid_meta['orcid']).iri,
    dbstuff.insertOrcidMetadata(
        orcid,
        orcid_meta['name'],
        orcid_meta['token_type'],
        orcid_meta['scope'],
        orcid_meta['access_token'],
        orcid_meta['refresh_token'],
        orcid_meta['expires_in'],
        openid_token=orcid_meta['id_token'] if 'id_token' in orcid_meta else None,  # openid extra thing
        user=user,
    )
    session.commit()


def _sigh_orcid_login_user_temp(orcid_meta):
    # TODO give them a session cookie but use the orcid
    # as the user id, they will have no groupname so we
    # use /u/ but it needs to be priv because they do have
    # to have their session cookie
    class tuser:
        is_active = True
        # reminder anon and auth are exact opposites
        is_anonymous = False
        is_authenticated = True
        via_auth = 'orcid'
        orcid = f'https://{config.orcid_host}/' + orcid_meta['orcid']
        id = orcid_meta['id_token']  # XXX NOTE THE ASYMMETRY
        # we put the orcid as an id on issue but when we load
        # it we move it to orcid and set id = None
        # however at this point if id = None then the token
        # will be for a user id None which is bad
        own_role = None
        groupname = None
        def get_id(self):
            return self.id

    fsession['_via_auth'] = tuser.via_auth
    fsession['_orcid_only'] = 'true'
    fl.login_user(tuser())


class Ops(EndBase):

    def get_func(self, nodes):
        mapping = {
            'login': self.login,
            'user-new': self.user_new,
            'user-login': self.user_login,
            'user-recover': self.user_recover,
            'orcid-new': self.orcid_new,
            'orcid-login': self.orcid_login,
            'orcid-land-new': self.orcid_landing_new,
            'orcid-land-login': self.orcid_landing_login,
            'ever': self.email_verify,
            'email-verify': self.email_verify,
            'pwrs': self.password_reset,
            'password-reset': self.password_reset,
        }
        return super().get_func(nodes, mapping=mapping)

    def orcid_new(self):
        url_orcid_land = url_for('Ops.orcid_landing_new /u/ops/orcid-land-new')
        return self._orcid(url_orcid_land)

    def _orcid(self, url_orcid_land, refresh=False, for_login=False):
        _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'
        if fl.current_user is not None and hasattr(fl.current_user, 'orcid') and fl.current_user.orcid:
            if for_login:
                orcid_meta_safe = {
                    # FIXME TODO leaving out name for now since I don't have a query that populates that right now
                    'orcid': fl.current_user.orcid,
                }
                response = {
                    'code': 200,
                    'orcid_meta': orcid_meta_safe,
                    'groupname': fl.current_user.groupname,
                }
                freiri = None
                if 'freiri' in request.args:
                    freiri = check_reiri(request.args['freiri'])
                    response['code'] = 302
                    response['redirect'] = freiri

                if _dopop:
                    return return_page(data=response, status=response['code'])
                else:
                    if freiri is not None:
                        return redirect(freiri, 302)

                    return 'orcid-login already logged in, check your cookies (use requests.Session)'

            # TODO need to backstop some issue here but I don't remember what it was
            abort(409, f'orcid already associated {fl.current_user.orcid}')  # FIXME TODO check error code on this

        if _dopop:
            c = '&' if '?' in url_orcid_land else '?'  # XXX I'm sure this is a bad assumption ...
            url_orcid_land += (c + _param_popup + '=true')

        if 'from' in request.args:
            c = '&' if '?' in url_orcid_land else '?'  # XXX I'm sure this is a bad assumption ...
            url_orcid_land += (c + 'from=' + request.args['from'])

        if 'freiri' in request.args:
            freiri = check_reiri(request.args['freiri'])
            if freiri:
                c = '&' if '?' in url_orcid_land else '?'  # XXX I'm sure this is a bad assumption ...
                url_orcid_land += (c + 'freiri=' + freiri)

        if _orcid_mock:
            code = _orcid_mock  # heh
            c = '&' if '?' in url_orcid_land else '?'  # XXX I'm sure this is a bad assumption ...
            return redirect(url_orcid_land + f'{c}code={code}', code=302)

        prompt = '&prompt=login' if refresh else ''
        scope = 'openid'  # /read-limited
        redirect_uri = f'{request.scheme}://{request.host}{url_orcid_land}'  # FIXME request.host can be spoofed ya? TODO figure out if it can be abused in combination with next= ...
        reiri = (f'https://{config.orcid_host}/oauth/authorize?client_id={config.orcid_client_id}'
                 f'&response_type=code&scope={scope}{prompt}&redirect_uri={redirect_uri}')
        return redirect(reiri, code=302)

    def orcid_login(self):
        # so apparently we get an access code every time they log in or something?
        url_orcid_land = url_for('Ops.orcid_landing_login /u/ops/orcid-land-login')
        refresh = 'from' in request.args and request.args['from'] == 'refresh'
        if refresh:
            request.args.pop('from')
        return self._orcid(url_orcid_land, refresh, for_login=True)

    @staticmethod
    def _make_orcid_code():
        return base64.urlsafe_b64encode(secrets.token_bytes(4))[:-2].decode()

    @staticmethod
    def _make_orcid_meta(expires_in_seconds=None):
        import uuid
        from hashlib import sha256
        import jwt
        om = dict(
            orcid=idlib.systems.orcid.genorcid(),
            name='Test Person',
            token_type='bearer',
            scope='openid',
            access_token=uuid.uuid4(),
            refresh_token=uuid.uuid4(),
            expires_in=631138518,)

        def get_at_hash(access_token):
            # see comment https://github.com/ORCID/ORCID-Source/blob/0f95b8b5951bbfbb285684bae2eee46b1ca932ca/orcid-core/src/main/java/org/orcid/core/oauth/openid/OpenIDConnectTokenEnhancer.java#L137-L146
            at = str(access_token)
            m = sha256()
            m.update(at.encode())
            hrm = m.digest()
            at_hash = base64.urlsafe_b64encode(hrm[:16])[:-2]
            return at_hash.decode()

        nowish = int(time())
        if expires_in_seconds is None:
            expires_in_seconds = (24 * 60 * 60)

        exp = nowish + expires_in_seconds
        tdat = dict(
            at_hash=get_at_hash(om['access_token']),
            aud=config.orcid_client_id,
            sub=om['orcid'],
            auth_time=nowish,
            iss='interlex-test-code',
            exp=exp,
            given_name=om['name'].split()[0],
            iat=nowish,
            family_name=om['name'].split()[-1],
            jti=str(uuid.uuid4()),
        )
        id_token = jwt.encode(tdat, iauth._orcid_mock_private_key, algorithm='RS256')
        om['id_token'] = id_token
        return om

    def _orcid_landing(self):
        if 'code' not in request.args:
            abort(400, 'missing required parameter ?code=')

        code = request.args['code']
        orcid_meta = self._orcid_landing_exchange(code)
        return orcid_meta

    def _orcid_landing_exchange(self, code):
        # FIXME TODO we will want to flag endpoints that make external network
        # calls or possibly literally sandbox it in another process
        if _orcid_mock:
            if code in _orcid_mock_codes:
                return _orcid_mock_codes[code]
            else:
                abort(401, f'orcid did not recognize code {code}')

        _redirect_uri, _ = request.url.split('code=', 1)
        redirect_uri = _redirect_uri[:-1]
        data = {
            'client_id': config.orcid_client_id,
            'client_secret': config.orcid_client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,  # seems like they want to confirm the exact redirect uri ... which we just landed at?
        }
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/x-www-form-urlencoded',}
        resp = requests.post(
            f'https://{config.orcid_host}/oauth/token',
            headers=headers,
            data=data)

        if not resp.ok:
            try:
                if resp.status_code < 500:
                    try:
                        log.debug(resp.json())
                    except Exception:
                        pass

                resp.raise_for_status()
            except Exception as e:
                log.exception(e)

            abort(401, 'orcid login failed')

        orcid_meta = resp.json()
        return orcid_meta

    _insert_orcid_meta = staticmethod(_sigh_insert_orcid_meta)
    _orcid_login_user_temp = staticmethod(_sigh_orcid_login_user_temp)

    def orcid_landing_login(self):
        orcid_meta = self._orcid_landing()  # aborts unless we get a valid response from orcid
        orcid, group_resp = self._orcid_check_already(orcid_meta)
        _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'
        if not group_resp:
            # TODO options
            # create new account
            # link existing account
            self._orcid_login_user_temp(orcid_meta)
            # TODO get email for autofill if we can
            reiri = url_for('Privu.user_new /u/priv/user-new') + '?from=orcid-login'
            if 'freiri' in request.args:
                freiri = check_reiri(request.args['freiri'])
                if freiri:
                    reiri += '&freiri=' + freiri

            if _dopop:
                _omsafe = 'orcid', 'name'
                orcid_meta_safe = {}
                for _k in _omsafe:
                    orcid_meta_safe[_k] = orcid_meta[_k]

                response = {
                    'code': 302,
                    'orcid_meta': orcid_meta_safe,
                    'redirect': reiri,
                }
                return return_page(data=response, status=302)
            else:
                return redirect(reiri, code=302)

        else:
            self._orcid_login(orcid, orcid_meta['id_token'], group_resp)
            if _dopop:
                _omsafe = 'orcid', 'name'
                orcid_meta_safe = {}
                for _k in _omsafe:
                    orcid_meta_safe[_k] = orcid_meta[_k]

                groupname = fl.current_user.groupname
                response = {
                    'code': 200,
                    'orcid_meta': orcid_meta_safe,
                    'groupname': groupname,
                }
                return return_page(data=response, status=200)
            else:
                return 'orcid-login successful, check your cookies (use requests.Session)'

    def _orcid_login(self, orcid, openid_token, group_resp):
            group_row = group_resp[0]

            _orcid = orcid
            class tuser:
                is_active = True  # TODO translate from the permission model
                is_anonymous = False
                is_authenticated = True
                via_auth = 'orcid'
                orcid = _orcid
                id = openid_token
                own_role = group_row.own_role
                groupname = group_row.groupname
                def get_id(self, __id=openid_token):
                    return __id

            fsession['_via_auth'] = tuser.via_auth
            fl.login_user(tuser())  # TODO I don't think there is an easy way to remember this stuff

    def _orcid_check_already(self, orcid_meta):
        kls = idlib.systems.orcid.OrcidSandbox if config.orcid_sandbox else idlib.Orcid
        orcid = kls._id_class(prefix='orcid', suffix=orcid_meta['orcid']).iri
        dbstuff = Stuff(self.session)
        return orcid, dbstuff.getUserByOrcid(orcid)

    def orcid_landing_new(self):
        # read from auth at start and isolate somewhere outside this class
        orcid_meta = self._orcid_landing()
        orcid, group_resp = self._orcid_check_already(orcid_meta)  # FIXME ideally we wouldn't have to do this ... and just handle the error but ...

        if group_resp:
            self._orcid_login(orcid, orcid_meta['id_token'], group_resp)
            group_row = group_resp[0]
            groupname = group_row.groupname
            if _param_popup in request.args and request.args[_param_popup].lower() == 'true':
                _omsafe = 'orcid', 'name'
                orcid_meta_safe = {}
                for _k in _omsafe:
                    orcid_meta_safe[_k] = orcid_meta[_k]

                _redir = f'/{groupname}/priv/settings'
                response = {
                    'code': 302,
                    'orcid_meta': orcid_meta_safe,
                    'redirect': _redir,
                    'settings_url': _redir,
                    'groupname': groupname,
                }

                return return_page(data=response, status=302)
            else:
                return redirect(f'/{groupname}/priv/settings?from=orcid-landing-new', code=302)
                #return 'you already have an InterLex account and have been logged in'

        self._insert_orcid_meta(self.session, orcid_meta)
        self._orcid_login_user_temp(orcid_meta)

        #reiri = url_for('Ops.user_new /u/ops/user-new')
        reiri = url_for('Privu.user_new /u/priv/user-new') + '?from=orcid-new'
        if 'freiri' in request.args:
            freiri = check_reiri(request.args['freiri'])
            if freiri:
                reiri += ('&freiri=' + freiri)

        return redirect(reiri, code=302)  # 302 more compat when responding to a get

    def user_new(self):
        ''' updated flow theory

        user can create a new account or sign up using orcid

        sign up using orcid, when complete, redirects to a page where they put in their username and email
        internally this means that we need to maintain an orcid only inflow?

        major advantage of this flow is that we don't have to validate orcids, we will only ever store
        what we get back from orcid itself

        use orcid -> orcid -> username, email, optional password
        new account -> username pass email -> orcid

        the question is what we do as a placeholder until we get the username in the orcid flow

        '''
        # TODO python social-auth-app-flask seems to have reasonable examples of how to integrate with social-core
        # so that we don't have to fight with all the crazyness XXX no ... I've actually done this twice already


        # FIXME if a user does not exist they will have no group
        # so which user should it go to? probably base? idk?
        # maybe a dedicated ops user? /ops/ops ? /nobody/ops ?

        # TODO email
        # password
        # TODO only orcid

        already_registered = fl.current_user is not None and hasattr(fl.current_user, 'groupname') and fl.current_user.groupname is not None
        _orcid = fl.current_user is not None and hasattr(fl.current_user, 'orcid') and fl.current_user.orcid
        orcid = _orcid if _orcid else None  # adjust types, sql doesn't like nulls being passed as false ...

        _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'

        if request.method == 'GET':
            # fine we'll send you a form to fill out
            _areg = f' You are already logged in as {fl.current_user.groupname}. <br>' if already_registered else ''
            if orcid is None:
                orcid_not = ' not'
                not_orcid_not = 'this is you'
            else:
                orcid_not = ''
                not_orcid_not = 'not you'

            _suwo = '<a href="/u/ops/orcid-new">Sign up with ORCiD</a> <br>' if orcid is None else ''
            message = f'''
{_suwo}
Required: username <br>
Required: email <br>
Required: password OR already associated ORCiD account <br>
Required: eventually associated ORCiD account <br>
Required: eventually verified email <br>

If you chose to sign up with ORCiD (you have{orcid_not}) the password is optional but encouraged. <br>
If you did not sign up with ORCiD ({not_orcid_not}) then a password is required so that you can resume your registration in case something goes wrong. <br>
If you did not sign up with ORCiD ({not_orcid_not}) then you will be directed to ORCiD after completion of this form. <br>

We suggest that you use a developer email account that can be disclosed
publicly since the email will be associated with your contributions (similar to
git) and if you sign up for notifications about terms and ontologies you may
receive quite a few during periods of active development.
<br>
'''

            _orcid_reg = ' After clicking Register you will be taken to ORCiD to associate your account.' if orcid is None else ''
            password_required = '' if orcid else 'required '
            user_new_form = f'''
<form action="" method="post" class="user-new">

  <div class="user-new">
    <label for="username">Username: </label>
    <input type="text" name="username" id="username" size="40" required />{_areg}
  </div>

  <div class="user-new">
    <label for="password">Password: </label>
    <input type="password" name="password" id="password" size="40" {password_required}/>
  </div>

  <div class="user-new">
    <label for="email">Email: </label>
    <input type="email" name="email" id="email" size="40" required />
  </div>

  <!--
  <div class="user-new">
    <label for="orcid">ORCiD: </label>
    <input type="url" name="orcid" id="orcid" size="37" required />
  </div>
  -->

  <div class="user-new">
    <input type="submit" value="Register" />{_orcid_reg} <br>
  </div>

</form>
'''
            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex Registration</title></head>
<body>
{user_new_form}
{message}
</body>
</html>'''

        if request.method != 'POST':
            if _dopop:
                # FIXME watch out for the control flow difference between abort and return
                return return_page(status=404)
            else:
                abort(404)

        errors = {}
        if 'username' not in request.form or not request.form['username']:
            username = None
            errors['username'] = ['required']
        else:
            username = request.form['username']
            def check_username(u):
                # this covers some but not all of the database username
                # restrictions, so additional errors may appear later
                # after we talk to the db
                lu = len(u)
                if lu > 40:
                    errors['username'] = ['too long']
                elif lu < 5:
                    errors['username'] = ['too short']
                else:
                    return True

            username_ok = check_username(username)
            if username_ok:
                existing = self.queries.getGroupExisting(username)
                if existing:
                    errors['username'] = ['exists']

        if 'password' not in request.form or not request.form['password']:
            password = None
            if not orcid:
                # password is optional in the orcid case
                errors['password'] = ['required']
        else:
            password = request.form['password']
            def password_check(p, lr=10):
                # this is a bad check but is absolute min that is sane now
                lp = len(p) >= lr
                d, u, l = False, False, False
                for char in p:
                    if char.isdigit():
                        d = True
                    elif char.isupper():
                        u = True
                    elif char.islower():
                        l = True

                errs = []
                for crit, err in ((lp, f'shorter than {lr}'),
                                  # aside from a min length requirement we
                                  # don't put restrictions, better ux on the
                                  # frontend showing estimated password
                                  # strength probably

                                  #(d, 'no digit'),
                                  #(u, 'no upper'),
                                  #(l, 'no lower'),
                                  ):
                    if not crit:
                        errs.append(err)
                if errs:
                    return errs

            pass_fail = password_check(password)
            if pass_fail:
                errors['password'] = pass_fail

        if 'email' not in request.form or not request.form['email']:
            email = None
            errors['email'] = ['required']
        else:
            email = request.form['email']
            def email_check(e):
                # we do not validate email structure beyond making sure
                # there is an @ in the middle somewhere all we care is that
                # the user can receive mail and click the validation link
                return (e.count('@') == 1 and
                        not e.startswith('@') and
                        not e.endswith('@') and
                        len(e.split()) == 1  # FIXME hack to detect whitespace
                        )

            email_ok = email_check(email)
            if not email_ok:
                errors['email'] = ['malformed']

        '''
        if 'orcid' not in request.form:
            # FIXME this is not the right way to do this, the right way to do
            # this according to orcid is to have user log in with orcid so they
            # never copy and paste the orcid
            orcid = None
            #errors['orcid'] = ['required']
        else:
            orcid = request.form['orcid']
            def orcid_check(o):
                # TODO better feedback on malformed
                try:
                    oid = idlib.Orcid(orcid)
                except idlib.exceptions.IdlibError as e:
                    errors['orcid'] = ['malformed']
                    return

                try:
                    if not oid.identifier.checksumValid:
                        errors['orcid'] = ['invalid checksum']
                        return
                except oid.identifier.OrcidChecksumError:
                    errors['orcid'] = ['checksum failure']
                    return

                return oid

            orcid_ok = orcid_check(orcid)
        '''

        if errors:
            if _dopop:
                return return_page(data={'errors': errors}, status=422)
            else:
                return json.dumps({'errors': errors}), 422, ctaj

        argon2_string = None if password is None else iauth.hash_password(password)
        email_verify = config.email_verify  # FIXME find the right place to query for this
        dbstuff = Stuff(self.session)
        try:
            user_id = dbstuff.user_new(username, email, argon2_string, orcid, email_verify=email_verify)
            self.session.commit()
        except Exception as e:
            # username format
            # orcid non-unique # we don't allow robot bot users right now
            # email non-unqiue
            self.session.rollback()
            if not e.orig.diag.constraint_name:
                log.exception(e)
                errors['unhandled'] = ['unhandled']
            elif e.orig.diag.constraint_name.startswith('groups_groupname_check'):
                args = (
                    e.orig.diag.schema_name,
                    e.orig.diag.table_name,
                    e.orig.diag.constraint_name,)
                asdf = dbstuff.getConstraint(*args)
                if not asdf:
                    log.critical(f'no constraint for: {args} ???')
                    errors['username'] = ['not sure']
                else:
                    constraint = asdf[0][1]
                    errors['username'] = [constraint]

            elif e.orig.diag.constraint_name == 'users_orcid_key':
                # XXX this can be used to check whether orcids are registered
                errors['orcid'] = ['exists']

            elif e.orig.diag.constraint_name in ('user_emails_email_key', 'email_lower_index'):
                # XXX this can be used to check whether emails are registered
                errors['email'] = ['exists']

            else:
                # _diag = {k:getattr(e.orig.diag, k) for k in dir(e.orig.diag) if not k.startswith('_')}
                log.exception(e)
                errors['unhandled'] = ['unhandled']

            if not errors:
                raise ValueError('we broke something')

            if _dopop:
                return return_page(data={'errors': errors}, status=422)
            else:
                return json.dumps({'errors': errors}), 422, ctaj

        if email_verify:
            try:
                self._start_email_verify(username, email)
            except Exception as e:
                # it is very bad for the user if we error out here because they
                # don't get their updated login token but their account exists on
                # the system, so they can't even logout
                log.exception(e)

        _orcid = orcid
        _id = fl.current_user.id if password is None else user_id[0].surrogate
        class tuser:
            is_active = True  # TODO translate from the permission model
            is_anonymous = False
            is_authenticated = True
            via_auth = 'orcid' if password is None else 'interlex'
            orcid = _orcid
            id = _id
            own_role = 'pending'
            groupname = username
            def get_id(self, __id=_id):
                return __id

        # FIXME do we need to call logout on the orcid only user?
        if '_orcid_only' in fsession:
            fsession.pop('_orcid_only')

        fsession['_via_auth'] = tuser.via_auth
        fl.login_user(tuser())

        if orcid is None:
            url_next = url_for('Priv.orcid_associate /<group>/priv/orcid-assoc', group=username) + '?from=user-new'
            if 'freiri' in request.args:
                freiri = check_reiri(request.args['freiri'])
                if freiri:
                    # FIXME likely want a way to show account creation successful or something after redirect
                    url_next += '&freiri=' + freiri

            if _dopop:
                return return_page(data={'redirect': url_next}, status=303)
            else:
                return redirect(url_next, 303)
        else:
            if 'application/json' in dict(request.accept_mimetypes):  # FIXME not the best way i think
                msg = 'Account creation and association with orcid successful.'
                out = {'message': msg}
                if email_verify:
                    msg += f' Confirmation email sent to {email}'
                    out['email'] = email

                if _dopop:
                    return return_page(data=out, status=201)
                else:
                    return json.dumps(out), 201, ctaj
            else:
                if 'freiri' in request.args:
                    freiri = check_reiri(request.args['freiri'])
                    if freiri:
                        # FIXME likely want a way to show account creation successful or something after redirect
                        if _dopop:
                            return return_page(data={'redirect': freiri}, status=303)
                        else:
                            return redirect(freiri, 303)

                elif 'from' in request.args:
                    frm = request.args['from']
                    if frm == 'orcid-new':
                        # e.g. someone went to orcid-new directly without coming from anywhere else
                        if _dopop:
                            return return_page(data={'redirect': f'/{username}/priv/settings?from=orcid-new-success'}, status=303)
                        else:
                            return redirect(f'/{username}/priv/settings?from=orcid-new-success', 303)

                msg = 'Account creation and association with orcid successful.'
                if email_verify:
                    msg += f' As a final step a verification email has been sent to {email}'

                if _dopop:
                    return return_page(data=msg, status=201)
                else:
                    return msg, 201

    def _start_email_verify(self, username, email):
        # this is usually a priv operation, but we call it
        # immediately after signup

        # XXX we could try to get the user's full name from their orcid record, but
        # we don't want to make any external calls in this workflow, the full name
        # will be filled in as part of the orcid workflow, not the email workflow

        # these tokens have a short lifetime so don't need to be quite as long so
        # using 24, also considered 33, it is important to avoid email linewrap
        # which because linewrap uses = which is the same as base64 padding
        dbstuff = Stuff(self.session)

        token = base64.urlsafe_b64encode(secrets.token_bytes(24))
        token_str = token.decode()
        if _email_mock:
            # well if you put lifetime seconds to 0 the logic is correct, but can never be verified (heh)
            resp = dbstuff.email_verify_start(username, email, token_str, 0, 10)
        else:
            resp = dbstuff.email_verify_start(username, email, token_str)

        self.session.commit()
        row = resp[0]

        minutes = row.lifetime_seconds // 60
        nowish = row.created_datetime
        startish = nowish + timedelta(seconds=row.delay_seconds)
        thenish = nowish + timedelta(seconds=row.lifetime_seconds)
        #scheme = 'https'  # FIXME ...
        #reference_host = self.reference_host  # FIXME vs actual host for testing
        #verification_link = f'{scheme}://{reference_host}/u/ops/email-verify?{token}'
        #verification_link = f'{scheme}://{reference_host}/u/ops/ever?t={token_str}'
        verification_link = f'{request.scheme}://{request.host}/u/ops/ever?t={token_str}'
        # FIXME TODO is it safe to use request.host for this? is it safe?
        reverify_link = f'{request.scheme}://{request.host}/{username}/priv/email-verify?email={url_quote(email)}'
        msg = msg_email_verify(
            email, nowish, startish, row.delay_seconds, minutes, thenish,
            verification_link, reverify_link)

        if _email_mock:
            _email_mock_tokens[email] = token_str
        else:
            # FIXME TODO figure out how to sub this out for testing too
            send_message(msg, get_smtp_spec())

    def user_recover(self):
        already_logged_in = fl.current_user is not None and hasattr(fl.current_user, 'groupname') and fl.current_user.groupname is not None
        if request.method == 'GET':
            _alog = f' You are already logged in as {fl.current_user.groupname}. <br>' if already_logged_in else ''
            _recovery_form = f'''
<form action="" method="post" class="recovery">

  <div class="recovery">
    <label for="username">Username: </label>
    <input type="text" name="username" id="username" required />{_alog}
  </div>

  <div class="recovery">
    <input type="submit" value="Recover Account" />
  </div>

</form>
'''
            body = f'''
InterLex Account Recovery <br>
{_recovery_form}
<br>
'''
            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex Account Recovery</title></head>
<body>
{body}
</body>
</html>'''

        elif request.method == 'POST':
            nowish = time()
            fixed = 1  # FIXME this has to deal with 99th percentile latency probably? so better to inject noise?
            then = nowish + fixed
            if already_logged_in:
                abort(409, f'Already logged in as {fl.current_user.groupname}')

            if not request.form or not request.form['username'].strip():
                abort(422, 'no username provided')

            username = request.form['username'].strip()
            # TODO check that notification service is responsive and do it up
            # here for timing consistency
            noti_responsive = True  # TODO
            if not noti_responsive:
                log.critical('notification system is not responsive')
                abort(503)

            dbstuff = Stuff(self.session)
            resp = dbstuff.getUserVerifiedEmails(username)
            generic_msg = (
                'If this account exists a recovery email has been sent '
                'to the primary email address associated with the account.')

            if not resp:
                sleep(then - time())
                return generic_msg, 200

            self._start_user_recover(username, resp)
            sleep(then - time())
            return generic_msg, 200
        else:
            abort(405)

    def _start_user_recover(self, username, emails):
        #breakpoint()
        # based heavily on _start_email_verify
        primaries = [r for r in emails if r.email_primary]
        if not primaries:
            # this should never happen
            log.critical(f'no primary verified email, something has gone very wrong {emails}')
            abort(500)

        primary_row = primaries[0]
        email = primary_row.email
        alts = [r.email for r in emails if not r.email_primary]

        # going with 33 instead of 24 for this one since it is for password reset
        token = base64.urlsafe_b64encode(secrets.token_bytes(33))
        token_str = token.decode()
        dbstuff = Stuff(self.session)
        if _reset_mock:
            resp = dbstuff.user_recover_start(username, token_str, 0, 10)
        else:
            resp = dbstuff.user_recover_start(username, token_str)

        self.session.commit()
        row = resp[0]

        minutes = row.lifetime_seconds // 60
        nowish = row.created_datetime
        startish = nowish + timedelta(seconds=row.delay_seconds)
        thenish = nowish + timedelta(seconds=row.lifetime_seconds)

        # FIXME TODO is it safe to use request.host for this? is it safe?
        reset_link = f'{request.scheme}://{request.host}/u/ops/pwrs?t={token_str}'
        msg = msg_user_recover(
            email, nowish, startish, row.delay_seconds, minutes, thenish, reset_link)
        alt_msgs = [msg_user_recover_alt(alt) for alt in alts]

        # TODO this is quite similar to the ever workflow
        # store token in database

        if _reset_mock:
            _reset_mock_tokens[username] = token_str
        else:
            # NONBLOCKING send reset email link to email primary
            # FIXME TODO figure out how to sub this out for testing too
            send_message(msg, get_smtp_spec())
            for alt_msg in alt_msgs:
                # NONBLOCKING send notification email to any other emails
                # TODO but only once per 24hr period or something?
                send_message(alt_msg, get_smtp_spec())

    def password_reset(self):
        # this is the back half of the user recover process
        # TODO
        # on success send an email confirming the change
        # do not automatically log the user in
        abort(501, 'TODO')

    def email_verify(self):
        """ callback point for email with token not to be confused with priv/email-verify """
        if 't' not in request.args or not request.args['t']:
            abort(400, 'missing verification token t=')

        def do_log(group, status, err_reason=None):
            _p_g = 'null' if group is None else group
            _m_prefix = f':email verification-request :status {status} :token-group {_p_g} '
            if fl.current_user is not None and fl.current_user.is_authenticated:
                if not hasattr(fl.current_user, 'groupname'):
                    # how did we manage this !?
                    msg = f':session-group null :session-id {fl.current_user.get_id()}'
                    if hasattr(fl.current_user, 'orcid'):
                        msg += f' :session-orcid {fl.current_user.orcid}'

                        log_ver.error(_m_prefix + msg)
                elif group is None:
                    msg = f':session-group {fl.current_user.groupname}'
                    if err_reason is not None:
                        msg += f' :reason "{err_reason}"'

                    log_ver.warning(_m_prefix + msg)
                elif fl.current_user.groupname != group:
                    msg = f':session-group {fl.current_user.groupname} :reason group-mismatch'
                    log_ver.critical(_m_prefix + msg)
                else:  # fl.current_user.groupname == group:
                    msg = f':session-group {fl.current_user.groupname}'
                    if err_reason is not None:
                        msg += f' :reason "{err_reason}"'

                    log_ver.info(_m_prefix + msg)
            else:
                msg = ':session null'
                log_ver.warning(_m_prefix + msg)

        token_str = request.args['t']
        dbstuff = Stuff(self.session)
        try:
            resp = dbstuff.email_verify_complete(token_str)
        except sa.exc.InternalError as e:
            if (e.orig.diag.source_function == 'exec_stmt_raise'
                and e.orig.diag.context is not None
                and e.orig.diag.context.startswith('PL/pgSQL function email_verify_complete(text)')):
                msg = e.orig.diag.message_primary
                group = e.orig.diag.message_detail if e.orig.diag.message_detail else None
                self.session.rollback()
                do_log(group, 'fail', msg)
                abort(404, msg)

            log_ver.exception(e)
            abort(404)

        if resp:
            self.session.commit()
            group = resp[0][0]
            do_log(group, 'success')
            _msg = f'email verification complete for {group}'
            try:
                already_logged_in = fl.current_user is not None and hasattr(fl.current_user, 'groupname') and fl.current_user.groupname is not None
                if already_logged_in:
                    # only redirect if already logged in, otherwise a 401 error will crop up
                    return redirect(f'/{group}/priv/settings?from=email-verify-success', 302)
                else:
                    # TODO consider redirecting to login with freiri set to /{group}/settings?from=email-verify-succes ?
                    return _msg

            except Exception as e:
                log.exception(e)
                return _msg

        else:
            # failure should look like an error not a null value on return so
            # we really should never get here
            breakpoint()
            abort(404)

    def login(self):
        # SIGH turns out that the UX for basic login is absolutely utterly horrible
        # so we provide the form as well
        already_logged_in = fl.current_user is not None and hasattr(fl.current_user, 'groupname') and fl.current_user.groupname is not None
        _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'
        aspopup_option = '?aspopup=true' if _dopop else ''
        _alog = f' You are already logged in as {fl.current_user.groupname}. <br>' if already_logged_in else ''
        # groupname is safe to pass to format here because it is coming from the db not the user
        _login_form = f'''
<form action="/u/ops/user-login{aspopup_option}" method="post" class="login">

  <div class="login">
    <label for="username">Username: </label>
    <input type="text" name="username" id="username" required />{_alog}
  </div>

  <div class="login">
    <label for="password">Password: </label>
    <input type="password" name="password" id="password" required />
  </div>

  <div class="login">
    <input type="submit" value="Login" />
  </div>

</form>
'''

        body = f'''
InterLex Login <br>
{_login_form}
<br>
<a href="/u/ops/orcid-login">Login with ORCiD</a> <br>
<a href="/u/ops/user-new">Signup</a> <br>
<a href="/u/ops/orcid-new">Signup with ORCiD</a> <br>
'''

        return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex Login</title></head>
<body>
{body}
</body>
</html>'''

    def user_login(self):
        # FIXME this needs to be able to detect whether a user is already
        # logged in as the same or another user

        # XXX NOTE this is pretty much only for development
        # because in production login is going to go directly
        # to orcid and /<group>/ops/login should pretty much never be used

        if False and request.method in ('GET', 'HEAD'):
            # only accept post with password on this endpoint
            # to prevent user name discovery, though obviously
            # there are other legitimate way to discover this
            # information in bulk
            return abort(405)

        if request.method == 'GET' and 'Authorization' not in request.headers:
            # allow basic login for now noting that the ux is really bad even for dev
            _ex_header = '{"Authorization": "Basic " + base64(username + ":" + password)}'
            _alt = f'''
To log in to InterLex use the basic auth dialog provided by your browser. <br>
If you are seeing this message you can refresh the page to get it back. <br>
Alternately send an HTTP GET request with headers containing <br>
<pre>
{_ex_header}
</pre>
            '''
            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex User Login</title></head>
<body>
{_alt}
</body>
</html>''', 401, {'WWW-Authenticate': 'Basic realm="InterLex"'}

        elif request.method == 'POST' or request.method == 'GET' and 'Authorization' in request.headers:
            # if the the group is not a user then 404 since can only log in to orcid mapped users
            # FIXME must check roles
            # FIXME forcing group == ops causes issues here
            basic_group_password = request.headers.get('Authorization', '')
            if 'username' in request.form and 'password' in request.form:
                pass_group = request.form['username']
                password = request.form['password']
                if not pass_group or not password:
                    if not pass_group and not password:
                        msg = 'missing username and password'
                    elif not pass_group:
                        msg = 'missing username'
                    elif not password:
                        msg = 'missing password'

                    abort(400, msg)

            elif basic_group_password:
                abasic, *_group_password = basic_group_password.split(None, 1)
                if abasic.lower() != 'basic' or not _group_password:  # FIXME do we force case sense or not here ...
                    abort(400)
                else:
                    b64_group_password = _group_password[0]

                group_password = base64.b64decode(b64_group_password).decode()
                pass_group, password = group_password.split(':', 1)
            else:
                abort(422, 'POST a username and password or set Authorization header')

            # FIXME TODO must also check users here to ensure actually allowed to log in
            dbstuff = Stuff(self.session)
            rows = dbstuff.getUserPassword(pass_group)
            if not rows:
                # not a user
                abort(401)

            group_row = rows[0]
            argon2_string = group_row.argon2_string
            password_matches = iauth.validate_password(argon2_string, password)

            if password_matches:
                # return the relevant session information so that the browser can store it and retain the session
                # or however that works?
                # TODO flask login or something
                # XXX if they came here directly just go ahead and give them the api token probably?? not quite sure
                # I'm sure this will change with the orcid stuff
                class tuser:
                    is_active = True  # TODO translate from the permission model
                    is_anonymous = False
                    is_authenticated = True  # FIXME but is it true?
                    via_auth = 'interlex'
                    orcid = group_row.orcid
                    id = group_row.surrogate
                    own_role = group_row.own_role  # FIXME could change ?
                    groupname = group_row.groupname
                    def get_id(self, __id=group_row.surrogate):
                        return __id

                remember = 'remember' in request.args and request.args['remember'].lower() == 'true'
                fsession['_via_auth'] = tuser.via_auth
                fl.login_user(tuser(), remember=remember)
                _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'
                if _dopop:
                    response = {
                        'code': 200,
                        'groupname': fl.current_user.groupname,
                    }
                    if fl.current_user.orcid:
                        orcid_meta_safe = {
                            # FIXME TODO leaving out name for now since I don't have a query that populates that right now
                            'orcid': fl.current_user.orcid,
                        }
                        response['orcid_meta'] = orcid_meta_safe

                if 'freiri' in request.args:
                    freiri = check_reiri(request.args['freiri'])
                    if freiri:
                        if _dopop:
                            response['code'] = 302
                            response['redirect'] = freiri
                            return return_page(data=response, status=302)
                        else:
                            return redirect(freiri, 302)  # 302 seems preferred over 303 for compat reasons?

                if _dopop:
                    return return_page(data=response, status=200)
                else:
                    return 'login successful, check your cookies (use requests.Session)'

            else:
                return abort(401)  # FIXME hrm what would the return code be here ...

        else:
            return abort(405)


class Privu(EndBase):

    def get_func(self, nodes):
        mapping = {
            'user-new': self.user_new,  # for orcid

            'orcid-land-change': self.orcid_landing_change,
            'orcid-land-assoc': self.orcid_landing_assoc,
        }
        return super().get_func(nodes, mapping=mapping)

    _start_email_verify = Ops._start_email_verify
    _user_new = Ops.user_new

    @basic0
    def user_new(self):
        # for the start from orcid workflow
        if 'from' in request.args:
            frm = request.args['from']
        else:
            # FIXME do we error in this case?
            frm = None

        return self._user_new()

    _insert_orcid_meta = staticmethod(_sigh_insert_orcid_meta)
    _orcid_login_user_temp = staticmethod(_sigh_orcid_login_user_temp)

    _orcid_landing = Ops._orcid_landing
    _orcid_landing_exchange = Ops._orcid_landing_exchange

    @basic0
    @fl.fresh_login_required  # there should always already be an existing session here, but just in case
    def orcid_landing_change(self, db=None):
        orcid_meta = self._orcid_landing()
        breakpoint()
        pass

    @basic0
    @fl.fresh_login_required  # there should always already be an existing session here, but just in case
    def orcid_landing_assoc(self, db=None):
        orcid_meta = self._orcid_landing()
        user = fl.current_user.groupname
        self._insert_orcid_meta(self.session, orcid_meta, user=user)
        _dopop = _param_popup in request.args and request.args[_param_popup].lower() == 'true'
        orcid_meta_safe = {}
        if _dopop:
            _omsafe = 'orcid', 'name'
            for _k in _omsafe:
                orcid_meta_safe[_k] = orcid_meta[_k]

        if 'freiri' in request.args:  # FIXME arg naming
            # FIXME TODO need a full return_user_to=url_encode_thing for all of
            # the login workflows maybe call it logged_in_from or something? if
            # it isn't set then don't return a final redirect
            freiri = check_reiri(request.args['freiri'])  # FIXME may need to un-urlencode it?
            if freiri:
                if _dopop:
                    response = {
                        'code': 302,
                        'orcid_meta': orcid_meta_safe,
                        'redirect': freiri,
                        'groupname': user,
                    }
                    return return_page(data=response, status=302)
                else:
                    return redirect(freiri, 302)  # 302 seems more standard than 303 for get

        elif 'from' in request.args:
            frm = request.args['from']
            if frm == 'user-new':
                # e.g. someone went to user-new directly without coming from anywhere else
                if _dopop:
                    _redir = f'/{user}/priv/settings?from=user-new-success'
                    response = {
                        'code': 302,
                        'orcid_meta': orcid_meta_safe,
                        'redirect': _redir,
                        'settings_url': _redir,
                        'groupname': user,
                    }
                    return return_page(data=response, status=302)

                else:
                    return redirect(f'/{user}/priv/settings?from=user-new-success', 302)

        orcid = f'https://{config.orcid_host}/' + orcid_meta['orcid']
        # FIXME vs 303 -> interlex.org ...
        if _dopop:
            response = {
                'code': 200,
                'orcid_meta': orcid_meta_safe,
                'groupname': user,
            }
            return return_page(data=response, status=200)
        else:
            return f'orcid {orcid} successfully associated with user account {user}', 200


class Priv(EndBase):

    _start_email_verify = Ops._start_email_verify

    def get_func(self, nodes):
        mapping = {
            'logout': self.logout,
            'upload': self.upload,
            'request-ingest': self.request_ingest,
            'pull-new': self.pull_new,  # FIXME TODO may need pull-ont-new pull-ent-new pull-ext-new pull-uri-new
            'entity-check': self.entity_check,
            'entity-new': self.entity_new,
            'entity-promote': self.entity_promote,
            'modify-a-b': self.modify_a_b,
            'modify-add-rem': self.modify_add_rem,

            'org-new': self.org_new,
            'committee-new': self.committee_new,

            'curation': self.curation,
            'settings': self.settings,

            # all below except noted require fresh login
            '<user>': self.user_role,
            'user_role_': self.user_role_,
            '<other_role_group>': self.role_other_group,
            'role_other_group_': self.role_other_group_,

            'password-change': self.password_change,  # tokens cannot be used for this one
            'user-deactivate': self.user_deactivate,

            'orcid-assoc': self.orcid_associate,
            'orcid-change': self.orcid_change,
            'orcid-dissoc': self.orcid_dissociate,

            'email-add': self.email_add,
            'email-del': self.email_del,
            '*email-verify': self.email_verify,  # fresh not required
            'email-primary': self.email_primary,

            'api-tokens': self.api_tokens,  # TODO elide fresh with refresh token ??? not quite sure here
            'api-token-new': self.api_token_new,
            'api-token-revoke': self.api_token_revoke,
            # revoke one is tricky, because an attacker try to exploit either scenario
            # but under the stolen cookie threat model rather than the got phished model
            # you don't want to give an attacker the ability to revoke tokens because that
            # can make it easier for them to complete an account takeover or generally mess
            # something up

        }
        return super().get_func(nodes, mapping=mapping)

    @basic
    def user_role_(self, group, db=None):
        dbstuff = Stuff(self.session)
        resp = dbstuff.groupRoles(group)
        if not resp:
            return json.dumps([]), 200, ctaj
        else:
            # TODO probably condense
            return json.dumps([[row.user_role, row.groupname] for row in resp]), 200, ctaj

    @basic
    @fl.fresh_login_required
    def user_role(self, group, user, db=None):
        if request.method == 'GET':
            pass
        elif request.method == 'PUT':
            pass
        elif request.method == 'DELETE':
            pass
        else:
            abort(405)

        breakpoint()
        # FIXME /<group>/priv/role/<user>
        # GET to show effective
        # PUT to create or change
        # DELETE to remove record
        # OPTIONS to list possible roles
        abort(501, 'TODO')

    @basic
    def role_other_group_(self, group, db=None):
        dbstuff = Stuff(self.session)
        resp = dbstuff.groupHasRoles(group)
        if not resp:
            return json.dumps([]), 200, ctaj
        else:
            # TODO probably condense
            return json.dumps([[row.user_role, row.groupname] for row in resp]), 200, ctaj

    @basic
    @fl.fresh_login_required
    def role_other_group(self, group, other_role_group, db=None):
        if request.method == 'GET':
            pass
        elif request.method == 'DELETE':
            pass
        else:
            abort(405)

        breakpoint()
        abort(501, 'TODO')

    @basic
    def request_ingest(self, group, db=None):
        if 'iri' not in request.json:
            return 'iri is a required field', 400

        _iri = request.json['iri']
        iri = URIRef(_name)

        if iri.startswith('file://'):
            return 'file:// scheme not allowed', 400

        # TODO record alternate name sources for files with same identity maybe?
        if self.reference_host in name:
            # FIXME TODO make sure that we don't ingest iris that
            # resolve back to the referene host via redirects
            return "cannot request ingest directly from interlex", 400

        # XXX do not attempt any dereferencing in this process can
        # call the db to check, everything else should be done via a
        # separate process
        nfl = self.queries.getNamesFirstLatest(iri)
        if iri in nfl:
            nfs = nfl[iri]['n_first_seen']
            nls = nfl[iri]['i_first_seen']
            li = nfl[iri]['identity'].hex()
            tys = nfl[iri]['type']

            msg = f'iri {tys} already tracked, first seen {nfs}, latest identity {li} first seen {nls}'
            resp = {'message': msg}
            return json.dumps(resp), 200, {'Content-Type': 'application/json'}
        else:
            task = tasks.load_iri_via_ingest.apply_async(
                (group, dbuser, reference_name, self.reference_host, name, expected_bound_name),
                serializer='pickle')
            # TODO inside of ingest we will need to handle the potential failure cases e.g. too big etc.
            job_url = request.scheme + '://' + self.reference_host + url_for("route_api_job", jobid=task.id)
            # FIXME TODO json response
            return (f'{iri} submitted for processing {job_url}', 202)

    @basic
    def upload(self, group, db=None):
        """ Expects files """
        # only POST
        # TODO auth

        dbuser = fl.current_user.groupname if hasattr(fl.current_user, 'groupname') else None
        #dbuser = db.user

        # TODO load stats etc
        raise NotImplementedError('todo use new way')
        try:
            loader = self.FileFromPost(group, dbuser, self.reference_host)
        except exc.NotGroup:
            return abort(404)

        header = request.headers
        create = request.form.get('create', False)
        if isinstance(create, str):
            create = create.lower()
            if create == 'true':
                create = True
            else:
                create = False

        names = []
        form_key = 'ontology-file'
        try:
            file = request.files[form_key]
        except KeyError:
            return f"expected form field named {form_key!r}", 400

        name = file.filename
        # as it turns out, we can actually trust Content-Length
        # because the server only reads that many bytes

        will_batch = loader.check(header)
        serialization = file.read()
        file.stream = None  # make it pickleable, just don't try to read anymore  # FIXME didn't work?!
        if will_batch:
            # FIXME sending the serialization very slow?
            # FIXME file.read() bad?! there has got to be a better way ...
            task = tasks.long_ffp.apply_async((group, dbuser, self.reference_host,
                                                header, file, serialization, create),
                                                serializer='pickle')
            job_url = (request.scheme +
                        '://' + self.reference_host +
                        url_for("route_api_job", jobid=task.id))
            return ('that\'s quite a large file you\'ve go there!\n'
                    f'it has been submitted for processing {job_url}', 202)
        else:
            setup_failed = loader(file, serialization, create)
            if setup_failed:
                return setup_failed
            names = {'reference_name':loader.reference_name,
                     'bound_name':loader.Loader.bound_name}
            load_failed = loader.load()
            if load_failed:
                print(load_failed)
                msg, code = load_failed
                data = {'error':msg, 'names':names}
                sigh = json.dumps(data)
                return sigh, code, {'Content-Type':'application/json'}
            else:
                return json.dumps(names), 200, {'Content-Type':'application/json'}

    @basic
    def curation(self, group, db=None):
        # curation dashboard view, overlaps a bit with pulls
        return 'TODO', 501

    @basic
    def settings(self, group, db=None):
        # TODO can handle logged in user x group membership and role in a similar way
        dbstuff = Stuff(self.session)
        recs = dbstuff.getUserSettings(group)
        user = [r for r in recs if r.rec_type == 'u'][0]
        emails = [r for r in recs if r.rec_type == 'e']
        keys = [r for r in recs if r.rec_type == 'k']
        ep = [e for e in emails if e.email_primary][0]
        def ev(dt):
            return 'null' if dt is None else f'"{isoformat(dt)}"'

        best = request.accept_mimetypes.best
        mimetype = (best if best and best != '*/*' and
                    'application/signed-exchange' not in best
                    else 'application/json')

        if mimetype == 'text/turtle':

            if 'from' in request.args:
                frm = request.args['from']
                if frm == 'orcid-landing-new':
                    prefix = f'# you already have an InterLex account associated with {fl.current_user.orcid}\n'
                elif frm == 'email-verify-success':
                    _vrow = sorted(emails, key=(lambda e: (e.email_validated is None, e.email_validated)))[-1]
                    _email = _vrow.email
                    prefix = f'# email address {_email} successfully validated\n'
                else:
                    log.error(f'TODO {frm} not handled')
                    prefix = ''
            else:
                prefix = ''

            emails_str = '\n\n' + '\n'.join([
                (f'<mailto:{e.email}> a ilxtr:interlex-email-record ;\n'
                f'  email:primary {e.email_primary};\n'
                f'  email:verified {ev(e.email_validated)} .')
                    for e in emails])

            keys_str = ('\n\n' + '\n'.join([
                ('[] a ilxtr:api-key-record ;\n'
                f'  key:key "{k.key}" ;\n'
                f'  key:type "{k.key_type}" ;\n'
                f'  key:scope "{k.key_scope}" ;\n'
                f'  key:created "{isoformat(k.created_datetime)}" ') +
                (f';\n  key:note {json.dumps(k.note)} ' if k.note else '') +
                (f';\n  key:lifetime-seconds {k.lifetime_seconds} ' if k.lifetime_seconds else '') +
                (f';\n  key:revoked "{isoformat(k.revoked_datetime)}" ' if k.revoked_datetime else '') + '.'
                for k in sorted(keys, key=(lambda r: r.created_datetime), reverse=True)])) if keys else ''

            orcid_line = '' if user.orcid is None else f'  settings:orcid <{user.orcid}> ;\n'
            out = prefix + (
                f'ilx:{group}/priv/settings a ilxtr:interlex-settings ;\n'
                '  skos:comment "completely fake ttlish representation of settings" ;\n'
                f'  settings:groupname "{group}" ;\n'
                f'  settings:email [ <mailto:{ep.email}> {ev(ep.email_validated)} ] ;\n'  # implicitly primary email
                f'{orcid_line}'
                '  settings:notification-prefs "email" ;\n'
                f'  settings:own-role "{user.own_role}" .'
            ) + emails_str + keys_str + '\n'
            return out, 200, {'Content-Type': 'text/turtle'}

        else:
            def ej(e):
                out = {'email': e.email, 'primary': e.email_primary}
                if e.email_validated is not None:
                    out['verified'] = isoformat(e.email_validated)
                return out

            def kj(k):
                out = {
                    'key': k.key,
                    'type': k.key_type,
                    'scope': k.key_scope,
                    'created': isoformat(k.created_datetime),
                }
                if k.note:
                    out['note'] = k.note

                if k.lifetime_seconds:
                    out['lifetime-seconds'] = k.lifetime_seconds

                if k.revoked_datetime:
                    out['revoked'] = isoformat(k.revoked_datetime)

                return out

            out = {
                'code': 200,
                'status': 200,
                'settings': {
                    'groupname': group,
                    'notification-preferences': 'email',  # TODO
                    'own-role': user.own_role,
                    'emails': [ej(e) for e in emails],
                }}

            if 'from' in request.args:
                frm = request.args['from']
                out['from'] = frm

            if user.orcid is not None:
                out['settings']['orcid'] = user.orcid

            if keys:
                out['settings']['keys'] = [
                    kj(k) for k in sorted(keys, key=(lambda r: r.created_datetime), reverse=True)]

            return json.dumps(out), 200, ctaj

    @basic
    def logout(self, group, db=None):
        # FIXME GET vs POST vs DELETE
        if request.method == 'GET':
            # check if logged in?
            # then log out
            if fl.current_user:
                # FIXME what do we do if the user is using an api key without a
                # session or even with a session? how to expire web tokens etc.
                # all the other lovely stuff about connecting web tokens to
                # specific computers etc.
                fl.logout_user()
            else:
                # TODO
                breakpoint()
                pass

            return 'logged out'
        else:
            return abort(405)

    @basic
    @fl.fresh_login_required
    def password_change(self, group, db=None):
        return 'TODO', 501

    @basic
    @fl.fresh_login_required
    def user_deactivate(self, group, db=None):
        # contributions are public, much like stack overflow etc.

        # you cannot delete past content or comments because they are part of
        # the scholarly record, any edits will be tracked

        # you can deactivate your account
        return 'TODO', 501

    _orcid = Ops._orcid
    @basic
    @fl.fresh_login_required  # FIXME should not be possible to remember login before orcid assoc or no?
    def orcid_associate(self, group, db=None):
        url_orcid_land = url_for('Privu.orcid_landing_assoc /u/priv/orcid-land-assoc')
        return self._orcid(url_orcid_land)

    @basic
    @fl.fresh_login_required
    def orcid_change(self, group, db=None):
        # can change as long as you can log into the other one and it isn't
        # already associated with another account, that is, you can't swap
        # orcids on two accounts you would need a third

        # or we do it as a dissoc and it deactivates the account ... may not want that though
        url_orcid_land = url_for('Privu.orcid_landing_change /u/priv/orcid-land-change')
        return self._orcid(url_orcid_land)

    @basic
    @fl.fresh_login_required
    def orcid_dissociate(self, group, db=None):
        # if this is implemented the user must have password set it can't just
        # be an orcid login
        return 'maybe do?', 501

    @basic
    @fl.fresh_login_required
    def email_add(self, group, db=None):
        if request.method == 'GET':
            email_add_form = '''
<form action="" method="post" class="email-add">

  <div class="email-add">
    <label for="email">Email: </label>
    <input type="email" name="email" id="email" size="40" required />
  </div>

  <div class="email-add">
    <input type="submit" value="Add Email" />
  </div>

</form>
'''
            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex Add Email</title></head>
<body>
{email_add_form}
</body>
</html>'''

        if request.method != 'POST':
            # should not get here because the router should have handled it already
            abort(405)

        # see user_new, TODO refactor so this is shared with user_new
        errors = {}
        if 'email' not in request.form or not request.form['email']:
            email = None
            errors['email'] = ['required']
        else:
            email = request.form['email']
            def email_check(e):
                return (e.count('@') == 1 and
                        not e.startswith('@') and
                        not e.endswith('@') and
                        len(e.split()) == 1  # FIXME hack to detect whitespace
                        )

            email_ok = email_check(email)
            if not email_ok:
                errors['email'] = ['malformed']

        if errors:
            return json.dumps({'errors': errors}), 422, {'Content-Type': 'application/json'}

        email_verify = config.email_verify  # FIXME find the right place to query for this
        dbstuff = Stuff(self.session)
        try:
            resp = dbstuff.email_add(group, email, email_verify=email_verify)
            self.session.commit()
        except Exception as e:
            self.session.rollback()

            if (e.orig.diag.source_function == 'exec_stmt_raise' and
                e.orig.diag.context.startswith('PL/pgSQL function user_email_row_invars()')):
                if e.orig.diag.message_primary.startswith('User has max'):
                    code = 409
                else:
                    code = 422

                abort(code, e.orig.diag.message_primary)

            if not e.orig.diag.constraint_name:
                log.exception(e)
                errors['unhandled'] = ['unhandled']
            elif e.orig.diag.constraint_name in ('user_emails_email_key', 'pk__user_emails'):
                errors['email'] = ['exists']
            else:
                log.exception(e)
                errors['unhandled'] = ['unhandled']

            if not errors:
                raise ValueError('we broke something')

            return json.dumps({'errors': errors}), 422, ctaj

        if email_verify:
            try:
                self._start_email_verify(group, email)
            except Exception as e:
                log.exception(e)

        return f'email {email} added', 200  # FIXME TODO unify with user_new code

    @basic
    @fl.fresh_login_required
    def email_del(self, group, db=None):
        # TODO must have at least one primary verified email
        return 'TODO', 501

    @basic
    def email_verify(self, group, db=None):
        # request to reverify email address if something went wrong, or token expired

        # it is safe to do this as a get request because the user must be logged in
        # and it is ok to pass the email as an arg because it must match one in the db
        if 'email' not in request.args or not request.args['email']:
            abort(400, 'missing ?email=')

        email = request.args['email']

        dbstuff = Stuff(self.session)
        emet = dbstuff.getUserEmailMeta(group, email)
        if not emet:
            _, url_param_string = request.url.rsplit('?', 1)
            if ' ' in email and '+' in url_param_string:
                return 'email contained a + sign that needs to be encoded as %2B because + means space in a url query string', 422

            return f'unknown email {email}'

        row = emet[0]

        if row.email_validated:
            return f'{email} already verified'
        else:
            if config.email_verify:  # FIXME find the right place to query for this
                self._start_email_verify(group, email)
                return f'a new verification email has been sent to {email}'
            else:
                return 'this instance of interlex does not require email verification'

    @basic
    @fl.fresh_login_required
    def email_primary(self, group, db=None):
        # set email address as primary
        return 'TODO', 501

    @basic
    @fl.fresh_login_required
    def api_tokens(self, group, db=None):
        dbstuff = Stuff(self.session)
        keys = dbstuff.getGroupApiKeys(group)
        out = [{'key': r.key} for r in keys]
        return json.dumps(out), 200, ctaj

    @basic
    @fl.fresh_login_required
    def api_token_new(self, group, db=None):
        # FIXME may need to cache these
        enum_types = [a for a, *_ in self.session.execute(sql_text('select unnest(enum_range(NULL::key_types))'))]
        enum_types.remove('refresh')
        enum_scopes = [a for a, *_ in self.session.execute(sql_text('select unnest(enum_range(NULL::key_scopes))'))]
        enum_scopes.remove('admin')  # iykyk let the db sort them out
        if request.method == 'GET':
            # have a form
            if 'application/json' in dict(request.accept_mimetypes):  # FIXME not the best way i think
                data = {
                    '$schema': 'https://json-schema.org/draft/2020-12/schema',
                    '$id': 'https://uri.interlex.org/schema/1/<group>/priv/api-token-new', # FIXME figure out what to do about this ...
                    'title': 'new api token request',
                    'type': 'object',
                    'required': ['token-type', 'scope'],
                    'properties': {
                        'token-type': {'type': 'string',
                                       'enum': enum_types,},
                        'scope': {'type': 'string',
                                  'enum': enum_scopes,},
                        'lifetime-seconds': {'type': 'integer',},
                        'note': {'type': 'string',}}}
                return data, 200, ctaj
            else:
                type_options = '\n      '.join([f'<option value="{t}">{t}</option>' for t in enum_types])
                scope_options = '\n      '.join([f'<option value="{t}">{t}</option>' for t in enum_scopes])
                api_token_new_form = f'''
<form action="" method="post" class="api-token-new">

  <div class="api-token-new">
    <label for="token-type">Type: </label>
    <select name="token-type" id="token-type">
      {type_options}
    </select>
  </div>

  <div class="api-token-new">
    <label for="scope">Scope: </label>
    <select name="scope" id="scope">
      {scope_options}
    </select>
  </div>

  <div class="api-token-new">
    <label for="lifetime-seconds">Lifetime seconds: </label>
    <input type="text" name="lifetime-seconds" id="lifetime-seconds" size="40" />
  </div>

  <div class="api-token-new">
    <label for="note">Note: </label>
    <input type="text" name="note" id="note" size="40" />
  </div>

  <div class="api-token-new">
    <input type="submit" value="New Api Key" />
  </div>

</form>
'''
            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex New Api Token</title></head>
<body>
{api_token_new_form}
</body>
</html>'''

        enum_types = set(enum_types)
        enum_scopes = set(enum_scopes)
        #log.debug(dict(request.accept_mimetypes))
        #log.debug('derp')
        r_is_json = 'application/json' in dict(request.accept_mimetypes)  # FIXME need better
        #log.debug(r_is_json)
        thing = request.get_json(force=True) if r_is_json else request.form  # FIXME TODO request.json -> abort(415) despite application/json being in accept ...
        #log.debug(thing)
        errors = {}
        if 'token-type' in thing:
            token_type = thing['token-type']
            if token_type not in enum_types:
                # XXX tecnically the db will take care of this but reduces calls to db
                errors['token-type'] = [f'unknown type {token_type}']
        else:
            errors['token-type'] = ['required']

        if 'scope' in thing:
            scope = thing['scope']
            if scope not in enum_scopes:
                # XXX tecnically the db will take care of this but reduces calls to db
                errors['token-type'] = [f'unknown type {token_type}']
        else:
            errors['scope'] = ['required']

        if errors:
            return json.dumps({'errors': errors}), 422, ctaj

        if 'lifetime-seconds' in thing and thing['lifetime-seconds']:
            try:
                lifetime_seconds = int(thing['lifetime-seconds'])
            except ValueError as e:
                als = thing['lifetime-seconds']
                abort(422, f'lifetime-seconds was not an integer {als!r}?')
        else:
            lifetime_seconds = None

        if 'note' in thing:
            _note = thing['note']
            _note = _note.strip()
            note = _note if _note else None
        else:
            note = None

        key_type = token_type[0]
        key = gen_key(key_type=key_type)
        dbstuff = Stuff(self.session)
        # FIXME TODO this defeinitely needs to be restricted to fresh logins (orcid ?prompt=login)
        # XXX FIXME for double insurance we likely want to use fl.current_user not group
        # even though it should be impossible to get through the @basic checks with the
        # auth_user not matching the group, making doubly sure is probably a good idea
        # HOWEVER that means we need to set fl.current_user on api key auth as well
        try:
            dbstuff.insertApiKey(group, key, token_type, scope, lifetime_seconds, note)
        except sa.exc.InternalError as e:
            if (e.orig.diag.source_function == 'exec_stmt_raise' and
                e.orig.diag.context.startswith('PL/pgSQL function api_keys_ensure_invars()')):
                abort(409, e.orig.diag.message_primary)
            else:
                log.exception(e)
                abort(500, 'something went wrong')

        self.session.commit()
        # since this is a critical path, close the loop and make sure the key
        # actually went in, because sometimes we for get that before insert
        # tiggers need to return new not null (derp)
        double_check = dbstuff.getGroupApiKeys(group)
        if double_check and key in set(r.key for r in double_check):
            return {'key': key}, 201, ctaj
        else:
            msg = f'{key} -/-> {double_check}'
            log.critical(msg)
            abort(500, 'something went very wrong')

    @basic
    @fl.fresh_login_required
    def api_token_revoke(self, group, db=None):
        if not request.json or 'key' not in request.json:
            abort(422, 'needs to be json {"key": key_to_revoke}')

        key = request.json['key']
        dbstuff = Stuff(self.session)
        rows = dbstuff.revokeApiKey(key)
        if rows:
            row = rows[0]
            out = {'key': row.key, 'revoked_datetime': row.revoked_datetime}
            return json.dumps(out), 200, ctaj
        else:
            breakpoint()
            abort(500, 'sigh')

    @basic
    def org_new(self, group, db=None):
        # TODO in the simplest case authed users would just be able to POST
        # to /<group>/ that they wanted to claim but of course it isn't
        # that easy because
        return (
            'If you would like to create a new organization please contact support@interlex.org '
            'with "new organization request" as the subject. Please include the name of the '
            'organization that you would like to create, a brief explaination of what it will '
            'be used for, and the interlex username associated with the email you are sending '
            'from which will become the owner of the new organization.'), 501

    @basic
    def committee_new(self, group, db=None):
        return 'TODO', 501

    @basic
    def pull_new(self, group, db=None):
        return 'TODO', 501

    _type_curies = [  # FIXME hardcoded
        'owl:Class',
        'owl:AnnotationProperty',
        'owl:ObjectProperty',
        'TODO:CDE',
        'TODO:FDE',
        'TODO:PDE',
    ]

    @staticmethod
    def _entproc(request):
        errors = {}
        if request.content_type == 'application/x-www-form-urlencoded':
            thing = request.form
        elif request.content_type == 'application/json':
            thing = request.json
        else:
            breakpoint()
            abort(415, 'json or form pls')

        for arg, req in (('rdf-type', True), ('label', True), ('exact', False)):
            if req and (arg not in thing or not thing[arg].strip()):
                errors[arg] = ['missing']
            elif arg == 'rdf-type' and thing['rdf-type'] not in Priv._type_curies:
                errors[arg] = [f'unknown rdf-type {thing[arg]!r}']

        return thing, errors

    @basic
    def entity_check(self, group):
        """
        see if any label or exact already exists
        obviously there is a toctou issue here
        and why entity-new returns an error (race conditions)
        """

        if request.method == 'GET':
            abort(501, 'TODO')  # TODO html form ...

        nm = OntGraph(bind_namespaces='none').namespace_manager
        nm.populate_from(self.queries.getGroupCuries('base'))  # FIXME
        thing, errors = self._entproc(request)
        if errors:
            od = {'errors': errors}
            return json.dumps(od), 422, ctaj

        rdf_type = nm.expand_curie(thing['rdf-type'])
        label = thing['label'].strip()
        exact = [e.strip() for e in thing['exact']] if 'exact' in thing else []
        label_or_exact = [label] + exact
        stypes = {o: 'exact' for o in exact}
        stypes[label] = 'label'
        dbstuff = Stuff(self.session)
        existing = dbstuff.checkEntity(label_or_exact)
        if existing:
            ex = {}
            for row in existing:
                subject = f'http://uri.interlex.org/{group}/{row.prefix}_{row.id}'
                o = row.o_lit
                pe = ilxtr.hasExactSynonym if row.p == 'exact' else rdfs.label
                ps = ilxtr.hasExactSynonym if stypes[row.o_lit] == 'exact' else rdfs.label
                if subject not in ex:
                    ex[subject] = []

                ex[subject].append({
                    'object': o,
                    'predicate_existing': pe,
                    'predicate_submitted':  ps,
                })
            resp = {'existing': ex}
            return json.dumps(resp), 409, ctaj

        return json.dumps({'existing': []}), 200, ctaj

    @basic
    def entity_promote(self, group):
        """
        promote an existing entity that does not have an ilx id to
        have an ilx id
        """

        # aka entity_map_existing
        # TODO this handles the case where there is an existing term that does
        # not have an interlex id

        if request.method == 'GET':
            abort(501, 'TODO')  # TODO html form ...

        # TODO part of the workflow which I don't think I explicated
        # below is what to do if during promotion the rdfs:label for a
        # term already exists, either it matches and should be added as
        # an existing id or it is actually a different term in which case
        # the user will need to provide a different label
        {'existing_id': '',
         'label': '',
         'exact': [],}
        abort(501, 'TODO')

    @basic
    def entity_new(self, group, db=None):
        """
        The workflow we want for this is a bit more complex than a simple form.
        minimally we need
        0. rdf:type
        0. rdfs:label

        really want but can't require
        0. rdfs:subClassOf/rdfs:subPropertyOf

        usually we also want
        0. definition:
        0. exactSynonym:
        0. synonyms:

        utility
        0. userUri:

        everything else
        0. any predicate

        the bigger issue is how we deal with existing terms and matches
        ideally search will be over the larger set of ontologies

        the actual process goes more like this
        0. checkbox about whether to automatically add the new term to the active ontology
           active ontology can be an ontology managed by an organization that the user has contributor status to (or something like that)
        0. if the user has an existing id see if we already have it, and if not ask them to request the upstream ontology for ingestion,
           if it is a small ontology this can be done quickly
           TODO: what if they only have the uri not the upstream ontology?
        0. if there is no existing id user types a label and any exact synonyms
        0. display the elasticsearch results
        0. check if an exact match exists in the current labels and exacts
        0. if yes they have two options, go to their version of the exact match to edit, or modify the label so that it no longer matches
        0. if they opt to edit their own term and there were additional exact synonyms then those should be added to their version of the existing term
        0. if there is an exact match to a label for a term from an ontology that does NOT currently have a interlex id then ask whether they
           want to use that ontogy term as the basis for a new interlex record, if not they need to explain in a comment why the exact match
           to an existing ontology term does not fit (need to add friction to pervent blindly proceeding here)
        0. at this point they should be flipped to the edit term page
        0. on the edit term page subClassOf/subPropertyOf and definition should be presented to be filled in
        0. sub*Of should be a text box that auto complete searches or takes a curie or iri, when they tab out an update is sent
        0. definition is free text and when they tab out the update is sent
        0. at this point they can start adding any predicates they want using the usual edit term page
        0. for ObjectProperties we also allow additional types to be added for e.g. TransitiveProperty etc.

        existing fields that need to be removed:
        existing ids
        is defined by
        description

        existing flow changes:
        additional predicate object pairs should not be added as part of the interstitial page
        after the label and exact synonyms are done an no matches confirmed the user should be taken to the edit term page for the new term NOT back to the page they were on previously
        """

        # TODO need a way to pass the ontologies to put the term in when it is created
        nm = OntGraph(bind_namespaces='none').namespace_manager
        nm.populate_from(self.queries.getGroupCuries('base'))  # FIXME
        if False:
            # TODO ideally we would derive these from the database as done here
            # but in reality there are three major types from owl that we support
            # and we likely will want separate types for cde, fde, and pde
            # Ontology and OntologySpec should not be listed on this interface
            rdf_types = self.queries.getTopLevelRdfTypes()
            def _sigh(iri):
                try:
                    return nm.curie(iri, generate=False)
                except KeyError:
                    return iri

            self._type_curies = [_sigh(t.o) for t in rdf_types]

        if request.method == 'GET':
            rdf_type_options = '\n      '.join([f'<option value="{t}">{t}</option>' for t in self._type_curies])
            _entity_new_form = f'''
<form action="" method="post" class="entity-new">

  <div class="entity-new">
    <label for="rdf-type">Type: </label>
    <select name="rdf-type" id="rdf-type">
      {rdf_type_options}
    </select>
  </div>

  <div class="entity-new">
    <label for="label">Label: </label>
    <input type="text" name="label" id="label" required />
  </div>

  <div class="entity-new">
    <input type="submit" value="New Entity" />
  </div>

</form>
'''

            return f'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head><title>InterLex New Api Token</title></head>
<body>
{_entity_new_form}
</body>
</html>'''

        elif request.method == 'POST':
            thing, errors = self._entproc(request)
            if errors:
                od = {'errors': errors}
                return json.dumps(od), 422, ctaj

            dbstuff = Stuff(self.session)
            rdf_type = nm.expand_curie(thing['rdf-type'])
            label = thing['label'].strip()
            exact = [e.strip() for e in thing['exact']] if 'exact' in thing else []
            try:
                resp = dbstuff.newEntity(rdf_type, label, exact)
            except sa.exc.IntegrityError as e:
                if e.orig.diag.constraint_name == 'current_interlex_labels_and_exacts_pkey':
                    self.session.rollback()
                    # FIXME two db roundtrips, could be done in a single trip
                    # by catching the exception in the db and adding the
                    # relevant information there
                    resp = self.queries.getCurrentLabelExactIlx(label, *exact)
                    existing = ['http://' + self.reference_host + f'/base/{frag_pref}_{id}' for frag_pref, id in resp]
                    return json.dumps({'error': 'already exists', 'existing': existing}), 409, ctaj

                log.exception(e)
                abort(501, 'something went wrong')

            new_uri = resp[0].newentity
            #reiri = new_uri  # XXX this will double redirect in prod
            reiri = new_uri.replace(self.reference_host, request.host).replace('http://', f'{request.scheme}://')
            self.session.commit()
            return redirect(reiri, 303)
        else:
            abort(405)

    @basic
    def modify_a_b(self, group, db=None):
        return 'TODO', 501

    @basic
    def modify_add_rem(self, group, db=None):
        return 'TODO', 501


class Pulls(EndBase):

    def get_func(self, nodes):
        mapping = {
            'pulls': self.pulls,
            '<pull>': self.pull,
            'merge': self.merge,
            'close': self.close,
            'reopen': self.reopen,
            'lock': self.lock,
        }
        return super().get_func(nodes, mapping=mapping)

    @basic
    def pulls(self, group):
        return 'TODO', 501

    @basic
    def pull(self, group, pull):
        return 'TODO', 501

    @basic
    def merge(self, group, pull):
        return 'TODO', 501

    @basic
    def close(self, group, pull):
        return 'TODO', 501

    @basic
    def reopen(self, group, pull):
        return 'TODO', 501

    @basic
    def lock(self, group, pull):
        return 'TODO', 501


class Ontologies(Endpoints):
    # FIXME this is really more of a dead class but that's ok
    # splits up the organization


    # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
    # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
    # TODO HEAD -> return owl:Ontology section

    @basic
    def ontologies_dns(self, group, dns_host, ont_path='', db=None):
        return self._ontologies(group=group,
                                filename=None,
                                extension=None,
                                ont_path=ont_path,
                                host=dns_host,
                                dns=True,
                                db=db)

    @basic
    def ontologies_dns_version(self, group, dns_host, ont_path, epoch_verstr_ont, filename_terminal,
                               extension=None, db=None):
        return self._ontologies_version(group=group,
                                        filename=None,
                                        epoch_verstr_ont=epoch_verstr_ont,
                                        filename_terminal=filename_terminal,
                                        extension=extension,
                                        ont_path=ont_path,
                                        host=dns_host,
                                        dns=True,
                                        db=db)

    @basic
    def ontologies_uris(self, group, filename, extension=None, ont_path='', db=None):
        # probably just slap a /uris/ on the front of the path
        return self._ontologies(group=group,
                                filename=filename,
                                extension=extension,
                                ont_path=ont_path,
                                uris=True,
                                db=db)

    @basic
    def ontologies_uris_version(self, group, filename, epoch_verstr_ont, filename_terminal,
                                extension=None, ont_path='', db=None):
        return self._ontologies_version(group=group,
                                        filename=filename,
                                        epoch_verstr_ont=epoch_verstr_ont,
                                        filename_terminal=filename_terminal,
                                        extension=extension,
                                        ont_path=ont_path,
                                        uris=True,
                                        db=db)

    @basic
    def ontologies_contributions(self, group, db=None):
        return 'TODO list of ontology contributions', 501

    @basic
    def ontologies_ilx_spec(self, group, frag_pref_id, extension=None, db=None):
        return self._ontologies_spec(group, frag_pref_id, extension=extension, from_ilx=True, db=db)

    @basic
    def ontologies_spec(self, *args, **kwargs):
        return self._ontologies_spec(*args, **kwargs)

    def _ontologies_spec(self, group, filename=None, ont_path='', extension=None,
                         dns_host=None, epoch_verstr_ont=None, filename_terminal=None,
                         from_ilx=False, db=None):
        # FIXME uris vs non-uris currently this assumes we are coming from uris
        # TODO figure out of /{group}/ontologies/{ilx_*,dns,etc.} also need specs ...
        # I'm leaving them off for now

        # the process
        # get the current head identity
        # reconstruct the graph at that identity
        # make the specified changes to the graph
        # ingest the new graph, pass the current head for identity relations insertion probably wasModifiedFromIdentity or something
        # update the current head ideantity the new identity

        # FIXME bug in rounting is that if you have //p1/p2/filename/spec that
        # will match the non-uris version with uris, when it should 404 due to
        # empty path
        if request.method in ('GET', 'HEAD'):
            return self._ontologies(
                group=group, filename=filename, ont_path=ont_path, extension=extension,
                uris=not from_ilx, spec=True, from_ilx=from_ilx, db=db)

        elif request.method == 'POST':
            # FIXME TODO handle this properly
            if 'Content-Type' not in request.headers:
                abort(415)

            ct = request.headers['Content-Type']
            if ct == 'application/json':
                if 'title' not in request.json:
                    abort(422, 'new ontologies minimally need a title')

                title = request.json['title']
                subjects = request.json['subjects'] if 'subjects' in request.json else []
            elif ct == 'application/ld+json':
                breakpoint()
                abort(501, 'TODO')
            elif ct == 'text/turtle':
                # TODO do we strip out bound version information from the spec?
                # maybe? we have the db version of when we saw the identity,
                # behavior a bit different for onts maintained inside interlex
                breakpoint()
                abort(501, 'TODO')
            else:
                abort(415, ct)

            opfn = '/' + os.path.join(ont_path, filename)  # TODO make sure works with all path combos
            dbstuff = Stuff(self.session)
            if subjects:
                ssub = set(subjects)  # TODO counter dupes
                # TODO make sure that no subjects are rdf record type before insert
                # TODO also make sure that the subjects are actually in interlex
                subject_types = dbstuff.subjectsObjects(rdf.type, subjects)  # FIXME handle this elsewhere
                bads = []
                record_types = {str(owl.Ontology), }
                sts = set()
                for s, o in subject_types:
                    sts.add(s)
                    if o in record_types:
                        bads.append((s, o))

                missing = ssub - sts
                if bads or missing:
                    msg = ''
                    if missing:
                        msg += f'unknown subjects: {missing} '

                    if bads:
                        msg += f'subjects with record types: {bads}'

                    abort(422, msg)

            try:
                spec_uri_resp = dbstuff.createOntology(self.reference_host, group, opfn)
            except sa.exc.IntegrityError as e:
                # TODO make sure it actually already exists in this case
                if e.orig.diag.constraint_name == 'ontologies_pkey':
                    abort(409, 'already created spec for')
                else:
                    log.exception(e)
                    breakpoint()
                    abort(500, 'oops')

            spec_uri = spec_uri_resp[0].spec
            graph = from_title_subjects_ontspec(spec_uri, title, subjects)
            dout = ingest_ontspec(graph, session=self.session)
            head_identity = dout['graph_combined_local_conventions_identity']
            dbstuff.updateSpecHead(spec_uri, head_identity)
            self.session.commit()
            iri = spec_uri.rsplit('/', 1)[0] + '.html'
            # BEHOLD! Your new ontology.
            return redirect(iri, 303)

        elif request.method == 'PATCH':
            j = request.json

            if 'add' in j:
                adds = j['add']
            else:
                adds = tuple()

            if 'del' in j:
                dels = j['del']
            else:
                dels = tuple()

            if not adds and not dels:
                abort(422, 'request missing both "add" and "del" properties')

            # FIXME beware uri host mismatch
            spec_uri = request.url  # FIXME TODO getGraphByIdentity
            trows = list(self.queries.getGraphByName(spec_uri))
            te = TripleExporter()
            existing_graph = OntGraph().populate_from_triples((te.triple(*r) for r in trows))
            for s, o in existing_graph[:dc.title:]:
                existing_title = str(o)
            existing_subjects = [str(s) for i, s in existing_graph[:ilxtr['include-subject']:]]
            se = set(existing_subjects)
            _sa = set(adds)
            sd = set(dels)
            errors = []
            add_already = se & _sa
            del_not_in = sd - se
            if add_already:
                msg = f'attempting to add entities already in ontology {sorted(add_already)}'
                errors.append(msg)

            if del_not_in:
                msg = f'attempting to del entities not in ontology {sorted(del_not_in)}'
                errors.append(msg)

            if errors:
                abort(422, '\n'.join(errors))

            sn = (se - sd) | _sa
            if sn == se:
                abort(422, 'operation would accomplish nothing')

            subjects = sorted(sn)
            title = j['title'] if 'title' in j else existing_title
            graph = from_title_subjects_ontspec(spec_uri, title, subjects)
            dout = ingest_ontspec(graph, session=self.session)
            head_identity = dout['graph_combined_local_conventions_identity']
            dbstuff = Stuff(self.session)
            dbstuff.updateSpecHead(spec_uri, head_identity)
            self.session.commit()
            iri = spec_uri.rsplit('/', 1)[0] + '.html'
            # BEHOLD! Your updated ontology.
            return redirect(iri, 303)
        else:
            abort(405)

    @basic
    def ontologies(self, *args, **kwargs):
        return self._ontologies(*args, **kwargs)

    def _ontologies(self, group, filename, extension=None, ont_path='', host=None,
                    dns=False, uris=False, spec=False, from_ilx=False, nocel=False, db=None):
        """ the main ontologies endpoint """
        # on POST for new file check to make sure that that the ontology iri matches the post endpoint
        # response needs to include warnings about any parts of the file that could not be lifted to interlex
        # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
        # we should be able to track file 'renames' without too much trouble
        #log.debug(group, filename, extension, ont_path)
        dbuser = fl.current_user.groupname if hasattr(fl.current_user, 'groupname') else None
        #dbuser = db.user  # FIXME make sure that the only way that db.user can be set is if it was an auth user
                        # the current implementation does not gurantee that, probably easiest to pass the token
                        # again for insurance ...
        #if user not in getUploadUsers(group):
        #log.debug(request.headers)

        if request.method == 'HEAD':
            # TODO return bound_name + metadata
            # XXX that probably violates http semantics though
            # and because these are dynamic in size we don't
            # actually know the content length or anything like that
            try:
                ext, mime, f = tripleRender.check(request)
            except exc.UnsupportedType:
                if extension is None:
                    abort(406)
                else:
                    abort(404)

            headers = {'Content-Type': mime}
            return '', 200, headers

        elif request.method == 'GET':
            if filename == 'scigraph-export':
                if extension != 'nt':
                    return "we only support 'application/n-triples' (.nt) for a full dump", 415
                oof = self.queries.dumpSciGraphNt(dbuser)
                def gen():
                    #yield from queries.ontology_header()  # TODO + send header first
                    yield from (('<http://uri.interlex.org/base/ontologies/scigraph-export> '
                                 '<http://www.w3.org/1999/02/22-rdf-syntax-ns#type> '
                                 '<http://www.w3.org/2002/07/owl#Ontology> .'),)
                    yield from (r[0].encode() for s in oof for r in s)
                return Response(gen(), mimetype='application/n-triples')
            elif filename == 'interlex':  # FIXME
                if extension != 'nt':
                    return "we only support 'application/n-triples' (.nt) for a full dump", 415
                oof = self.queries.dumpAllNt(dbuser)
                # FIXME TODO task this sucker and have it dump to disk by qualifier
                # FIXME user auth
                def gen():
                    #yield from (r[0].tobytes() for s in oof for r in s)
                    # returning bytes is about a second slower on pypy
                    # using convert_to, which is weird, but ok
                    yield from (r[0].encode() for s in oof for r in s)
                    # pypy throughput is ~80MBps cpython ~ 20MBps
                #te = TripleExporter()
                def _gen():
                    for r in oof:
                        yield te.nt(*r)
                        # unscientific benchmarks
                        # te.nt pypy3 17s cpython3.6 24s
                        # FIXME 31 seconds for 262MB, pypy3 23s
                        #s, p, o = te.star_triple(*r)
                        #yield f'{s.n3()} {p.n3()} {o.n3()} .\n'.encode()
                        
                return Response(gen(), mimetype='application/n-triples')
                #object_to_existing = self.queries.getResponseExisting(oof, type='o')
                #PREFIXES, graph = self.getGroupCuries(group)
                #_ = [graph.add(te.star_triple(*r)) for r in oof]
                #return tripleRender(request, graph, user, 'FIXMEFIXME', object_to_existing)
            elif dns:
                name_type = 'bound'
                local_convention_rows = self.queries.getCuriesByName(uri_string, type=name_type)
                graph_rows = self.queries.getGraphByName(uri_string, type=name_type)
            elif uris or from_ilx:
                # TODO virtual vs managed vs scratch ...
                # virtual can't post to, only spec
                # managed is own /uris/ + that allows post and will go through the term mapping flow and scratch space ... ends up being quite complex
                # i think in theory everything can ultimately become a managed ontology but impl will take some work
                opfn = os.path.join(ont_path, filename)
                if uris:
                    opfn = 'ontologies/uris/' + opfn
                else:
                    opfn = 'ontologies/' + opfn

                #extension = '' if extension is None else f'.{extension}'  # this is needed by render not query (duh)
                scheme = 'http'  # FIXME TODO ... still need to determine
                # what we are going to normalize scheme to for uri use
                # ... I'm leaning more and more to http
                ont_uri = f'{scheme}://{self.reference_host}/{group}/{opfn}'
                spec_uri = f'{ont_uri}/spec'
                # FIXME bad match in the paths again where going to ont instead of ont spec

                graph = OntGraph()
                tr_kwargs = {}
                if spec:
                    # TODO check that there is an ontology at all before trying to get triples
                    curies = {p: n for p, n in self.queries.getCuriesByName(spec_uri)}
                    graph_rows = self.queries.getGraphByName(spec_uri)
                    title = f'spec for {ont_uri}'
                    tr_kwargs['simple'] = True
                else:
                    # get the spec config triples
                    # and the raw triples (for now)
                    # TODO obviously we need to be deriving from the heads of various perspectives, but we aren't there yet
                    # for now we pull everything from the triples table
                    curies = self.queries.getGroupCuries(group)  # TODO derive from spec if spec has rules for it
                    graph_rows = self.queries.generateOntologyFromSpec(spec_uri)
                    if not graph_rows:
                        abort(404)

                    title = 'TODO derive from dc:title or the ontologies table'

                graph.namespace_manager.populate_from(curies)
                te = TripleExporter()
                for r in graph_rows:
                    graph.add(te.triple(*r))

                return tripleRender(request, graph, group, None, None, tuple(), title, redirect=False, **tr_kwargs)

            else:
                pass

            breakpoint()
            abort(501, 'TODO')

        elif request.method == 'POST':
            extension = '.' + extension if extension else ''
            match_path = os.path.join(ont_path, filename + extension)
            path = os.path.join('ontologies', match_path)  # FIXME get middle from request?
            #request_reference_name = request.headers['']
            #request_reference_name = request.url  # ??
            reference_name = self.build_reference_name(group, path)
            try:
                print('pretty sure that we are catching this in basic and basic2 now...')
            except exc.NotGroup:
                return abort(404)

            existing = False  # TODO check if the file already exists
            # check what is being posted
            #breakpoint()
            #if requests.args:
                #log.debug(request.args)
            #elif request.json is not None:  # jsonld u r no fun
                #log.debug(request.json)
                #{'iri':'http://purl.obolibrary.org/obo/uberon.owl'}
            #elif request.data:
                #log.debug(request.data)

            if not existing:
                if request.files:
                    # TODO retrieve and if existing-iri make sure stuff matches
                    log.debug(request.files)
                if request.json is not None:  # jsonld u r no fun
                    log.debug(request.json)
                    if 'name' in request.json:
                        _name = request.json['name']  # FIXME not quite right?
                        name = URIRef(_name)
                        if name.startswith('file://'):
                            return 'file:// scheme not allowed', 400

                        if 'bound-name' in request.json:
                            _expected_bound_name = request.json['bound-name']
                            expected_bound_name = URIRef(_expected_bound_name)
                        else:
                            expected_bound_name = None

                        # FIXME this should be handled elsewhere for user
                        if match_path not in name and match_path not in expected_bound_name:
                            return f'No common name between {expected_bound_name} and {reference_name}', 400

                        # FIXME this needs to just go as a race
                        # either await sleep(limit) or await load(thing)
                        raise NotImplementedError('TODO new workflow please')
                        try:
                            loader = self.FileFromIRI(group, dbuser, reference_name)
                            #task = tasks.multiple(loader, name, expected_bound_name)
                            # task.jobid
                            # then wait for our max time and return the jobid/tracker or the result
                            #return task.get()  # timeout=10 or something
                            will_batch = loader.check(name)
                            if will_batch and not nocel:
                                if False:
                                    # and of course with this version api gets caught,
                                    # probably session is the issue
                                    tasks.session = self.session
                                    tasks.base_ffi(group, dbuser, reference_name,
                                                self.reference_host, name, expected_bound_name)
                                    # so.owl load works fine but uberon load seems eternal
                                    # and never finishes for some reason
                                    return 'DEBUG'
                                task = tasks.long_ffi.apply_async((group, dbuser, reference_name,
                                                                   self.reference_host, name, expected_bound_name),
                                                                  serializer='pickle')
                                # ya so this doesn't quite work ...
                                #task = tasks.long_load.apply_async((loader, expected_bound_name),
                                                                   #serializer='pickle')

                                job_url = request.scheme + '://' + self.reference_host + url_for("route_api_job", jobid=task.id)
                                return ('that\'s quite a large file you\'ve go there!'
                                        f'\nit has been submitted for processing {job_url}', 202)
                        except exc.NameCheckError as e:
                            abort(e.code, {'message': e.message})

                        setup_ok = loader(expected_bound_name)
                        if setup_ok is not None:
                            return setup_ok

                        out = loader.load()

                        # TODO get actual user from the api key
                        # out = f(user, filepath, ontology_iri, new=True)
                        #breakpoint()
                        log.debug('should be done running?')

                        # TODO return loading stats etc
                        return out

                #if 'external-iri' in request.args:
                    # cron jobs and webhooks... for the future on existing iris
                    # frankly we can just peek
                    #external_iri = request.args['external-iri']
                # elif 'crawl' in request.args['']


            return 'POST TODO\n'

        # much easier to implement this way than current attempts
        return request.path + '\n'

    @basic
    def ontologies_version(self, *args, **kwargs):
        return self._ontologies_version(*args, **kwargs)

    def _ontologies_version(self, group, filename, epoch_verstr_ont,
                            filename_terminal, extension=None, ont_path='', host=None, dns=False, uris=False, db=None):
        if filename != filename_terminal:
            abort(404)  # 400 maybe ?
        else:
            return request.path, 501


class Versions(Endpoints):
    # TODO own/diff here could make it much easier to view changes
    @basic
    def ilx(self, group, epoch_verstr_id, frag_pref_id, extension=None, db=None):
        # TODO epoch and reengineer how ilx is implemented
        # so that queries can be conducted at a point in time
        # sigh dataomic
        # or just give up on the reuseabilty of the query structure?
        return super()._ilx(group=group, frag_pref_id=frag_pref_id, extension=extension)  # have to use kwargs for basic

    @basic
    def readable(self, group, epoch_verstr_id, word, db=None):
        return request.path, 501

    @basic
    def uris(self, group, epoch_verstr_id, uri_path, db=None, read_private=False):
        return request.path, 501

    @basic
    def curies_(self, group, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group, epoch_verstr=epoch_verstr_id)
        return request.path, 501
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic
    def curies(self, group, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path, 501


class Own(Ontologies):
    @basic2
    def uris(self, group, other_group, uri_path, db=None, read_private=False):
        return request.path, 501

    @basic2
    def curies_(self, group, other_group, db=None):
        PREFIXES, g = self.getGroupCuries(group)
        otherPREFIXES, g = self.getGroupCuries(other_group)
        return request.path, 501
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group, prefix_iri_curie, db=None):
        return request.path, 501

    @basic2
    def ontologies_(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies(self, group, other_group, filename, extension=None, ont_path='', db=None):
        # this is useful for some auto generated ontologies that could be different
        # consider that you want to see /tgbugs/own/sparc/ontologies/community-terms
        # that is useful because otherwise you would have to figure out how they
        # were generating that list which is a pain
        return request.path, 501

    @basic2
    def ontologies_ilx(self, group, other_group, frag_pref_id, extension=None, db=None):
        abort(404)  # this doesn't really exist but would be a pain to remove from the path gen

    @basic2
    def ontologies_version(self, group, other_group, filename, epoch_verstr_ont,
                            filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            abort(404)
        else:
            return request.path, 501

    @basic2
    def ontologies_uris(self, group, other_group, filename, extension=None, ont_path='', db=None):
        return request.path, 501

    @basic2
    def ontologies_uris_version(self, group, other_group, filename, epoch_verstr_ont,
                                filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            abort(404)
        else:
            return request.path, 501

    @basic2
    def ontologies_contributions(self, *args, **kwargs):
        abort(404)  # doesn't exist but hard to remove from generation

    @basic2
    def ontologies_spec(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies_dns(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies_dns_version(self, *args, **kwargs):
        abort(501)

    @basic2
    def other(self, *args, **kwargs):
        abort(404)  # FIXME ideally remove from uri generation

    @basic2
    def versions(self, *args, **kwargs):
        abort(404)  # FIXME ideally remove from uri generation


class OwnVersions(Own, Versions):
    @basic2
    def ilx(self, group, other_group, epoch_verstr_id, frag_pref_id, extension=None, db=None):
        return request.path, 501

    @basic2
    def readable(self, group, other_group, epoch_verstr_id, word, db=None):
        return request.path, 501

    @basic2
    def uris(self, group, other_group, epoch_verstr_id, uri_path, db=None, read_private=False):
        return request.path, 501

    @basic2
    def curies_(self, group, other_group, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group, epoch_verstr=epoch_verstr_id)
        return request.path, 501
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path, 501


class Diff(Ontologies):
    @basic2
    def ilx(self, group, other_group_diff, frag_pref_id, extension=None, db=None):
        frag_pref, id = frag_pref_id.split('_')
        funcs = [self._even_more_basic(grp, frag_pref, id, db)
                 for grp in (group, other_group_diff)]

        stuff = [self._ilx_impl(grp, frag_pref, id, func) for grp, func in
                 zip((group, other_group_diff), funcs)]

        this = stuff[0][0]
        that = stuff[1][0]

        add, rem, same = this.diffFromGraph(that)

        # VERY TODO
        # probably need a DiffRender ...

        return ('<pre>' + '\nADDED\n' +
                add.ttl + '\nREMOVED\n' +
                rem.ttl + '\nSAME\n' +
                same.ttl +
                '</pre>'), 501

    @basic  # FIXME basic 2???
    def lexical(self, group, other_group_diff, label, db=None):
        # FIXME the logic here is all wonky
        do_redirect, identifier_or_defs = self.queries.getByLabel(label, group)
        if do_redirect:
            # FIXME could be a user level redirect
            return ''  # no difference
        elif not identifier_or_defs:
            return 'REDLINK -> AMBIGUATION -> TODO'
        else:
            other_do_redirect, other_identifier_or_defs = self.queries.getByLabel(label, other_group_diff)
            if other_do_redirect:
                # FIXME this is actually probably where we want to do this diff ...
                return 'FIXME we need to handle this properly for diffing, probably need to return the actual value'
            else:
                PREFIXES, g = self.getGroupCuries(group)
                defs = [(g.qname(s), d) for s, d in identifier_or_defs]
                other_defs = [(g.qname(s), d) for s, d in other_identifier_or_defs]
                title = f'{label} (disambiguation)'  # mirror wiki
                # TODO resolve existing_iri mappings so they don't show up here
                return htmldoc(h2tag(f'{label} (disambiguation)'),
                               render_table(tuple(), btag(group), ''),  # TODO links to user pages?
                               render_table(defs, 'Identifier',
                                            atag(definition, 'definition:')),
                               render_table(tuple(), btag(other_group_diff), ''),
                               render_table(other_defs, 'Identifier',
                                            atag(definition, 'definition:')),
                               title=title,
                               styles=(table_style,))

    @basic2
    def readable(self, group, other_group_diff, word, db=None):
        return request.path, 501

    @basic2
    def uris(self, group, other_group_diff, uri_path, db=None, read_private=False):
        return request.path, 501

    @basic2
    def curies_(self, group, other_group_diff, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group_diff)
        return request.path, 501
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group_diff, prefix_iri_curie, db=None):
        return request.path, 501

    @basic2
    def ontologies_(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies(self, group, other_group_diff, filename, extension=None, ont_path='', db=None):
        return request.path, 501

    @basic2
    def ontologies_ilx(self, group, other_group_diff, frag_pref_id, extension=None, db=None):
        return self.ilx(group=group, other_group_diff=other_group_diff, frag_pref_id=frag_pref_id, extension=extension)

    @basic2
    def ontologies_version(self, group, other_group_diff, filename,
                            epoch_verstr_ont, filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            abort(404)
        else:
            return request.path, 501

    @basic2
    def ontologies_uris(self, group, other_group_diff, filename, extension=None, ont_path='', db=None):
        return request.path

    @basic2
    def ontologies_uris_version(self, group, other_group_diff, filename,
                            epoch_verstr_ont, filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            abort(404)
        else:
            return request.path, 501

    @basic2
    def ontologies_contributions(self, *args, **kwargs):
        return abort(404)  # doesn't exist but hard to remove from generation

    @basic2
    def ontologies_spec(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies_dns(self, *args, **kwargs):
        abort(501)

    @basic2
    def ontologies_dns_version(self, *args, **kwargs):
        abort(501)

    @basic2
    def other(self, *args, **kwargs):
        abort(404)  # FIXME ideally remove from uri generation

    @basic2
    def versions(self, *args, **kwargs):
        abort(404)  # FIXME ideally remove from uri generation


class DiffVersions(Diff, Versions):
    @basic2
    def ilx(self, group, other_group_diff, epoch_verstr_id, frag_pref_id, extension=None, db=None):
        return request.path, 501

    @basic2
    def readable(self, group, other_group_diff, epoch_verstr_id, word, db=None):
        return request.path, 501

    @basic2
    def uris(self, group, other_group_diff, epoch_verstr_id, uri_path, db=None, read_private=False):
        return request.path, 501

    @basic2
    def curies_(self, group, other_group_diff, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group_diff, epoch_verstr=epoch_verstr_id)
        return request.path, 501
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group_diff, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path, 501


class VersionsOwn(Endpoints):
    pass  # TODO


class VersionsDiff(Endpoints):
    pass  # TODO
