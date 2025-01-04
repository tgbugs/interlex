import os
import re
import json
from functools import wraps
import sqlalchemy as sa
import flask_login as fl
from flask import request, redirect, url_for, abort, Response
from rdflib import URIRef  # FIXME grrrr
from htmlfn import atag, btag, h2tag, htmldoc
from htmlfn import table_style, render_table, redlink_style
from pyontutils.core import makeGraph
from pyontutils.utils import TermColors as tc
from pyontutils.namespaces import makePrefixes, definition
from sqlalchemy.sql import text as sql_text
from interlex import tasks
from interlex import config
from interlex import exceptions as exc
from interlex.auth import Auth
from interlex.core import diffCuries, makeParamsValues, default_prefixes
from interlex.dump import TripleExporter, Queries
from interlex.load import FileFromIRIFactory, FileFromPostFactory, TripleLoaderFactory, BasicDBFactory, UnsafeBasicDBFactory
from interlex.utils import log as _log
from interlex.config import ilx_pattern  # FIXME pull from database probably
from interlex.render import TripleRender  # FIXME need to move the location of this

log = _log.getChild('endpoints')

tripleRender = TripleRender()


def getBasicDB(self, group, request):
    #log.debug(f'{group}\n{request.method}\n{request.url}\n{request.headers}')

    try:
        # FIXME pretty sure this isn't quite right
        # XXX yeah, auth_group is the wrong way to do this
        # we have to check user persmissions in the group during
        # authenticate_request
        auth_group, auth_user, scope, auth_token, read_private = self.auth.authenticate_request(request)
    except self.auth.ExpiredTokenError:
        abort(401, {'message': (
            'Your token has expired, please get a '
            f'new one at {self.link_to_new_token}')})
    except self.auth.AuthError:
        abort(400, {'message': 'Your token could not be verified.'})  # FIXME pull the message up?

    logged_in_user = fl.current_user  # actually we can access this wherever we need now
    if logged_in_user is not None and not logged_in_user.is_anonymous:
        li_user = logged_in_user.groupname
    else:
        li_user = None

    if request.method in ('HEAD', 'GET'):
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

            kwargs['db'] = db

            if 'read_private' in kwargs:
                breakpoint()
                kwargs['read_private'] = read_private

        return function(self, *args, **kwargs)

    return basic_checks


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


class Endpoints:
    def __init__(self, db, rules_req_auth):
        self.db = db
        self.session = self.db.session
        self.queries = Queries(self.session)
        self.auth = Auth(self.session, rules_req_auth)
        #self.FileFromIRI = FileFromIRIFactory(self.session)  # FIXME I think these go in tasks
        #self.FileFromPost = FileFromPostFactory(self.session)  # FIXME I think these go in tasks
        self.BasicDB = BasicDBFactory(self.session)
        self.UnsafeBasicDB = UnsafeBasicDBFactory(self.session)

    def session_execute(self, sql, params=None):
        return self.session.execute(sql_text(sql), params=params)

    @property
    def reference_host(self):
        return self.queries.reference_host

    @property
    def link_to_new_token(self):
        return 'TODO url_for', 501

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
            log.debug('not group?')
            return None

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

    def get_func(self, nodes):
        #ilx_get = ilx_pattern + '.<extension>'  # FIXME TODO where did we need this again?
        mapping = {
            'ilx':self.ilx,
            'other':self.other,
            '*versions':self.versions,
            #ilx_get:self.ilx_get,
            '*ilx_get':self.ilx_get,
            'ops':self.ops,
            'priv':self.priv,
            'lexical':self.lexical,
            'readable':self.readable,
            'uris':self.uris,
            'curies_':self.curies_,
            'curies':self.curies,

            # FIXME how to deal with own/other for ontologies/uris ?
            # FIXME ontologies are weird with need to be here ...
            # but eithe you duplicate functions or you duplicate diff and own classes
            'ontologies_':self.ontologies_,
            'ontologies':self.ontologies,
            'version':self.ontologies_version,  # FIXME collision prone?

            '*ont_ilx_get':self.ontologies_ilx,
            '*uris_ont':self.ontologies_uris,
            '*<path:uris_ont_path>':self.ontologies_uris,
            '*uris_version':self.ontologies_uris_version,

            'contributions_':self.contributions_,
            'contributions':self.contributions,
            '*contributions_ont':self.ontologies_contributions,

            'upload':self.upload,
            'prov':self.prov,

            'mapped':self.mapped,

            'new-entity': self.new_entity,
            'modify-a-b': self.modify_a_b,
            'modify-add-rem': self.modify_add_rem,
        }
        for node in nodes[::-1]:
            if node in mapping:
                return mapping[node]
        else:
            raise KeyError(f'could not find any value for {nodes}')

    def new_entity(self): return 'NOT IMPLEMENTED\n', 400
    def modify_a_b(self): return 'NOT IMPLEMENTED\n', 400
    def modify_add_rem(self): return 'NOT IMPLEMENTED\n', 400

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

    def ops(self, group, operation):
        # FIXME this needs to be able to detect whether a user is already
        # logged in as the same or another user
        from interlex import auth as iauth

        if operation == 'signup':
            # TODO email
            # password
            # TODO only orcid
            if request.method != 'POST':
                return abort(404)

            password = 'lol'
            argon2_string = iauth.hash_password(password)
            # TODO multiple operations see cli.Ops.password
            #sql = 'INSERT INTO user_passwords (user_id, argon2_string) VALUES ((SELECT id FROM groups WHERE groupname :groupname JOIN users ON groups.id = users.id), :argon2_string)'
            params = dict(groupname=group, argon2_string=argon2_string)
            breakpoint()
            return abort(404)

        if operation == 'login':
            # XXX NOTE this is pretty much only for development
            # because in production login is going to go directly
            # to orcid and /<group>/ops/login should pretty much never be used
            if request.method == 'GET':
                # only accept post with password on this endpoint
                # to prevent user name discovery, though obviously
                # there are other legitimate way to discover this
                # information in bulk
                return abort(404)

            elif request.method == 'POST':
                # if the the group is not a user then 404 since can only log in to orcid mapped users
                # FIXME must check roles
                sql = 'SELECT * FROM groups WHERE groupname = :groupname'  # FIXME case insensitive match here or no? I think no, insense only when someone tries to create a case variant and we block them
                # FIXME TODO must also check users here to ensure actually allowed to log in
                rows = list(self.session_execute(sql, dict(groupname=group)))
                basic_group_password_or_password = request.headers.get('Authorization', '')
                if not basic_group_password_or_password or not rows:  # order matters to try to minimize timing attack risk
                    return abort(404)

                group_row = rows[0]

                abasic, *_group_password_or_password = basic_group_password_or_password.split(None, 1)
                if abasic.lower() != 'basic' or not _group_password_or_password:  # FIXME do we force case sense or not here ...
                    return abort(404)  # FIXME maybe malformed from client
                else:
                    group_password_or_password = _group_password_or_password[0]

                sql = 'SELECT argon2_string FROM user_passwords WHERE user_id = :user_id'
                params = {'user_id': group_row.id}
                rows = list(self.session_execute(sql, params))
                if not rows:
                    return abort(404)  # not a user

                user_password = rows[0]
                argon2_string = user_password.argon2_string
                if ':' in group_password_or_password:
                    pass_group, password = group_password_or_password.split(':', 1)
                    # try password
                    if pass_group != group:  # passwords with colons yo
                        # XXX watch out for timing attacks
                        password_matches = iauth.validate_password(argon2_string, group_passworld_or_password)
                        # try the whole thing
                        # fail if no match
                    else:
                        password_matches = iauth.validate_password(argon2_string, password)
                else:
                    password = group_password_or_password
                    password_matches = iauth.validate_password(argon2_string, password)

                if password_matches:
                    # return the relevant session information so that the browser can store it and retain the session
                    # or however that works?
                    # TODO flask login or something
                    # XXX if they came here directly just go ahead and give them the api token probably?? not quite sure
                    # I'm sure this will change with the orcid stuff
                    class tuser:
                        is_active = True  # TODO translate from the permission model
                        def get_id(self, __id=group_row.id):
                            return __id

                    fl.login_user(tuser())
                    return 'login successful, check your cookies (use requests.Session)'
                else:
                    return abort(401)  # FIXME hrm what would the return code be here ...
                
        elif operation == 'logout':
            # FIXME this does not go here because it requires auth ...
            if request.method == 'GET':
                # check if logged in?
                # then log out
                fl.logout_user()
                return 'logged out'
            else:
                return abort(404)

        else:
            # unsupported operation
            abort(404)

        breakpoint()

    @basic
    def priv(self, group, page, db=None):
        # separate privilidged pages from ops which technically don't require privs

        # TODO check user first

        if page == 'settings':
            # TODO can handle logged in user x group membership and role in a similar way
            return (
                'ilx:group/priv/settings a ilxtr:interlex-settings ;\n'
                'skos:comment "completely fake ttlish representation of settings" ;\n'
                f'settings:groupname "{group}" ;\n'
                'settings:email "email" ;\n'
                'settings:orcid "orcid-id-thing-yeah" ;\n'
                'settings:notification-prefs "email" ;\n'
                'settings:api-token "maybe we just put this here sure why not" ;\n'
                'settings:own-role "maybe we just put this here sure why not" ;\n'
                '.')

        elif page == 'api-token':
            return 'TODO-lol-token'

        else:
            return abort(404)

    def _ilx(self, group, frag_pref, id, func):
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
    def ilx(self, group, frag_pref_id, db=None):
        frag_pref, id = frag_pref_id.split('_')
        # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}
        func = self._even_more_basic(group, frag_pref, id, db)
        graph, object_to_existing, title, labels = self._ilx(group, frag_pref, id, func)
        return tripleRender(request, graph, group, frag_pref, id,
                            object_to_existing, title, labels=labels)

    @basic
    def ilx_get(self, group, frag_pref_id, extension, db=None):
        # TODO these are not cool uris
        # TODO move this lookup to config?
        return self.ilx(group=group, frag_pref_id=frag_pref_id, db=db)
        #return tripleRender(request, g, group, id, object_to_existing, title)

    @basic
    def other(self, group, frag_pref_id, db=None):
        return 'NOT IMPLEMENTED', 400

    @basic
    def versions(self, group, frag_pref_id, db=None):
        return 'NOT IMPLEMENTED', 400

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
                _ = [g.g.add(te.triple(*r)) for r in resp]
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

            values = tuple((cp, ip) for cp, ip in to_add.items())

            # FIXME impl in load pls
            values_template, params = makeParamsValues(values,
                                                        constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
            params['group'] = group
            base = 'INSERT INTO curies (group_id, curie_prefix, iri_namespace) VALUES '
            sql = base + values_template
            try:
                resp = self.session_execute(sql, params)
                self.session.commit()
                return message, 201
            except sa.exc.IntegrityError as e:
                self.session.rollback()
                return f'Curie exists\n{e.orig.pgerror}', 409  # conflict
                return f'Curie exists\n{e.args[0]}', 409  # conflict
        else:
            PREFIXES, g = self.getGroupCuries(group)

        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

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
                           'AND (e.group_id = :group_id OR e.group_id = 0)')  # base vs curated
                    args = dict(iri=iri, group_id=db.group_id)
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

                        resp = self.queries.getBySubject(iri, group)
                        te = TripleExporter()
                        _ = [graph.add(te.triple(*r)) for r in resp]
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
    def upload(self, group, db=None):
        """ Expects files """
        # only POST
        # TODO auth

        dbuser = db.user

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
    def ontologies_(self, group, db=None):
        """ The terminal ontologies query does go on endpoints """
        return json.dumps('your list sir')

    @basic
    def ontologies_ilx(self, group, frag_pref_id, extension, db=None):
        # FIXME termset
        return self.ilx(group=group, frag_pref_id=frag_pref_id, db=db)

    @basic
    def ontologies(self, *args, **kwargs):
        """ needed because ontologies appear under other routes """
        raise NotImplementedError('should not be hitting this')

    @basic
    def ontologies_version(self, *args, **kwargs):
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


class Ontologies(Endpoints):
    # FIXME this is really more of a dead class but that's ok
    # splits up the organization


    # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
    # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
    # TODO HEAD -> return owl:Ontology section

    @basic
    def ontologies_uris(self, group, filename, extension=None, ont_path='', db=None):
        # probably just slap a /uris/ on the front of the path
        return self.ontologies(group=group,
                               filename=filename,
                               extension=extension,
                               ont_path='uris/' + ont_path,
                               db=db)

    @basic
    def ontologies_uris_version(self, group, filename, epoch_verstr_ont, filename_terminal,
                                extension=None, ont_path='', db=None):
        return self.ontologies_version(group=group,
                                       filename=filename,
                                       epoch_verstr_ont=epoch_verstr_ont,
                                       filename_terminal=filename_terminal,
                                       extension=extension,
                                       ont_path='uris/' + ont_path,
                                       db=db)

    @basic
    def ontologies_contributions(self, group, db=None):
        return 'TODO list of ontology contributions', 501

    @basic
    def ontologies(self, group, filename, extension=None, ont_path='', db=None, nocel=False):
        """ the main ontologies endpoint """
        # on POST for new file check to make sure that that the ontology iri matches the post endpoint
        # response needs to include warnings about any parts of the file that could not be lifted to interlex
        # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
        # we should be able to track file 'renames' without too much trouble
        #log.debug(group, filename, extension, ont_path)
        dbuser = db.user  # FIXME make sure that the only way that db.user can be set is if it was an auth user
                        # the current implementation does not gurantee that, probably easiest to pass the token
                        # again for insurance ...
        #if user not in getUploadUsers(group):
        #log.debug(request.headers)

        if request.method == 'HEAD':
            # TODO return bound_name + metadata
            return 'HEAD TODO\n'

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

            return 'NOT IMPLEMENTED\n', 400

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
    def ontologies_version(self, group, filename, epoch_verstr_ont,
                            filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            abort(404)  # 400 maybe ?
        else:
            return request.path, 501



class Versions(Endpoints):
    # TODO own/diff here could make it much easier to view changes
    @basic
    def ilx(self, group, epoch_verstr_id, frag_pref_id, db=None):
        # TODO epoch and reengineer how ilx is implemented
        # so that queries can be conducted at a point in time
        # sigh dataomic
        # or just give up on the reuseabilty of the query structure?
        return super().ilx(group=group, frag_pref_id=frag_pref_id, db=db)  # have to use kwargs for basic

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
    def ontologies(self, group, other_group, filename, extension=None, ont_path='', db=None):
        # this is useful for some auto generated ontologies that could be different
        # consider that you want to see /tgbugs/own/sparc/ontologies/community-terms
        # that is useful because otherwise you would have to figure out how they
        # were generating that list which is a pain
        return request.path, 501

    @basic2
    def ontologies_ilx(self, group, other_group, frag_pref_id, extension, db=None):
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
        return abort(404)  # doesn't exist but hard to remove from generation


class OwnVersions(Own, Versions):
    @basic2
    def ilx(self, group, other_group, epoch_verstr_id, frag_pref_id, db=None):
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
    def ilx(self, group, other_group_diff, frag_pref_id, db=None):
        frag_pref, id = frag_pref_id.split('_')
        funcs = [self._even_more_basic(grp, frag_pref, id, db)
                 for grp in (group, other_group_diff)]

        stuff = [self._ilx(grp, frag_pref, id, func) for grp, func in
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
    def ontologies(self, group, other_group_diff, filename, extension=None, ont_path='', db=None):
        return request.path, 501

    @basic2
    def ontologies_ilx(self, group, other_group_diff, frag_pref_id, extension, db=None):
        return self.ilx(group=group, other_group_diff=other_group_diff, frag_pref_id=frag_pref_id, db=db)

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


class DiffVersions(Diff, Versions):
    @basic2
    def ilx(self, group, other_group_diff, epoch_verstr_id, frag_pref_id, db=None):
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


