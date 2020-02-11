import os
import json
from functools import wraps
import sqlalchemy as sa
from flask import request, redirect, url_for, abort, Response
from rdflib import URIRef  # FIXME grrrr
from htmlfn import atag, btag, h2tag, htmldoc
from htmlfn import table_style, render_table, redlink_style
from pyontutils.core import makeGraph
from pyontutils.utils import TermColors as tc
from pyontutils.namespaces import makePrefixes, definition
from interlex import tasks
from interlex import config
from interlex.exc import NotGroup, NameCheckError, UnsupportedType
from interlex.auth import Auth
from interlex.core import printD, diffCuries, makeParamsValues, default_prefixes
from interlex.dump import TripleExporter, Queries
from interlex.load import FileFromIRIFactory, FileFromPostFactory, TripleLoaderFactory, BasicDBFactory, UnsafeBasicDBFactory
from interlex.config import ilx_pattern
from interlex.render import TripleRender  # FIXME need to move the location of this
from IPython import embed

tripleRender = TripleRender()


def getBasicDB(self, group, request):
    #printD(f'{group}\n{request.method}\n{request.url}\n{request.headers}')
    try:
        auth_group, auth_user, scope, auth_token = self.auth.authenticate_request(request)
    except self.auth.ExpiredTokenError:
        return f'Your token has expired, please get a new one at {self.link_to_new_token}', 401
    except self.auth.AuthError:
        return 'Your token could not be verified.', 400  # FIXME pull the message up?

    if request.method in ('HEAD', 'GET'):
        db = self.getBasicInfoReadOnly(group, auth_user)

    else:

        if auth_token:
            if auth_group != group:
                return f'This token is not valid for group {group}', 401

            if not auth_user:  # this should be impossible ...
                if group == 'api':  # should this be hardcoded? probably
                    return 'FIXME what do we want to do here?', 401
                else:
                    # not 403 because this way we are ignorant by default
                    # we dont' have to wonder whether the url they were
                    # looking for was private or not (most shouldn't be)
                    return abort(404)

        db = self.getBasicInfo(group, auth_user, auth_token)

    return db, auth_user


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
            maybe_db, _ = getBasicDB(self, group, request)
            if not isinstance(maybe_db, BasicDBFactory):
                if maybe_db is None:
                    return abort(404)
                else:
                    return maybe_db
            else:
                db = maybe_db

            kwargs['db'] = db

        return function(self, *args, **kwargs)

    return basic_checks


def basic2(function):
    @wraps(function)
    def basic2_checks(self, *args, **kwargs):
        group = kwargs['group']  # FIXME really group
        if 'db' not in kwargs:  # being called via super() probably
            maybe_db, auth_user = getBasicDB(self, group, request)
            if not isinstance(maybe_db, BasicDBFactory):
                if maybe_db is None:
                    return abort(404)
                else:
                    return maybe_db
            else:
                db = maybe_db

            kwargs['db'] = db

        if 'other_group' in kwargs:
            other_group = kwargs['other_group']
        elif 'other_group_diff' in kwargs:
            other_group = kwargs['other_group_diff']

        db2 = self.getBasicInfoReadOnly(other_group, auth_user)
        if db2 is None:
            return abort(404)

        db.other = db2
        return function(self, *args, **kwargs)

    return basic2_checks


class Endpoints:
    def __init__(self, db):
        self.db = db
        self.session = self.db.session
        self.queries = Queries(self.session)
        self.auth = Auth(self.session)
        self.FileFromIRI = FileFromIRIFactory(self.session)  # FIXME I think these go in tasks
        self.FileFromPost = FileFromPostFactory(self.session)  # FIXME I think these go in tasks
        self.BasicDB = BasicDBFactory(self.session)
        self.UnsafeBasicDB = UnsafeBasicDBFactory(self.session)

    @property
    def reference_host(self):
        return self.queries.reference_host

    @property
    def link_to_new_token(self):
        return 'TODO url_for'

    def getBasicInfo(self, group, auth_user, token):
        try:
            return self.BasicDB(group, auth_user, token, read_only=False)
        except NotGroup:
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
        except NotGroup:
            printD('not group?')
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
        #printD(PREFIXES)
        g = makeGraph(group + '_curies_helper', prefixes=PREFIXES if PREFIXES else default_prefixes)
        return PREFIXES, g

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
        ilx_get = ilx_pattern + '.<extension>'
        mapping = {
            ilx_pattern:self.ilx,
            ilx_get:self.ilx_get,
            'lexical':self.lexical,
            'readable':self.readable,
            'uris':self.uris,
            'curies_':self.curies_,
            'curies':self.curies,
            'ontologies_':self.ontologies_,
            'ontologies':self.ontologies,
            'version':self.ontologies_version,  # FIXME collision prone?
            'contributions_':self.contributions_,
            'contributions':self.contributions,
            'upload':self.upload,
            'prov':self.prov,
        }
        for node in nodes[::-1]:
            if node in mapping:
                return mapping[node]
        else:
            raise KeyError(f'could not find any value for {nodes}')

    def isIlxIri(self, iri):
        # FIXME the is a horrible way to define valid uri structure
        scheme, rest = iri.split('://', 1)
        prefix, maybe_ilx = rest.rsplit('/', 1)
        if prefix.startswith(self.reference_host) and maybe_ilx.startswith('ilx_'):  # TODO allow configurable prefix here
            _, group, _ = (prefix + '/').split('/', 2)  # at trailing in case group was terminal
            _, id = maybe_ilx.split('_')
            return group, id

    # TODO PATCH
    @basic
    def ilx(self, group, id, db=None):
        # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}

        if group != 'base' and group != 'latest':
            sql = 'SELECT id FROM interlex_ids WHERE id = :id'
            try:
                res = next(self.session.execute(sql, dict(id=id)))
                id = res.id
                #printD(id, db.group_id)
            except StopIteration:
                return abort(404)

        try:
            _, _, func = tripleRender.check(request)
        except UnsupportedType as e:
            return e.message, e.code

        PREFIXES, g = self.getGroupCuries(group)
        resp = self.queries.getById(id, group)
        #printD(resp)
        # TODO formatting rules for subject and objects
        object_to_existing = self.queries.getResponseExisting(resp, type='o')

        te = TripleExporter()
        _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

        # TODO list users with variants from base and/org curated
        # we need an 'uncurated not latest' or do we?
        if group == 'base':
            title = f'ILX:{id}'
        else:
            title = f'ilx.{group}:ilx_{id}'

        if func == tripleRender.ttl_html:  # FIXME hackish?
            # FIXME getting additional content from the db based on file type
            # leads to breakdown of separation of concerns due to statefulness
            # slow but probably worth it for enhancing readability
            iris = set(e for t in g.g for e in t if isinstance(e, URIRef))
            labels = {URIRef(s):label for s, label in self.queries.getLabels(group, iris)}
        else:
            labels = None

        return tripleRender(request, g, group, id, object_to_existing, title, labels=labels)

    @basic
    def ilx_get(self, group, id, extension, db=None):
        # TODO these are not cool uris
        # TODO move this lookup to config?
        return self.ilx(group=group, id=id, db=db)
        #return tripleRender(request, g, group, id, object_to_existing, title)

    @basic
    def lexical(self, group, label, db=None):
        # TODO FIXME consider normalization in cases where there is not an exact match?
        # like with my request to n2t, check for exact, then normalize
        do_redirect, identifier_or_defs = self.queries.getByLabel(label, group)
        if do_redirect:
            if self.reference_host not in identifier_or_defs:
                # FIXME temporary workaround for finding a uri that goes elsewhere
                curie = self.curies(prefix_iri_curie=identifier_or_defs, group=request.view_args['group'])
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
            except UnsupportedType as e:
                return e.message, e.code

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
        return 'TODO identity for group contribs directly to interlex'

    @basic
    def contributions(self, *args, **kwargs):
        return 'TODO slicing on contribs ? or use versions?'

    # TODO POST ?private if private PUT (to change mapping) PATCH like readable
    @basic
    def uris(self, group, uri_path, db=None):
        # owl:Class, owl:*Property
        # owl:Ontology
        # /<group>/ontologies/obo/uberon.owl << this way
        # /<group>/uris/obo/uberon.owl << no mapping to ontologies here
        title = f'uris.{group}:{uri_path}'
        PREFIXES, mgraph = self.getGroupCuries(group)
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
            _ = [mgraph.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

            return tripleRender(request, mgraph, group, id, object_to_existing)

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
                return message, 409
            elif not to_add:
                return 'No new curies were added.', 409  # FIXME

            values = tuple((cp, ip) for cp, ip in to_add.items())

            # FIXME impl in load pls
            values_template, params = makeParamsValues(values,
                                                        constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
            params['group'] = group
            base = 'INSERT INTO curies (group_id, curie_prefix, iri_prefix) VALUES '
            sql = base + values_template
            try:
                resp = self.session.execute(sql, params)
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
    def curies(self, group, prefix_iri_curie, db=None):
        # FIXME confusion between group (aka group) and logged in group :/
        #printD(prefix_iri_curie)
        PREFIXES, g = self.getGroupCuries(group)
        qname, expand = g.qname, g.expand
        if prefix_iri_curie.startswith('http') or prefix_iri_curie.startswith('file'):  # TODO decide about urlencoding
            iri = prefix_iri_curie
            curie = qname(iri)
            return curie
        elif ':' in prefix_iri_curie:
            curie = prefix_iri_curie
            prefix, suffix = curie.split(':', 1)
            if prefix == 'ILX':  # TODO more matches?
                id = suffix
            else:
                id = None

            try:
                iri = expand(curie)
            except KeyError:
                return f'Unknown prefix {prefix}', 404

            maybe_ilx = self.isIlxIri(iri)
            if not suffix and maybe_ilx:
                group, id = maybe_ilx
                # overwrite user here because there are (admittedly strange)
                # cases where someone will have a curie that points to another
                # user's namespace, and we already controlled for the requesting user
                # when we asked for their curies
                # TODO FIXME consider how this interacts with whether the user has
                # set to have all the common curies point to their own space
                # TODO failover behavior for curies is needed for the full consideration

            if 'local' in request.args and request.args['local'].lower() == 'true':
                if id is None:
                    sql = ('SELECT ilx_id FROM existing_iris AS e WHERE e.iri = :iri '
                            'AND (e.group_id = :group_id OR e.group_id = 0)')  # base vs curated
                    args = dict(iri=iri, group_id=db.group_id)
                    try:
                        resp = next(self.session.execute(sql, args))
                        id = resp.ilx_id
                    except AttributeError as e:
                        embed()
                        raise e
                    except StopIteration:
                        # FIXME this breaks the semantics, but it seems to be the only
                        # current way to get the local interlex content view of unmapped
                        # terms, which we do need a solution for, even if the plan is to
                        # force all terms to be mapped
                        try:
                            _, _, func = tripleRender.check(request)
                        except UnsupportedType as e:
                            return e.message, e.code

                        resp = self.queries.getBySubject(iri, group)
                        te = TripleExporter()
                        _ = [g.g.add(te.triple(*r)) for r in resp]
                        object_to_existing = self.queries.getResponseExisting(resp, type='o')
                        # FIXME we need to abstract TripleRender to work with any ontology name
                        # FIXME we probably need a uri.interlex.org/base/iri/purl.obolibrary.org/obo/ trick ...
                        # as a way to resolve to local content ...
                        # this is the much better solution here

                        if func == tripleRender.ttl_html:  # FIXME hackish?
                            # FIXME getting additional content from the db based on file type
                            # leads to breakdown of separation of concerns due to statefulness
                            # slow but probably worth it for enhancing readability
                            iris = set(e for t in g.g for e in t if isinstance(e, URIRef))
                            labels = {URIRef(s):label for s, label in self.queries.getLabels(group, iris)}
                        else:
                            labels = None

                        id = 'None-FIXMETODO'
                        title = 'InterLex local' + curie
                        return tripleRender(request, g, group, id, object_to_existing, title, labels=labels)
                        return abort(404)
                        pass

                return redirect(url_for(f'Endpoints.ilx /<group>/{ilx_pattern}',
                                        group=group, id=id), code=302)

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
        try:
            loader = self.FileFromPost(group, dbuser, self.reference_host)
        except NotGroup:
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

    # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
    # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
    # TODO HEAD -> return owl:Ontology section
    @basic
    def ontologies_(self, group, db=None):
        return json.dumps('your list sir')

    @basic
    def ontologies(self, group, filename, extension=None, ont_path='', db=None):
        # on POST for new file check to make sure that that the ontology iri matches the post endpoint
        # response needs to include warnings about any parts of the file that could not be lifted to interlex
        # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
        # we should be able to track file 'renames' without too much trouble
        #printD(group, filename, extension, ont_path)
        dbuser = db.user  # FIXME make sure that the only way that db.user can be set is if it was an auth user
                        # the current implementation does not gurantee that, probably easiest to pass the token
                        # again for insurance ...
        #if user not in getUploadUsers(group):
        #printD(request.headers)

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
                #PREFIXES, mgraph = self.getGroupCuries(group)
                #_ = [mgraph.g.add(te.star_triple(*r)) for r in oof]
                #return tripleRender(request, mgraph, user, 'FIXMEFIXME', object_to_existing)

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
            except NotGroup:
                return abort(404)

            existing = False  # TODO check if the file already exists
            # check what is being posted
            #embed()
            #if requests.args:
                #printD(request.args)
            #elif request.json is not None:  # jsonld u r no fun
                #printD(request.json)
                #{'iri':'http://purl.obolibrary.org/obo/uberon.owl'}
            #elif request.data:
                #printD(request.data)

            if not existing:
                if request.files:
                    # TODO retrieve and if existing-iri make sure stuff matches
                    printD(request.files)
                if request.json is not None:  # jsonld u r no fun
                    printD(request.json)
                    if 'name' in request.json:
                        name = request.json['name']  # FIXME not quite right?
                        if name.startswith('file://'):
                            return 'file:// scheme not allowed', 400

                        if 'bound-name' in request.json:
                            expected_bound_name = request.json['bound-name']
                        else:
                            expected_bound_name = None

                        # FIXME this should be handled elsewhere for user
                        if match_path not in name and match_path not in expected_bound_name:
                            return f'No common name between {expected_bound_name} and {reference_name}', 400

                        # FIXME this needs to just go as a race
                        # either await sleep(limit) or await load(thing)
                        try:
                            loader = self.FileFromIRI(group, dbuser, reference_name)
                            #task = tasks.multiple(loader, name, expected_bound_name)
                            # task.jobid
                            # then wait for our max time and return the jobid/tracker or the result
                            #return task.get()  # timeout=10 or something
                            will_batch = loader.check(name)
                            if will_batch:
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
                        except NameCheckError as e:
                            return e.message, e.code

                        setup_ok = loader(expected_bound_name)
                        if setup_ok is not None:
                            return setup_ok

                        out = loader.load()

                        # TODO get actual user from the api key
                        # out = f(user, filepath, ontology_iri, new=True)
                        #embed()
                        printD('should be done running?')

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
            return abort(404)
        else:
            return 'TODO\n'

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
        return 'TODO\n'


class Versions(Endpoints):
    # TODO own/diff here could make it much easier to view changes
    @basic
    def ilx(self, group, epoch_verstr_id, id, db=None):
        # TODO epoch and reengineer how ilx is implemented
        # so that queries can be conducted at a point in time
        # sigh dataomic
        # or just give up on the reuseabilty of the query structure?
        return super().ilx(group=group, id=id, db=db)  # have to use kwargs for basic

    @basic
    def readable(self, group, epoch_verstr_id, word, db=None):
        return request.path

    @basic
    def uris(self, group, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic
    def curies_(self, group, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic
    def curies(self, group, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class Own(Endpoints):
    @basic2
    def uris(self, group, other_group, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, group, other_group, db=None):
        PREFIXES, g = self.getGroupCuries(group)
        otherPREFIXES, g = self.getGroupCuries(other_group)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group, prefix_iri_curie, db=None):
        return request.path

    @basic2
    def ontologies(self, group, other_group, filename, extension=None, ont_path='', db=None):
        return request.path

    @basic2
    def ontologies_version(self, group, other_group, filename, epoch_verstr_ont,
                            filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            return abort(404)
        else:
            return 'TODO\n'


class OwnVersions(Own, Versions):
    @basic2
    def ilx(self, group, other_group, epoch_verstr_id, id, db=None):
        return request.path

    @basic2
    def readable(self, group, other_group, epoch_verstr_id, word, db=None):
        return request.path

    @basic2
    def uris(self, group, other_group, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, group, other_group, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class Diff(Endpoints):
    @basic2
    def ilx(self, group, other_group_diff, id, db=None):
        return request.path

    @basic
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
        return request.path

    @basic2
    def uris(self, group, other_group_diff, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, group, other_group_diff, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group_diff)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group_diff, prefix_iri_curie, db=None):
        return request.path
    @basic2
    def ontologies(self, group, other_group_diff, filename, extension=None, ont_path='', db=None):
        return request.path
    @basic2
    def ontologies_version(self, group, other_group_diff, filename,
                            epoch_verstr_ont, filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            return abort(404)
        else:
            return 'TODO\n'


class DiffVersions(Diff, Versions):
    @basic2
    def ilx(self, group, other_group_diff, epoch_verstr_id, id, db=None):
        return request.path
    @basic2
    def readable(self, group, other_group_diff, epoch_verstr_id, word, db=None):
        return request.path
    @basic2
    def uris(self, group, other_group_diff, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, group, other_group_diff, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(group)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_group_diff, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, group, other_group_diff, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class VersionsOwn(Endpoints):
    pass  # TODO


class VersionsDiff(Endpoints):
    pass  # TODO


