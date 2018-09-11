import os
import json
from datetime import datetime
from functools import wraps
import rdflib
import sqlalchemy as sa
from flask import request, redirect, url_for, abort
from pyontutils.core import makeGraph
from pyontutils.utils import TermColors as tc
from pyontutils.ttlser import CustomTurtleSerializer
from pyontutils.htmlfun import atag, btag, h2tag, htmldoc
from pyontutils.htmlfun import table_style, details_style, render_table
from pyontutils.qnamefix import cull_prefixes
from pyontutils.namespaces import makePrefixes, definition
from pyontutils.closed_namespaces import rdf, rdfs, owl
from interlex import config
from interlex.exc import NotGroup, NameCheckError
from interlex.auth import Auth
from interlex.core import printD
from interlex.dump import TripleExporter, Queries
from interlex.load import FileFromIRIFactory, FileFromPostFactory, TripleLoaderFactory, BasicDBFactory, UnsafeBasicDBFactory
from interlex import tasks
from interlex.config import ilx_pattern
from IPython import embed


class TripleRender:
    def __init__(self):
        self.mimetypes = {'text/html':self.html,
                          'application/json':self.json,
                          'text/ttl':self.ttl,  # not real
                          'text/turtle':self.ttl,}

    def __call__(self, request, mgraph, user, id, object_to_existing, title=None):
        mimetype = request.mimetype if request.mimetype else 'text/html'
        if not mgraph.g:
            if mimetype == 'text/html':
                return abort(404)
            else:
                return '', 404
        try:
            out = self.mimetypes[mimetype](request, mgraph, user, id, object_to_existing, title)
            return out, 200, {'Content-Type': mimetype}
        except KeyError:
            print(mimetype)
            return abort(415)

    def iri_selection_logic(self):  # TODO
        """ For a given set of conversion rules (i.e. from a user)
            when given an iri, convert it to the preferred form.
            Use a precedence list base on
            1. users
            2. orgs
            3. curie prefixes
            4. iri prefixes (?)
            5. etc ...
            See the ilx spec doc for this. We want this in its own class
            and will just be calling it from here. """

    def curie_selection_logic(self):
        """ Same as iri selection but for curies """

    def html(self, request, mgraph, user, id, object_to_existing, title):
        graph = mgraph.g
        cts = CustomTurtleSerializer(graph)
        gsortkey = cts._globalSortKey
        psortkey = lambda p: cts.predicate_rank[p]
        def sortkey(triple):
            s, p, o = triple
            return gsortkey(s), psortkey(p), gsortkey(o)

        trips = (tuple(atag(e, mgraph.qname(e))
                       if isinstance(e, rdflib.URIRef) and e.startswith('http')
                       else str(e)
                       for e in t)
                 for t in sorted(graph, key=sortkey))

        return htmldoc(render_table(trips, 'subject', 'predicate', 'object'),
                       title=title,
                       styles=(table_style,))

    def ttl(self, request, mgraph, user, id, object_to_existing, title):
        graph = mgraph.g
        nowish = datetime.utcnow()  # request doesn't have this
        epoch = nowish.timestamp()
        iso = nowish.isoformat()
        ontid = rdflib.URIRef(f'http://uri.interlex.org/{user}'
                              f'/ontologies/ilx_{id}')
        ver_ontid = rdflib.URIRef(ontid + f'/version/{epoch}/ilx_{id}')
        graph.add((ontid, rdf.type, owl.Ontology))
        graph.add((ontid, owl.versionIRI, ver_ontid))
        graph.add((ontid, owl.versionInfo, rdflib.Literal(iso)))
        graph.add((ontid, rdfs.comment, rdflib.Literal('InterLex single term result for '
                                                       f'{user}/ilx_{id} at {iso}')))
        # TODO consider data identity?
        ng = cull_prefixes(graph, {k:v for k, v in graph.namespaces()})  # ICK as usual
        return ng.g.serialize(format='nifttl')

    def json(self, request, mgraph, user, id, object_to_existing, title):
        # lol
        graph = mgraph.g
        ng = cull_prefixes(graph, {k:v for k, v in graph.namespaces()})  # ICK as usual
        out = {'prefixes': {k:v for k, v in ng.g.namespaces()},
               'triples': [[mgraph.qname(e)
                            if isinstance(e, rdflib.URIRef) and e.startswith('http')
                            else str(e)
                            for e in t ]
                           for t in graph]}
        return json.dumps(out)


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
            group = kwargs['user']  # FIXME really group
        except KeyError as e:
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
        group = kwargs['user']  # FIXME really group
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

        if 'other_user' in kwargs:
            other_group = kwargs['other_user']
        elif 'other_user_diff' in kwargs:
            other_group = kwargs['other_user_diff']

        db2 = self.getBasicInfoReadOnly(other_group, auth_user)
        if db2 is None:
            return abort(404)

        db.other = db2
        return function(self, *args, **kwargs)

    return basic2_checks


class Endpoints:
    reference_host = None  # this has to be set globally later
    def __init__(self, db):
        self.db = db
        self.session = self.db.session
        self.auth = Auth(self.session)
        self.FileFromIRI = FileFromIRIFactory(self.session)  # FIXME I think these go in tasks
        self.FileFromPost = FileFromPostFactory(self.session)  # FIXME I think these go in tasks
        self.BasicDB = BasicDBFactory(self.session)
        self.UnsafeBasicDB = UnsafeBasicDBFactory(self.session)
        self.queries = Queries(self.session, self)

    @property
    def link_to_new_token(self):
        return 'TODO url_for'

    def getBasicInfo(self, group, user, token):
        try:
            return self.BasicDB(group, user, token, read_only=False)
        except NotGroup:
            return None

    def getBasicInfoReadOnly(self, group, user):
        """ Read only access means that any identifiers that are provisional
            cannot be seen by people who do not have edit acces. This is intention,
            and is an attempt to allow editors to work in their own space without
            risking 'identifier escape' """
        # this code is intentionally reproduced so that the function name
        # stands out to the (human) reader
        try:
            # we keep the user for provenance and auditing purposes
            return self.UnsafeBasicDB(group, user, read_only=True)
        except NotGroup:
            printD('not group?')
            return None

    def getGroupCuries(self, group, epoch_verstr=None):
        PREFIXES = self.queries.getGroupCuries(group, epoch_verstr)
        currentHost = request.headers['Host']
        PREFIXES = {cp:ip.replace('uri.interlex.org', currentHost) if config.debug else ip
                    # TODO app.debug should probably be switched out for something configurable
                    for cp, ip in PREFIXES.items()}
        #printD(PREFIXES)
        g = makeGraph(group + '_curies_helper', prefixes=PREFIXES)
        return PREFIXES, g

    def build_reference_name(self, user, path):
        # need this for testing, in an ideal world we read from headers
        return os.path.join(f'https://{self.reference_host}', user, path)

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
        mapping = {
            ilx_pattern:self.ilx,
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

    # TODO PATCH
    @basic
    def ilx(self, user, id, db=None):
        # TODO allow PATCH here with {'add':[triples], 'delete':[triples]}

        if user != 'base' and user != 'latest':
            sql = 'SELECT id FROM interlex_ids WHERE id = :id'
            try:
                res = next(self.session.execute(sql, dict(id=id)))
                id = res.id
                #printD(id, db.group_id)
            except StopIteration:
                return abort(404)

        PREFIXES, g = self.getGroupCuries(user)
        resp = self.queries.getById(id, user)
        #printD(resp)
        # TODO formatting rules for subject and objects
        object_to_existing = self.queries.getResponseExisting(resp, type='o')

        te = TripleExporter()
        _ = [g.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

        # TODO list users with variants from base and/org curated
        # we need an 'uncurated not latest' or do we?
        if user == 'base':
            title = f'ILX:{id}'
        else:
            title = f'ilx.{user}:ilx_{id}'

        return tripleRender(request, g, user, id, object_to_existing, title)

    @basic
    def lexical(self, user, label, db=None):
        do_redirect, identifier_or_defs = self.queries.getByLabel(label, user)
        if do_redirect:
            return redirect(identifier_or_defs)
        elif not identifier_or_defs:
            return 'REDLINK -> AMBIGUATION -> TODO'
        else:
            PREFIXES, g = self.getGroupCuries(user)
            defs = [(g.qname(s), d) for s, d in identifier_or_defs]
            title = f'{label} (disambiguation)'  # mirror wiki
            # TODO resolve existing_iri mappings so they don't show up here
            content = render_table(defs, 'Identifier', atag(definition, 'definition:')),
            return htmldoc(h2tag(f'{label} (disambiguation)'),
                           content, title=title, styles=(table_style,))

    # TODO PATCH only admin can change the community readable mappings just like community curies
    @basic
    def readable(self, user, word, db=None):
        return request.path

    @basic
    def contributions_(self, user, db=None):
        # without at type lands at the additions and deletions page
        return 'TODO identity for user contribs directly to interlex'

    @basic
    def contributions(self, *args, **kwargs):
        return 'TODO slicing on contribs ? or use versions?'

    # TODO POST ?private if private PUT (to change mapping) PATCH like readable
    @basic
    def uris(self, user, uri_path, db=None):
        # owl:Class, owl:*Property
        # owl:Ontology
        # /<user>/ontologies/obo/uberon.owl << this way
        # /<user>/uris/obo/uberon.owl << no mapping to ontologies here
        title = f'uris.{user}:{uri_path}'
        PREFIXES, mgraph = self.getGroupCuries(user)
        resp = self.queries.getByGroupUriPath(user, uri_path, redirect=False)
        if not resp:
            iri = request.url
            suggestions = ''  # TODO this requires them to have uploaded or we guess the suffix
            # FIXME content type :/
            return htmldoc(f'404 error. <b>{user} {uri_path}</b> has not been mapped to an InterLex id!\n{suggestions}',
                            title='404 ' + title), 404

        else:
            object_to_existing = self.queries.getResponseExisting(resp, type='o')

            te = TripleExporter()
            _ = [mgraph.g.add(te.triple(*r)) for r in resp]  # FIXME ah type casting

            return tripleRender(request, mgraph, user, id, object_to_existing)

    # TODO POST PUT PATCH
    # just overload post? don't allow changing? hrm?!?!
    @basic
    def curies_(self, user, db=None):
        # TODO auth
        PREFIXES, g = self.getGroupCuries(user)
        if request.method == 'POST':
            # TODO diff against existing
            if request.json is None:
                return 'No curies were sent\n', 400
            newPrefixes = request.json

            ok, to_add, existing, message = diffCuries(PREFIXES, newPrefixes)
            # FIXME this is not inside a transaction so it could fail!!!!
            if not ok:
                return message, 409

            values = tuple((cp, ip) for cp, ip in to_add.items())

            # FIXME impl in load pls
            values_template, params = makeParamsValues(values,
                                                        constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
            params['group'] = user
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


        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    # TODO POST PATCH PUT
    @basic
    def curies(self, user, prefix_iri_curie, db=None):
        PREFIXES, g = self.getGroupCuries(user)
        qname, expand = g.qname, g.expand
        if prefix_iri_curie.startswith('http') or prefix_iri_curie.startswith('file'):  # TODO decide about urlencoding
            iri = prefix_iri_curie
            curie = qname(iri)
            return curie
        elif ':' in prefix_iri_curie:
            curie = prefix_iri_curie
            try:
                iri = expand(curie)
            except KeyError:
                prefix, *_ = curie.split(':')
                return f'Unknown prefix {prefix}', 404
            if 'local' in request.args and request.args['local'].lower() == 'true':
                sql = ('SELECT ilx_id FROM existing_iris AS e WHERE e.iri = :iri '
                        'AND (e.group_id = :group_id OR e.group_id = 0)')  # base vs curated
                try:
                    resp = next(self.session.execute(sql, dict(iri=iri, group_id=db.group_id)))
                    return redirect(url_for(f'Endpoints.ilx /<user>/{ilx_pattern}',
                                            user=user, id=resp.ilx_id), code=302)
                except AttributeError as e:
                    embed()
                    raise e
                except StopIteration:
                    return abort(404)
                    pass

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
    def upload(self, user, db=None):
        """ Expects files """
        # only POST
        # TODO auth

        # TODO load stats etc
        try:
            loader = self.FileFromPost(user, user, self.reference_host)
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
        for name, file in request.files.items():
            setup_ok = loader(file, header, create)
            if setup_ok is not None:
                return setup_ok
            names.append({'reference_name':loader.reference_name,
                            'bound_name':loader.Loader.bound_name})  # sigh json
            load_ok = loader.load()
            if load_ok is not None:
                msg, code = load_ok
                data = {'error':msg, 'names':names}
                sigh = json.dumps(data)
                return sigh, code, {'Content-Type':'application/json'}

        return json.dumps(names)

    # TODO enable POST here from users (via apikey) that are contributor or greater in a group admin is blocked from posting in this way
    # TODO curies from ontology files vs error on unknown? vs warn that curies were not added << last option best, warn that they were not added
    # TODO HEAD -> return owl:Ontology section
    @basic
    def ontologies_(self, user, db=None):
        return json.dumps('your list sir')

    @basic
    def ontologies(self, user, filename, extension=None, ont_path='', db=None):
        # on POST for new file check to make sure that that the ontology iri matches the post endpoint
        # response needs to include warnings about any parts of the file that could not be lifted to interlex
        # TODO for ?iri=external-iri validate that uri_host(external-iri) and /ontologies/... ... match
        # we should be able to track file 'renames' without too much trouble
        #printD(user, filename, extension, ont_path)
        group = user  #  FIXME
        user = db.user  # FIXME make sure that the only way that db.user can be set is if it was an auth user
                        # the current implementation does not gurantee that, probably easiest to pass the token
                        # again for insurance ...
        #if user not in getUploadUsers(group):
        #printD(request.headers)

        if request.method == 'HEAD':
            # TODO return bound_name + metadata
            return 'HEAD TODO\n'
        if request.method == 'POST':
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
                            loader = self.FileFromIRI(group, user, reference_name, self.reference_host)
                            #task = tasks.multiple(loader, name, expected_bound_name)
                            # task.jobid
                            # then wait for our max time and return the jobid/tracker or the result
                            #return task.get()  # timeout=10 or something
                            will_batch = loader.check(name)
                            if will_batch:
                                # and of course with this version api gets caught,
                                # probably session is the issue
                                tasks.session = self.session
                                tasks.base_ffi(group, user, reference_name,
                                               self.reference_host, name, expected_bound_name)
                                # so.owl load works fine but uberon load seems eternal
                                # and never finishes for some reason
                                return 'DEBUG'
                                task = tasks.long_ffi.apply_async((group, user, reference_name,
                                                                   self.reference_host, name, expected_bound_name),
                                                                  serializer='pickle')
                                # ya so this doesn't quite work ...
                                #task = tasks.long_load.apply_async((loader, expected_bound_name),
                                                                   #serializer='pickle')
                                embed()
                                return f'that\'s quite a large file you\'ve go there!\nit has been submitted for processing {task.id}', 202
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
    def ontologies_version(self, user, filename, epoch_verstr_ont,
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
    def ilx(self, user, epoch_verstr_id, id, db=None):
        # TODO epoch and reengineer how ilx is implemented
        # so that queries can be conducted at a point in time
        # sigh dataomic
        # or just give up on the reuseabilty of the query structure?
        return super().ilx(user=user, id=id, db=db)  # have to use kwargs for basic

    @basic
    def readable(self, user, epoch_verstr_id, word, db=None):
        return request.path

    @basic
    def uris(self, user, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic
    def curies_(self, user, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(user, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic
    def curies(self, user, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class Own(Endpoints):
    @basic2
    def uris(self, user, other_user, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, user, other_user, db=None):
        PREFIXES, g = self.getGroupCuries(user)
        otherPREFIXES, g = self.getGroupCuries(other_user)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, user, other_user, prefix_iri_curie, db=None):
        return request.path

    @basic2
    def ontologies(self, user, other_user, filename, extension=None, ont_path='', db=None):
        return request.path

    @basic2
    def ontologies_version(self, user, other_user, filename, epoch_verstr_ont,
                            filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            return abort(404)
        else:
            return 'TODO\n'


class OwnVersions(Own, Versions):
    @basic2
    def ilx(self, user, other_user, epoch_verstr_id, id, db=None):
        return request.path

    @basic2
    def readable(self, user, other_user, epoch_verstr_id, word, db=None):
        return request.path

    @basic2
    def uris(self, user, other_user, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, user, other_user, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_user, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, user, other_user, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class Diff(Endpoints):
    @basic2
    def ilx(self, user, other_user_diff, id, db=None):
        return request.path

    @basic
    def lexical(self, user, other_user_diff, label, db=None):
        # FIXME the logic here is all wonky
        do_redirect, identifier_or_defs = self.queries.getByLabel(label, user)
        if do_redirect:
            # FIXME could be a user level redirect
            return ''  # no difference
        elif not identifier_or_defs:
            return 'REDLINK -> AMBIGUATION -> TODO'
        else:
            other_do_redirect, other_identifier_or_defs = self.queries.getByLabel(label, other_user_diff)
            if other_do_redirect:
                # FIXME this is actually probably where we want to do this diff ...
                return 'FIXME we need to handle this properly for diffing, probably need to return the actual value'
            else:
                PREFIXES, g = self.getGroupCuries(user)
                defs = [(g.qname(s), d) for s, d in identifier_or_defs]
                other_defs = [(g.qname(s), d) for s, d in other_identifier_or_defs]
                title = f'{label} (disambiguation)'  # mirror wiki
                # TODO resolve existing_iri mappings so they don't show up here
                return htmldoc(h2tag(f'{label} (disambiguation)'),
                               render_table(tuple(), btag(user), ''),  # TODO links to user pages?
                               render_table(defs, 'Identifier',
                                            atag(definition, 'definition:')),
                               render_table(tuple(), btag(other_user_diff), ''),
                               render_table(other_defs, 'Identifier',
                                            atag(definition, 'definition:')),
                               title=title,
                               styles=(table_style,))

    @basic2
    def readable(self, user, other_user_diff, word, db=None):
        return request.path

    @basic2
    def uris(self, user, other_user_diff, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, user, other_user_diff, db=None):
        PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_user_diff)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, user, other_user_diff, prefix_iri_curie, db=None):
        return request.path
    @basic2
    def ontologies(self, user, other_user_diff, filename, extension=None, ont_path='', db=None):
        return request.path
    @basic2
    def ontologies_version(self, user, other_user_diff, filename,
                            epoch_verstr_ont, filename_terminal, extension=None, ont_path='', db=None):
        if filename != filename_terminal:
            return abort(404)
        else:
            return 'TODO\n'


class DiffVersions(Diff, Versions):
    @basic2
    def ilx(self, user, other_user_diff, epoch_verstr_id, id, db=None):
        return request.path
    @basic2
    def readable(self, user, other_user_diff, epoch_verstr_id, word, db=None):
        return request.path
    @basic2
    def uris(self, user, other_user_diff, epoch_verstr_id, uri_path, db=None):
        return request.path

    @basic2
    def curies_(self, user, other_user_diff, epoch_verstr_id, db=None):
        PREFIXES, g = self.getGroupCuries(user)  # TODO OwnVersionsVersions for double diff (not used here)
        otherPREFIXES, g = self.getGroupCuries(other_user_diff, epoch_verstr=epoch_verstr_id)
        return 'TODO\n'
        return json.dumps(PREFIXES), 200, {'Content-Type': 'application/json'}

    @basic2
    def curies(self, user, other_user_diff, epoch_verstr_id, prefix_iri_curie, db=None):
        return request.path


class VersionsOwn(Endpoints):
    pass  # TODO


class VersionsDiff(Endpoints):
    pass  # TODO


