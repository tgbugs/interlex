"""
database queries that are more than select e.g. all the user and group
stuff beyond dump and load
"""

from sqlalchemy.sql import text as sql_text
from interlex import config
from interlex.core import makeParamsValues
from interlex.utils import log

log = log.getChild('dbstuff')


class Stuff:
    def __init__(self, session):
        self.session = session

    def session_execute(self, sql, params=None):
        return self.session.execute(sql_text(sql), params=params)

    def insert_curies(self, group, curies):
        values = tuple((cp, ip) for cp, ip in curies.items())

        # FIXME impl in load pls
        values_template, params = makeParamsValues(values,
                                                   constants=('persFromGroupname(:group)',))  # FIXME surely this is slow as balls
        params['group'] = group
        base = 'INSERT INTO curies (perspective, curie_prefix, iri_namespace) VALUES '
        sql = base + values_template
        return self.session_execute(sql, params)

    def org_new(self, orgname, creator):
        params = dict(groupname=orgname, creator=creator)
        # FIXME TODO ensure that creator own_role is owner ?
        sql = '''
WITH grow AS (INSERT INTO groups (groupname) VALUES (:groupname) RETURNING id),
gro AS (INSERT INTO orgs (id, creator_id) SELECT id, idFromGroupname(:creator) FROM grow),
oup AS (INSERT INTO user_permissions (group_id, user_id, user_role) SELECT id, idFromGroupname(:creator), 'owner' FROM grow)
SELECT o.id FROM orgs AS o JOIN groups AS g ON g.id = o.id WHERE g.groupname = :groupname
'''
        return list(self.session_execute(sql, params=params))

    def user_new(self, username, email, argon2_string=None, orcid=None, email_verify=True):
        params = dict(groupname=username, email=email)

        if orcid is not None:
            params['orcid'] = orcid
            sql_users = 'gru AS (INSERT INTO users (id, orcid) SELECT id, :orcid FROM grow RETURNING id),'
        else:
            sql_users = 'gru AS (INSERT INTO users (id) SELECT id FROM grow RETURNING id),'

        if argon2_string is not None:
            params['argon2_string'] = argon2_string
            # plpgsql cte insert trigger
            # https://www.postgresql.org/message-id/CAHzbRKf3fXdOeway0yQ5+XJz3vObe_T6C=TYMdh6tFw33jUxcA@mail.gmail.com
            # https://www.postgresql.org/message-id/CAKFQuwYsCPJwNwSjvsP-FVEiojCgLoWpeir%3Dczuk311MKTs69w%40mail.gmail.com
            # https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING
            # The sub-statements in WITH are executed concurrently with each
            # other and with the main query. Therefore, when using
            # data-modifying statements in WITH, the order in which the
            # specified updates actually happen is unpredictable.
            sql_pass = 'INSERT INTO user_passwords (user_id, argon2_string) SELECT user_id, :argon2_string FROM gre RETURNING user_id'
        else:
            sql_pass = 'SELECT user_id FROM gre'

        if email_verify:
            ever, ever_val = '', ''
        else:
            ever = ', email_validated'
            ever_val = ', CURRENT_TIMESTAMP'
            # using CURRENT_TIMESTAMP means we can detect unvalidated emails,
            # also user email_validated will be true but no email will be

        sql = f'''
WITH grow AS (INSERT INTO groups (groupname) VALUES (:groupname) RETURNING id),
{sql_users}
gre AS (INSERT INTO user_emails (user_id, email, email_primary{ever}) SELECT id, :email, TRUE{ever_val} FROM gru RETURNING user_id)
{sql_pass};
SELECT uss.user_id, uss.surrogate FROM user_session_surrogates AS uss LEFT JOIN groups AS g ON g.id = uss.user_id WHERE g.groupname = :groupname;
'''
        # FIXME TODO wrap all of these functions in an error handler that
        # translates the sql error
        return list(self.session_execute(sql, params=params))

    def _user_new(self, username, argon2_string, orcid, email):
        # FIXME TODO orcid and argon2_string are optional

        # TODO multiple operations see cli.Ops.password
        #sql = 'INSERT INTO user_passwords (user_id, argon2_string) VALUES ((SELECT id FROM groups WHERE groupname :groupname JOIN users ON groups.id = users.id), :argon2_string)'
        params = dict(groupname=username, argon2_string=argon2_string, orcid=orcid, email=email)
        sql = '''
WITH grow AS (INSERT INTO groups (groupname) VALUES (:groupname) RETURNING id),
gru AS (INSERT INTO users (id, orcid) SELECT id, :orcid FROM grow RETURNING id),
gre AS (INSERT INTO user_emails (user_id, email, email_primary) SELECT id, :email, TRUE FROM gru RETURNING user_id)
INSERT INTO user_passwords (user_id, argon2_string) SELECT user_id, :argon2_string FROM gre RETURNING user_id
'''
        return list(self.session_execute(sql, params=params))

    def email_add(self, group, email, email_verify=True):
        args = dict(group=group, email=email)

        if email_verify:
            ever, ever_val = '', ''
        else:
            ever = ', email_validated'
            ever_val = ', CURRENT_TIMESTAMP'
            # using CURRENT_TIMESTAMP means we can detect unvalidated emails,
            # also user email_validated will be true but no email will be

        sql = f'INSERT INTO user_emails (user_id, email, email_primary{ever}) VALUES (idFromGroupname(:group), :email, FALSE{ever_val}) RETURNING email'
        return list(self.session_execute(sql, args))

    def getUserEmailMeta(self, group, email):
        # need group to prevent cross group requests for email validation
        args = dict(group=group, email=email)
        sql = 'select * from user_emails where email = :email and user_id = idFromGroupname(:group)'
        return list(self.session_execute(sql, args))

    def email_verify_start(self, group, email, token, delay_seconds=None, lifetime_seconds=None):
        if lifetime_seconds is not None and delay_seconds is None:
            msg = 'delay_seconds cannot be None if lifetime_seconds is not None'
            raise TypeError(msg)

        args = dict(group=group, email=email, token=token)

        if delay_seconds is None:
            sql = '''
INSERT INTO emails_validating (user_id, email, token) VALUES
(idFromGroupname(:group), :email, :token)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''

        else:
            args['delay_seconds'] = delay_seconds
            if lifetime_seconds is None:
                sql = '''
INSERT INTO emails_validating (user_id, email, token, delay_seconds) VALUES
(idFromGroupname(:group), :email, :token, :delay_seconds)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''
            else:
                args['lifetime_seconds'] = lifetime_seconds
                sql = '''
INSERT INTO emails_validating (user_id, email, token, delay_seconds, lifetime_seconds) VALUES
(idFromGroupname(:group), :email, :token, :delay_seconds, :lifetime_seconds)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''
        return list(self.session_execute(sql, args))

    def email_verify_complete(self, token):
        args = dict(token=token)
        sql = 'SELECT email_verify_complete(:token)'
        return list(self.session_execute(sql, args))  # FIXME this can and will error on token ver failure

    def user_recover_start(self, group, token, delay_seconds=None, lifetime_seconds=None):
        if lifetime_seconds is not None and delay_seconds is None:
            msg = 'delay_seconds cannot be None if lifetime_seconds is not None'
            raise TypeError(msg)

        args = dict(group=group, token=token)

        if delay_seconds is None:
            sql = '''
INSERT INTO users_recovering (user_id, token) VALUES
(idFromGroupname(:group), :token)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''

        else:
            args['delay_seconds'] = delay_seconds
            if lifetime_seconds is None:
                sql = '''
INSERT INTO users_recovering (user_id, token, delay_seconds) VALUES
(idFromGroupname(:group), :token, :delay_seconds)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''
            else:
                args['lifetime_seconds'] = lifetime_seconds
                sql = '''
INSERT INTO users_recovering (user_id, token, delay_seconds, lifetime_seconds) VALUES
(idFromGroupname(:group), :token, :delay_seconds, :lifetime_seconds)
RETURNING created_datetime, delay_seconds, lifetime_seconds
'''
        return list(self.session_execute(sql, args))

    def getUserPassword(self, group):
        sql = '''
SELECT * FROM groups AS g
JOIN users AS u ON g.id = u.id
JOIN user_passwords AS up ON up.user_id = u.id
JOIN user_session_surrogates AS uss ON uss.user_id = u.id
WHERE g.groupname = :groupname AND g.own_role <= 'pending'
'''
        return list(self.session_execute(sql, dict(groupname=group)))

    def insertOrcidMetadata(self, orcid, name, token_type, token_scope, token_access, token_refresh, lifetime_seconds,
                            openid_token=None, user=None):
        args = dict(
            orcid=orcid,
            name=name,
            token_type=token_type,
            token_scope=token_scope,
            token_access=token_access,
            token_refresh=token_refresh,
            lifetime_seconds=lifetime_seconds)

        idt, idtv = ('', '') if openid_token is None else (', openid_token', ', :openid_token')

        sql = f'''
INSERT INTO orcid_metadata (orcid, name, token_type, token_scope, token_access, token_refresh, lifetime_seconds{idt})
VALUES (:orcid, :name, :token_type, :token_scope, :token_access, :token_refresh, :lifetime_seconds{idtv})
'''

        if openid_token is not None:
            args['openid_token'] = openid_token

        if user is not None:
            args['group'] = user
            sql += ';\nUPDATE users SET orcid = :orcid WHERE id = idFromGroupname(:group);\n'

        return self.session_execute(sql, args)

    def updateUserOrcid(self, user, orcid):
        # this should pretty much never be used by itself because the only time
        # an orcid in the users table should be updated is when we go from null
        # -> something and in the very rare case that a user actively wants to
        # change their associated orcid for some reason (e.g. institutions
        # behaving badly) then we should be reauthing and calling
        # insertOrcidMetadata with user not None
        raise NotImplementedError('do not use this')
        args = dict(group=user, orcid=orcid)
        sql = 'UPDATE users SET orcid = :orcid WHERE id = idFromGroupname(:group)'
        list(self.session_execute(sql, args))

    def getOrcidMetadataUserByOrcid(self, orcid):
        args = dict(orcid=orcid)
        sql = ('SELECT om.*, u.id, u.orcid as user_orcid '
               'FROM orcid_metadata AS om LEFT JOIN users AS u ON u.orcid = om.orcid WHERE om.orcid = :orcid')
        return list(self.session_execute(sql, args))

    def getUserByOrcid(self, orcid):
        args = dict(orcid=orcid)
        sql = "SELECT * FROM users AS u JOIN groups AS g ON g.id = u.id WHERE u.orcid = :orcid AND g.own_role <= 'pending'"
        return list(self.session_execute(sql, args))

    def getUserById(self, user_id):
        # have to allow login for pending users so they can fix broken email and orcid
        args = dict(user_id=user_id)
        sql = "SELECT * FROM groups AS g JOIN users AS u ON g.id = u.id WHERE g.own_role <= 'pending' AND u.id = :user_id"
        return list(self.session_execute(sql, args))

    def getUserBySurrogate(self, surrogate):
        args = dict(surrogate=surrogate)
        sql = ("SELECT * "
               "FROM groups AS g "
               "JOIN users AS u ON g.id = u.id "
               "JOIN user_session_surrogates AS uss ON u.id = uss.user_id "
               "WHERE g.own_role <= 'pending' AND uss.surrogate = :surrogate")
        return list(self.session_execute(sql, args))

    def insertApiKey(self, group, key, token_type, scope, lifetime_seconds=None, note=None):
        nnopts = {k: v for k, v in dict(lifetime_seconds=lifetime_seconds, note=note).items() if v is not None}
        args = dict(group=group, key=key, key_type=token_type, scope=scope, **nnopts)
        if nnopts:
            optionals = ', ' + ', '.join(k for k, v in nnopts.items())
            optionalvs = ', ' + ', '.join(':' + k for k, v in nnopts.items())
        else:
            optionals = ''
            optionalvs = ''

        sql = (f'INSERT INTO api_keys (user_id, key, key_type, key_scope{optionals}) VALUES '
               f'(idFromGroupname(:group), :key, :key_type, :scope{optionalvs})')
        return self.session_execute(sql, args)

    def revokeApiKey(self, group, key):
        # group is only here for a bit of insurace
        args = dict(group=group, key=key)
        sql = ('UPDATE api_keys SET revoked_datetime = CURRENT_TIMESTAMP '
               'WHERE key = :key AND user_id = idFromGroupname(:group) AND revoked_datetime IS NULL; '
               'SELECT key, revoked_datetime FROM api_keys WHERE key = :key;')
        return list(self.session_execute(sql, args))

    def getGroupApiKeys(self, group):
        args = dict(group=group)
        sql = 'SELECT * FROM api_keys WHERE user_id = idFromGroupname(:group)'
        # FIXME TODO do we return revoked an expried here as long as they have not been culled?
        return list(self.session_execute(sql, args))

    def getUserRoleForGroups(self, user, groups):
        args = dict(user=user, groups=tuple(groups))
        sql = '''
select gg.groupname, gg.own_role, up.user_role
from user_permissions as up
join groups as gg on gg.id = up.group_id
where gg.groupname in :groups and up.user_id = idFromGroupname(:user)
'''
        return list(self.session_execute(sql, args))

    def getUserAndMetaByApiKey(self, api_key):
        # XXX for consideration, this function is intended to be used ONLY
        # in a context where key validity logic is run immediately after
        # there is similar logic in sql cullExpiredThings and it might
        # make sense to keep all the logic for retrieving api keys in
        # a single stored procedure and always use that instead of the
        # python logic MUST follow as implemented in Auth.authenticate_request
        args = dict(api_key=api_key)
        sql = (
            'select a.key_scope, a.created_datetime, a.lifetime_seconds, '
            'a.revoked_datetime, g.groupname, g.own_role, u.orcid '
            'from api_keys as a '
            'join groups as g on g.id = a.user_id '
            'join users as u on g.id = u.id '
            'where a.key = :api_key '
            # note that you won't be able to get api keys at all
            # until email and orcid workflows are done

            # if a user is deactivated, deleted, banned, erased,
            # etc. then this becomes an unknown token error while
            # we clean up the tokens from the database
            "and g.own_role < 'pending'")
        return list(self.session_execute(sql, args))

    def groupHasRoles(self, group):
        # TODO include term level permissions
        args = dict(group=group)
        sql = '''
select up.user_role, g.groupname
from user_permissions as up
join groups as g on up.group_id = g.id
where up.user_id = idFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def groupRoles(self, group):
        args = dict(group=group)
        sql = '''
select up.user_role, g.groupname
from user_permissions as up
join groups as g on up.user_id = g.id
where up.group_id = idFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def getOrgSettings(self, group):
        pass

    def getUserOverview(self, group):
        args = dict(group=group)
        sql = '''
select g.groupname, u.orcid, om.name, g.created_datetime,
ARRAY(select gp.groupname from groups as gp
        join user_permissions as up on gp.id = up.group_id
       where up.user_id = idFromGroupname(:group) and up.user_role < 'view') as member_of,
ARRAY(select (psup.subject, psup.user_role) from perspective_subject_user_permissions as psup
      -- TODO likely need the perspective as well
       where psup.user_id = idFromGroupname(:group)
        ) as edrev_of
from groups as g
join users as u on g.id = u.id
join orcid_metadata as om on om.orcid = u.orcid
where g.id = idFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def getUserVerifiedEmails(self, group):
        args = dict(group=group)
        sql = '''
SELECT *
FROM users AS u
JOIN groups AS g ON g.id = u.id
JOIN user_emails AS ue on ue.user_id = u.id AND ue.email_validated IS NOT NULL
WHERE g.groupname = :group
'''
        return list(self.session_execute(sql, args))

    def getUserSettings(self, group):
        # FIXME move to dbstuff
        args = dict(group=group)
        sql = '''
SELECT 'u' as rec_type,
g.groupname,
g.own_role,
u.orcid,

null as email,
null as email_primary,
null as email_validated,

null::text as key,
null::key_types as key_type,
null::key_scopes as key_scope,
null::text as note,
null::TIMESTAMP as created_datetime,
null::integer as lifetime_seconds,
null::TIMESTAMP as revoked_datetime

FROM groups AS g JOIN users AS u ON u.id = g.id
WHERE g.id = idFromGroupname(:group)

UNION

SELECT 'e' as rec_type,
null,
null,
null,

ue.email,
ue.email_primary,
ue.email_validated,

null::text,
null::key_types,
null::key_scopes,
null::text,
null::TIMESTAMP,
null::integer,
null::TIMESTAMP

FROM user_emails AS ue
WHERE ue.user_id = idFromGroupname(:group)

UNION

SELECT 'k' as rec_type,
null,
null,
null,

null,
null,
null,

ak.key,
ak.key_type,
ak.key_scope,
ak.note,
ak.created_datetime,
ak.lifetime_seconds,
ak.revoked_datetime

FROM api_keys AS ak
WHERE ak.user_id = idFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def getGroupOntologies(self, group):
        args = dict(group=group)
        # TODO big major todo
        sql = '''
select * from ontologies as o
join identities as ids on o.spec_head_identity = ids.identity
where o.perspective = persFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def getFreeOntologies(self):
        # FIXME TODO dedupe when there are multiple loads probably
        sql = '''
select n.name, n.first_seen from names as n
join name_to_identity as nti on n.name = nti.name
join identities as ids on nti.identity = ids.identity
join identity_relations as irs on irs.s = ids.identity
where nti.type = 'bound' and uri_host(n.name) != reference_host()
and (ids.type = 'serialization' and irs.p = 'parsedTo' or ids.type != 'serialization')
'''
        return list(self.session_execute(sql))

    def subjectsObjects(self, predicate, subjects):
        args = dict(subjects=tuple(subjects), predicate=predicate)
        sql = 'select t.s, t.o from triples as t where t.p = :predicate and t.s in :subjects'
        return list(self.session_execute(sql, args))

    def checkEntity(self, label_and_exacts):
        args = dict(loe=tuple(label_and_exacts))
        sql = 'select * from current_interlex_labels_and_exacts as cile where o_lit in :loe'
        return list(self.session_execute(sql, args))

    def newEntity(self, group, rdf_type, label, exacts=None):
        if not config.use_real_frag_pref:
            frag_pref = 'tmp'
        # FIXME TODO need the expanded values for rdf_type
        elif rdf_type in ('owl:Class', 'owl:AnnotationProperty', 'owl:ObjectProperty'):
            frag_pref = 'ilx'
        elif rdf_type == 'TODO:CDE':
            frag_pref = 'cde'
        elif rdf_type == 'TODO:FDE':
            frag_pref = 'fde'
        elif rdf_type == 'TODO:PDE':
            frag_pref = 'pde'
        else:
            raise TypeError(f'unknown rdf_type {rdf_type}')

        if exacts is None:
            exacts = []

        args = dict(rdf_type=rdf_type, frag_pref=frag_pref, label=label, exacts=exacts, group=group)
        sql = 'SELECT newEntity(:rdf_type, :frag_pref, :label, :exacts, :group)'
        return list(self.session_execute(sql, args))

    def createOntology(self, reference_host, group, path):
        spec = f'http://{reference_host}/{group}/ontologies/uris{path}/spec'
        args = dict(group=group, path=path, spec=spec)
        sql = '''
INSERT INTO ontologies (perspective, ont_path, spec) VALUES
(persFromGroupname(:group), :path, :spec) RETURNING spec
'''
        return list(self.session_execute(sql, args))

    def updateSpecHead(self, spec, head_identity):
        args = dict(head_identity=head_identity, spec=spec)
        sql = '''
UPDATE ontologies SET spec_head_identity = :head_identity WHERE spec = :spec
'''
        self.session_execute(sql, args)

    def getConstraint(self, schema, table, constraint):
        # https://dba.stackexchange.com/a/214877
        args = dict(schema=schema, table=table, constraint=constraint)
        sql = '''
SELECT con.conname, pg_get_constraintdef(con.oid)
       FROM pg_catalog.pg_constraint con
            INNER JOIN pg_catalog.pg_class rel
                       ON rel.oid = con.conrelid
            INNER JOIN pg_catalog.pg_namespace nsp
                       ON nsp.oid = connamespace
       WHERE nsp.nspname = :schema
             AND rel.relname = :table
             AND con.conname = :constraint
'''
        return list(self.session_execute(sql, args))

    def deleteExistingIrisForGroup(self, group, iris):
        args = dict(group=group, iris=iris)
        sql = 'delete from existing_iris where perspective = persFromGroupname(:group) and iri in :iris'
        self.session_execute(sql, args)

    def insertExistingIrisForGroup(self, group, values):
        # FIXME TODO qc the iris that are being added
        values_template, params = makeParamsValues(
            values, constants=('persFromGroupname(:group)',))
        params['group'] = group
        sql = ('insert into existing_iris (perspective, ilx_prefix, ilx_id, iri) VALUES ' + values_template)
        self.session_execute(sql, params)

    def insertLaex(self, values):
        # FIXME the setup for this is incorrect at the moment because everything is enforced globally
        # since we don't have the curated subset up and running so we use base for everything
        # also, there is tension here when there are completely new terms ... i suspect they go
        # into curated immediately for new terms when it is just label/exact and the new id because
        # we need to index something ... design still needs more thought
        values_template, params = makeParamsValues(values)
        sql = ('insert into current_interlex_labels_and_exacts (p, prefix, id, o_lit) VALUES' + values_template)
        self.session_execute(sql, params)

    def insertUrisForGroup(self, group, uri_paths):
        values_template, params = makeParamsValues(
            values, constants=('persFromGroupname(:group)',))
        params['group'] = group
        sql = ('insert into uris (perspective, uri_path) VALUES ' + values_template)
        self.session_execute(sql, params)

