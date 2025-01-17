"""
database queries that are more than select e.g. all the user and group
stuff beyond dump and load
"""

from sqlalchemy.sql import text as sql_text
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
                                                   constants=('idFromGroupname(:group)',))  # FIXME surely this is slow as balls
        params['group'] = group
        base = 'INSERT INTO curies (group_id, curie_prefix, iri_namespace) VALUES '
        sql = base + values_template
        return self.session_execute(sql, params)

    def user_new(self, username, email, argon2_string=None, orcid=None):
        params = dict(groupname=username, email=email)

        if orcid is not None:
            params['orcid'] = orcid
            sql_users = 'gru AS (INSERT INTO users (id, orcid) SELECT id, :orcid FROM grow RETURNING id),'
        else:
            sql_users = 'gru AS (INSERT INTO users (id) SELECT id FROM grow RETURNING id),'

        if argon2_string is not None:
            params['argon2_string'] = argon2_string
            sql_pass = 'INSERT INTO user_passwords (user_id, argon2_string) SELECT user_id, :argon2_string FROM gre RETURNING user_id'
        else:
            sql_pass = 'SELECT user_id FROM gre'

        sql = f'''
WITH grow AS (INSERT INTO groups (groupname) VALUES (:groupname) RETURNING id),
{sql_users}
gre AS (INSERT INTO user_emails (user_id, email, email_primary) SELECT id, :email, TRUE FROM gru RETURNING user_id)
{sql_pass}
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

    def getUserPassword(self, group):
        sql = '''
SELECT * FROM groups AS g
JOIN users AS u ON g.id = u.id
JOIN user_passwords AS up ON up.user_id = u.id
WHERE g.groupname = :groupname AND g.own_role <= 'pending'
'''
        return list(self.session_execute(sql, dict(groupname=group)))

    def insertOrcidMetadata(self, orcid, name, token_type, token_scope, token_access, token_refresh, lifetime_seconds, openid_token=None, user=None):
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
            'a.revoked_datetime, g.groupname '
            'from api_keys as a '
            'join groups as g on g.id = a.user_id '
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
join triples as t on o.spec = t.s
where o.group_id = idFromGroupname(:group)
'''
        return list(self.session_execute(sql, args))

    def subjectsObjects(self, predicate, subjects):
        args = dict(subjects=tuple(subjects), predicate=predicate)
        sql = 'select t.s, t.o from triples as t where t.p = :predicate and t.s in :subjects'
        return list(self.session_execute(sql, args))

    def createOntology(self, reference_host, group, path):
        spec = f'http://{reference_host}/{group}/ontologies/uris{path}/spec'
        args = dict(group=group, path=path, spec=spec)
        sql = '''
INSERT INTO ontologies (group_id, ont_path, spec) VALUES
(idFromGroupname(:group), :path, :spec) RETURNING spec
'''
        return list(self.session_execute(sql, args))

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

