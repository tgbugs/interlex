"""
database queries that are more than select e.g. all the user and group
stuff beyond dump and load
"""

from sqlalchemy.sql import text as sql_text
from interlex.core import makeParamsValues


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
        return self.session_execute(sql, args)

    def getUserPassword(self, group):
        sql = '''
SELECT * FROM groups AS g
JOIN users AS u ON g.id = u.id
JOIN user_passwords AS up ON up.user_id = u.id
WHERE g.groupname = :groupname AND g.own_role <= 'pending'
'''
        return list(self.session_execute(sql, dict(groupname=group)))

    def insertOrcidMetadata(self, orcid, name, token_type, token_scope, token_access, token_refresh, lifetime_seconds, user=None):
        args = dict(
            orcid=orcid,
            name=name,
            token_type=token_type,
            token_scope=token_scope,
            token_access=token_access,
            token_refresh=token_refresh,
            lifetime_seconds=lifetime_seconds)
        sql = '''
INSERT INTO orcid_metadata (orcid, name, token_type, token_scope, token_access, token_refresh, lifetime_seconds)
VALUES (:orcid, :name, :token_type, :token_scope, :token_access, :token_refresh, :lifetime_seconds)
'''
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

    def getUserByOrcid(self, orcid):
        args = dict(orcid=orcid)
        sql = "SELECT * FROM users AS u JOIN groups AS g ON g.id = u.id WHERE u.orcid = :orcid AND g.own_role <= 'pending'"
        return list(self.session_execute(sql, args))
