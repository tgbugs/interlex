from datetime import datetime, timedelta
import argon2
import flask_login as fl
from interlex.utils import log
from sqlalchemy.sql import text as sql_text

ph = argon2.PasswordHasher(
    # want this to run a bit slower than default
    # so keep parallelism down following owasp argon2 recs
    # t 3 m 128 p 1 gives on the order of 170ms on an i7-4770K
    time_cost=3,
    memory_cost=128 * 1024,
    parallelism=1,
)


def hash_password(password):
    try:
        log.debug('beg')
        return ph.hash(password)
    finally:
        log.debug('end')


def validate_password(argon2_string, password):
    try:
        log.debug('beg')
        return ph.verify(argon2_string, password)
    except argon2.exceptions.VerifyMismatchError as e:
        return False
    finally:
        log.debug('end')

# https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/
# https://stackoverflow.com/questions/30092226/calculate-crc32-correctly-with-python

# ixp_
# ixr_
# ixw_
# base62 + 6 digits of crc32 checksum

# we do not need all the complexity of jwts given our scale
import binascii
from idlib.utils import makeEnc
base62_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijlkmnopqrstuvwxyz'
base62encode, base62decode = makeEnc(base62_alphabet)
hrm = b'0' * 22
chrm = binascii.crc32(hrm)
tenc = hrm + chrm.to_bytes(4, byteorder='big')
enc = base62encode(int.from_bytes(tenc, byteorder='big'))
penc = 'ixp_' + enc
###
_denc = base62decode(penc[4:])
denc = int.to_bytes(_denc, 26, byteorder='big')
key, crc = denc[:-4], denc[-4:]
binascii.crc32(key) == int.from_bytes(crc, byteorder='big')


def key_from_auth_value(auth_value):
    # FIXME TODO must test this, gh impl mentions zero padding which i don't have right now
    raw_key = auth_value[7:]  # strip 'Bearer '
    prefix, _key, _crc = raw_key[:4], raw_key[4:-6], raw_key[-6:]  # this isn't the exact inverse might break
    _denc = base62decode(_key + _crc)
    denc = int.to_bytes(_denc, 26, byteorder='big')
    key, crc = denc[:-4], denc[-4:]
    # FIXME should be able to do the split while still in the encoded form yeah?
    if binascii.crc32(key) != int.from_bytes(crc, byteorder='big'):
        msg = 'crc checksum failed'
        raise Auth.MangledTokenError(msg)

    return raw_key.encode()  # its a bytea in the database


class Auth:

    log = log.getChild('auth')

    class AuthError(Exception):
        def __init__(self, request, extra_info, *args, **kwargs):
            # NOTICE:  only log plain text that does not have the current secret
            # ah class scope
            # TODO make sure access route has the actual source not nginx
            # FIXME use extra
            breakpoint()
            ll = getattr(Auth.log, self.log_level)
            ll(f'{self.__class__.__name__} - {extra_info} - {request.remote_addr} - {request.url} - \n{request.headers}')
            super().__init__(*args, **kwargs)

    class MalformedRequestHeader(AuthError):
        log_level = 'info'

    class MissingTokenError(AuthError):
        log_level = 'info'

    class MangledTokenError(AuthError):
        log_level = 'warning'

    class UnknownTokenError(AuthError):
        log_level = 'warning'

    class RevokedTokenError(AuthError):
        log_level = 'info'

    class InvalidScopeError(AuthError):
        log_level = 'info'

    class CannotTrustTokenError(AuthError):
        """ If these are attached to the auth class is there
            some way that a malicious actor could change/remove
            this thing to get around the error? """
        log_level = 'error'

    class WeMayHaveAProblemError(AuthError):
        log_level = 'critical'

    class ScopeError(WeMayHaveAProblemError):
        pass

    class EpochError(WeMayHaveAProblemError):
        pass

    class ExpiredTokenError(AuthError):
        log_level = 'info'

    class NotAuthorizedError(AuthError):
        log_level = 'warning'

    class InternalRequest:
        headers = 'Internal-Request: True'  # XXX obviously this can't be True and needs to be random if we actually wanted to do this
        url = 'check-the-logs'
        remote_addr = "THEY'RE IN THE DATABASE!!!"

    def __init__(self, session, rules_req_auth):
        self.session = session  # this is always needed now
        # we do need two things to improve this though
        # 1 swap out of this class every 30 mins or something
        # 2 a secured admin api endpoint that will revoke
        # the key
        # or the current secret
        # and immediately reup this needs to use an orthogonal auth system
        self.scopes = ('read-only', 'group-read-only', 'group-auto-pull'
                       # FIXME from db please
                       'issued-user-only', 'check-group', 'admin')
        # there isn't such a thing as a group write for prov reasons, and group-auto-pull
        # is only useful for reducing the computational load on interlex
        # admin gives you the ability to wipe whole qualifiers from existence
        # check group is probably the only one we need for the most part
        self.private_key = 'a;lskdjfa;slkdjf;alksdjf;alkjg;aslkdjf;alskdfjas;dlkfj'
        self.current_secret = 'LOL-PLEASE-GET-ME-FROM-THE-DATABASE'
        self.revoked_secrets = 'i was leaked by some idiot', 'whoops data went everywhere'

        self.rules_req_auth = rules_req_auth
        #if not rules_maybe_auth:
            #msg = 'rules_maybe_auth should never be empty'
            #raise ValueError(msg)

    def decrypt(self, token):
        # do not implement this yourself, is this coming from orcid?
        # all tokens should be encrypted with the 'public' key?
        # and then the private used to verify or something like that
        fake_expand = token + ' ' + token + ' 1701912161 check-group ' + 'LOL-PLEASE-GET-ME-FROM-THE-DATABASE'  # XXX XXX XXX XXX FIXME TODO
        return fake_expand


    def decodeToken(self, request, token):
        assert isinstance(token, str)
        plain_text = self.decrypt(token)

        try:
            group, auth_user, issued_utc_epoch_str, scope, maybe_secret_at_epoch = plain_text.split(' ')  # FIXME this is a dangerous field sep
        except ValueError as e:
            # there is a vanishingly small chance that the current secret could show it in a mangled token
            raise self.MangledTokenError(request, plain_text)

        try:
            issued_utc_epoch = int(issued_utc_epoch_str)
        except ValueError:
            raise self.EpochError(request, issued_utc_epoch_str, f'Token decoded but the epoch isnt an integer {issued_utc_epoch_str}')

        if scope not in self.scopes:
            raise self.ScopeError(request, scope, 'Token decoded but the scope isnt known {scope}')
            
        if maybe_secret_at_epoch != self.current_secret:
            if maybe_secret_at_epoch in self.revoked_secrets:
                raise self.CannotTrustTokenError(request, plain_text)
            else:
                raise self.WeMayHaveAProblemError(request, plain_text.rsplit(' ', 1)[0], 'Looks like a key leaked...')

        return group, auth_user, scope, issued_utc_epoch

    def decodeTokenSimple(self, token):
        irequest = self.InternalRequest()
        try:
            group, auth_user, scope, issued_utc_epoch = self.decodeToken(irequest, token)
            # FIXME for long running requests what happens if we start authed
            # and finish after we cross the line?
            return group, auth_user
        except self.AuthError:
            # downstream logger will deal with this
            return None, None

    def authenticate_request(self, request):
        now = datetime.utcnow()

        write_requires_auth = request.method in ('POST', 'PATCH', 'PUT')
        read_might_require_auth = (
            request.method in ('GET', 'HEAD', 'OPTIONS') and
            request.url_rule.rule in self.rules_req_auth)
        # FIXME read might require auth is the WRONG way to handle this
        # because it means the system is not safe by default for the scratch
        # space, read never requires auth, we just won't return any values if
        # auth user is not provided for the scratch space
        request_needs_auth_or_auth_user = write_requires_auth or read_might_require_auth

        if 'Authorization' in request.headers:
            auth_value = request.headers['Authorization']
        elif write_requires_auth:
            msg = f'{request.method} requires authorization, but no token was provided'
            raise self.MissingTokenError(msg)
        else:
            return None, None, None, None, None

        if not auth_value.startswith('Bearer '):
            msg = 'Authorization header did not start with "Bearer "'
            raise self.MalformedRequestHeader(request, msg)

        # TODO edge case for when request was made vs when it will end
        # for long running queries start and end might cross the liftime
        provided_key = key_from_auth_value(auth_value)  # XXX will raise on malformed key
        resp = list(self.session.execute(
            sql_text(('select a.key_scope, a.created_datetime, a.lifetime_seconds, '
                      'a.revoked_datetime, g.groupname '
                      'from api_keys as a '
                      'join groups as g on g.id = a.user_id '
                      'where a.key = :provided_key '
                      # note that you won't be able to get api keys at all
                      # until email and orcid workflows are done

                      # if a user is deactivated, deleted, banned, erased,
                      # etc. then this becomes an unknown token error while
                      # we clean up the tokens from the database
                      "and g.own_role < 'pending'")),
            params=dict(provided_key=provided_key)))

        if not resp:
            msg = 'the provided token is not known to this system'
            raise self.UnknownTokenError(request, msg)

        row = resp[0]
        if row.revoked_datetime is not None:
            # XXX DO NOT RETURN ANY INFORMATION ABOUT REVOCATION TIME
            # it can be used by an attacker to estimate response time
            msg = 'the provided token has been revoked'
            raise self.RevokedTokenError(request, msg)

        if row.created_datetime + timedelta(seconds=row.lifetime_seconds) >= now:
            # TODO need a way to document how long after
            # expiration tokens are rotated out
            msg = 'the provided token has expired'
            raise self.ExpiredTokenError(request, msg)

        # if a token is provided we MUST check it even if the request
        # does not actually require authorization, doing otherwise
        # creates systematic risk of mishandling a malformed, expired, etc.
        # token at some point further down the pipeline
        if not request_needs_auth_or_auth_user:
            # FIXME make sure this fails safe ? or is this
            # this fail safe point? this is the point i think

            # for GET i think only
            # ontologies
            # uris
            # priv
            return None, None, None, None, None

        # scope/method mismatch is checked first because we don't need an
        # additional query
        scope = row.key_scope
        if write_requires_auth and scope.endswith('-only'):
            msg = f'token has invalid scope {scope} for method {request.method}'
            raise self.InvalidScopeError(request, msg)

        def gvk(k):
            return request.view_args[k] if k in request.view_args else None

        request_group = gvk('group')
        request_group_other = gvk('other_group')
        request_group_other_diff = gvk('other_group_diff')

        auth_user = row.groupname

        rgroups = [rg for rg in
                    (request_group,
                    request_group_other,
                    request_group_other_diff)
                    if rg is not None]
        need_group_perms = [rg for rg in rgroups if rg != auth_user]
        _read_private = read_might_require_auth  # XXX unfortunately have to start on and turn off
        if need_group_perms:
            # if auth_user == request_group then unless we aborted on scope
            # mismatch (i.e. we never get here), all requests are allowed
            # so we only have to check mismatched cases
            resp = list(self.session.execute(sql_text(
                ('''
select g.groupname, g.own_role, p.user_role
from user_permissions as p
join groups as g on g.id = p.group_id
where g.groupname in :groups and p.user_id = idFromGroupName(:user)
''')
            ), params=dict(groups=need_perms, user=auth_user)))

            write_roles = {'owner', 'contributor'}
            read_roles = {'owner', 'contributor', 'curator', 'view'}
            if resp:
                for row in resp:
                    if write_requires_auth:
                        if row.own_role == 'org':
                            # if request.url_rule.rule not in merge /ops/:
                            msg = 'TODO /<org>/pulls/<number>/ops/ or something'
                            raise NotImplementedError(msg)

                        if row.user_role not in write_roles:
                            msg = 'user lacks authorization for this operation'
                            raise self.NotAuthorizedError(msg)

                    elif read_might_require_auth:
                        if row.user_role in read_roles:
                            _read_private = _read_private and True
                        else:
                            _read_private = False

                    else:
                        msg = 'should not happen'
                        raise NotImplementedError(msg)
            else:
                if write_requires_auth:
                    msg = (f'requested group does not exist or user lacks authorization for this operation')
                    # if someone sends us a non-existent group we don't
                    # differentiate that here
                    raise self.NotAuthorizedError(request, msg)
                elif read_might_require_auth:
                    _read_private = False
                else:
                    msg = 'should not happen'
                    raise NotImplementedError(msg)

        # FIXME TODO priv endpoints
        read_private = _read_private or not need_group_perms
        group = None
        token = None

        if False:  # old
            maybe_token = auth_value.split(' ', 1)[-1]
            maybe_group, maybe_auth_user, scope, issued_utc_epoch = self.decodeToken(request, maybe_token)  # errors spawn here, do not catch
            issued_utc_datetime = datetime.fromtimestamp(issued_utc_epoch)  # NOTE our timestamps are issued in utc so we dont convert
            five_years = timedelta(days=365 * 5)  # FIXME set this via config?
            expiration = issued_utc_datetime + five_years
            if now > expiration:  # TODO TESTING
                # FIXME I don't think this is actually the right place to be returning these values
                # I think we need another layer inbetween
                expired = f'expired {now - expiration} ago'
                raise self.ExpiredTokenError(request, expired)  # observe that we cant even accidentally log plain_text here
            else:
                auth_user = maybe_auth_user
                group = maybe_group
                token = maybe_token

        return group, auth_user, scope, token, read_private
