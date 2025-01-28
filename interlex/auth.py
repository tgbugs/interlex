from datetime import datetime, timedelta
import uuid
import argon2
import secrets
import binascii
import jwt
from jwt import exceptions as jwtexc
import flask_login as fl
from flask import abort, url_for, g as flask_context_globals, session as fsession
from idlib.utils import makeEnc
from interlex import config
from interlex.utils import log
from interlex.dbstuff import Stuff

_orcid_mock_public_key = None
_orcid_mock_private_key = None

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
        log.log(9, 'beg')
        return ph.hash(password)
    finally:
        log.log(9, 'end')


def validate_password(argon2_string, password):
    try:
        log.log(9, 'beg')
        return ph.verify(argon2_string, password)
    except argon2.exceptions.VerifyMismatchError as e:
        return False
    finally:
        log.log(9, 'end')

# https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/
# https://stackoverflow.com/questions/30092226/calculate-crc32-correctly-with-python

# ixp_
# ixr_
# ixw_
# base62 + 6 digits of crc32 checksum

# we do not need all the complexity of jwts given our scale
base62_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijlkmnopqrstuvwxyz'
base62encode, base62decode = makeEnc(base62_alphabet)
max_30 = base62decode('z' * 30) + 1


def gen_key(key_type='p'):
    int_key = secrets.randbelow(max_30)
    actual_key = int.to_bytes(int_key, 23, byteorder='big')
    return _gen_key(actual_key, key_type=key_type)


def _gen_key(actual_key, key_type='p'):
    chrm = binascii.crc32(actual_key)
    chrm_bytes = chrm.to_bytes(4, byteorder='big')
    tenc = actual_key + chrm_bytes
    int_enc = int.from_bytes(tenc, byteorder='big')
    enc = base62encode(int_enc)
    lz = 36 - len(enc)
    penc = f'ix{key_type}_' + ('0' * lz) + enc
    return penc


def _decompose_key(raw_key, fail=True):
    prefix, _key, _crc = raw_key[:4], raw_key[4:-6], raw_key[-6:]  # this isn't the exact inverse might break
    _denc = base62decode(_key + _crc)
    denc = int.to_bytes(_denc, 27, byteorder='big')
    key, crc = denc[:-4], denc[-4:]
    # FIXME should be able to do the split while still in the encoded form yeah?
    if binascii.crc32(key) != int.from_bytes(crc, byteorder='big'):
        msg = 'crc checksum failed'
        if fail:
            raise Auth.MangledTokenError(None, msg)

    return key, crc


def key_from_auth_value(auth_value):
    # FIXME TODO must test this, gh impl mentions zero padding which i don't have right now
    raw_key = auth_value[7:]  # strip 'Bearer '
    _decompose_key(raw_key)
    return raw_key


class Auth:

    log = log.getChild('auth')

    class AuthError(Exception):
        def __init__(self, request, extra_info, *args, **kwargs):
            # NOTICE:  only log plain text that does not have the current secret
            # ah class scope
            # TODO make sure access route has the actual source not nginx
            # FIXME use extra
            if request is not None:
                ll = getattr(Auth.log, self.log_level)
                ll(f'{self.__class__.__name__} - {extra_info} - {request.remote_addr} - {request.url} - \n{request.headers}')

            self.extra_info = extra_info
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

    class HasNotCompletedVerificationError(AuthError):
        log_level = 'info'

    class InternalRequest:
        headers = 'Internal-Request: True'  # XXX obviously this can't be True and needs to be random if we actually wanted to do this
        url = 'check-the-logs'
        remote_addr = "THEY'RE IN THE DATABASE!!!"

    def __init__(self, session, rules_req_auth):
        self.session = session  # this is always needed now
        self.orcid_openid_jwkc = jwt.PyJWKClient(f'https://{config.orcid_host}/oauth/jwks')
        self.orcid_openid_sk = self.orcid_openid_jwkc.get_signing_keys()[0]

        # we do need two things to improve this though
        # 1 swap out of this class every 30 mins or something
        # 2 a secured admin api endpoint that will revoke
        # the key
        # or the current secret
        # and immediately reup this needs to use an orthogonal auth system
        #self.scopes = ('read-only', 'group-read-only', 'group-auto-pull'
                       # FIXME from db please
                       #'issued-user-only', 'check-group', 'admin')
        # there isn't such a thing as a group write for prov reasons, and group-auto-pull
        # is only useful for reducing the computational load on interlex
        # admin gives you the ability to wipe whole qualifiers from existence
        # check group is probably the only one we need for the most part
        #self.private_key = 'a;lskdjfa;slkdjf;alksdjf;alkjg;aslkdjf;alskdfjas;dlkfj'
        #self.current_secret = 'LOL-PLEASE-GET-ME-FROM-THE-DATABASE'
        #self.revoked_secrets = 'i was leaked by some idiot', 'whoops data went everywhere'

        self.rules_req_auth = rules_req_auth
        #if not rules_maybe_auth:
            #msg = 'rules_maybe_auth should never be empty'
            #raise ValueError(msg)

    def decrypt(self, token):
        raise NotImplementedError('old do not use')
        # do not implement this yourself, is this coming from orcid?
        # all tokens should be encrypted with the 'public' key?
        # and then the private used to verify or something like that
        fake_expand = token + ' ' + token + ' 1701912161 check-group ' + 'LOL-PLEASE-GET-ME-FROM-THE-DATABASE'  # XXX XXX XXX XXX FIXME TODO
        return fake_expand

    def decodeToken(self, request, token):
        raise NotImplementedError('old do not use')
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
        raise NotImplementedError('old do not use')
        irequest = self.InternalRequest()
        try:
            group, auth_user, scope, issued_utc_epoch = self.decodeToken(irequest, token)
            # FIXME for long running requests what happens if we start authed
            # and finish after we cross the line?
            return group, auth_user
        except self.AuthError:
            # downstream logger will deal with this
            return None, None

    def _orcid_jwt(self, openid_token):
        # TODO so much lurking complexity in here :/
        # retrieve the signing key at start up or similar
        # if the token we receive was not signed by that key
        # then we abort and tell the user to sign in again
        # orcid tokens expire in 24 hrs it seems
        # audience is the client id

        # i think that we don't actually need to store the token in the
        # database, because what we will do is use it as the session id
        # so orcid sessions can last at most 24 hrs but without the ability
        # to revoke (for now until I can figure out how to deal with that)
        # looks like that is what jti is for? https://stackoverflow.com/a/29946630

        # https://github.com/ORCID/ORCID-Source/blob/main/orcid-web/ORCID_AUTH_WITH_OPENID_CONNECT.md
        # the openid public key for openid_token is a https://orcid.org/oauth/jwks
        # see also https://orcid.org/.well-known/openid-configuration

        sk = self.orcid_openid_sk
        if _orcid_mock_public_key is None:
            key = sk.key
        else:
            key = _orcid_mock_public_key

        detok = jwt.decode(openid_token, key, sk.algorithm_name, audience=config.orcid_client_id)

        return detok

    def load_user(self, surrogate):
        dbstuff = Stuff(self.session)
        if not isinstance(surrogate, uuid.UUID):
            if isinstance(surrogate, str):  # this is now the orcid openid jwt
                try:
                    detok = self._orcid_jwt(surrogate)  # TODO error handling
                except jwtexc.ExpiredSignatureError as e:
                    # FIXME TODO this needs to redirect to a login page and clear the session
                    msg = 'please log in again'
                    raise self.ExpiredTokenError(msg) from e

                orcid = f'https://{config.orcid_host}/' + detok['sub']
                orcid_pending = '_orcid_only' in fsession and fsession['_orcid_only'] == 'true'
                if orcid_pending:
                    rows = dbstuff.getOrcidMetadataUserByOrcid(orcid)
                else:
                    rows = dbstuff.getUserByOrcid(orcid)

                if not rows:
                    # somehow someone got a session cookie but we didn't record
                    # their orcid, which either means we have a bug or our
                    # flask session secret key got leaked
                    log.critical(f'decoded cookie but no orcid_metadata for {orcid}')
                    return

                orcid_row = rows[0]
                if orcid_pending and orcid_row.id is not None:
                    # FIXME do we send the user a header to tell the user agent
                    # to clear cookies or something along with the new cookie?
                    msg = ('attempt to connect with orcid only session cookie '
                           'when a orcid + user is present on the system, you '
                           'probably want to replace the session cookie?')
                    abort(401, msg)

                class tuser:
                    is_active = True  # maybe we set this to False?
                    is_anonymous = False
                    is_authenticated = True
                    via_auth = 'orcid'
                    orcid = orcid_row.orcid
                    id = surrogate
                    own_role = None if orcid_pending else orcid_row.own_role
                    groupname = None if orcid_pending else orcid_row.groupname
                    def get_id(self):
                        return self.id

                return tuser()
            else:
                msg = f'{surrogate!r} is a {type(surrogate)}'
                raise TypeError(msg)

        rows = dbstuff.getUserBySurrogate(surrogate)
        if not rows:
            # similar logic as with the orcid above, if we make it this far
            # and there is a valid session cookie that we can decode that
            # decodes to something that could be mistaken for a valid user
            # id but that somehow does not exist then something is VERY wrong
            log.critical(f'decoded cookie but no user for {surrogate}')
            # FIXME TODO so the other case where this can happen is when
            # a user has been banned, also, we need to implement alternative tokens
            # so that we can invalidate other sessions e.g. on password change
            # see https://flask-login.readthedocs.io/en/latest/#alternative-tokens
            return
        else:
            class tuser:
                is_active = True
                # is_anonymous and is_authenticated are exact opposites due to
                # some lingering history inherited from django or something
                is_anonymous = False
                is_authenticated = True
                via_auth = 'interlex'
                orcid = rows[0].orcid
                id = rows[0].surrogate
                own_role = rows[0].own_role
                groupname = rows[0].groupname
                def get_id(self):
                    return self.id

            return tuser()

    def refresh_login(self):
        orcid_login = '_via_auth' in fsession and fsession['_via_auth'] == 'orcid'
        if orcid_login:
            base = url_for('Ops.login /u/ops/orcid-login')
        else:
            base = url_for('Ops.login /u/ops/login')

        get_back_here = ''  # TODO
        return redirect(base + '?from=refresh' + '&next=' + get_back_here, 302)

    def authenticate_request(self, request):
        # FIXME this should almost certainly be decorated with
        # @lm.request_loader at a later stage ...
        now = datetime.utcnow()
        # unauthed requests don't really need this
        request._auth_datetime = now

        write_requires_auth = request.method in ('POST', 'PATCH', 'PUT', 'DELETE')
        read_requires_auth = 'priv' in request.url_rule.rule  # FIXME not the best way to do it
        read_might_require_auth = (
            request.method in ('GET', 'HEAD', 'OPTIONS') and
            request.url_rule.rule in self.rules_req_auth)
        # FIXME read might require auth is the WRONG way to handle this
        # because it means the system is not safe by default for the scratch
        # space, read never requires auth, we just won't return any values if
        # auth user is not provided for the scratch space
        request_needs_auth_or_auth_user = write_requires_auth or read_requires_auth or read_might_require_auth

        logged_in_user = fl.current_user
        if logged_in_user is not None and logged_in_user.is_authenticated:
            if hasattr(logged_in_user, 'groupname') and logged_in_user.groupname is not None:
                li_user = logged_in_user.groupname
                orcid_user = None
            else:
                # orcid only users do not have a groupname but are technically authed
                li_user = None
                orcid_user = logged_in_user
        else:
            li_user = None
            orcid_user = None

        def no_token_ok(r):
            _notok = [
                'logout',
                'settings',
                'role',
                'role-other',
                'password-change',  # TODO figure out what to do about accounts without email validation
                'user-deactivate',
                'orcid-assoc',
                'orcid-change',
                'orcid-dissoc',
                # i do imagine that there might be some crazy scenario where a user has an orcid
                # somehow loses access after creating the user account and never set a password
                # and never verified the email address, and that means that they can't get back in
                # to the account because they can't login with orcid and don't have a password set
                # however if that happens I will happily point to this comment in my reply to the
                # support ticket, we assume that the user can lose or not have two of the three
                # things and still recover the account or complete the process, if they lose the
                # third, well, problem, we could force password as insurace, but let's see
                'email-add',
                'email-del',
                'email-verify',
                'email-primary',
                # api-token* requires email and orcid verification complete but that is checked later
                'api-tokens',
                'api-token-new',
                'api-token-revoke',
            ]
            notok = set(f'/<group>/priv/{p}' for p in _notok)  # FIXME
            return r.url_rule.rule in notok

        if 'Authorization' in request.headers:
            auth_value = request.headers['Authorization']
            if (request.url_rule.rule in ('/<group>/priv/password-change', '/<group>/priv/user-deactivate') or
                request.url_rule.rule.startswith('email-') or
                request.url_rule.rule.startswith('orcid-')):
                # auth can only modify at or below its own level since tokens
                # can be leaked etc. the can only be used to generate new
                # tokens not do things like add a new email or change the
                # primary email or orcid because that can allow an account
                # takeover with nothing but the token

                # early abort, don't bother checking anything
                msg = 'cannot use token to change password, email, or orcid'
                abort(401, msg)
        elif li_user is not None and no_token_ok(request):
            # we don't actually check for pending here, we only allow
            # specific resources and operations to be accessed if
            # password login is being used
            auth_value = None
        elif li_user is not None and request.url_rule.rule == '/u/priv/user-new':
            # FIXME does this logic go here ? i put it here to avoid producing
            # confusing error mesages if we hit write_requires_auth ...
            abort(409, 'cannot create a new user when already logged in')
        elif li_user is not None and request.url_rule.rule == '/u/priv/orcid-land-assoc':
            scope = 'settings-only'
            return None, li_user, scope, None, None
        elif orcid_user is not None and request.url_rule.rule == '/u/priv/user-new':
            # the only privilidged thing an orcid only user can do is go
            # stright to user-new, register-only is not a scope in the db
            scope = 'register-only'
            return None, None, scope, None, None
        elif write_requires_auth:
            if li_user:
                msg = f'{request.method} requires token authorization, but login was provided'
            else:
                msg = f'{request.method} requires authorization, but none was provided'

            raise self.MissingTokenError(request, msg)
        elif read_requires_auth:
            if li_user:
                msg = f'{request.url_rule.rule} requires token authorization, but login was provided'
            else:
                msg = f'{request.url_rule.rule} requires authorization, but none was provided'

            raise self.MissingTokenError(request, msg)
        else:
            return None, None, None, None, None

        user_meta = None
        dbstuff = Stuff(self.session)
        if auth_value is not None:
            if not auth_value.startswith('Bearer '):
                msg = 'Authorization header did not start with "Bearer "'
                raise self.MalformedRequestHeader(request, msg)

            # TODO edge case for when request was made vs when it will end
            # for long running queries start and end might cross the liftime
            try:
                provided_key = key_from_auth_value(auth_value)  # XXX will raise on malformed key
            except self.MangledTokenError as e:
                raise self.MangledTokenError(request, e.extra_info)

            resp = dbstuff.getUserAndMetaByApiKey(provided_key)

            if not resp:
                msg = 'the provided token is not known to this system'
                raise self.UnknownTokenError(request, msg)

            user_meta = row = resp[0]
            if row.revoked_datetime is not None:
                # XXX DO NOT RETURN ANY INFORMATION ABOUT REVOCATION TIME
                # it can be used by an attacker to estimate response time
                msg = 'the provided token has been revoked'
                raise self.RevokedTokenError(request, msg)

            if row.lifetime_seconds is not None and row.created_datetime + timedelta(seconds=row.lifetime_seconds) >= now:
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
            if write_requires_auth and scope.startswith('read-'):
                msg = f'token has invalid scope {scope} for method {request.method}'
                raise self.InvalidScopeError(request, msg)

            auth_user = row.groupname

        elif li_user is not None:
            scope = 'settings-only'  # note that settings- implies user-
            auth_user = li_user
            if logged_in_user.own_role != 'owner':  # pending user
                if request.url_rule.rule.startswith('/<group>/priv/api-token'):
                    msg = 'email and orcid verfication must be completed to access this resource'
                    raise self.HasNotCompletedVerificationError(request, msg)

        else:
            msg = 'more like not implemented correctly amirite'
            raise NotImplementedError(msg)

        def gvk(k):
            return request.view_args[k] if k in request.view_args else None

        request_group = gvk('group')
        request_group_other = gvk('other_group')
        request_group_other_diff = gvk('other_group_diff')
        rgroups = [rg for rg in
                   (request_group,
                    request_group_other,
                    request_group_other_diff)
                   if rg is not None]
        need_group_perms = [rg for rg in rgroups if rg != auth_user]
        _read_private = read_might_require_auth  # XXX unfortunately have to start on and turn off
        if need_group_perms:
            if scope.endswith('-only'):
                msg = f'token has invalid scope {scope} for other groups'
                raise self.InvalidScopeError(request, msg)

            # if auth_user == request_group then unless we aborted on scope
            # mismatch (i.e. we never get here), all requests are allowed
            # so we only have to check mismatched cases
            resp = dbstuff.getUserRoleForGroups(auth_user, need_group_perms + ['empty'])
            write_roles = {'admin', 'owner', 'contributor'}
            read_roles = {'admin', 'owner', 'contributor', 'curator', 'view'}
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

        if (auth_user is not None and
            (fl.current_user is None or
             not hasattr(fl.current_user, 'groupname'))):
            #fl.login_user()
            # can't use login_user because that sets a session cookie which we don't want
            # though the docs do mention something about this e.g.
            # see https://flask-login.readthedocs.io/en/latest/#disabling-session-cookie-for-apis
            class tuser:
                is_active = True
                is_anonymous = False
                is_authenticated = True
                via_auth = 'api'
                orcid = user_meta.orcid
                id = 'from-api-key'
                own_role = user_meta.own_role
                groupname = auth_user
                def get_id(self):
                    return self.id

            flask_context_globals.api_login = True
            fsession['_via_auth'] = tuser.via_auth
            fl.login_user(tuser())

        return group, auth_user, scope, token, read_private
