from datetime import datetime, timedelta
from interlex.utils import log


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

    class MangledTokenError(AuthError):
        log_level = 'warning'

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

    class InternalRequest:
        headers = 'Internal-Request: True'
        url = 'check-the-logs'
        remote_addr = "THEY'RE IN THE DATABASE!!!"

    def __init__(self, session):
        session  # we do not keep this around, it is only used at init
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

    def authenticate_request(self, request):  # TODO there's got to be a module for this
        request_user = request.view_args['group']  # TODO do this here?
        now = datetime.utcnow()
        auth_value = request.headers.get('Authorization', '')
        if auth_value.startswith('Bearer '):
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
        else:
            group = None
            auth_user = None
            scope = None
            token = None

        return group, auth_user, scope, token

