from smtplib import SMTP
from email.message import EmailMessage
from email.headerregistry import Address
from pyontutils.utils_fast import isoformat
from .utils import log
from .config import auth

log = log.getChild('notifi')


__spec = None
def get_smtp_spec():
    global __spec
    if __spec is None:
        host = auth.get('smtp-host')
        port = int(auth.get('smtp-port'))
        __spec = dict(host=host, port=port, local_hostname='mail.interlex.org', timeout=10)

    return __spec


def send_message(msg, smtp_spec):
    with SMTP(**smtp_spec) as smtp:
        resp = smtp.send_message(msg)

    log.info(resp)
    return resp


def check_host(smtp_spec):
    log.debug(smtp_spec)
    with SMTP(**smtp_spec) as smtp:
        resp = smtp.noop()

    log.info(resp)
    return resp


def make_message(frm, to, subject, body):
    msg = EmailMessage()
    msg['From'] = frm
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)
    return msg


def isofnm(dt):
    return isoformat(dt, timespec='seconds')


_email_test_target = None


def msg_email_verify(
        user_email, now, start, delay_seconds, minutes, expires,
        verification_link, reverify_link):
    to = Address(addr_spec=user_email)
    real_to = to if _email_test_target is None else Address(addr_spec=_email_test_target)
    inow, istart, iexpires = [isofnm(dt).replace('T', ' ') for dt in (now, start, expires)]
    return make_message(
        Address('InterLex', addr_spec='noreply@interlex.org'),
        real_to,
        'InterLex account email address verification',
        # FIXME TODO if we direct people through the orcid workflow immediately
        # then we might be able to extend the email verification time since
        # they will be occupied with the orcid flow
        f'''Hi!

Someone (hopefully you) created a new InterLex account with this email
address ({to.addr_spec})

If it wasn't you, please ignore this email and do not click any of the links.

If it was you, click the following link in about {delay_seconds} seconds to confirm

{verification_link}

The confirmation link will work starting at {istart}
approximately {delay_seconds} seconds after this email was sent
and will expire at {iexpires}
approximately {minutes} minutes after this email was sent.

Sent   {inow}
Start  {istart}
Expire {iexpires}

If you have not already completed your orcid account verification
process you will be redirected to complete that process as well.

If this confirmation link has expired please request another at
{reverify_link}

If something has gone wrong please email support@interlex.org

Thanks!
''',
    )


def msg_user_recover(
        user_email, now, start, delay_seconds, minutes, expires,
        reset_link):
    to = Address(addr_spec=user_email)
    real_to = to if _email_test_target is None else Address(addr_spec=_email_test_target)
    inow, istart, iexpires = [isofnm(dt).replace('T', ' ') for dt in (now, start, expires)]
    return make_message(
        Address('InterLex', addr_spec='noreply@interlex.org'),
        real_to,
        'InterLex account recovery',
        f'''Hi!

Someone (hopefully you) issued a request to recover the
InterLex account associated with this email
address ({to.addr_spec})

If it wasn't you, please ignore this email and do not click any of the links.

If it was you, click the following link in about {delay_seconds} seconds
to reset your account password.

{reset_link}

The reset link will work starting at {istart}
approximately {delay_seconds} seconds after this email was sent
and will expire at {iexpires}
approximately {minutes} minutes after this email was sent.

Sent   {inow}
Start  {istart}
Expire {iexpires}

If something has gone wrong please email support@interlex.org

Thanks!
''',
    )


def msg_user_recover_alt(user_email):
    to = Address(addr_spec=user_email)
    real_to = to if _email_test_target is None else Address(addr_spec=_email_test_target)
    inow, istart, iexpires = [isofnm(dt).replace('T', ' ') for dt in (now, start, expires)]
    return make_message(
        Address('InterLex', addr_spec='noreply@interlex.org'),
        real_to,
        'InterLex account activity',
        f'''Hi!

Someone (hopefully you) issued a request to recover the InterLex
account associated with this alternate email address. A separate
email with a recovery link was sent to the primary email account.

Thanks!
''',
    )


def main():
    import base64, secrets
    from datetime import timedelta
    from pyontutils.utils_fast import utcnowtz

    smtp_spec_testing = dict(host='localhost', port=25, local_hostname='mail.interlex.org', timeout=10)
    check_host(smtp_spec_testing)

    username = 'tom-test'
    email = None
    nowish = utcnowtz()
    delay_seconds = 60
    lifetime_seconds = 900
    minutes = lifetime_seconds // 60
    startish = nowish + timedelta(seconds=delay_seconds)
    thenish = nowish + timedelta(seconds=lifetime_seconds)

    token_str = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode()

    scheme = 'https'
    reference_host = 'uri.interlex.org'
    verification_link = f'{scheme}://{reference_host}/u/ops/ever?{token_str}'
    reverify_link = f'{scheme}://{reference_host}/{username}/priv/email-verify'  # FIXME obviously wrong link

    msg = msg_email_verify(
        email, nowish, startish, delay_seconds, minutes, thenish,
        verification_link, reverify_link)

    print(msg._payload)
    send_message(msg, smtp_spec_testing)
    breakpoint()


if __name__ == '__main__':
    main()
