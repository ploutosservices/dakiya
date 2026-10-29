"""ONE SEND, AND ITS RECORD.

`send()` is the only function that hands a message over — to Google for a `workspace` or
`gmail` inbox, to an SMTP submission door for an `smtp` one. Its writes are
transactions of its own: a refusal from the grant check on is recorded `refused` and committed,
and a send is recorded `sending` and committed BEFORE the way out is called, then settled `sent`
or `failed` — so a crash leaves a row that says a send was attempted, and never a mail with no row.
"""
from __future__ import annotations

import base64
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Mapping, Optional

from . import rules, store


def _google(url: str, body: bytes, headers: dict) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        text = e.read().decode('utf-8', 'replace')
        said = None
        try:
            err = json.loads(text)
            inner = err.get('error')
            said = err.get('error_description') or (inner.get('message') if isinstance(inner, dict) else inner)
        except (ValueError, AttributeError):
            pass
        raise rules.GoogleRefused(f'{e.code}: {said or text[:300]}') from None
    except urllib.error.URLError as e:
        raise rules.GoogleRefused(f'Google was not reached: {e.reason}') from None


def gmail_send(cred: rules.Credential, send_as: str, raw: bytes, recipients=None) -> str:
    """Google's way out: a token for the inbox (how, by its account kind), then base64url of the whole
    message, posted as `raw` for user `me`; Gmail's id back. Gmail reads the recipients from
    the headers, so `recipients` is not used."""
    token = _google('https://oauth2.googleapis.com/token',
                    urllib.parse.urlencode(rules.token_request(cred, send_as)).encode(),
                    {'Content-Type': 'application/x-www-form-urlencoded'})['access_token']
    sent = _google('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
                   json.dumps({'raw': base64.urlsafe_b64encode(raw).decode()}).encode(),
                   {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    return sent['id']


def smtp_send(cred: rules.Credential, send_as: str, raw: bytes, recipients) -> str:
    """An `smtp` inbox's hand-over. STARTTLS (TLS 1.2 or above, the
    door verified against <P>_CA and its name checked against the host of <P>_ADDRESS),
    presenting this service's certificate, no AUTH. MAIL FROM the inbox, RCPT each envelope
    recipient; a refusal at either is RSET and QUIT with nothing handed over. Then DATA, byte
    for byte. One attempt, no retry. The door's 250 to DATA back — its "queued as …"."""
    host, _, port = cred.values['address'].rpartition(':')
    try:
        ctx = ssl.create_default_context(cafile=cred.values['ca'])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cred.values['cert'], cred.values['key'])
        with smtplib.SMTP(host, int(port), timeout=60) as s:
            s.ehlo()
            if not s.has_extn('starttls'):
                raise rules.MailOutRefused(f'the mail-out door at {host}:{port} offers no STARTTLS: nothing was handed over')
            s.starttls(context=ctx)
            s.ehlo()
            code, said = s.mail(send_as)
            if code != 250:
                s.rset()
                raise rules.MailOutRefused(f'MAIL FROM:<{send_as}> refused: {code} {said.decode("utf-8", "replace")}')
            for r in recipients:
                code, said = s.rcpt(r)
                if code not in (250, 251):
                    s.rset()
                    raise rules.MailOutRefused(f'RCPT TO:<{r}> refused: {code} {said.decode("utf-8", "replace")}')
            code, said = s.data(raw)
            if code != 250:
                raise rules.MailOutRefused(f'DATA refused: {code} {said.decode("utf-8", "replace")}')
            return said.decode('utf-8', 'replace')
    except rules.MailOutRefused:
        raise
    except smtplib.SMTPResponseException as e:
        raise rules.MailOutRefused(f'{e.smtp_code} {e.smtp_error.decode("utf-8", "replace")}') from None
    except (smtplib.SMTPException, OSError, ValueError) as e:   # ssl.SSLError is an OSError
        raise rules.MailOutRefused(f'the mail-out door was not reached: {e}') from None


def send(application: str, ask: rules.Ask, env: str, environ: Optional[Mapping[str, str]] = None,
         deliver=None) -> dict:
    """Send one message for `ask.tenant`, as `application`, and record that it was asked.

    `env` is this deployment's MAIL_SEND_ENV, already read; the caller's identity and the body's
    shape were proved before this is called. The rest of the refusals' order is here: the grant,
    the From inbox, the tenant's address off production, the parts' size, the credential,
    Google or the SMTP server. Raises Refused, GoogleRefused or MailOutRefused, and the row says
    so; an error of the store itself is not caught here (the caller answers 500)."""
    environ = os.environ if environ is None else environ
    inbox = eff = raw = None
    try:
        with store.connect(environ) as conn, conn.cursor() as cur:
            rules.authorise(application, ask.tenant, 'send', store.grants(cur, application))
            inbox = rules.inbox_for(store.inboxes(cur, ask.tenant), ask.tenant, ask.message.from_address)
            receives = rules.receives_at(env, ask.tenant, None if rules.is_production(env)
                                         else store.receives_at(cur, ask.tenant))
            rules.check_size(ask.message)
            eff = rules.effective(env, inbox, ask.message, receives)
            raw = rules.build_raw(inbox, eff, ask.message)
            cred = rules.key_for(inbox, environ)
    except rules.Refused as x:
        with store.connect(environ) as conn, conn.cursor() as cur:
            store.record(cur, application, ask, env, 'refused', x.detail, inbox, eff, raw)
        raise
    smtp = inbox.account_kind == 'smtp'
    deliver = deliver or (smtp_send if smtp else gmail_send)
    with store.connect(environ) as conn, conn.cursor() as cur:
        row_id = store.record(cur, application, ask, env, 'sending', None, inbox, eff, raw)
    try:
        said = deliver(cred, inbox.address, raw, eff.recipients)
    except rules.Undelivered as x:
        with store.connect(environ) as conn, conn.cursor() as cur:
            store.settle(cur, row_id, 'failed', error=str(x)[:2000])
        raise
    except Exception as x:
        with store.connect(environ) as conn, conn.cursor() as cur:
            store.settle(cur, row_id, 'failed', error=f'{type(x).__name__}: {x}'[:2000])
        raise
    gmail_id, queue_id = (None, said) if smtp else (said, None)
    with store.connect(environ) as conn, conn.cursor() as cur:
        store.settle(cur, row_id, 'sent', gmail_id=gmail_id, queue_id=queue_id)
    return {'id': row_id, 'gmail_id': gmail_id, 'message_id': eff.message_id,
            'sent_to': eff.recipients, 'environment': env}
