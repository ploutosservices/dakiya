"""THE RULES OF A SEND — pure functions over values handed in, no database, no Google, no
environment of their own.

What this module enforces:

  * WHO CALLS is an application, proved by its client certificate: the proxy in front writes
    `<identity header>: CN=<application>@<environment>` and this module reads nothing else
    about the caller (`caller`). The caller's environment must be the door's own. A tenant is
    acted for only under a grant (`authorise`).
  * A SENDING SERVICE, NOT A COMPOSE SERVICE: every field SMTP supports is taken from the
    caller, none is forced on it, and what it does not give is filled — Reply-To, Date and
    Message-ID. Content is never invented
    and never interpreted: an empty subject or body goes as given. `from` is one of
    the tenant's inboxes; there is no default sender.
  * PRODUCTION IS UNRESTRICTED, Cc, Bcc and every header included. OFF PRODUCTION NO
    MAIL LEAVES: To and Reply-To become the tenant's `receives_at`, Cc
    and Bcc and every header naming a recipient are removed, the subject starts
    `[<environment>]: ` and the HTML opens with one paragraph naming everyone production would
    have sent it to.
  * HTML ONLY: the service sends only HTML; plain text from the caller becomes one <p> per
    paragraph.
"""
from __future__ import annotations

import base64
import binascii
import email.utils
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

# Only sending is asked of Google. The service account's grant is wider; what is ASKED is this and only this.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# The verbs the door offers. Reading is the next verb and is NOT built; until it is
# designed, authorise() refuses every verb but this one, whatever a grant row says.
VERBS = frozenset({'send'})

# The whole body, nineteen names. Anything else is refused by name.
FIELDS = ('tenant', 'from', 'from_name', 'acting_user', 'purpose', 'to', 'cc', 'bcc', 'subject',
          'html', 'text', 'reply_to', 'date', 'message_id', 'in_reply_to', 'references', 'headers',
          'attachments', 'inline')

# The header fields with a name of their own, as the body spells them and as the wire does.
HEADER_FIELDS = (('reply_to', 'Reply-To'), ('date', 'Date'), ('message_id', 'Message-ID'),
                 ('in_reply_to', 'In-Reply-To'), ('references', 'References'))

# A `headers` name that has its own field or that the door builds. Refused, so no
# header is given twice.
OWN_HEADERS = frozenset({'from', 'to', 'cc', 'bcc', 'subject', 'reply-to', 'date', 'message-id',
                         'in-reply-to', 'references', 'mime-version', 'content-type',
                         'content-transfer-encoding', 'return-path'})

# The `headers` that name a recipient of mail, removed off production — recipients of
# this message, a read receipt, a list's mailto button, a bounce, a reply.
NAMES_A_RECIPIENT = frozenset({
    'resent-to', 'resent-cc', 'resent-bcc',
    'disposition-notification-to', 'return-receipt-to', 'read-receipt-to', 'x-confirm-reading-to',
    'list-unsubscribe', 'list-post', 'list-help', 'list-subscribe', 'list-owner', 'list-unsubscribe-post',
    'errors-to',
    'mail-reply-to', 'mail-followup-to'})

# Google takes 25 MB ENCODED (Google's documented limit); base64 adds a third,
# so 18 MB of attachment and inline parts is what fits. The whole JSON body is capped above
# that, before it is read (app.py).
MAX_PART_BYTES = 18 * 1024 * 1024
MAX_BODY_BYTES = 26 * 1024 * 1024

# RFC 5322 §2.1.1: a line is at most 998 octets. The door does not fold what it does not parse.
MAX_LINE = 998
# RFC 2047 §2: an encoded word is at most 75 characters; `=?UTF-8?B?` and `?=` take 12, and
# 45 bytes of UTF-8 are 60 of base64.
_WORD_BYTES = 45

# The values each account kind places under its prefix. `smtp`: the door's
# host:port, then three FILE PATHS — the certificate this service presents, its key, and the CA
# that verifies the door — read at send time.
KEY_SUFFIXES = {
    'workspace': ('_CLIENT_EMAIL', '_PRIVATE_KEY'),
    'gmail':     ('_CLIENT_ID', '_CLIENT_SECRET', '_REFRESH_TOKEN'),
    'smtp':      ('_ADDRESS', '_CERT', '_KEY', '_CA'),
}
SMTP_FILES = ('_CERT', '_KEY', '_CA')

_ADDRESS = re.compile(r'^[^@\s<>,;"]+@[^@\s<>,;"]+\.[^@\s<>,;"]+$')
_TENANT = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')
_PURPOSE = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')
_HEADER_NAME = re.compile(r'^[A-Za-z0-9-]+$')
_PRINTABLE = re.compile(r'^[\x20-\x7e\t]*$')
_CN = re.compile(r'(?:^|(?<!\\)[,/])\s*CN=([a-z0-9][a-z0-9_-]*)@([a-z0-9][a-z0-9_-]*)\s*(?:$|[,/])')
# RFC 5322 specials: a display name holding one is a quoted string.
_SPECIALS = re.compile(r'[()<>\[\]:;@\\,."]')


class Refused(Exception):
    """The send is not made. `status` is what the door answers: 403 who is calling, 411/413
    size, 422 the body or the message, 503 a setting this deployment has not set."""
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Undelivered(Exception):
    """The way out did not take the message: 502, in its own words, the last refusal there is."""


class GoogleRefused(Undelivered):
    """Google answered and it was not a yes. Its own words."""


class MailOutRefused(Undelivered):
    """An `smtp` inbox's door was not reached, or refused at MAIL FROM, a RCPT or DATA. Its words."""


@dataclass
class Part:
    """An attachment (`filename`) or an inline part (`content_id`)."""
    content_type: str
    data: bytes
    filename: str = ''
    content_id: str = ''


@dataclass
class Message:
    """What the caller gave. A field it did not give is None (or empty), never a default."""
    from_address: str
    to: Sequence[str]
    subject: str
    html: str
    purpose: str
    from_name: Optional[str] = None
    cc: Sequence[str] = ()
    bcc: Sequence[str] = ()
    reply_to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[str] = None
    headers: Sequence[tuple] = ()
    attachments: Sequence[Part] = ()
    inline: Sequence[Part] = ()


@dataclass
class Ask:
    """A posted send: the tenant it is for, the person the caller says it is for, the message."""
    tenant: str
    acting_user: Optional[str]
    message: Message


@dataclass
class Inbox:
    """One row of `inbox`: an address the tenant sends from, and how it is signed for."""
    tenant: str
    address: str
    account_kind: str
    key_env: str


@dataclass
class Credential:
    """The placed values for an inbox's prefix. `workspace`: client_email and a PEM; `gmail`:
    client_id, client_secret, refresh_token."""
    kind: str
    values: dict


@dataclass
class Effective:
    """What actually leaves, after the filling and the off-production rewrite; `removed` is the
    recipient-naming headers that rewrite took out."""
    to: list
    cc: list
    bcc: list
    reply_to: str
    subject: str
    html: str
    date: str
    message_id: str
    headers: list
    environment: str
    removed: list = field(default_factory=list)

    @property
    def recipients(self) -> list:
        """Who the mail goes to: To, Cc and Bcc (the record's `sent_to`)."""
        return [*self.to, *self.cc, *self.bcc]


# ── who is calling ───────────────────────────────────────────────────────────────────────

IDENTITY_HEADER = 'X-Client-Identity'


def identity_header(environ: Mapping[str, str]) -> str:
    """The header the proxy writes the verified identity in: MAIL_SEND_IDENTITY_HEADER, or
    X-Client-Identity when it is not set."""
    return (environ.get('MAIL_SEND_IDENTITY_HEADER') or '').strip() or IDENTITY_HEADER


def caller(header: Optional[str], own_environment: Optional[str], name: str = IDENTITY_HEADER) -> str:
    """The application named by the certificate the proxy verified, read from the header
    `name`. No header, or one that names no `CN=<application>@<environment>`: 403. A deployment
    with no MAIL_SEND_ENV: 503. The CN's environment is not this deployment's: 403 by name (the
    identity is checked before the environment)."""
    if not header or not header.strip():
        raise Refused(403, f'no identity: a send is made by an application presenting its client '
                           f'certificate at this door ({name})')
    m = _CN.search(header.strip())
    if not m:
        raise Refused(403, f'the identity {header.strip()[:120]!r} names no CN=<application>@<environment>')
    application, env = m.group(1), m.group(2)
    if not own_environment:
        environment({})
    if env != own_environment:
        raise Refused(403, f'{application}@{env} is not an application of this deployment ({own_environment}); '
                           f'a door answers its own environment only')
    return application


def authorise(application: str, tenant: str, verb: str, grants: Iterable[tuple]) -> None:
    """THE ONE PERMISSION HOOK. Every request passes here with its verb; a verb the
    door does not offer is refused whatever the rows say, and an application acts for a tenant
    only where a grant row says (application, tenant, verb)."""
    if verb not in VERBS:
        raise Refused(403, f'the verb {verb!r} is not offered by this door (only: {", ".join(sorted(VERBS))})')
    if (application, tenant, verb) not in set(grants):
        raise Refused(403, f'{application} holds no grant to {verb} for the tenant {tenant}')


# ── which deployment this is ─────────────────────────────────────────────────────────────────

def environment(environ: Mapping[str, str]) -> str:
    """The placed value, with NO default: unset is a refusal, not 'development'. The word is
    the one the CNs of this deployment carry (`dev`, `staging`, `production`)."""
    env = (environ.get('MAIL_SEND_ENV') or '').strip()
    if not env:
        raise Refused(503, 'MAIL_SEND_ENV is not set in this deployment — no mail is sent from a '
                           'deployment that cannot say which it is')
    return env


def is_production(env: str) -> bool:
    return env == 'production'


# ── whose address it leaves from, and where a tenant's test mail goes ──────────────────

def inbox_for(rows: Sequence[Mapping], tenant: str, asked: str) -> Inbox:
    """The live inbox row of `tenant` whose address is `asked`, compared trimmed and
    lower-cased. None of them: refused 422, naming the tenant. The door never picks
    one for the caller."""
    want = asked.strip().lower()
    for r in rows:
        if r['address'].strip().lower() == want:
            return Inbox(r['tenant'], r['address'], r['account_kind'], r['key_env'])
    raise Refused(422, f'from: {asked.strip()} is not an inbox of the tenant {tenant}')


def receives_at(env: str, tenant: str, address: Optional[str]) -> Optional[str]:
    """Off production, the tenant's ONE address its mail goes to (its `tenant` row).
    None placed: refused 503, naming the tenant. In production it is not asked."""
    if is_production(env):
        return None
    if not address:
        raise Refused(503, f'the tenant {tenant} has no address its mail goes to off production '
                           f'(no `tenant` row): nothing is sent from {env}')
    return address


# ── who receives ───────────────────────────────────────────────────────────────────────

OPENING_STYLE = ('background:#fef3c7;border:1px solid #f59e0b;border-radius:4px;padding:8px 12px;'
                 'margin:0 0 16px 0;font-size:12px;color:#92400e;font-family:Arial,sans-serif;')


def opening(to: Sequence[str], cc: Sequence[str] = (), bcc: Sequence[str] = (),
            reply_to: Optional[str] = None, removed: Sequence[tuple] = ()) -> str:
    """The off-production paragraph: everyone production would have sent it to, escaped — the To list,
    then each Cc, Bcc, asked Reply-To and recipient-naming header that was removed."""
    said = [f'In production, this email will be sent to {", ".join(to)}.']
    if cc:
        said.append(f'Cc: {", ".join(cc)}.')
    if bcc:
        said.append(f'Bcc: {", ".join(bcc)}.')
    if reply_to:
        said.append(f'Reply-To: {reply_to}.')
    said += [f'{name}: {value}.' for name, value in removed]
    return f'<p style="{OPENING_STYLE}">{_escape(" ".join(said))}</p>'


def effective(env: str, inbox: Inbox, msg: Message, receives: Optional[str] = None,
              now: Optional[float] = None, mint: Optional[str] = None) -> Effective:
    """THE ONE FUNCTION every send passes. What the caller left out of the header fields above
    is filled: Reply-To the From inbox, Date the clock (`now`), Message-ID minted (`mint`, a
    test's). In production nothing else is touched. Anywhere else To
    and Reply-To become `receives`, Cc, Bcc and every header naming a recipient go, the subject
    starts `[<environment>]: ` and the HTML opens with the paragraph — directly inside <body>,
    or first when there is none."""
    to = [a.strip() for a in msg.to]
    cc = [a.strip() for a in msg.cc]
    bcc = [a.strip() for a in msg.bcc]
    date = msg.date if msg.date is not None else email.utils.formatdate(now, usegmt=True)
    message_id = msg.message_id if msg.message_id is not None else \
        f'<{mint or uuid.uuid4()}@{inbox.address.rsplit("@", 1)[1]}>'
    reply_to = msg.reply_to if msg.reply_to is not None else inbox.address
    if is_production(env):
        return Effective(to, cc, bcc, reply_to, msg.subject, msg.html, date, message_id,
                         list(msg.headers), env)
    receives = receives_at(env, inbox.tenant, receives)
    kept = [(n, v) for n, v in msg.headers if n.lower() not in NAMES_A_RECIPIENT]
    removed = [(n, v) for n, v in msg.headers if n.lower() in NAMES_A_RECIPIENT]
    para = opening(to, cc, bcc, msg.reply_to, removed)
    html, n = re.subn(r'(<body[^>]*>)', lambda m: m.group(1) + para, msg.html, count=1, flags=re.I)
    if not n:
        html = para + msg.html
    return Effective([receives], [], [], receives, f'[{env}]: {msg.subject}', html, date, message_id,
                     kept, env, removed)


def _escape(s: str) -> str:
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


# ── which values sign ──────────────────────────────────────────────────────────────────

def key_for(inbox: Inbox, environ: Mapping[str, str]) -> Credential:
    """The placed values for the inbox's prefix, by its account kind. A Workspace key is placed
    as ONE LINE OF BASE64 of the PEM, and a whole PEM, or one
    with its line breaks written as \\n, is read as the same key. A value not set: 503
    naming it. NO FALLBACK in any deployment."""
    suffixes = KEY_SUFFIXES.get(inbox.account_kind)
    if suffixes is None:
        raise Refused(503, f'the inbox {inbox.address} names the account kind {inbox.account_kind!r}, '
                           f'which this door cannot sign for')
    values = {}
    for suffix in suffixes:
        v = (environ.get(inbox.key_env + suffix) or '').strip()
        if not v:
            raise Refused(503, f'{inbox.key_env + suffix} is not set in this deployment')
        values[suffix.lstrip('_').lower()] = v
    if inbox.account_kind == 'smtp':
        host, _, port = values['address'].rpartition(':')
        if not host or not port.isdigit():
            raise Refused(503, f'{inbox.key_env}_ADDRESS is placed but is not host:port')
        for suffix in SMTP_FILES:
            if not readable(values[suffix.lstrip('_').lower()]):
                raise Refused(503, f'{inbox.key_env + suffix} names a file this service cannot open and read')
    if inbox.account_kind == 'workspace':
        key = values['private_key']
        if '-----BEGIN' not in key:
            try:
                key = base64.b64decode(key, validate=True).decode()
            except (binascii.Error, ValueError, UnicodeDecodeError):
                raise Refused(503, f'{inbox.key_env}_PRIVATE_KEY is placed but is neither a PEM nor base64 of one') from None
        values['private_key'] = key.replace('\\n', '\n')
    return Credential(inbox.account_kind, values)


def readable(path: str) -> bool:
    """The file opens and reads — bytes, not parsed: a PEM fault is the handshake's 502."""
    try:
        with open(path, 'rb') as f:
            f.read(1)
        return True
    except OSError:
        return False


def placed(kind: str, prefix: str, environ: Mapping[str, str]) -> bool:
    """Health's yes/no for one prefix: every value its kind needs placed, and for `smtp` each
    of the three files readable."""
    suffixes = KEY_SUFFIXES.get(kind, ('',))
    if not all((environ.get(prefix + s) or '').strip() for s in suffixes):
        return False
    return kind != 'smtp' or all(readable(environ[prefix + s].strip()) for s in SMTP_FILES)


# ── the body ────────────────────────────────────────────────────────────────────────────

def _one_line(s: str) -> bool:
    return '\r' not in s and '\n' not in s


def _address(name: str, a) -> str:
    if not isinstance(a, str) or not _one_line(a) or not _ADDRESS.match(a.strip()):
        raise Refused(422, f'{name}: not an address')
    return a.strip()


def _addresses(name: str, listed, required: bool) -> list:
    if listed is None and not required:
        return []
    if not isinstance(listed, list) or (required and not listed):
        raise Refused(422, f'{name}: a non-empty list of addresses' if required else f'{name}: a list of addresses')
    return [_address(name, a) for a in listed]


def _header_value(name: str, wire: str, v) -> str:
    """The three checks on a caller-given header value, and nothing about its shape: a
    string on one line, of printable ASCII (RFC 5322 §2.2), the line no longer than 998."""
    if not isinstance(v, str):
        raise Refused(422, f'{name}: a string')
    if not _one_line(v):
        raise Refused(422, f'{name}: on one line')
    if not _PRINTABLE.match(v):
        raise Refused(422, f'{name}: printable ASCII only (the door writes it as given and does not encode it)')
    if len(wire) + 2 + len(v) > MAX_LINE:
        raise Refused(422, f'{name}: the header line is over {MAX_LINE} octets')
    return v


def text_to_html(text: str) -> str:
    """Plain text to HTML: CRLF and CR become LF; a paragraph is a run of lines between blank lines (a line
    of only whitespace is blank); each is one <p>, escaped, its line breaks kept as <br>."""
    paras, run = [], []
    for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        if line.strip():
            run.append(_escape(line))
        elif run:
            paras.append(run)
            run = []
    if run:
        paras.append(run)
    return ''.join('<p>' + '<br>'.join(p) + '</p>' for p in paras)


def ask_from(body) -> Ask:
    """A door's JSON body, as an Ask, or refused 422 naming the field (every 422 of the body
    comes before the store is asked). The nineteen names of FIELDS and no others."""
    if not isinstance(body, dict):
        raise Refused(422, 'the body is a JSON object')
    unknown = sorted(k for k in body if k not in FIELDS)
    if unknown:
        raise Refused(422, f'{", ".join(unknown)}: not a field of this door (it takes {", ".join(FIELDS)})')

    tenant = body.get('tenant')
    if not isinstance(tenant, str) or not _TENANT.match(tenant):
        raise Refused(422, 'tenant: a tenant key (lower-case letters, digits and -), e.g. acme')
    if body.get('from') is None:
        raise Refused(422, 'from: required — one of the tenant\'s inboxes')
    from_address = _address('from', body['from'])
    from_name = body.get('from_name')
    if from_name is not None and (not isinstance(from_name, str) or not _one_line(from_name)):
        raise Refused(422, 'from_name: text on one line')
    if 'acting_user' not in body:
        raise Refused(422, 'acting_user: required — the person the send is made for, or null for a script')
    acting = body['acting_user']
    if acting is not None:
        acting = _address('acting_user', acting)
    purpose = body.get('purpose')
    if not isinstance(purpose, str) or not _PURPOSE.match(purpose):
        raise Refused(422, 'purpose: a short name for the record (letters, digits, . _ -)')

    to = _addresses('to', body.get('to'), required=True)
    cc = _addresses('cc', body.get('cc'), required=False)
    bcc = _addresses('bcc', body.get('bcc'), required=False)

    subject = body.get('subject')
    if subject is None:
        subject = ''
    if not isinstance(subject, str):
        raise Refused(422, 'subject: a string')
    if not _one_line(subject):
        raise Refused(422, 'subject: on one line')

    if body.get('text') is not None and body.get('html') is not None:
        raise Refused(422, 'text: one body — give text or html, not both')
    if body.get('text') is not None:
        if not isinstance(body['text'], str):
            raise Refused(422, 'text: a string')
        html = text_to_html(body['text'])
    else:
        html = body.get('html')
        if html is None:
            html = ''
        if not isinstance(html, str):
            raise Refused(422, 'html: a string')

    given = {k: (_header_value(k, wire, body[k]) if body.get(k) is not None else None)
             for k, wire in HEADER_FIELDS}

    headers = body.get('headers')
    if headers is None:
        headers = {}
    if not isinstance(headers, dict):
        raise Refused(422, 'headers: an object of header name to string')
    pairs = []
    for n, v in headers.items():
        if not _HEADER_NAME.match(n):
            raise Refused(422, f'headers: {n[:60]!r} is not a header name (letters, digits and -)')
        if n.lower() in OWN_HEADERS:
            raise Refused(422, f'headers: {n} has its own field or is the door\'s to write')
        pairs.append((n, _header_value(f'headers.{n}', n, v)))

    def parts(name, label):
        listed = body.get(name)
        if listed is None:
            return []
        if not isinstance(listed, list):
            raise Refused(422, f'{name}: a list')
        out = []
        for a in listed:
            if not isinstance(a, dict):
                raise Refused(422, f'{name}: each is an object')
            for k in (label, 'content_type'):
                v = a.get(k)
                if not isinstance(v, str) or not v or not _one_line(v) or any(c in v for c in '"<>'):
                    raise Refused(422, f'{name}.{k}: required, on one line, without a quote or <>')
            try:
                data = base64.b64decode(a.get('data') or '', validate=True)
            except (ValueError, TypeError):
                raise Refused(422, f'{name}.data: not base64') from None
            p = Part(content_type=a['content_type'], data=data)
            setattr(p, label, a[label])
            out.append(p)
        return out

    msg = Message(from_address=from_address, to=to, subject=subject, html=html, purpose=purpose,
                  from_name=from_name or None, cc=cc, bcc=bcc, headers=pairs,
                  attachments=parts('attachments', 'filename'), inline=parts('inline', 'content_id'),
                  **given)
    return Ask(tenant, acting, msg)


def check_size(msg: Message) -> None:
    """The parts' decoded size, checked after the From inbox is known."""
    total = sum(len(p.data) for p in list(msg.attachments) + list(msg.inline))
    if total > MAX_PART_BYTES:
        raise Refused(413, f'attachments and inline parts: {total} bytes, and {MAX_PART_BYTES} is the most that fits')


# ── the message itself ─────────────────────────────────────────────────────────────────

def encode_words(text: str) -> str:
    """RFC 2047 encoded words, UTF-8, base64, each at most 75 characters — split
    between characters, never inside one — folded one per continuation line."""
    words, chunk = [], b''
    for ch in text:
        b = ch.encode()
        if len(chunk) + len(b) > _WORD_BYTES:
            words.append(chunk)
            chunk = b''
        chunk += b
    if chunk:
        words.append(chunk)
    return '\r\n '.join('=?UTF-8?B?' + base64.b64encode(w).decode() + '?=' for w in words)


def encode_subject(subject: str) -> str:
    """The Subject: encoded words; an empty Subject is the bare header."""
    return encode_words(subject) if subject else ''


def format_from(address: str, name: Optional[str]) -> str:
    """An address header: `Name <address>` with a display name, the bare address with none. A name that
    is not plain ASCII is encoded words; one holding an RFC 5322 special is quoted."""
    if not name:
        return address
    if not _one_line(name):
        raise Refused(422, 'from_name: on one line')
    if not name.isascii():
        return f'{encode_words(name)} <{address}>'
    if _SPECIALS.search(name):
        return '"' + name.replace('\\', '\\\\').replace('"', '\\"') + f'" <{address}>'
    return f'{name} <{address}>'


def _b64_lines(data: bytes) -> list:
    b = base64.b64encode(data).decode()
    return [b[i:i + 76] for i in range(0, len(b), 76)] or ['']


def build_raw(inbox: Inbox, eff: Effective, msg: Message, stamp: Optional[str] = None) -> bytes:
    """The whole message, as bytes. The door's own headers first, then the caller's `headers`
    as given. The HTML is one text/html part; with inline parts,
    multipart/related round it, each part base64 with its Content-ID; with
    attachments, multipart/mixed round the body, each attachment base64 with its own type and
    filename. From carries the inbox row's spelling. Bcc is written for
    Gmail to read and strip; an `smtp` inbox's message carries none — its Bcc are
    envelope recipients only. `stamp` names the boundaries and is the clock
    unless a test hands one in."""
    stamp = stamp or str(time.time_ns())
    lines = [f'From: {format_from(inbox.address, msg.from_name)}',
             f'To: {", ".join(eff.to)}']
    if eff.cc:
        lines.append(f'Cc: {", ".join(eff.cc)}')
    if eff.bcc and inbox.account_kind != 'smtp':
        lines.append(f'Bcc: {", ".join(eff.bcc)}')
    lines += [f'Reply-To: {eff.reply_to}',
              f'Subject: {encode_subject(eff.subject)}' if eff.subject else 'Subject:',
              f'Date: {eff.date}',
              f'Message-ID: {eff.message_id}']
    if msg.in_reply_to is not None:
        lines.append(f'In-Reply-To: {msg.in_reply_to}')
    if msg.references is not None:
        lines.append(f'References: {msg.references}')
    lines.append('MIME-Version: 1.0')
    lines += [f'{n}: {v}' for n, v in eff.headers]
    body = ['Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '',
            *_b64_lines(eff.html.encode())]

    if msg.inline:
        rel = f'rel_{stamp}'
        related = [f'Content-Type: multipart/related; boundary="{rel}"', '', f'--{rel}', *body, '']
        for p in msg.inline:
            related += [f'--{rel}',
                        f'Content-Type: {p.content_type}',
                        f'Content-ID: <{p.content_id}>',
                        'Content-Disposition: inline',
                        'Content-Transfer-Encoding: base64', '',
                        *_b64_lines(p.data), '']
        related.append(f'--{rel}--')
        body = related

    if msg.attachments:
        mixed = f'mixed_{stamp}'
        lines += [f'Content-Type: multipart/mixed; boundary="{mixed}"', '', f'--{mixed}', *body, '']
        for a in msg.attachments:
            lines += [f'--{mixed}',
                      f'Content-Type: {a.content_type}; name="{a.filename}"',
                      f'Content-Disposition: attachment; filename="{a.filename}"',
                      'Content-Transfer-Encoding: base64', '',
                      *_b64_lines(a.data), '']
        lines.append(f'--{mixed}--')
    else:
        lines += body
    return '\r\n'.join(lines).encode()


# ── Google ─────────────────────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def assertion(client_email: str, private_key_pem: str, send_as: str, now: Optional[int] = None) -> str:
    """A Workspace inbox's signed request for a token: this service account, acting as the
    inbox, asking for SCOPES and nothing else."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(time.time()) if now is None else now
    head = _b64url(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())
    claims = _b64url(json.dumps({
        'iss': client_email, 'sub': send_as, 'scope': ' '.join(SCOPES),
        'aud': 'https://oauth2.googleapis.com/token', 'iat': now, 'exp': now + 600,
    }).encode())
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = key.sign(f'{head}.{claims}'.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f'{head}.{claims}.{_b64url(signature)}'


def token_request(cred: Credential, send_as: str) -> dict:
    """The form posted to Google's token endpoint. Workspace: the JWT bearer grant, scope in
    the assertion. Gmail: the refresh-token grant — its scope was fixed when the account
    granted it, and nothing wider is asked here."""
    if cred.kind == 'workspace':
        return {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': assertion(cred.values['client_email'], cred.values['private_key'], send_as)}
    return {'grant_type': 'refresh_token', 'client_id': cred.values['client_id'],
            'client_secret': cred.values['client_secret'], 'refresh_token': cred.values['refresh_token']}
