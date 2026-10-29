#!/usr/bin/env python3
"""THE MAIL SERVICE AGAINST ITS RULES — the cases one by one, each under a label of this file's
own (a number, `body` for what is refused before anything is asked, C1–C4 for who calls).

Everything is asked of the PURE functions of mailsend.rules — no database, no Google, no
environment of this process.

    S  a From inbox of the tenant    S2  a second one    R  the tenant's receives_at
    a@x, b@x, c@x  outside addresses
"""
import base64
import email
import email.header
import email.policy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from mailsend import rules                                               # noqa: E402

S, S2, R = 's@t.example', 's2@t.example', 'r@t.example'
A, B, C, D = 'a@x.example', 'b@x.example', 'c@x.example', 'd@x.example'
ROWS = [{'tenant': 'acme', 'address': S, 'account_kind': 'workspace', 'key_env': 'K'},
        {'tenant': 'acme', 'address': S2, 'account_kind': 'workspace', 'key_env': 'K'}]
HTML = '<html><body><p>hi</p></body></html>'
fail = 0


def check(case, what, got, want):
    global fail
    if got != want:
        fail += 1
        print(f'FAIL case {case}: {what}\n      want {want!r}\n      got  {got!r}')


def refused(case, what, f, status, *named):
    global fail
    try:
        f()
    except rules.Refused as x:
        if x.status != status or not all(n in x.detail for n in named):
            fail += 1
            print(f'FAIL case {case}: {what} — refused {x.status} "{x.detail}", want {status} naming {named}')
        return
    fail += 1
    print(f'FAIL case {case}: {what} — was not refused')


def body(**kw):
    b = {'tenant': 'acme', 'from': S, 'acting_user': None, 'purpose': 'test.conformance',
         'to': [A], 'subject': 'Hello', 'html': HTML}
    b.update(kw)
    return {k: v for k, v in b.items() if v is not ...}


def run(env, receives=R, **kw):
    """The body through the door's pure path: parsed, its inbox found, the rules applied."""
    ask = rules.ask_from(body(**kw))
    inbox = rules.inbox_for(ROWS, ask.tenant, ask.message.from_address)
    return inbox, rules.effective(env, inbox, ask.message, receives, now=0, mint='m'), ask.message


def head(raw: bytes) -> list:
    return raw.decode().split('\r\n\r\n')[0].split('\r\n')


def header(raw: bytes, name: str):
    """A header of the message as a reader parses it (unfolded, decoded), or None."""
    v = email.message_from_bytes(raw, policy=email.policy.default)[name]
    return None if v is None else str(v)


OPEN = 'In production, this email will be sent to '

# ── cases 1–4, 9, 10, 13–16, 22: who receives, by environment ────────────────────────────
table = [
    #  n   environment    kw                                        → to   → reply-to  → subject           opening names
    (1,  'production', {},                                          [A],   S,          'Hello',            None),
    (2,  'dev',        {},                                          [R],   R,          '[dev]: Hello',     A),
    (3,  'staging',    {'from': S2, 'to': [A, B]},                  [R],   R,          '[staging]: Hello', f'{A}, {B}'),
    (4,  'dev',        {'from': f'  {S.upper()}  '},                [R],   R,          '[dev]: Hello',     A),
    (9,  'production', {'reply_to': B},                             [A],   B,          'Hello',            None),
    (10, 'dev',        {'reply_to': B},                             [R],   R,          '[dev]: Hello',     f'{A}. Reply-To: {B}'),
    (13, 'production', {'subject': ...},                            [A],   S,          '',                 None),
    (14, 'dev',        {'subject': ''},                             [R],   R,          '[dev]: ',          A),
    (22, 'production', {'to': [f' {A} ']},                          [A],   S,          'Hello',            None),
]
for n, env, kw, want_to, want_reply, want_subject, names in table:
    inbox, e, _ = run(env, **kw)
    check(n, 'To', e.to, want_to)
    check(n, 'Reply-To', e.reply_to, want_reply)
    check(n, 'Subject', e.subject, want_subject)
    if names is None:
        check(n, 'no opening line', OPEN in e.html, False)
        check(n, 'the HTML as given', e.html, HTML)
    else:
        check(n, 'the opening paragraph is directly inside <body>',
              e.html.startswith('<html><body><p style="') and f'{OPEN}{names}.</p><p>hi</p>' in e.html, True)
check(4, 'From carries the row\'s spelling', run('dev', **{'from': f'  {S.upper()}  '})[0].address, S)

_, e, _ = run('production', html=...)
check(15, 'no html, no text: one empty body', e.html, '')
_, e, _ = run('dev', html='')
check(16, 'an empty html off production is the opening line alone',
      e.html.startswith('<p style=') and e.html.endswith(f'{OPEN}{A}.</p>'), True)

# HTML with no <body> carries the off-production paragraph first; the addresses are escaped
_, e, _ = run('dev', html='<p>fragment</p>')
check(13, 'a fragment carries the paragraph first', e.html.startswith('<p style=') and e.html.endswith('</p><p>fragment</p>'), True)
check(13, 'the To list is escaped', '&lt;' in rules.opening(['x<y@z.example']), True)

# ── cases 7, 8, 22a: Cc, Bcc and the headers that name a recipient ─────────────────────
inbox, e, m = run('production', cc=[B], bcc=[C])
raw = rules.build_raw(inbox, e, m, stamp='T')
check(7, 'production: To, Cc, Bcc as asked', (e.to, e.cc, e.bcc, e.recipients), ([A], [B], [C], [A, B, C]))
check(7, 'the Cc and Bcc headers are written (Gmail strips Bcc)',
      (header(raw, 'Cc'), header(raw, 'Bcc')), (B, C))
inbox, e, m = run('dev', cc=[B], bcc=[C], headers={'Resent-To': D, 'X-A': '1'})
raw = rules.build_raw(inbox, e, m, stamp='T')
check(8, 'off production: R alone', (e.to, e.cc, e.bcc, e.recipients), ([R], [], [], [R]))
check(8, 'no Cc, Bcc or Resent-To in the message; X-A kept',
      (header(raw, 'Cc'), header(raw, 'Bcc'), header(raw, 'Resent-To'), header(raw, 'X-A')), (None, None, None, '1'))
check(8, 'the opening line names them all', f'{OPEN}{A}. Cc: {B}. Bcc: {C}. Resent-To: {D}.</p>' in e.html, True)
leaks = {'List-Unsubscribe': '<mailto:u@x.example>', 'Errors-To': 'e@x.example', 'Read-Receipt-To': 'r@x.example',
         'Mail-Reply-To': 'm@x.example', 'Disposition-Notification-To': 'n@x.example'}
inbox, e, m = run('dev', headers=leaks)
raw = rules.build_raw(inbox, e, m, stamp='T')
check('22a', 'none of the removed headers is in the message', [header(raw, n) for n in leaks], [None] * len(leaks))
check('22a', 'each is named in the opening line',
      all(rules._escape(f'{n}: {v}.') in e.html for n, v in leaks.items()), True)
inbox, e, m = run('production', headers=leaks)
check(14, 'production sends every one of them', [header(rules.build_raw(inbox, e, m, stamp='T'), n) for n in leaks],
      list(leaks.values()))

# ── cases 5, 6, 11, 17–21, 31d–31f: refused ───────────────────────────────────────────────
refused(5, 'From with no row for the tenant', lambda: run('dev', **{'from': 'z@t.example'}), 422, 'acme')
refused(6, 'no From', lambda: run('dev', **{'from': ...}), 422, 'from')
refused(11, 'text and html', lambda: run('dev', text='plain'), 422, 'text')
refused(17, 'an unknown field', lambda: run('dev', foo=1), 422, 'foo')
for label, to in (('no to', ...), ('an empty to', []), ('to as a string', A)):
    refused(18, label, lambda to=to: run('dev', to=to), 422, 'to')
refused(19, 'from_name with CR LF', lambda: run('dev', from_name='K\r\nBcc: z@x.example'), 422, 'from_name')
refused(20, 'reply_to with CR LF', lambda: run('dev', reply_to=f'{B}\r\nBcc: z@x.example'), 422, 'reply_to')
refused('20a', 'subject with LF', lambda: run('dev', subject='a\nb'), 422, 'subject')
refused('20b', 'an address with a name', lambda: run('dev', to=[f'Ann <{A}>']), 422, 'to')
refused(21, 'no acting_user key', lambda: run('dev', acting_user=...), 422, 'acting_user')
check(21, 'acting_user null passes', rules.ask_from(body()).acting_user, None)
for h in ({'Bcc': B}, {'CC': B}):
    refused('31d', f'{h} in headers', lambda h=h: run('dev', headers=h), 422, list(h)[0])
for h in ({'Subject': 'x'}, {'Content-Type': 'x'}, {'Return-Path': 'x'}):
    refused('31e', f'{h} in headers', lambda h=h: run('dev', headers=h), 422, list(h)[0])
for h in ({'X-A': 'a\r\nb'}, {'Bad Name': 'a'}, {'X-A': 'café'}, {'X-A': 'x' * 1000}):
    refused('31f', f'{str(h)[:40]} in headers', lambda h=h: run('dev', headers=h), 422, 'headers')
refused('6c', 'a non-ASCII Message-ID', lambda: run('dev', message_id='<é@x>'), 422, 'message_id')
refused('6c', 'cc not a list', lambda: run('dev', cc=B), 422, 'cc')

# ── case 12: the environment has no default ────────────────────────────────────────────
refused(12, 'MAIL_SEND_ENV unset', lambda: rules.environment({}), 503, 'MAIL_SEND_ENV')
refused(12, 'MAIL_SEND_ENV empty', lambda: rules.environment({'MAIL_SEND_ENV': '  '}), 503, 'MAIL_SEND_ENV')
check(12, 'production is the one word', [rules.is_production(v) for v in ('production', 'Production', 'prod', 'dev')],
      [True, False, False, False])

# ── cases 23, 24: the tenant's receives_at ──────────────────────────────────────────────
refused(23, 'off production, a tenant with no tenant row', lambda: run('dev', receives=None), 503, 'acme')
check(24, 'in production it is not asked', run('production', receives=None)[1].to, [A])

# ── cases 25–30: headers ─────────────────────────────────────────────────────────────────
check(25, 'subject Café', rules.encode_subject('Café'), '=?UTF-8?B?Q2Fmw6k=?=')
long = '[staging]: ' + 'Ünïcödé subject words ' * 9
words = rules.encode_subject(long).split('\r\n ')
check('25a', 'a long subject is several words, none over 75 characters',
      (len(words) > 1, max(len(w) for w in words) <= 75), (True, True))
check('25a', 'decoded, the whole subject', str(email.header.make_header(email.header.decode_header(rules.encode_subject(long)))), long)
check(26, 'a name with a special is quoted', rules.format_from(S, 'Doe, Jane'), f'"Doe, Jane" <{S}>')
check('26a', 'a name that is not ASCII is encoded words', rules.format_from(S, 'Jäne').startswith('=?UTF-8?B?'), True)
check('26b', 'a plain name is not quoted', rules.format_from(S, 'Jane Doe'), f'Jane Doe <{S}>')
check(27, 'From with no name', rules.format_from(S, None), S)
inbox, e, m = run('production')
raw = rules.build_raw(inbox, e, m, stamp='T')
check(28, 'Date the clock, UTC; Message-ID minted at the From domain',
      ('Date: Thu, 01 Jan 1970 00:00:00 GMT' in head(raw), header(raw, 'Message-ID'), e.message_id),
      (True, '<m@t.example>', '<m@t.example>'))
given = {'date': 'Mon, 1 Jan 2024 00:00:00 +0000', 'message_id': '<x@y>', 'in_reply_to': '<p@y>', 'references': '<o@y> <p@y>'}
inbox, e, m = run('production', **given)
h = head(rules.build_raw(inbox, e, m, stamp='T'))
check(29, 'each header written as given, byte for byte',
      [f'Date: {given["date"]}' in h, f'Message-ID: {given["message_id"]}' in h,
       f'In-Reply-To: {given["in_reply_to"]}' in h, f'References: {given["references"]}' in h, e.message_id],
      [True, True, True, True, '<x@y>'])
check(30, 'no In-Reply-To, no References', [l for l in head(raw) if l.startswith(('In-Reply-To:', 'References:'))], [])
inbox, e, m = run('production', subject='')
check(13, 'an empty Subject is the bare header', 'Subject:' in head(rules.build_raw(inbox, e, m, stamp='T')), True)

# ── cases 31–31c: plain text, and the headers that pass through ──────────────────────────
check(31, 'text to paragraphs', run('production', html=..., text='Hello\nworld\n\nBye <you>')[1].html,
      '<p>Hello<br>world</p><p>Bye &lt;you&gt;</p>')
check('31a', 'CRLF folded, a whitespace line is blank, edges dropped',
      run('production', html=..., text='\r\n\nA\r\n  \nB\n\n')[1].html, '<p>A</p><p>B</p>')
check('31b', 'an all-blank text is an empty body', run('production', html=..., text='   \n')[1].html, '')
passing = {'Sender': 'ops@t.example', 'X-Purpose': 'drill', 'Keywords': 'a, b'}
inbox, e, m = run('dev', headers=passing)
h = head(rules.build_raw(inbox, e, m, stamp='T'))
check('31c', 'each passes through as given, after the door\'s own',
      ([f'{k}: {v}' in h for k, v in passing.items()], h.index('Sender: ops@t.example') > h.index('MIME-Version: 1.0')),
      ([True, True, True], True))

# ── case 32: the one scope; the key's forms; case 38, a gmail token ──────────────────────
check(32, 'scopes', rules.SCOPES, ['https://www.googleapis.com/auth/gmail.send'])
WS = rules.Inbox('acme', S, 'workspace', 'P')
GM = rules.Inbox('acme', 'f@gmail.example', 'gmail', 'G')
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    claims = rules.assertion('sa@p.iam.example', pem, S, now=1000).split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
    check(32, 'the scope ASKED of Google', claims['scope'], 'https://www.googleapis.com/auth/gmail.send')
    check(32, 'asked as the From inbox', (claims['iss'], claims['sub']), ('sa@p.iam.example', S))
    # compared as a yes or no: a failing check must not print a key, even a throwaway one
    for form, placed in (('one line of base64 (the placed form)', base64.b64encode(pem.encode()).decode()),
                         ('a PEM with \\n written out', pem.replace('\n', '\\n')),
                         ('a whole PEM', pem)):
        cred = rules.key_for(WS, {'P_CLIENT_EMAIL': 'sa@p.iam.example', 'P_PRIVATE_KEY': placed})
        check(32, f'{form} is read back whole', (cred.values['client_email'], cred.values['private_key'].strip() == pem.strip()),
              ('sa@p.iam.example', True))
    check(32, 'a workspace token request is the JWT grant',
          rules.token_request(cred, S)['grant_type'], 'urn:ietf:params:oauth:grant-type:jwt-bearer')
except ImportError:
    fail += 1
    print('FAIL case 32: cryptography is not importable — the assertion was not checked')

# ── case 36: the credential by account kind ───────────────────────────────────────────────
refused(36, 'workspace, nothing placed', lambda: rules.key_for(WS, {}), 503, 'P_CLIENT_EMAIL')
refused(36, 'workspace, half placed', lambda: rules.key_for(WS, {'P_CLIENT_EMAIL': 'x@y.example'}), 503, 'P_PRIVATE_KEY')
refused(36, 'workspace, a key that is neither', lambda: rules.key_for(WS, {'P_CLIENT_EMAIL': 'x@y.example', 'P_PRIVATE_KEY': '!!'}),
        503, 'P_PRIVATE_KEY')
refused(36, 'gmail, the refresh token missing', lambda: rules.key_for(GM, {'G_CLIENT_ID': 'i', 'G_CLIENT_SECRET': 's'}),
        503, 'G_REFRESH_TOKEN')
gm = rules.key_for(GM, {'G_CLIENT_ID': 'i', 'G_CLIENT_SECRET': 's', 'G_REFRESH_TOKEN': 'r'})
check(38, 'a gmail inbox asks for a token with its refresh token, and nothing wider',
      rules.token_request(gm, GM.address),
      {'grant_type': 'refresh_token', 'client_id': 'i', 'client_secret': 's', 'refresh_token': 'r'})
refused(36, 'an account kind the door cannot sign for', lambda: rules.key_for(rules.Inbox('t', S, 'imap', 'X'), {}), 503, 'imap')


# ── cases 33–35: the message ─────────────────────────────────────────────────────────────
def parts(raw: bytes):
    """Top-level content type, then each part's content type, in order — read by hand."""
    text = raw.decode()
    top_head, _, rest = text.partition('\r\n\r\n')
    top = [l for l in top_head.split('\r\n') if l.lower().startswith('content-type:')][0]
    return top, [l for l in rest.split('\r\n') if l.lower().startswith('content-type:')], text


inbox, e, m = run('production', from_name='Jane Doe')
top, inner, text = parts(rules.build_raw(inbox, e, m, stamp='T'))
check(33, 'one text/html part', (top, inner), ('Content-Type: text/html; charset=UTF-8', []))
check(26, 'the From header on a real message', head(text.encode())[0], f'From: Jane Doe <{S}>')

csv = {'filename': 'r.csv', 'content_type': 'text/csv', 'data': base64.b64encode(b'a,b\n1,2\n').decode()}
inbox, e, m = run('production', attachments=[csv])
top, inner, text = parts(rules.build_raw(inbox, e, m, stamp='T'))
check(34, 'top level with an attachment', top, 'Content-Type: multipart/mixed; boundary="mixed_T"')
check(34, 'the html, then the attachment', inner, ['Content-Type: text/html; charset=UTF-8', 'Content-Type: text/csv; name="r.csv"'])
tail = text.split('--mixed_T')[-2]
check(34, 'the last part is a base64 attachment named r.csv',
      ('Content-Disposition: attachment; filename="r.csv"' in tail, 'Content-Transfer-Encoding: base64' in tail,
       base64.b64encode(b'a,b\n1,2\n').decode() in tail), (True, True, True))
check(34, 'the message ends with the closing boundary', text.endswith('--mixed_T--'), True)

logo = {'content_id': 'logo', 'content_type': 'image/png', 'data': base64.b64encode(b'\x89PNG').decode()}
inbox, e, m = run('production', inline=[logo], attachments=[csv])
top, inner, text = parts(rules.build_raw(inbox, e, m, stamp='T'))
check(35, 'mixed › related › html, the inline part, then the attachment',
      (top, inner), ('Content-Type: multipart/mixed; boundary="mixed_T"',
                     ['Content-Type: multipart/related; boundary="rel_T"', 'Content-Type: text/html; charset=UTF-8',
                      'Content-Type: image/png', 'Content-Type: text/csv; name="r.csv"']))
check(35, 'the part carries its Content-ID, inline', ('Content-ID: <logo>' in text, 'Content-Disposition: inline' in text), (True, True))
inbox, e, m = run('production', inline=[logo])
check(35, 'with no attachment the top is related', parts(rules.build_raw(inbox, e, m, stamp='T'))[0],
      'Content-Type: multipart/related; boundary="rel_T"')

# ── body: what is refused before anything is asked───────────────────────────────────────
refused('body', 'a line break in an address', lambda: run('dev', to=[f'{A}\r\nBcc: z@x.example']), 422, 'to')
refused('body', 'a line break in a filename', lambda: run('dev', attachments=[{**csv, 'filename': 'a\r\n.csv'}]), 422, 'filename')
refused('body', 'a line break in a Content-ID', lambda: run('dev', inline=[{**logo, 'content_id': 'l\no'}]), 422, 'content_id')
refused('body', 'attachment data that is not base64', lambda: run('dev', attachments=[{**csv, 'data': '!!'}]), 422, 'base64')
refused('body', 'a tenant that is not a key', lambda: run('dev', tenant='Acme Ltd'), 422, 'tenant')
big = rules.Message(S, [A], 's', '<p/>', 'p', attachments=[rules.Part('application/octet-stream', b'\0' * (rules.MAX_PART_BYTES + 1), 'big.bin')])
refused('body', 'parts over the cap', lambda: rules.check_size(big), 413, 'attachments')

# ── C1–C4: who calls ─────────────────────────────────────────────────────────────────────
refused('C1', 'no identity', lambda: rules.caller(None, 'dev'), 403, 'no identity')
refused('C1', 'no CN', lambda: rules.caller('O=Example', 'dev'), 403, 'CN=')
check('C1', 'the identity header, not placed', rules.identity_header({}), 'X-Client-Identity')
check('C1', 'the identity header, placed', rules.identity_header({'MAIL_SEND_IDENTITY_HEADER': ' X-Verified '}), 'X-Verified')
refused('C1', 'no identity names the placed header', lambda: rules.caller('', 'dev', 'X-Verified'), 403, 'X-Verified')
refused('C1', 'a CN after an escaped comma is not the identity', lambda: rules.caller('O=x\\,CN=billing@dev', 'dev'), 403, 'CN=')
check('C1', 'a CN after a real separator is', rules.caller('O=x,CN=billing@dev', 'dev'), 'billing')
refused('C2', 'another environment', lambda: rules.caller('CN=billing@staging', 'dev'), 403, 'billing@staging', 'dev')
refused('C2', 'an identity at a deployment with no MAIL_SEND_ENV', lambda: rules.caller('CN=billing@dev', None), 503, 'MAIL_SEND_ENV')
check('C2', 'the CN names the application', rules.caller('CN=portal@dev', 'dev'), 'portal')
check('C2', 'inside a longer subject', rules.caller('O=Example,CN=billing@dev', 'dev'), 'billing')
refused('C3', 'no grant for the tenant', lambda: rules.authorise('portal', 'acme', 'send', [('billing', 'acme', 'send')]),
        403, 'portal', 'acme')
rules.authorise('billing', 'acme', 'send', [('billing', 'acme', 'send')])
refused('C4', 'a verb the door does not offer', lambda: rules.authorise('billing', 'acme', 'read', [('billing', 'acme', 'read')]),
        403, 'read', 'not offered')

if fail:
    print(f'\n{fail} conformance check(s) FAILED')
    sys.exit(1)
print('mail-send: the conformance cases hold, and the refusals refuse')
