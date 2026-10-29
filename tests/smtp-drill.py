#!/usr/bin/env python3
"""THE `smtp` INBOX AGAINST A LOCAL STAND-IN (each check labelled 40–48, this file's own numbering).

No environment: the stand-in is a socket server on 127.0.0.1 written on the standard library,
speaking EHLO, STARTTLS, MAIL, RCPT, RSET, DATA and QUIT; its CA, server and client certificates
are made for the run with `cryptography`; the service's store is replaced by a list in memory. So
it runs anywhere the requirements are installed, beside conformance.py:

    python tests/smtp-drill.py

It grades what the stand-in was HANDED, not what the code says it sent.
"""
import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from mailsend import rules, send, store                                  # noqa: E402

from cryptography import x509                                            # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization         # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa                # noqa: E402
from cryptography.x509.oid import NameOID                                # noqa: E402
import ipaddress                                                         # noqa: E402

fail = 0


def check(case, what, got, want):
    global fail
    ok = got == want
    print(f'  {case:>3} {what:<70} {"ok" if ok else "FAIL"}' + ('' if ok else f'\n      want {want!r}\n      got  {got!r}'))
    fail += 0 if ok else 1


# ── certificates for the run ──────────────────────────────────────────────────────────────────
DIR = tempfile.mkdtemp(prefix='smtp-drill-')
NOW = datetime.datetime.now(datetime.timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, cn, issuer_key=None, issuer_cn=None, ca=False, san=None):
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn or cn))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(minutes=5)).not_valid_after(NOW + datetime.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or subject_key).public_key()),
                        critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(issuer_key or subject_key, hashes.SHA256())


def _write(name, obj):
    path = os.path.join(DIR, name)
    with open(path, 'wb') as f:
        if isinstance(obj, x509.Certificate):
            f.write(obj.public_bytes(serialization.Encoding.PEM))
        else:
            f.write(obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return path


ca_key, other_key = _key(), _key()
ca = _cert(ca_key, 'drill CA', ca=True)
other_ca = _cert(other_key, 'another CA', ca=True)
SAN = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
srv_key, cli_key, bad_key = _key(), _key(), _key()
CA = _write('ca.pem', ca)
SRV_CERT = _write('server.pem', _cert(srv_key, 'localhost', ca_key, 'drill CA', san=SAN))
SRV_KEY = _write('server.key', srv_key)
BAD_CERT = _write('bad-server.pem', _cert(bad_key, 'localhost', other_key, 'another CA', san=SAN))
BAD_KEY = _write('bad-server.key', bad_key)
CLI_CERT = _write('client.pem', _cert(cli_key, 'mail-send@dev', ca_key, 'drill CA'))
CLI_KEY = _write('client.key', cli_key)


# ── the stand-in ──────────────────────────────────────────────────────────────────────────────
class StandIn:
    """One connection's worth of SMTP. `seen` is what it was handed, in order."""

    def __init__(self, starttls=True, refuse_mail=False, refuse_rcpt=(), data_code=250,
                 cert=SRV_CERT, key=SRV_KEY):
        self.starttls, self.refuse_mail, self.refuse_rcpt, self.data_code = starttls, refuse_mail, set(refuse_rcpt), data_code
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=CA)
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.seen, self.client_cn, self.data, self.connections = [], None, None, 0
        self.mail_from, self.rcpt = None, []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        self.connections += 1
        tls = False
        f = conn.makefile('rb')

        def say(line):
            conn.sendall(line.encode() + b'\r\n')

        try:
            say('220 stand-in ESMTP')
            while True:
                line = f.readline()
                if not line:
                    return
                cmd = line.decode().strip()
                verb = cmd.split(' ', 1)[0].split(':', 1)[0].upper()
                self.seen.append(('TLS ' if tls else '') + verb)
                if verb in ('EHLO', 'HELO'):
                    ext = ['250-stand-in', '250-SIZE 26214400'] + (['250-STARTTLS'] if self.starttls and not tls else [])
                    for e in ext:
                        say(e)
                    say('250 8BITMIME')
                elif verb == 'STARTTLS' and self.starttls and not tls:
                    say('220 go ahead')
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile('rb')
                    tls = True
                    peer = conn.getpeercert()
                    self.client_cn = dict(x[0] for x in peer['subject']).get('commonName') if peer else None
                elif verb == 'MAIL':
                    self.mail_from = cmd.split(':', 1)[1].strip()
                    say('553 5.7.1 sender refused by the stand-in' if self.refuse_mail else '250 2.1.0 ok')
                elif verb == 'RCPT':
                    addr = cmd.split(':', 1)[1].strip().strip('<>')
                    self.rcpt.append(addr)
                    say('554 5.7.1 recipient refused by the stand-in' if addr in self.refuse_rcpt else '250 2.1.5 ok')
                elif verb == 'DATA':
                    say('354 end with .')
                    buf = b''
                    while True:
                        l = f.readline()
                        if l in (b'.\r\n', b''):
                            break
                        buf += l[1:] if l.startswith(b'..') else l
                    self.data = buf
                    say('250 2.0.0 Ok: queued as DRILL123' if self.data_code == 250 else
                        f'{self.data_code} 4.7.1 tempfail from the stand-in')
                elif verb == 'RSET':
                    say('250 2.0.0 ok')
                elif verb == 'QUIT':
                    say('221 bye')
                    return
                else:
                    say('502 5.5.2 not offered')
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ── the store, in memory ──────────────────────────────────────────────────────────────────────
ROWS, TENANTS = [], {'acme': 'owner@example.com'}
INBOX = {'tenant': 'acme', 'address': 'noreply@example.org', 'account_kind': 'smtp', 'key_env': 'MAIL_OUT'}


@contextmanager
def _connect(environ=None):
    yield _Conn()


class _Conn:
    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _record(cur, application, ask, env, status, error=None, inbox=None, eff=None, raw=None):
    ROWS.append({'id': len(ROWS) + 1, 'status': status, 'error': error, 'sent_to': eff.recipients if eff else [],
                 'subject': eff.subject if eff else None, 'gmail_id': None, 'queue_id': None})
    return len(ROWS)


def _settle(cur, row_id, status, gmail_id=None, error=None, queue_id=None):
    ROWS[row_id - 1].update(status=status, gmail_id=gmail_id, error=error, queue_id=queue_id)


store.connect = _connect
store.grants = lambda cur, app: [('drill', 'acme', 'send')]
store.inboxes = lambda cur, tenant: [INBOX] if tenant == 'acme' else []
store.receives_at = lambda cur, tenant: TENANTS.get(tenant)
store.record, store.settle = _record, _settle


def environ_for(port, **drop):
    e = {'MAIL_OUT_ADDRESS': f'localhost:{port}', 'MAIL_OUT_CERT': CLI_CERT, 'MAIL_OUT_KEY': CLI_KEY, 'MAIL_OUT_CA': CA}
    for k in drop:
        e.pop(k)
    return e


def ask(subject='Hello', bcc=()):
    return rules.Ask('acme', None, rules.Message(
        from_address='noreply@example.org', to=['a@x.example'], bcc=list(bcc), subject=subject,
        html='<html><body><p>drill</p></body></html>', purpose='drill.smtp'))


def run(stand, env='production', a=None, environ=None):
    """send() as the door calls it; the answer, or the refusal's (status, words)."""
    try:
        return send.send('drill', a or ask(), env, environ=environ or environ_for(stand.port)), None
    except rules.Refused as x:
        return None, (x.status, x.detail)
    except rules.MailOutRefused as x:
        return None, (502, str(x))


print('smtp inbox against a local stand-in')

s = StandIn()
captured = {}
_build = rules.build_raw
rules.build_raw = lambda *a, **k: captured.setdefault('raw', _build(*a, **k))
out, err = run(s, a=ask(bcc=['hidden@x.example']))
rules.build_raw = _build
check(40, 'production: 200 with gmail_id null, sent to To and Bcc',
      (err, out and out['gmail_id'], out and out['sent_to']), (None, None, ['a@x.example', 'hidden@x.example']))
check(40, 'STARTTLS came before MAIL, and MAIL, RCPT, DATA under TLS',
      [v for v in s.seen if v in ('STARTTLS', 'MAIL', 'TLS MAIL', 'TLS RCPT', 'TLS DATA')],
      ['STARTTLS', 'TLS MAIL', 'TLS RCPT', 'TLS RCPT', 'TLS DATA'])
check(40, 'the client certificate was presented', s.client_cn, 'mail-send@dev')
check(40, 'MAIL FROM is the inbox; RCPT the envelope recipients', (s.mail_from, s.rcpt),
      ('<noreply@example.org>', ['a@x.example', 'hidden@x.example']))
check(40, 'DATA is byte for byte the built message', s.data, captured['raw'] + b'\r\n')
check(40, 'the message carries no Bcc header', b'\r\nBcc:' in captured['raw'].split(b'\r\n\r\n')[0], False)
check(40, 'record `sent`, with the door\'s queue_id', (ROWS[-1]['status'], ROWS[-1]['queue_id'], ROWS[-1]['gmail_id']),
      ('sent', '2.0.0 Ok: queued as DRILL123', None))

s = StandIn()
out, err = run(s, env='dev')
check(41, 'dev: RCPT the tenant\'s receives_at alone', s.rcpt, ['owner@example.com'])
check(41, 'the subject is tagged, the opening line names a@x',
      (ROWS[-1]['subject'], b'a@x.example' in __import__('base64').b64decode(
          b''.join(s.data.split(b'\r\n\r\n', 1)[1].split(b'\r\n')))), ('[dev]: Hello', True))

s = StandIn(refuse_rcpt=['a@x.example'])
out, err = run(s)
check(42, 'a refused RCPT: 502 naming the address, no DATA, record `failed`',
      (err and err[0], err and 'a@x.example' in err[1], 'TLS DATA' in s.seen, ROWS[-1]['status']), (502, True, False, 'failed'))
check(42, 'RSET before QUIT', s.seen[-2:], ['TLS RSET', 'TLS QUIT'])

s = StandIn(cert=BAD_CERT, key=BAD_KEY)
out, err = run(s)
check(43, 'a door certificate from another CA: 502, nothing handed over, `failed`',
      (err and err[0], 'TLS MAIL' in s.seen, s.data, ROWS[-1]['status']), (502, False, None, 'failed'))

for need in ('MAIL_OUT_ADDRESS', 'MAIL_OUT_CERT', 'MAIL_OUT_KEY', 'MAIL_OUT_CA'):
    s = StandIn()
    n = len(ROWS)
    out, err = run(s, environ=environ_for(s.port, **{need: 1}))
    check(44, f'{need} missing: 503 naming it, `refused`, no connection',
          (err and err[0], err and need in err[1], ROWS[-1]['status'], len(ROWS) - n, s.connections), (503, True, 'refused', 1, 0))
s = StandIn()
e = environ_for(s.port)
e['MAIL_OUT_CA'] = os.path.join(DIR, 'not-there.pem')
out, err = run(s, environ=e)
check(44, 'a path that does not open: 503 naming it, no connection',
      (err and err[0], err and 'MAIL_OUT_CA' in err[1], s.connections), (503, True, 0))

s = StandIn(starttls=False)
out, err = run(s)
check(45, 'no STARTTLS offered: no MAIL sent, 502, `failed` (the negative control)',
      (err and err[0], any('MAIL' in v for v in s.seen), ROWS[-1]['status']), (502, False, 'failed'))

s = StandIn(refuse_mail=True)
out, err = run(s)
check(46, 'MAIL FROM refused: no RCPT, no DATA, 502 in its words, `failed`',
      (err and err[0], err and 'sender refused by the stand-in' in err[1],
       any(v.endswith(('RCPT', 'DATA')) for v in s.seen), ROWS[-1]['status']), (502, True, False, 'failed'))

s = StandIn(data_code=451)
out, err = run(s)
check(47, 'DATA answered 451: 502 in its words, `failed`, one attempt',
      (err and err[0], err and '451' in err[1], ROWS[-1]['status'], s.connections, s.seen.count('TLS DATA')),
      (502, True, 'failed', 1, 1))

TENANTS.pop('acme')
s = StandIn()
n = len(ROWS)
out, err = run(s, env='dev')
check(48, 'dev, the tenant with no `tenant` row: 503 naming it, `refused`, no connection',
      (err and err[0], err and 'acme' in err[1], ROWS[-1]['status'], len(ROWS) - n, s.connections),
      (503, True, 'refused', 1, 0))

print(f'\n{fail} check(s) FAILED' if fail else '\nmail-send: the smtp inbox hands over what it must, and refuses what it must')
sys.exit(1 if fail else 0)
