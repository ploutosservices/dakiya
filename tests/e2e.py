#!/usr/bin/env python3
"""THE DEMO DEPLOYMENT, END TO END — through the proxy, out to the SMTP catcher.

    E2E_URL=https://nginx:8443 E2E_CERTS=/certs E2E_CAUGHT=http://smtp:8025 python tests/e2e.py

Run by `docker compose run --build --rm tests`. It grades what the catcher RECEIVED, not what the
service says it sent: the demo is a dev environment, so a mail asked for an outside address must
arrive at the tenant's own address, marked as not production.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

URL, CERTS, CAUGHT = os.environ['E2E_URL'], os.environ['E2E_CERTS'], os.environ['E2E_CAUGHT']
fail = 0


def check(what, got, want):
    global fail
    ok = got == want
    print(f'  {what:<72} {"ok" if ok else "FAIL"}' + ('' if ok else f'\n      want {want!r}\n      got  {got!r}'))
    fail += 0 if ok else 1


def call(method, path, body=None, cert=None, headers=None):
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, 'ca.pem'))
    if cert:
        ctx.load_cert_chain(os.path.join(CERTS, f'{cert}.pem'), os.path.join(CERTS, f'{cert}.key'))
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method,
                                 headers={**({'Content-Type': 'application/json'} if data else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


def caught():
    with urllib.request.urlopen(CAUGHT + '/api/v1/messages', timeout=10) as r:
        return json.load(r).get('messages') or []


def until_up():
    for _ in range(60):
        try:
            if call('GET', '/v1/health')[0] == 200:
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    sys.exit('the service did not answer /v1/health within a minute')


until_up()
ASK = {'tenant': 'acme', 'from': 'billing@acme.example', 'acting_user': None, 'purpose': 'demo',
       'to': ['someone@example.com'], 'subject': 'Your invoice',
       'html': '<html><body><p>Hello.</p></body></html>'}

print('health and identity')
status, body = call('GET', '/v1/health')
check('health answers 200 with no certificate', status, 200)
check('health names the store ok and every key placed', (body.get('store'), body.get('keys')), ('ok', {'DEMO_SMTP': True}))
check('a send with no certificate: 403', call('POST', '/v1/send', ASK)[0], 403)
check('a typed identity header with no certificate: 403 (the proxy clears it)',
      call('POST', '/v1/send', ASK, headers={'X-Client-Identity': 'CN=demo@dev'})[0], 403)
check('a send from another environment (demo@production): 403', call('POST', '/v1/send', ASK, 'demo@production')[0], 403)
check('a send by an application with no grant (other@dev): 403', call('POST', '/v1/send', ASK, 'other@dev')[0], 403)
check('a field the door does not take: 422', call('POST', '/v1/send', {**ASK, 'colour': 'red'}, 'demo@dev')[0], 422)

print('a send, outside production')
before = len(caught())
status, body = call('POST', '/v1/send', ASK, 'demo@dev')
check('demo@dev sends for acme: 200', status, 200)
check('the answer names where it went: the tenant, not the outside address', body.get('sent_to'), ['desk@acme.example'])
for _ in range(20):
    got = caught()
    if len(got) > before:
        break
    time.sleep(0.5)
check('the catcher received exactly one mail', len(got) - before, 1)
if len(got) > before:
    m = got[0]
    to = [a.get('Address') for a in m.get('To') or []] + [a.get('Address') for a in m.get('Cc') or []] \
        + [a.get('Address') for a in m.get('Bcc') or []]
    check('it reached the tenant only', to, ['desk@acme.example'])
    check('it came from the inbox asked for', (m.get('From') or {}).get('Address'), 'billing@acme.example')
    check('its subject says it is not production', (m.get('Subject') or '').startswith('[dev]'), True)

print()
if fail:
    sys.exit(f'mail-send end to end: {fail} check(s) failed')
print('mail-send end to end: the demo sends, refuses and keeps mail inside the tenant')
