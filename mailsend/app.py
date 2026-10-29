"""THE DOOR — `mail-send`, every application's one way to send mail.

    POST /v1/send     send one message; the answer carries the record's id
    GET  /v1/health   no identity needed: the store, the environment, which keys are placed

No door reads the record back, and no door writes an inbox or a grant.

WHO MAY CALL is an application whose client certificate the TLS-terminating proxy in front
verified: the proxy writes `<identity header>: CN=<application>@<environment>` and destroys one
the client typed. The header's name is the setting MAIL_SEND_IDENTITY_HEADER (default
X-Client-Identity). Where the proxy must be the only way in, this process listens on a unix
socket in a directory only the proxy's user may enter; on a developer's box, on loopback.

    ./run.sh      MAIL_SEND_UDS behind the proxy, or MAIL_SEND_PORT on a developer's box;
                  run.sh refuses neither, both, and a port in production. Start it there,
                  not with uvicorn directly, which skips those checks.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict

from . import rules, send as sending, store

app = FastAPI(title='mail-send', version='1',
              description='A mail service: one door every application sends through.')


class Closed(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Sent(Closed):
    id: int
    gmail_id: Optional[str]
    message_id: str
    sent_to: list[str]
    environment: str


class NotSent(Closed):
    sent: bool
    error: str


class Health(Closed):
    status: str
    environment: Optional[str]
    store: str
    keys: dict[str, bool]


def _refused(status: int, detail: str) -> JSONResponse:
    return JSONResponse({'sent': False, 'error': detail}, status_code=status)


_REFUSALS = {s: {'model': NotSent} for s in (403, 411, 413, 422, 503)}


@app.post('/v1/send', responses={200: {'model': Sent}, 502: {'model': NotSent}, **_REFUSALS})
async def send(request: Request) -> JSONResponse:
    """SEND ONE MESSAGE for a tenant, from one of its inboxes. The caller may give every field;
    the door fills Reply-To, Date and Message-ID when it does not. Production
    sends exactly what was given; anywhere else no mail leaves the tenant — To and Reply-To are
    the tenant's address, Cc, Bcc and recipient headers go, the subject and the HTML's first
    paragraph say so. Refusals come in a fixed order — the stated size, who calls, then the body, then the
    store's answers; from the grant check on, each leaves a `send` row. The send itself is
    synchronous (the store, Google, SMTP), so it runs in the thread pool, never on the event loop."""
    declared = request.headers.get('content-length', '')
    if not declared.isdigit():
        return _refused(411, 'a send states its Content-Length')
    if int(declared) > rules.MAX_BODY_BYTES:
        return _refused(413, f'a send is at most {rules.MAX_BODY_BYTES} bytes; this one states {declared}')
    try:
        env = (os.environ.get('MAIL_SEND_ENV') or '').strip() or None
        name = rules.identity_header(os.environ)
        application = rules.caller(request.headers.get(name), env, name)
    except rules.Refused as x:
        return _refused(x.status, x.detail)
    raw = await request.body()
    if len(raw) > rules.MAX_BODY_BYTES:
        return _refused(413, f'a send is at most {rules.MAX_BODY_BYTES} bytes')
    try:
        ask = rules.ask_from(json.loads(raw))
    except ValueError:
        return _refused(422, 'the body is not JSON')
    except rules.Refused as x:
        return _refused(x.status, x.detail)
    try:
        return JSONResponse(await run_in_threadpool(sending.send, application, ask, env))
    except rules.Refused as x:
        return _refused(x.status, x.detail)
    except rules.GoogleRefused as x:
        return _refused(502, f'Google refused: {x}')
    except rules.MailOutRefused as x:
        return _refused(502, f'the mail-out door refused: {x}')


@app.get('/v1/health', responses={200: {'model': Health}, 503: {'model': Health}})
def health() -> JSONResponse:
    """No identity and no data: whether the store answers, which environment this deployment says
    it is, and for each inbox's key prefix whether EVERY value its account kind needs is placed
    (two for a Workspace inbox, three for a Gmail one, four for an smtp one, whose three files
    must also open and read) — names and yes/no only, never a value."""
    env = (os.environ.get('MAIL_SEND_ENV') or '').strip() or None
    keys: dict[str, bool] = {}
    try:
        with store.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT DISTINCT key_env, account_kind FROM inbox WHERE NOT is_deleted ORDER BY key_env')
            for r in cur.fetchall():
                keys[r['key_env']] = rules.placed(r['account_kind'], r['key_env'], os.environ)
        state = 'ok'
    except Exception as x:   # the store's own words, which name no secret
        state = f'unreachable: {type(x).__name__}'
    ok = state == 'ok' and env is not None
    return JSONResponse({'status': 'ok' if ok else 'degraded', 'environment': env, 'store': state, 'keys': keys},
                        status_code=200 if ok else 503)
