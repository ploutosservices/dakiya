"""THE SERVICE'S OWN STORE — its Postgres, reached by MAIL_SEND_DSN alone.

It holds the inbox, tenant and grant rows (written by migration, never through a door) and the
record of every send. It knows no table of any application it sends for.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from typing import Optional

from . import rules


def dsn(environ=None) -> str:
    value = ((os.environ.get('MAIL_SEND_DSN') if environ is None else environ.get('MAIL_SEND_DSN')) or '').strip()
    if not value:
        raise rules.Refused(503, 'MAIL_SEND_DSN is not set in this deployment — the service has no store')
    return value


@contextmanager
def connect(environ=None):
    """One connection, one transaction: committed on a clean exit, rolled back on any other."""
    import psycopg2
    import psycopg2.extras
    conn = psycopg2.connect(dsn(environ), cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def grants(cur, application: str) -> list:
    cur.execute('SELECT application, tenant, verb FROM "grant" WHERE application = %s AND NOT is_deleted',
                [application])
    return [(r['application'], r['tenant'], r['verb']) for r in cur.fetchall()]


def inboxes(cur, tenant: str) -> list:
    """The tenant's live inbox rows: the addresses it may send from."""
    cur.execute('SELECT tenant, address, account_kind, key_env FROM inbox WHERE tenant = %s AND NOT is_deleted',
                [tenant])
    return cur.fetchall()


def receives_at(cur, tenant: str) -> Optional[str]:
    """The tenant's one address for mail off production, or None."""
    cur.execute('SELECT receives_at FROM tenant WHERE tenant = %s AND NOT is_deleted', [tenant])
    r = cur.fetchone()
    return r['receives_at'] if r else None


def asked(msg: rules.Message) -> dict:
    """Everyone the caller asked the mail to reach (the record's `asked_to`)."""
    out = {'to': [str(a) for a in msg.to], 'cc': list(msg.cc), 'bcc': list(msg.bcc)}
    if msg.reply_to is not None:
        out['reply_to'] = msg.reply_to
    named = {n: v for n, v in msg.headers if n.lower() in rules.NAMES_A_RECIPIENT}
    if named:
        out['headers'] = named
    return out


def record(cur, application: str, ask: rules.Ask, env: Optional[str], status: str,
           error: Optional[str] = None, inbox: Optional[rules.Inbox] = None,
           eff: Optional[rules.Effective] = None, raw: Optional[bytes] = None) -> int:
    """One row of `send`. No body and no bytes: names, sizes and sha256s. The From
    is the one asked whenever the inbox was not found — every recorded row has one."""
    msg = ask.message
    parts = [{'filename': a.filename, 'content_type': a.content_type, 'bytes': len(a.data),
              'sha256': hashlib.sha256(a.data).hexdigest()} for a in (msg.attachments or [])]
    parts += [{'content_id': p.content_id, 'content_type': p.content_type, 'bytes': len(p.data),
               'sha256': hashlib.sha256(p.data).hexdigest()} for p in (msg.inline or [])]
    cur.execute(
        """INSERT INTO send (application, tenant, acting_user, purpose, environment, from_address,
                             from_name, asked_to, sent_to, subject, reply_to, message_id, parts,
                             message_sha256, status, error)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        [application, ask.tenant, ask.acting_user, str(msg.purpose)[:80], env,
         inbox.address if inbox else msg.from_address, msg.from_name,
         json.dumps(asked(msg)), json.dumps(eff.recipients if eff else []),
         eff.subject if eff else str(msg.subject or '')[:998],
         eff.reply_to if eff else msg.reply_to, eff.message_id if eff else msg.message_id,
         json.dumps(parts), hashlib.sha256(raw).hexdigest() if raw else None, status, error])
    return cur.fetchone()['id']


def settle(cur, row_id: int, status: str, gmail_id: Optional[str] = None, error: Optional[str] = None,
           queue_id: Optional[str] = None) -> None:
    cur.execute('UPDATE send SET status = %s, gmail_id = %s, queue_id = %s, error = %s WHERE id = %s',
                [status, gmail_id, queue_id, error, row_id])
