#!/usr/bin/env python3
"""The demo's rows: one tenant, one inbox it sends from, and one application allowed to send for it.

    python demo/seed.py          (MAIL_SEND_DSN names the store; run after the migrations)

The service never writes these through a door: who may send, for whom and from which address is
the operator's decision, written straight into the store. Running it twice changes nothing.
"""
import os

import psycopg2

ROWS = [
    ('tenant', ('tenant', 'receives_at'), ('acme', 'desk@acme.example')),
    ('inbox', ('tenant', 'address', 'account_kind', 'key_env'), ('acme', 'billing@acme.example', 'smtp', 'DEMO_SMTP')),
    ('"grant"', ('application', 'tenant', 'verb', 'asked_by'), ('demo', 'acme', 'send', 'demo')),
]

with psycopg2.connect(os.environ['MAIL_SEND_DSN']) as conn, conn.cursor() as cur:
    for table, cols, values in ROWS:
        where = ' AND '.join(f'{c} = %s' for c in cols)
        cur.execute(f'SELECT 1 FROM {table} WHERE {where} AND NOT is_deleted', values)
        if not cur.fetchone():
            cur.execute(f'INSERT INTO {table} ({", ".join(cols)}) VALUES ({", ".join(["%s"] * len(cols))})', values)
print('seeded: tenant acme, inbox billing@acme.example (smtp), grant demo -> acme')
