"""THE SERVICE'S SCHEMA, versioned — four properties, on this store.

  ORDERED     0001, 0002 … applied by name
  ONCE        recorded in `schema_migration`; an applied version is never re-run
  IMMUTABLE   an applied file's checksum is stored; an edited one is refused by name
  SERIALISED  one advisory lock across the run

Run at DEPLOY, once, by one process — never at boot: two processes creating one table at
start-up can take a deployment down.

    python -m mailsend.schema_migrate --check    pending, and drift (exit 1 on drift); it creates
                                                 the bookkeeping table if it is absent
    python -m mailsend.schema_migrate --apply    apply what is pending
"""
from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timezone

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'migrations')

# Any 64-bit constant, the same in every process that migrates this store ('mail' in ASCII).
LOCK = 0x6D61696C

TABLE = """
CREATE TABLE IF NOT EXISTS schema_migration (
    version     TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL,
    applied_by  TEXT
)
"""


def on_disk() -> list[tuple[str, str, str]]:
    out = []
    for fn in sorted(os.listdir(DIR)):
        if fn.endswith('.sql'):
            sql = open(os.path.join(DIR, fn), encoding='utf-8').read()
            out.append((fn[:-4], hashlib.sha256(sql.encode()).hexdigest(), sql))
    return out


def state(conn):
    with conn.cursor() as cur:
        cur.execute(TABLE)
        conn.commit()
        cur.execute('SELECT version, sha256 FROM schema_migration')
        have = {r['version']: r['sha256'] for r in cur.fetchall()}
    disk = on_disk()
    return ([(v, s, q) for v, s, q in disk if v not in have],
            [(v, have[v], s) for v, s, _ in disk if v in have and have[v] != s])


def check(conn) -> int:
    pending, drifted = state(conn)
    for v, was, now in drifted:
        print(f'DRIFTED  {v}  applied as {was[:12]}… and the file is now {now[:12]}…')
    for v, _, _ in pending:
        print(f'PENDING  {v}')
    if drifted:
        print(f'\n{len(drifted)} applied migration(s) EDITED — a migration that has run is immutable; add a new one.')
        return 1
    print(f'\n{len(pending)} pending, {len(on_disk()) - len(pending)} applied, none drifted')
    return 0


def apply(conn) -> int:
    with conn.cursor() as cur:
        cur.execute('SELECT pg_advisory_lock(%s)', [LOCK])
    conn.commit()
    try:
        pending, drifted = state(conn)
        if drifted:
            return check(conn)
        for version, sha, sql in pending:
            # each migration and its record in ONE transaction
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute('INSERT INTO schema_migration (version, sha256, applied_at, applied_by) '
                            'VALUES (%s,%s,%s,%s)',
                            [version, sha, datetime.now(timezone.utc), os.environ.get('MAIL_SEND_ENV', 'unknown')])
            conn.commit()
            print(f'applied  {version}')
        if not pending:
            print('nothing pending')
        return 0
    finally:
        with conn.cursor() as cur:
            cur.execute('SELECT pg_advisory_unlock(%s)', [LOCK])
        conn.commit()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (['--check'], ['--apply']):
        print('usage: python -m mailsend.schema_migrate --check | --apply', file=sys.stderr)
        return 2
    import psycopg2
    import psycopg2.extras
    from .store import dsn
    conn = psycopg2.connect(dsn(), cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        return apply(conn) if argv == ['--apply'] else check(conn)
    finally:
        conn.close()


if __name__ == '__main__':
    sys.exit(main())
