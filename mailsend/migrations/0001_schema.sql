-- THE SERVICE'S STORE: four tables, and no rows. Rows are written by the operator straight into
-- the store (an INSERT, or a migration of the operator's own), never through the HTTP API: which
-- inbox a tenant sends from, which application may send for which tenant, and where a tenant's mail
-- goes off production are the deployment's facts, not the code's. demo/seed.py shows all three.

-- grant — which application may act for which tenant, by VERB. `application` is the name in
-- the caller's certificate CN. `verb` is 'send' alone; a read grant later is a new row, not a
-- change to this table. `asked_by` names who asked for the row.
CREATE TABLE IF NOT EXISTS "grant" (
    id           SERIAL PRIMARY KEY,
    created      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted   BOOLEAN NOT NULL DEFAULT FALSE,
    deleted      TIMESTAMPTZ,
    application  TEXT NOT NULL,
    tenant       TEXT NOT NULL,
    verb         TEXT NOT NULL CHECK (verb IN ('send')),
    asked_by     TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS grant_one ON "grant" (application, tenant, verb) WHERE NOT is_deleted;

-- send — every send asked by a verified caller from the grant check on, sent or not, for
-- whatever tenant key it named. No body and no
-- attachment bytes: for a Google inbox the copy is in the mailbox's Sent folder; an SMTP
-- door keeps none. This row holds the proof of which bytes left (message_sha256). Written `sending` and committed BEFORE the way out is called.
--   asked_to  everyone the caller asked for: to, cc, bcc, reply_to, and each header naming a
--             recipient that was removed off production
--   sent_to   the To, Cc and Bcc the message actually left with
--   parts     each attachment and inline part by name, type, size and sha256
--   gmail_id  Gmail's id for a Google inbox; queue_id the SMTP door's answer to DATA
CREATE TABLE IF NOT EXISTS send (
    id              SERIAL PRIMARY KEY,
    created         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application     TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    acting_user     TEXT,
    purpose         TEXT NOT NULL,
    environment     TEXT,
    from_address    TEXT,
    asked_to        JSONB NOT NULL DEFAULT '[]',
    sent_to         JSONB NOT NULL DEFAULT '[]',
    subject         TEXT,
    parts           JSONB NOT NULL DEFAULT '[]',
    message_sha256  TEXT,
    gmail_id        TEXT,
    status          TEXT NOT NULL CHECK (status IN ('sending', 'sent', 'refused', 'failed')),
    error           TEXT,
    from_name       TEXT,
    reply_to        TEXT,
    message_id      TEXT,
    queue_id        TEXT
);
CREATE INDEX IF NOT EXISTS send_by_tenant ON send (tenant, created DESC);

-- inbox — an address a tenant sends FROM; several per tenant, the caller names which. No
-- default of any kind.
--   account_kind  'workspace' — a Google Workspace domain's inbox, signed for by a service
--                 account with domain-wide delegation (<P>_CLIENT_EMAIL, <P>_PRIVATE_KEY);
--                 'gmail' — an ordinary Gmail account's own grant, a refresh token
--                 (<P>_CLIENT_ID, <P>_CLIENT_SECRET, <P>_REFRESH_TOKEN);
--                 'smtp' — handed to an SMTP submission door over STARTTLS, presenting this
--                 service's client certificate, no SMTP AUTH (<P>_ADDRESS as host:port, and
--                 the file paths <P>_CERT, <P>_KEY, <P>_CA).
--   key_env       the PREFIX of those placed values; a key is never in a table.
CREATE TABLE IF NOT EXISTS inbox (
    id            SERIAL PRIMARY KEY,
    created       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted    BOOLEAN NOT NULL DEFAULT FALSE,
    deleted       TIMESTAMPTZ,
    tenant        TEXT NOT NULL,
    address       TEXT NOT NULL,
    account_kind  TEXT NOT NULL CONSTRAINT inbox_account_kind_check CHECK (account_kind IN ('workspace', 'gmail', 'smtp')),
    key_env       TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS inbox_one ON inbox (tenant, lower(address)) WHERE NOT is_deleted;

-- tenant — ONE address per tenant that its mail goes to when the deployment is not production.
-- A tenant with inboxes and no row here cannot send off production: 503, recorded `refused`.
CREATE TABLE IF NOT EXISTS tenant (
    id           SERIAL PRIMARY KEY,
    created      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted   BOOLEAN NOT NULL DEFAULT FALSE,
    deleted      TIMESTAMPTZ,
    tenant       TEXT NOT NULL,
    receives_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_one ON tenant (tenant) WHERE NOT is_deleted;
