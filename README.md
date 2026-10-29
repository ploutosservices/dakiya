# dakiya

A mail-sending service: one HTTP API that every application in an organisation sends mail through.
Applications never hold a mailbox credential; the service does, and it decides, from rows only the
operator writes, which application may send for which tenant and from which address.

Its distinctive part is the **non-production guard**. Unless the service is configured as
`production`, no mail ever leaves the tenant: whatever addresses the caller asked for, the mail goes
to the tenant's own address, the subject is prefixed with the environment (`[dev]: Your invoice`), and
the message opens with a paragraph naming everyone production would have sent it to. A staging copy of
production data can therefore send mail freely without reaching a real customer.

In the code, the logs and the error messages the service calls itself **mail-send**, and its Python
package is `mailsend`; dakiya is the product's name.

## Words used here

| word | meaning |
|---|---|
| deployment | one running copy of the service with its own store and its own environment word |
| environment | the word in `MAIL_SEND_ENV`; only the exact, lower-case `production` sends unrestricted |
| tenant | an organisation the service sends for, by a key such as `acme` |
| inbox | an address a tenant sends from, with the kind of credential it uses (`account_kind`) |
| grant | a row saying application X may send for tenant Y |
| receives_at | the one address a tenant's mail goes to outside production |
| purpose | a short name the caller gives each send, kept in its record |
| set | an environment variable given a value; the error messages say "not set in this deployment" |
| the mail-out door | where an `smtp` inbox hands mail over: an SMTP submission server |

## What it does

- `POST /v1/send` sends one message for a tenant, from one of that tenant's inboxes, and records it.
- `GET /v1/health` says whether the store answers, which environment the service is, and whether each
  inbox's credentials are set (names and yes/no only, never a value).

There is no endpoint to read the record back and none to write an inbox or a grant.

Each inbox hands mail over one of three ways, by its `account_kind`:

| kind | how the mail leaves | settings under the inbox's prefix (`key_env`) |
|---|---|---|
| `workspace` | Gmail API, as the inbox, through a Google service account with domain-wide delegation | `_CLIENT_EMAIL`, `_PRIVATE_KEY` |
| `gmail` | Gmail API with the inbox's own OAuth refresh token | `_CLIENT_ID`, `_CLIENT_SECRET`, `_REFRESH_TOKEN` |
| `smtp` | an SMTP submission server: STARTTLS (TLS 1.2+), the server's certificate verified against `_CA` and its name against the host in `_ADDRESS`, this service's client certificate presented, no AUTH | `_ADDRESS` (host:port), `_CERT`, `_KEY`, `_CA` |

Setting up Google is Google's: for `workspace`, a service account with domain-wide delegation granted
the scope `https://www.googleapis.com/auth/gmail.send` for the inbox's domain; for `gmail`, an OAuth
client and a refresh token for that scope, obtained once by the inbox's owner.

## Security model

- **The proxy is the identity.** A caller is an application presenting a client certificate to a
  TLS-terminating proxy in front of the service. The proxy verifies it and writes the subject into a
  header (`X-Client-Identity: CN=<application>@<environment>` by default) and must **clear that header
  on every request without a verified certificate**, so a caller cannot type it (`demo/nginx.conf`).
  The service believes the header and nothing else about the caller.
- **So the service must be reachable only through the proxy.** Use `MAIL_SEND_UDS`: a unix socket in a
  directory only the proxy's user can enter. `MAIL_SEND_PORT` (loopback) has no proxy in front, so any
  process on that machine can send as any application; it is for a developer's machine only, and
  `run.sh` refuses it when `MAIL_SEND_ENV` is `production`.
- **Authorisation is the certificate's CN alone.** The CN must be one whole relative name of the subject
  (`CN=billing@production`, matched between commas or slashes), its environment must equal the
  service's own (a `production` certificate is refused by a `dev` service and the other way round),
  and the application needs a grant for the tenant. An escaped comma (`\,`) inside another attribute
  is not a separator. Issue certificates accordingly: anyone holding one for `billing@production` can
  send as billing for every tenant billing is granted. The service checks no revocation list; that
  is the proxy's (nginx `ssl_crl`).
- **`acting_user` is the caller's word.** It is recorded, not checked.
- **Health is public.** `/v1/health` needs no certificate and names the environment and the inboxes'
  key prefixes (never a value). Put it behind the proxy's client verification if that matters to you.
- **Off production, mail stays in the tenant** (above): To and Reply-To become the tenant's
  `receives_at`; Cc, Bcc and every header naming a recipient are removed. The guard is exactly as good
  as `MAIL_SEND_ENV`: a misspelt `production` stays guarded, but a deployment set to `production` sends
  to whoever is asked.

## Try it

You need Docker with Compose v2.

    docker compose run --build --rm tests
    docker compose down -v

This starts PostgreSQL, applies the schema, seeds one tenant (`acme`, receiving at
`desk@acme.example`), one `smtp` inbox (`billing@acme.example`) and one grant (application `demo` may
send for `acme`), starts the service behind nginx with a throwaway CA, and an SMTP catcher
([Mailpit](https://mailpit.axllent.org/)) in place of the outside world. Then it runs the rule tests,
the SMTP hand-over test and an end-to-end test, and exits with their result. Every mail is caught,
never delivered; while the demo runs, `http://127.0.0.1:8025` shows them.

To send one yourself, start it (`docker compose up -d`), copy the demo certificates out of their volume
(the volume is named after the compose project, `dakiya-demo`), and call it:

    docker run --rm -v dakiya-demo_certs:/c -v "$PWD/demo-certs":/out alpine cp -r /c/. /out
    curl --cacert demo-certs/ca.pem --cert demo-certs/demo@dev.pem --key demo-certs/demo@dev.key \
         --resolve nginx:8443:127.0.0.1 https://nginx:8443/v1/send \
         -H 'Content-Type: application/json' \
         -d '{"tenant":"acme","from":"billing@acme.example","acting_user":null,"purpose":"try",
              "to":["someone@example.com"],"subject":"Hello","html":"<p>Hi</p>"}'
    docker compose down -v

`--resolve` is needed because the proxy's certificate is issued to the name `nginx`. The answer's
`sent_to` is `["desk@acme.example"]`: the demo is `dev`, so the mail stayed in the tenant.

**The demo is for trying it, never for exposure.** PostgreSQL trusts every connection, the Mailpit page
has no login, the socket is world-writable, the certificates live two days and their keys are readable
by every container, and `demo-certs/` is written as root (it is in `.gitignore`).

## Run it without Docker

Python 3.12 and PostgreSQL. From this directory:

    python -m venv venv && venv/bin/pip install -r requirements.txt
    export MAIL_SEND_DSN='host=... dbname=... user=...'
    venv/bin/python -m mailsend.schema_migrate --apply
    export MAIL_SEND_ENV=staging MAIL_SEND_UDS=/run/mail-send/mail-send.sock    # and each inbox's settings
    MAIL_SEND_PYTHON=venv/bin/python ./run.sh

`run.sh` starts uvicorn on the socket (or on `MAIL_SEND_PORT`) and refuses to start with neither, with
both, or with a port in production; start the service with it, not with uvicorn directly, which skips
those checks. `MAIL_SEND_PYTHON` names the interpreter it runs (default `python3`). Every setting, with the demo's values, is in `.env.example`; outside Compose, export them in the
service's environment (a systemd `EnvironmentFile=` takes that file's format). The `Dockerfile` builds
the same thing as an image.

## Operating it

Apply `mailsend/migrations` at deploy time, once, by one process:

    python -m mailsend.schema_migrate --check     # pending, and drift (exit 1 on drift); creates its own
                                                  # bookkeeping table if absent
    python -m mailsend.schema_migrate --apply

An applied migration is recorded with its checksum and an edited one is refused by name.

The tenant, inbox and grant rows are written by the operator straight into the store, never through
the API. `demo/seed.py` writes the demo's three; by hand:

    INSERT INTO tenant (tenant, receives_at) VALUES ('acme', 'desk@acme.example');
    INSERT INTO inbox (tenant, address, account_kind, key_env)
         VALUES ('acme', 'billing@acme.example', 'smtp', 'ACME_SMTP');      -- settings ACME_SMTP_*
    INSERT INTO "grant" (application, tenant, verb, asked_by)
         VALUES ('billing', 'acme', 'send', 'who asked for it');            -- application = the CN's name

A row is retired by setting `is_deleted`, never deleted, so the record keeps its meaning.

An inbox's `_CERT`, `_KEY` and `_CA` are file paths; a Workspace `_PRIVATE_KEY` is the PEM itself, or
base64 of it, or the PEM with its line breaks written as `\n`.

## The send

The body is a JSON object; a field the service does not know is refused by name (422).

| field | |
|---|---|
| `tenant` | required: the tenant key (lower-case letters, digits and `-`) |
| `from` | required: one of the tenant's inboxes |
| `acting_user` | required: the person the send is made for, or `null` for a script |
| `purpose` | required: a short name for the record (letters, digits, `.` `_` `-`), e.g. `invoice` |
| `to` | required: one or more addresses |
| `cc`, `bcc` | optional. Bcc reaches its recipients for every kind: an `smtp` inbox gives them only in the envelope; a Google inbox writes a `Bcc:` header, which Gmail removes before delivery |
| `subject` | one line; may be empty |
| `html` or `text` | one body, not both (422). The service sends HTML only: `text` becomes one `<p>` per paragraph, its line breaks kept |
| `from_name`, `reply_to`, `date`, `message_id`, `in_reply_to`, `references` | header fields; Reply-To defaults to the From inbox, Date and Message-ID are filled when not given |
| `headers` | further header fields as an object; printable ASCII on one line; a field with its own entry above, or one the service writes, is refused |
| `attachments` | a list of `{filename, content_type, data}`, `data` in base64 |
| `inline` | a list of `{content_id, content_type, data}`, for `cid:` images in the HTML |

Limits: the request body at most 26 MB; attachments and inline parts together at most 18 MB decoded
(Google's documented limit is 25 MB encoded).

A send is recorded `sending` before the mail is handed over and settled `sent` or `failed` after, so a
crash leaves a row saying a send was attempted, never a mail with no row. A refusal from the grant
check on is recorded `refused`. The answer is `{id, gmail_id, message_id, sent_to, environment}`.

| status | meaning |
|---|---|
| 403 | no verified identity, another environment's identity, or no grant for this tenant |
| 411, 413 | no Content-Length, or a body over the limit |
| 422 | a field is missing, malformed or unknown, or `from` is not the tenant's inbox |
| 502 | Google or the SMTP server refused the hand-over (the record says why) |
| 500 | the store failed mid-send, or Google answered without a token; the row may be left `sending` |
| 503 | a setting is missing: `MAIL_SEND_ENV`, `MAIL_SEND_DSN`, an inbox's credentials, or (outside production) the tenant's `receives_at` row |

## Tests

- `tests/conformance.py`: the rules, check by check, against the pure functions (no database, no
  network). The checks carry this file's own labels: a number, `body`, or `C1`–`C4` for who may call.
- `tests/smtp-drill.py`: the `smtp` hand-over against a local stand-in server with certificates made
  for the run; it grades what the server was handed.
- `tests/e2e.py`: the Compose demo end to end, through the proxy to the catcher.

The first two run anywhere the requirements are installed:

    python tests/conformance.py
    python tests/smtp-drill.py

The third reads `E2E_URL`, `E2E_CERTS` and `E2E_CAUGHT`, which the Compose file sets. No CI
configuration ships; run them in yours.

## Known limitations

- `requirements.txt` and the images are not pinned to exact versions.
- The image runs as root and is not hardened.
- No rate or volume limit, and no idempotency key: a failure after a delivered hand-over can leave the
  row `sending` and answer 500, and a caller that retries sends twice. Retrying is the caller's
  decision.
- A refusal from the grant check on writes a row for whatever tenant key the caller named, so a
  certified caller can grow the `send` table; nothing prunes it, and it keeps every recipient, subject
  and `acting_user` for good.
- A request's body (up to 26 MB) is held whole and copied while it is decoded and encoded; there is no
  cap on concurrent sends.
- A send opens up to four short database connections, and a Google inbox takes a fresh OAuth token
  for every send.
- An attachment's filename goes into its header as given, without RFC 2231 encoding; an attachment
  with empty `data` is sent empty.
- Tested by the files here: the rules, the SMTP hand-over and the demo end to end in `dev`. Not tested
  here: sending through Google, and production mode end to end.

## License

Apache License 2.0; see `LICENSE` and `NOTICE`.
