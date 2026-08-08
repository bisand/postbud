# postbud

Transactional mail for [regnmed](https://github.com/bisand/regnmed), regnid
and networco. A small Rust service that accepts mail over HTTP, keeps it
until it is delivered, remembers what happened to it, and never writes to an
address that has already bounced.

It is **not** an MTA. Delivery is Postfix's job — MX resolution,
per-destination concurrency, TLS policy, DSN generation. postbud sits in
front of it and owns the three things Postfix structurally cannot:

| | Why Postfix can't |
| --- | --- |
| **A suppression list** | Postfix has no concept of "never send here again". |
| **Per-message delivery status the sending application can query** | The answer lives in a log file, minutes later. |
| **Per-tenant authentication bound to sending domains** | One SASL credential lets any product send as any other. |

## Why it exists

regnmed already records that a message was *handed off* (`utsendelse`,
migration 0020). It cannot record whether it was *delivered* — and "did the
customer get the invoice?" is a question its users ask.

More urgently: regnid's mail worker retries a failed handoff on
`[1s, 5s, 30s, 60s, 120s]` and then drops the message, leaving only a
JetStream advisory nothing consumes. A total window of **216 seconds**. That
is survivable against a hosted API; against a single self-hosted relay that
gets kernel updates, any outage longer than four minutes silently destroys
invoices. postbud persists on accept and retries for **just over two days**
(`postbud-core::retry`, pinned by a test that fails if the window ever drops
below a day).

## Shape

```
regnmed ─┐
         ├─ HTTP ─→ postbud ─ SMTP ─→ Postfix ─→ the internet
networco ┘         (cluster)         (STW VM, owns the IP + PTR + DKIM key)
                      │                  │
                   Postgres         bounces ─→ postbud bounce-ingest
```

postbud runs in the k3s cluster, next to the applications and the database.
The relay runs on its own VM with its own IPv4 and PTR record, and holds no
credentials and no state worth backing up: losing it costs an IP address,
not a secret. The DKIM private key exists in exactly one place — OpenDKIM on
the relay host — and never in this repository.

**One identifier survives all three hops.** The caller's idempotency key
(regnmed passes its `utsendelse` id) identifies the business event; Postfix's
queue id, captured from its `250 Ok: queued as …` response, is stored on the
message and is the only handle a bounce arriving on Thursday carries for an
invoice sent on Monday. Designing that in on day one is why debugging stays
a single query instead of grepping timestamps across three logs.

## Quick start

```bash
cp .env.example .env
cargo run -p postbud-cli -- migrate
cargo run -p postbud-cli -- tenant add --name regnmed --domain bogen.tech
cargo run -p postbud-cli -- serve     # API
cargo run -p postbud-cli -- worker    # delivery, separate process
cargo test --workspace
```

The API key is printed once and cannot be recovered — postbud stores only
its SHA-256 digest.

```bash
curl -X POST localhost:8080/v1/messages \
  -H "Authorization: Bearer pb_live_…" \
  -H "Content-Type: application/json" \
  -d '{"idempotency_key":"utsendelse-42",
       "from":"no-reply@bogen.tech","to":"kunde@example.no",
       "subject":"Faktura 1001","text":"Vedlagt."}'
```

## Integrating

**regnid needs no code change.** It already speaks SMTP submission
(`src/transport.rs`: `MAIL_TRANSPORT=smtp`, `SMTP_HOST`, `SMTP_PORT`,
`SMTP_TLS`). Point it at the relay and it keeps working; its JetStream rail
can be retired later, on its own schedule, rather than as a precondition.

**networco implements `IEmailService` against the HTTP API** — the interface
in `apps/shared/Services/IEmailService.cs` currently has no implementation
and no DI registration anywhere in the solution, so this is its first one.

**One rail, not two.** If postbud ends up running *beside* regnid's mail
worker rather than in front of it, there are two suppression lists, they
disagree, and one system keeps mailing addresses the other knows are dead.
That is the single decision that determines whether this helps.

## Layout

- `crates/postbud-core` — pure policy: addresses, retry schedule, DSN
  parsing, tenant authorization. No I/O.
- `crates/postbud-db` — Postgres: queue, suppression list, delivery history.
- `crates/postbud-relay` — the handoff to Postfix, and the worker loop.
- `crates/postbud-api` — the HTTP API (axum).
- `crates/postbud-cli` — the `postbud` binary.
- `docs/postfix/` — relay configuration, the bounce pipe, and DNS.

## Conventions

Prose is **English throughout**, including `docs/`. This differs from
regnmed, whose `docs/` are Norwegian because they are audit-facing —
revisorer and certification processes read them. Nothing here is audit-facing,
the licence is permissive, and the only Norwegian word that carries meaning
is the name. Written down so it stays a decision rather than becoming drift.

Run `cargo fmt --all` before committing.

## Not built

- **Inbound mail.** The relay accepts a short allowlist (bounces, `abuse@`,
  `postmaster@`, DMARC reports) and rejects everything else at RCPT time.
  regnmed's `e-post-inn` (migration 0032) still waits on an MX that does not
  exist yet; standing that up means either a bigger relay VM or content
  scanning in the cluster.
- **Scheduled sending, templates, open/click tracking.** Deliberate. The
  applications own their content; postbud moves it.
- **A web UI.** The API and the CLI are the surface.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
