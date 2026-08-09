# postbud

***Postbud*** *(Norwegian, "mail carrier"): the person who takes your
letters and is responsible for them until they are delivered. That is
the whole job description, and the reason for the name.*

Self-hosted transactional mail. A small Rust service that accepts mail
over HTTP, keeps it until it is delivered, remembers what happened to it,
and never writes to an address that has already bounced.

It is **not** an MTA. Delivery is Postfix's job — MX resolution,
per-destination concurrency, TLS policy, DSN generation. postbud sits in
front of it and owns the three things Postfix structurally cannot:

| | Why Postfix can't |
| --- | --- |
| **A suppression list** | Postfix has no concept of "never send here again". |
| **Per-message delivery status the sending application can query** | The answer lives in a log file, minutes later. |
| **Per-tenant authentication bound to sending domains** | One SASL credential lets any product send as any other. |

## Why it exists

An application's own dispatch log records that a message was *handed
off*. It cannot record whether it was *delivered* — and "did the customer
get the invoice?" is a question users ask.

More urgently: the in-app retry loop postbud replaces typically retries a
failed handoff on something like `[1s, 5s, 30s, 60s, 120s]` and then
drops the message — a total window of a few minutes. That is survivable
against a hosted API; against a single self-hosted relay that gets kernel
updates, any outage longer than the window silently destroys invoices.
postbud persists on accept and retries for **just over two days**
(`postbud-core::retry`, pinned by a test that fails if the window ever
drops below a day).

## Shape

```
app A ─┐
       ├─ HTTP ─→ postbud ─ SMTP ─→ Postfix ─→ the internet
app B ─┘         (cluster)         (own VM, owns the IP + PTR + DKIM key)
                    │                  │
                 Postgres         bounces ─→ postbud bounce-ingest
```

postbud runs wherever the applications run. The relay runs on its own VM
with its own IPv4 and PTR record, and holds no credentials and no state
worth backing up: losing it costs an IP address, not a secret. The DKIM
private key exists in exactly one place — OpenDKIM on the relay host —
and never in this repository.

**One identifier survives all three hops.** The caller's idempotency key
identifies the business event; Postfix's queue id, captured from its
`250 Ok: queued as …` response, is stored on the message and is the only
handle a bounce arriving on Thursday carries for an invoice sent on
Monday. Designing that in on day one is why debugging stays a single
query instead of grepping timestamps across three logs.

## Quick start

```bash
cp .env.example .env
cargo run -p postbud-cli -- migrate
cargo run -p postbud-cli -- tenant add --name my-app --domain example.com
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
  -d '{"idempotency_key":"dispatch-42",
       "from":"no-reply@example.com","to":"customer@example.net",
       "subject":"Invoice 1001","text":"Attached."}'
```

With `ADMIN_TOKEN` set, `/admin` serves the admin UI: dashboard, delivery
log, suppression list, tenant administration (including key rotation) and
the raw bounce feed. See docs/architecture.md §9.

## Integrating

**The HTTP API is the only way to send.** The relay accepts submission
solely from postbud's delivery worker — nothing can relay around the
suppression list, the idempotent dedup and the delivery record.

Each sending system is a **tenant**: its own API key (stored as a
digest), bound to an explicit list of sending domains. Submit with
`POST /v1/messages`, poll `GET /v1/messages/{id}`, manage the
suppression list under `/v1/suppressions`.

**One rail, not two.** If postbud ends up running *beside* an
application's own mail path rather than in front of it, there are two
suppression lists, they disagree, and one system keeps mailing addresses
the other knows are dead. That is the single decision that determines
whether this helps.

## Layout

- `crates/postbud-core` — pure policy: addresses, retry schedule, DSN
  parsing, tenant authorization. No I/O.
- `crates/postbud-db` — Postgres: queue, suppression list, delivery history.
- `crates/postbud-relay` — the handoff to Postfix, and the worker loop.
- `crates/postbud-api` — the HTTP API (axum).
- `crates/postbud-cli` — the `postbud` binary.
- `ui/admin` — the admin SPA (Svelte 5 + daisyUI); `dist/` is committed
  and embedded into the binary, so building the Rust workspace never
  needs node. Rebuild with `scripts/build-ui.sh`.
- `docs/postfix/` — relay configuration, the bounce pipe, and DNS.
- `deploy/` + `flux/` — a reference Kubernetes deployment (kustomize,
  Flux-pulled). Adapt or ignore.

## Conventions

Prose is **English throughout**, including `docs/`.

Run `cargo fmt --all` before committing.

## Not built

- **Inbound mail.** The relay accepts a short allowlist (bounces,
  `abuse@`, `postmaster@`, DMARC reports) and rejects everything else at
  RCPT time — which is what keeps it free of a filtering stack and
  comfortable in 2 GB.
- **Scheduled sending, templates, open/click tracking.** Deliberate. The
  applications own their content; postbud moves it.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
