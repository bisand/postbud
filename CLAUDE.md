# postbud — project context

Transactional mail for regnmed, regnid and networco. Rust + Postgres,
Apache-2.0. Sits in front of a Postfix relay; is **not** an MTA.

Full reasoning in [docs/architecture.md](docs/architecture.md); the
reputation checklist in [docs/dns.md](docs/dns.md).

## Architecture decisions (do not silently revisit)

- **postbud never delivers mail itself.** No MX resolution, no
  per-destination queues, no TLS negotiation with strangers, no DSN
  generation. It builds MIME, hands it to one smarthost, and records what
  the smarthost said. Postfix owns delivery.
- **One rail, not two.** postbud REPLACES regnid's JetStream mail worker as
  the delivery path. Two rails means two suppression lists that disagree,
  and one system mailing addresses the other knows are dead.
- **One identifier survives all three hops**: caller's idempotency key →
  Postfix queue id (parsed from `250 Ok: queued as …`, stored on the
  message) → the same id in the bounce's `X-Postfix-Queue-ID`. That header
  carries the ORIGINAL message's queue id, not the bounce's — which is why
  it works as a join key. The response format is pinned by a test.
- **Only permanent failures suppress.** A needless retry costs a
  connection; a wrong "permanent" costs an invoice. `4.2.2` (mailbox full)
  must never suppress. Bounce-driven suppressions are global, manual ones
  per-tenant, and lifting is a soft delete.
- **The retry window is ~49 hours**, against regnid's 216 seconds. That gap
  is the reason this service exists;
  `retry_window_survives_an_overnight_outage` fails if it is shortened.
- **Tenants are bound to sending domains.** Exact match, no implied
  subdomains — a leaked regnmed key must not be able to send as networco.
- **No secrets in this repo.** The DKIM private key lives on the relay host
  and nowhere else. API keys are stored as SHA-256 digests (a 32-byte
  random key needs no password hash) and shown exactly once.
- **Message bodies are personal data** and are purged after
  `BODY_RETENTION_DAYS`; the delivery record is kept forever.

## Workspace layout

- `crates/postbud-core` — pure policy, no I/O: addresses, retry schedule,
  DSN parsing, tenant authorization.
- `crates/postbud-db` — Postgres: queue, suppression list, delivery
  history. sqlx runtime API (no live DB needed to build).
- `crates/postbud-relay` — the handoff to Postfix + the worker loop.
- `crates/postbud-api` — axum HTTP API. Adding `Tenant` as a handler
  argument is what protects a route — one seam, no endpoint can forget.
- `crates/postbud-cli` — the `postbud` binary.
- `docs/postfix/` — relay config, the bounce pipe, the RCPT allowlist.

## Development

```sh
docker compose up -d          # Postgres 18 on 5434 (regnmed's dev db holds 5433)
cp .env.example .env
cargo run -p postbud-cli -- migrate
cargo run -p postbud-cli -- tenant add --name regnmed --domain bogen.tech
cargo run -p postbud-cli -- serve     # API
cargo run -p postbud-cli -- worker    # delivery, separate process
cargo test --workspace
```

`serve` and `worker` are separate commands on purpose: the API must stay
responsive while the relay is unreachable.

Run `cargo fmt --all` before every commit.

## Language policy

**English throughout, including `docs/`.** This differs from regnmed, whose
`docs/` are Norwegian because they are audit-facing (revisorer,
certification). Nothing here is audit-facing, the licence is permissive,
and the only Norwegian word that carries meaning is the name. Recorded so
it stays a decision rather than becoming drift — regnmed's own CLAUDE.md
documents what happens when it does.

## Status

Scaffold, verified end to end against a real Postgres 18: submit, idempotent
dedup, from-domain rejection, 401 on a bad key, bounce → queue-id join →
global suppression, transient bounce correctly NOT suppressing, attachment
stored with digest.

**Not built yet:** integration tests that skip politely without
`DATABASE_URL` (the regnmed pattern), deploy manifests, a CI workflow, the
relay VM itself, and the regnid cutover.
