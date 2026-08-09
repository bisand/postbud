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
- **The API is the only way to send** (2026-08-09). Postfix's `mynetworks`
  is loopback + the pod CIDR; the tailnet is deliberately NOT trusted, so
  nothing can relay around the suppression list and the delivery record.
  Port 25 public is inbound bounces only (`reject_unauth_destination`).
- **The admin surface** (`/admin`, docs/architecture.md §9) authenticates
  with `ADMIN_TOKEN` — separate from tenant keys because it mints and
  revokes them. Unset = honest 503. The UI is Svelte 5 + daisyUI in
  `ui/admin/`, dist CHECKED IN and embedded via include_dir (cargo never
  needs node); rebuild with `scripts/build-ui.sh`, CI fails when dist
  drifts from source. Key rotation kills the old key atomically.

## Workspace layout

- `crates/postbud-core` — pure policy, no I/O: addresses, retry schedule,
  DSN parsing, tenant authorization.
- `crates/postbud-db` — Postgres: queue, suppression list, delivery
  history. sqlx runtime API (no live DB needed to build).
- `crates/postbud-relay` — the handoff to Postfix + the worker loop.
- `crates/postbud-api` — axum HTTP API. Adding `Tenant` as a handler
  argument is what protects a route — one seam, no endpoint can forget.
- `crates/postbud-cli` — the `postbud` binary.
- `ui/admin` — the admin SPA (Vite + Svelte 5 runes + Tailwind 4 +
  daisyUI 5). `dist/` is committed; `scripts/build-ui.sh` refreshes it.
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

In production at ServeTheWorld (k3s + Flux, GHCR images, tailnet-only
API): regnid test AND prod deliver through postbud; SPF/DKIM/DMARC
verified passing at Gmail. Admin surface live at `/admin` (dashboard,
delivery log, suppressions, tenants incl. key rotation, bounce feed) —
browser-verified. SMTP submission closed to everything but the worker.

**Not built yet:** integration tests that skip politely without
`DATABASE_URL` (the regnmed pattern — only the admin-auth tests run
DB-free today), the networco cutover (paused; code written in
networco-app), and the PTR record (provider ticket pending).
