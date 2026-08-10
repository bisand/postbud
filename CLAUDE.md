# postbud — project context

Self-hosted transactional mail, Rust + Postgres, Apache-2.0. Sits in
front of a Postfix relay; is **not** an MTA.

postbud is a GENERIC system: nothing in this repository names the
applications that happen to use an installation of it, and changes must
keep it that way. Installation-specific facts (tenants, hosts, cutover
history) live outside the repo.

Full reasoning in [docs/architecture.md](docs/architecture.md); the
reputation checklist in [docs/dns.md](docs/dns.md).

## Architecture decisions (do not silently revisit)

- **postbud never delivers mail itself.** No MX resolution, no
  per-destination queues, no TLS negotiation with strangers, no DSN
  generation. It builds MIME, hands it to one smarthost, and records what
  the smarthost said. Postfix owns delivery.
- **One rail, not two.** postbud REPLACES an application's own mail path
  rather than running beside it. Two rails means two suppression lists
  that disagree, and one system mailing addresses the other knows are
  dead.
- **One identifier survives all three hops**: caller's idempotency key →
  Postfix queue id (parsed from `250 Ok: queued as …`, stored on the
  message) → the same id in the bounce's `X-Postfix-Queue-ID`. That header
  carries the ORIGINAL message's queue id, not the bounce's — which is why
  it works as a join key. The response format is pinned by a test.
- **Only permanent failures suppress.** A needless retry costs a
  connection; a wrong "permanent" costs an invoice. `4.2.2` (mailbox full)
  must never suppress. Bounce-driven suppressions are global, manual ones
  per-tenant, and lifting is a soft delete.
- **The retry window is ~49 hours**, against the few minutes of the in-app
  loops this replaces. That gap is the reason this service exists;
  `retry_window_survives_an_overnight_outage` fails if it is shortened.
- **Tenants are bound to sending domains.** Exact match, no implied
  subdomains — a leaked key for one tenant must not be able to send as
  another. The Message-ID's domain is the SENDER's domain, never an
  installation hostname baked into the code.
- **No secrets in this repo.** The DKIM private key lives on the relay
  host and nowhere else. API keys are stored as SHA-256 digests (a 32-byte
  random key needs no password hash) and shown exactly once.
- **Message bodies are personal data** and are purged after
  `BODY_RETENTION_DAYS`; the delivery record is kept forever.
- **The API is the only way to send.** The relay's `mynetworks` is
  loopback + the pod/host network of the delivery worker and nothing
  wider, so nothing can relay around the suppression list and the
  delivery record. Public port 25 is inbound bounces only
  (`reject_unauth_destination`).
- **The admin surface** (`/admin`, docs/architecture.md §9) authenticates
  two ways: OIDC login (issuer-configurable RP, code+PKCE, id_token
  verified against the issuer's JWKS — the token proves identity, postbud
  decides authorization) and `ADMIN_TOKEN` as the break-glass/machine
  path (always the admin role). Authorization lives in the `admin_user`
  TABLE (Users section): roles `admin`/`viewer`, grants soft-ended never
  deleted, last admin protected under row locks, `ADMIN_OIDC_USERS` env
  allowlist governs ONLY while the table is empty. Read endpoints take
  `Admin`, mutating ones `AdminWrite` — a viewer gets 403, and no
  handler can forget. Audit fields carry the actor's name. Neither
  credential set = honest 503; half-set OIDC fails at startup. The UI
  is Svelte 5 + daisyUI in `ui/admin/`, dist CHECKED IN and embedded via
  include_dir (cargo never needs node); rebuild with
  `scripts/build-ui.sh`, CI fails when dist drifts from source. Key
  rotation kills the old key atomically.
- **Domain verification** (docs/architecture.md §10): sending domains
  are a registry (expected SPF, DKIM selector + public key, MX); the
  worker checks real DNS every 15 min until green, then daily. Rules are
  pure in `postbud-core::dnscheck` and encode the two real incidents:
  duplicate SPF = PermError even if one matches, and DKIM compared to
  the signing key byte-for-byte. Resolver failure skips, never records.
  Checks are insert-only history. `DNS_SPF_DEFAULT` prefills new
  domains.
- **Applied migrations are never edited** — sqlx checksums them. Their
  comments are part of the record, even where newer policy (like this
  file's genericity rule) would phrase them differently today.

## Workspace layout

- `crates/postbud-core` — pure policy, no I/O: addresses, retry schedule,
  DSN parsing, tenant authorization.
- `crates/postbud-db` — Postgres: queue, suppression list, delivery
  history. sqlx runtime API (no live DB needed to build).
- `crates/postbud-relay` — the handoff to Postfix + the worker loop.
- `crates/postbud-api` — axum HTTP API. Adding `Tenant` as a handler
  argument is what protects a route — one seam, no endpoint can forget.
  `Admin` is the same seam for the admin surface.
- `crates/postbud-cli` — the `postbud` binary.
- `ui/admin` — the admin SPA (Vite + Svelte 5 runes + Tailwind 4 +
  daisyUI 5). `dist/` is committed; `scripts/build-ui.sh` refreshes it.
- `docs/postfix/` — relay config, the bounce pipe, the RCPT allowlist.
- `deploy/` + `flux/` — reference kustomize deployment, Flux-pulled.

## Development

```sh
docker compose up -d          # Postgres 18 on 5434
cp .env.example .env
cargo run -p postbud-cli -- migrate
cargo run -p postbud-cli -- tenant add --name my-app --domain example.com
cargo run -p postbud-cli -- serve     # API (ADMIN_TOKEN in .env enables /admin)
cargo run -p postbud-cli -- worker    # delivery, separate process
cargo test --workspace
```

`serve` and `worker` are separate commands on purpose: the API must stay
responsive while the relay is unreachable.

Run `cargo fmt --all` before every commit. Commit messages carry no
attribution trailers.

## Language policy

**English throughout, including `docs/`.** The only Norwegian word that
carries meaning is the name.

## Status

Deployed and verified end to end: submit → deliver → bounce → suppress,
SPF/DKIM/DMARC passing at the major receivers, admin surface
browser-verified, SMTP submission closed to everything but the worker.

**Not built yet:** DB-backed integration tests that skip politely without
`DATABASE_URL` (only the admin-auth tests run DB-free today), and inbound
mail (see README "Not built").
