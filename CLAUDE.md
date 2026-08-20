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
- **The relay runs in the cluster**, not on the host: Postfix, opendkim
  and the queue reporter are three containers in one pod
  (deploy/relay.yaml), with `hostNetwork` so inbound port 25 sees the
  real client address and outbound still leaves as the node's IP. Its
  config is NOT in this repo -- main.cf names hosts and domains -- so the
  ConfigMaps are created out of band like the secrets. `strategy:
  Recreate`, because two Postfix masters on one spool is queue
  corruption; the relay images are pinned APART from postbud's in
  kustomization.yaml so a dashboard release does not stop mail.
- **The relay reports its queue back** (Postfix's `showq` socket ->
  `POST /v1/relay/queue`, deploy/queue-report.yaml). This does NOT
  walk back the decision above: nothing here resolves MX, queues, or
  negotiates TLS. It closes the reporting gap that decision leaves --
  a 4xx deferral produces no bounce, so a blocked destination left
  every message looking like a clean handoff. Queue ids present are
  still with the relay; absent ones have left, which means delivered
  UNLESS a bounce says otherwise, and never for a handoff inside the
  grace window. The reporter is a DaemonSet running the same
  `FROM scratch` image under `queue-report`, which is why showq is
  parsed in Rust rather than shelling out to `postqueue` -- there is no
  shell in that image, and adding Postfix for one command would cost
  40 MB on every postbud image. State lives in three mutable columns on
  `message`, not a history table: "still deferred" repeated every 5s is one fact, and
  the history worth keeping is already in `delivery_attempt` and
  `bounce_report`.
- **One identifier survives all three hops**: caller's idempotency key →
  Postfix queue id (parsed from `250 Ok: queued as …`, stored on the
  message) → the same id in the bounce's `X-Postfix-Queue-ID`. That header
  carries the ORIGINAL message's queue id, not the bounce's — which is why
  it works as a join key. The response format is pinned by a test.
- **The envelope sender is `bounces@<sending domain>`, not the `From:`
  header.** A DSN returns to the envelope sender, and a mail library
  derives it from `From:` unless told otherwise -- but `From:` is the
  address a person replies to, so it is aliased to a human mailbox, and
  every bounce then lands there instead of the ingest pipe. Nothing fails
  visibly: the mail arrives, to the wrong reader, and the suppression list
  learns nothing. Same domain as the sender, so SPF alignment does not
  move. `BOUNCE_MAILBOX` names the local part; empty restores the old
  behaviour for a relay that cannot accept the address.
- **Only permanent failures about the RECIPIENT suppress.** A needless
  retry costs a connection; a wrong "permanent" costs an invoice. `4.2.2`
  (mailbox full) must never suppress, and neither may a permanent code
  that blames anything but the address: `5.7.x` is policy -- a domain at
  DMARC `p=reject` with broken auth earns one per message, each naming a
  perfectly healthy recipient. `should_suppress` is an allowlist of the
  addressing codes PLUS a short list of phrases in which a receiver says
  the mailbox is missing in its own words -- sendmail answers a dead
  address with `553 5.3.0 ... No such user here`, filing it under MAIL
  SYSTEM where the code alone can never suppress. Both sit behind the
  permanence check, and it is the one seam that decides. Bounce-driven
  suppressions are global, manual ones per-tenant, and lifting is a soft
  delete.
- **The retry window is ~49 hours**, against the few minutes of the in-app
  loops this replaces. That gap is the reason this service exists;
  `retry_window_survives_an_overnight_outage` fails if it is shortened.
- **Tenants are bound to sending domains.** Exact match, no implied
  subdomains — a leaked key for one tenant must not be able to send as
  another. Changing that binding is recorded: `tenant_domain_change`
  (0010) is insert-only and carries the actor and the before-value, in
  the same transaction as the change. It was a destructive UPDATE, and
  answering "was this a misconfiguration or a bypass?" once took
  inference from message timestamps because the direct evidence did not
  exist. The LIVE list stays on `tenant.from_domains` where the send path
  reads it — nothing reads the history to make a decision. The Message-ID's domain is the SENDER's domain, never an
  installation hostname baked into the code.
- **No secrets in this repo.** The DKIM private key is a Kubernetes
  Secret, mounted into the opendkim container -- NOT a file on a host any
  more, and never in git. That was a deliberate trade: a hostPath key is
  better protected at rest (k3s does not encrypt secrets by default) but
  invisible to `kubectl`, absent from every manifest, and forgotten the
  day the node is rebuilt. `scripts/secrets-sync.sh` takes and restores
  copies, showing fingerprints rather than values. API keys are stored as
  SHA-256 digests (a 32-byte random key needs no password hash) and shown
  exactly once.
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
  Lookups go to PUBLIC resolvers (Cloudflare/Google), never the host's:
  an ISP resolver serving a stale NXDOMAIN made the checker report
  "missing" for live records. `DNS_RESOLVERS` overrides.
  Checks are insert-only history. `DNS_SPF_DEFAULT` prefills new
  domains. The checker also asks the RELAY, over SMTP, whether it will
  accept `bounces@<domain>` -- the envelope sender every message now
  carries, and the address a DSN comes back to. Two RCPTs on one
  connection and the CONTRAST is the answer: postbud probes from inside
  `mynetworks`, where a domain the relay merely forwards for accepts
  anything, so a second address that cannot exist is what separates
  "listed mailbox" from "would forward". Skipped when no MX is expected
  (the domain receives no bounces) and when the relay cannot be reached;
  like `report_auth` it is NOT part of `valid`, which drives the recheck
  cadence.
- **DMARC aggregate reports are evidence, never instructions.** The
  registry says what DNS should carry and `dnscheck` says what it does
  carry; only the receivers say what they CONCLUDED -- the one outcome
  postbud cannot see for itself, since a message quarantined at the far
  end is still a clean `250 Ok: queued as ...`. Parsing is pure in
  `postbud-core::dmarc`: gzip/zip/bare sniffed by magic bytes rather than
  filename, decompression capped, DOCTYPE refused and failure messages
  clipped, because the address in a `rua=` tag is open to anyone on the
  internet. Storage (0008) is insert-only, deduped on
  `(org_name, report_id)` because reporters redeliver, and keeps the raw
  XML so a parser fix can be replayed over history. Nothing parsed here
  may drive suppression, domain status, or any other automatic action.
  The reports are FETCHED, not received: the worker opens one outbound
  IMAP connection to one configured mailbox (`DMARC_EMAIL_IMAP`,
  `_USERNAME`, `_PASSWORD`; off entirely when unset, a startup error when
  half set). That does not revisit "postbud never delivers mail itself"
  and is not the inbound mail the README lists as unbuilt -- no port is
  listened on and no MX is resolved. Every message in the mailbox is
  examined and then MOVED to `DMARC_EMAIL_ARCHIVE` (unreadable ones to
  `DMARC_EMAIL_FAILURES`, which defaults to the same folder) -- leaving
  the inbox is what marks a message handled, NOT the read flag, because
  the mailbox belongs to a person too and somebody opening it in a mail
  client would otherwise starve the poller of every report they had
  looked at. Mail that is not a report is counted apart from mail that
  would not parse: only the second is a problem. `dmarc-import` reads
  files for backfill, `dmarc-fetch` makes one pass by hand. A domain's
  reported traffic also gets a verdict (`dmarc::alignment`): failing needs
  BOTH a meaningful count and a meaningful share, because forwarding
  through a list loses a few percent for ever and a rate on three
  messages is arithmetic. It never names a cause -- forged mail fails
  exactly as DMARC intends -- so the wording sends the reader to the
  per-source table, the only thing that separates "our relay broke" from
  "a stranger is forging us". The admin
  page (`/admin` -> DMARC) is READ-ONLY for every role -- there is no
  mutating endpoint and there must never be one. It leads with which
  mechanism carried DMARC rather than the pass rate, because a domain
  riding DKIM alone reads as a flawless 100% right up until the day the
  key rotates.
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
