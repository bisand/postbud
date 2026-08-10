# Architecture

The decisions, and what each one is protecting against. Written down
because every one of them is cheap now and expensive after the first
production send.

## 1. postbud is not an MTA

Delivery stays with Postfix: MX resolution, per-destination concurrency and
rate limiting, TLS policy against thousands of differently-broken receivers,
DSN generation, queue management on the wire. That is decades of accumulated
edge cases, and reimplementing it in Rust would be trading all of it for a
weekend's work.

postbud owns what Postfix structurally cannot:

- **The suppression list.** Postfix has no concept of "never send here
  again".
- **Per-message delivery status the sending application can query.**
  An application's own dispatch log records that a message was handed
  off; it can never record whether it arrived, because the answer turns
  up minutes later in a log file.
- **Per-tenant authentication bound to sending domains.** One SASL
  credential on a shared relay lets any product send as any other.

## 2. One rail, not two

Applications often already have some outbound-mail machinery of their
own — a queue, a retry loop, a transport. postbud must **replace** that
delivery path, not sit beside it. Two rails means two suppression lists,
and a suppression list that disagrees with itself is worse than none: one
system keeps writing to an address the other has already learned is dead,
and the receiving provider scores the IP, not the sender.

The application keeps whatever internal queueing it likes — the cutover
point is only where mail leaves the application: it goes to postbud's
API, and nowhere else.

## 3. One identifier survives all three hops

The cost of putting a service in front of the relay is a third hop:
application → postbud → Postfix → the internet. Each hop is somewhere mail
can get stuck and a separate log to correlate.

That cost is paid once, at the start, by carrying one identifier through:

| Hop | Identifier |
| --- | --- |
| Application → postbud | the caller's idempotency key (its own id for the business event) |
| postbud → Postfix | Postfix's queue id, read from `250 2.0.0 Ok: queued as …` and stored on the message |
| Bounce → postbud | the same queue id, in the DSN's `X-Postfix-Queue-ID` |

A subtlety worth stating because it is easy to get backwards:
`X-Postfix-Queue-ID` in the `message/delivery-status` part is the queue id of
the **original** message, not of the bounce. That is precisely why it works
as a join key, and it is what lets a bounce arriving Thursday be tied to an
invoice sent Monday. `postbud-relay` pins the response format in a test,
because the day Postfix rephrases that line is the day bounce correlation
silently stops working.

## 4. The retry window

The in-app retry loops postbud replaces typically retry on something like
`[1s, 5s, 30s, 60s, 120s]` and give up after five attempts — a total
window of a few minutes, after which the message is gone and the only
trace is an advisory nothing consumes.

Against a hosted API that never reboots, this is invisible. Against a single
self-hosted VM that takes kernel updates, any outage longer than four
minutes destroys invoices with no record. postbud persists on accept and
retries over **just over two days** (`postbud-core::retry`), front-loaded
because most relay failures are a restart that clears in seconds, then
spread out because after an hour the cause needs a human.

`retry_window_survives_an_overnight_outage` fails if that window is ever
shortened below a day. It is the test the crate exists for.

## 5. Suppression semantics

**Only a permanent failure suppresses.** The asymmetry is deliberate and
runs through the whole codebase: a needless retry costs a connection, a
wrong "permanent" costs an invoice and a customer who quietly stops hearing
from you. A full mailbox is `4.2.2` and must never suppress — it is the most
common way a naive suppression list starts silently dropping real mail.

**Bounce-driven suppressions are global; manual ones are per-tenant.** A
hard bounce is a fact about the mailbox, not about who was writing to it, so
one product learning an address is dead protects the other's reputation too.
A human deciding not to write to someone is a fact about that product only.

**Lifting is a soft delete.** "Suppressed on the 3rd, lifted on the 9th" is
the history someone needs when a customer reports they stopped receiving
invoices. A hard delete answers nothing.

**A suppressed submission is recorded, not rejected.** It returns 202 with
`status: "suppressed"`. The request was well-formed and postbud made a
decision about it; failing the call would tell the caller their code is
wrong when it is the address that is dead.

## 6. Where each piece runs

| | Runs on | Holds |
| --- | --- | --- |
| postbud + Postgres | wherever the apps run | queue, suppression list, delivery history, message bodies |
| Postfix + OpenDKIM | its own VM, own IPv4 + PTR | the IP reputation, the DKIM private key |

The relay holds no application credentials and no state worth backing up:
losing that VM costs an IP address, not a secret. The DKIM private key
exists in exactly one place and never in this repository.

**Only the delivery worker may inject mail.** Postfix's `mynetworks` is
loopback plus the network the worker actually submits from — and nothing
wider. A broader trusted range (a VPN, an office network) would let any
machine on it relay directly, bypassing the suppression list, the
idempotent dedup and the delivery record; with the narrow rule, every
message on the wire has passed the API. Port 25 from the internet stays
open solely for inbound bounces to the RCPT allowlist —
`reject_unauth_destination` refuses relay from strangers as it always
did.

If the relay is down, postbud keeps accepting and queueing, and the
`relayhost` escape hatch can point elsewhere while it is drained. If the
cluster is down, the applications are down too, so there is nothing to send.

## 7. Message bodies are personal data

Invoices carry names, addresses and amounts. The **delivery record** is
operational history and is kept; the **content** has no reason to outlive
the delivery it existed for. `postbud purge` blanks bodies and attachments
of finished messages after `BODY_RETENTION_DAYS` (default 30), leaving the
delivery attempts, the queue id and the bounce reports intact.

## 8. Deliberately not built

- **Inbound mail.** The relay accepts a short RCPT allowlist — bounces,
  `abuse@`, `postmaster@`, DMARC reports — and rejects everything else
  before any content is accepted, which is what keeps it free of a
  filtering stack and comfortable in 2 GB. A real inbound MX means either
  a larger relay VM or content scanning next to the applications, and the
  second is the better answer.
- **An SMTP submission listener in postbud.** The API is the only way in;
  the relay accepts submission from nowhere but the delivery worker
  (section 6). Writing a submission server here would only be worth it to
  give SMTP callers the suppression list and the delivery record; if that
  day comes, it is a component, not a redesign.
- **Templates, scheduled sending, open/click tracking.** The applications
  own their content. Tracking pixels in particular are a reputation and
  privacy cost with no upside for transactional mail.
- **Multiple relays / failover.** One relay, one IP, one reputation. Adding
  a second IP splits reputation at exactly the volume where it is already
  thin.

## 9. The admin surface

`/admin` is a Svelte 5 + daisyUI app compiled into `ui/admin/dist`
(checked in, embedded into the binary with `include_dir` — cargo never
needs node; CI proves dist matches source).
It serves a dashboard, the delivery log with per-message attempt history
and joined bounces, the suppression list (block/lift, global or
per-tenant), tenant administration (create, edit domains, deactivate,
rotate key — rotation kills the old key in the same statement), and the
raw bounce feed.

The unbounded lists (messages, suppressions, bounces) are **keyset-paged**
end to end: the API returns `{items, next}` where `next` is the cursor for
the following page, discovered by fetching one row beyond the limit — no
OFFSET, no COUNT(*), so page fifty costs what page one costs. The message
detail is a route (`#messages/{id}`), so the browser's Back button returns
to the list with its filters and page intact. The tenant list is
deliberately unpaged — it is bounded by the number of sending systems.

Authentication has two independent paths:

- **OIDC login** (optional): postbud is a relying party against any
  spec-compliant issuer (`ADMIN_OIDC_ISSUER`, `ADMIN_OIDC_CLIENT_ID`).
  The SPA runs authorization-code + PKCE; the code exchange is proxied
  through `/admin/api/oidc/token` (no issuer CORS, optional client
  secret stays server-side); API calls carry the id_token, verified
  against the issuer's JWKS (iss, aud = our client id, exp, RS256).
  The issuer owns accounts and passwords; **authorization stays here**,
  in the `admin_user` table, managed from the Users section: each grant
  is an email or subject id with a role — `admin` (everything) or
  `viewer` (sees everything, changes nothing; mutations answer 403).
  Grants are soft-ended, never deleted; a role change is an end plus a
  new row; the last admin can be neither removed nor demoted (checked
  under row locks, so two concurrent removals cannot both succeed).
  While the table is empty, the `ADMIN_OIDC_USERS` environment
  allowlist governs — the bootstrap window — and the first row closes
  it, after which the variable can be dropped.
  Mutating endpoints take the `AdminWrite` extractor and read endpoints
  `Admin`, so no handler can forget to ask; every audit field
  (`suppression.source`, `removed_by`, `created_by`…) carries the
  actor's name, never a generic "admin".
- **`ADMIN_TOKEN`** — the break-glass and machine path, deliberately
  separate from the tenant keys: a tenant key sends mail, the admin
  credential mints and revokes tenant keys. An issuer outage must not
  lock the operator out of their own mail admin.

With neither configured the surface answers an honest 503. The API port
should never be on the public internet (firewall it to a private
network); these credentials are defence in depth, not the only wall. The
UI keeps its credential in sessionStorage — it dies with the tab.

**Serving it over TLS on a private network.** The plain HTTP port stays
reachable from the private network as the break-glass path, and a
reverse proxy on the same host adds `https://<host>/admin` on 443. Ours
is Tailscale Serve — a two-word command, an automatically renewed
Let's Encrypt certificate, and no listener on any public interface —
but any local proxy does. Worth doing even behind a VPN: the padlock
means the browser treats the origin as SECURE, which is what
`crypto.subtle`, service workers and cookie flags all gate on, and the
plain-HTTP fallbacks that exist for insecure origins stop being needed.
Remember to register the new origin's redirect URI with the OIDC issuer
alongside the old one, or login works on one address and silently 400s
on the other.

Everything the admin can do is READ or STATE: the evidence tables
(delivery attempts, bounce reports, suppression history) are only ever
read or superseded, never rewritten — lifting a suppression is a soft
delete with `removed_by`, the same discipline as everywhere else.
