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
  regnmed's `utsendelse` log (migration 0020) records that a message was
  handed off; it can never record whether it arrived, because the answer
  turns up minutes later in a log file.
- **Per-tenant authentication bound to sending domains.** One SASL
  credential on a shared relay lets any product send as any other.

## 2. One rail, not two

regnid already is a mail service: JetStream `REGNID_MAIL`, work-queue
retention, `Nats-Msg-Id` dedup, a durable consumer, backoff, three
transports. regnmed publishes onto it through the `regnmed-mail` crate. Its
own CLAUDE.md states the doctrine: *plattformen har ÉN mail-rail*.

postbud must **replace** that delivery path, not sit beside it. Two rails
means two suppression lists, and a suppression list that disagrees with
itself is worse than none: one system keeps writing to an address the other
has already learned is dead, and the receiving provider scores the IP, not
the sender.

The migration is free on both sides, which is the point:

- **regnid needs no code change.** `src/transport.rs` already speaks SMTP
  submission (`MAIL_TRANSPORT=smtp`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`).
  Point it at the relay. Its JetStream rail can be retired later, on its own
  schedule, rather than as a precondition.
- **networco has no mail capability at all today.**
  `apps/shared/Services/IEmailService.cs` declares a one-method interface
  with no implementation and no DI registration anywhere in the solution.
  postbud is its first one, not a replacement.

## 3. One identifier survives all three hops

The cost of putting a service in front of the relay is a third hop:
application → postbud → Postfix → the internet. Each hop is somewhere mail
can get stuck and a separate log to correlate.

That cost is paid once, at the start, by carrying one identifier through:

| Hop | Identifier |
| --- | --- |
| Application → postbud | the caller's idempotency key (regnmed passes its `utsendelse` id) |
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

regnid's mail worker retries on `[1s, 5s, 30s, 60s, 120s]` and gives up
after five attempts — **216 seconds**. Once `max_deliver` is exceeded the
message leaves the work-queue stream and the only trace is a
`MAX_DELIVERIES` advisory nothing consumes.

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
| postbud + Postgres | k3s cluster | queue, suppression list, delivery history, message bodies |
| Postfix + OpenDKIM | STW VM, own IPv4 + PTR | the IP reputation, the DKIM private key |

The relay holds no application credentials and no state worth backing up:
losing that VM costs an IP address, not a secret. The DKIM private key
exists in exactly one place and never in this repository — the same rule
regnmed's secrets policy applies to the Maskinporten key.

**Only the delivery worker may inject mail** (tightened 2026-08-09).
Postfix's `mynetworks` is loopback plus the pod CIDR — the tailnet is
deliberately NOT trusted, although the original setup trusted it. A
tailnet CIDR would let any enrolled machine relay directly, bypassing the
suppression list, the idempotent dedup and the delivery record; with the
pod-only rule, every message on the wire has passed the API. Port 25 from
the internet stays open solely for inbound bounces to the RCPT allowlist —
`reject_unauth_destination` refuses relay from strangers as it always did.

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
  filtering stack and comfortable in 2 GB. regnmed's `e-post-inn`
  (migration 0032) still waits on an MX that does not exist; standing that
  up means either a larger relay VM or content scanning in the cluster,
  and the second is the better answer.
- **An SMTP submission listener in postbud.** The API is the only way in.
  regnid originally spoke SMTP to the relay; since the cutover it publishes
  through the postbud API like everything else, and the relay no longer
  accepts submission from anywhere but the delivery worker (section 6).
  Writing a submission server here would only be worth it to give SMTP
  callers the suppression list and the delivery record; if that day comes,
  it is a component, not a redesign.
- **Templates, scheduled sending, open/click tracking.** The applications
  own their content. Tracking pixels in particular are a reputation and
  privacy cost with no upside for transactional mail.
- **Multiple relays / failover.** One relay, one IP, one reputation. Adding
  a second IP splits reputation at exactly the volume where it is already
  thin.

## 9. The admin surface

`/admin` is a Svelte 5 + daisyUI app compiled into `ui/admin/dist`
(checked in, embedded into the binary with `include_dir` — cargo never
needs node, regnmed's portal discipline; CI proves dist matches source).
It serves a dashboard, the delivery log with per-message attempt history
and joined bounces, the suppression list (block/lift, global or
per-tenant), tenant administration (create, edit domains, deactivate,
rotate key — rotation kills the old key in the same statement), and the
raw bounce feed.

Authentication is a single `ADMIN_TOKEN`, deliberately separate from the
tenant keys: a tenant key sends mail, the admin token mints and revokes
tenant keys — a strictly greater privilege that must not be reachable from
a leaked tenant credential. Unset, the surface answers an honest 503. The
NodePort is reachable only from loopback and the tailnet, so the admin UI
is never on the public internet; the token is defence in depth, not the
only wall. The UI keeps the token in sessionStorage — it dies with the
tab.

Everything the admin can do is READ or STATE: the evidence tables
(delivery attempts, bounce reports, suppression history) are only ever
read or superseded, never rewritten — lifting a suppression is a soft
delete with `removed_by`, the same discipline as everywhere else.
