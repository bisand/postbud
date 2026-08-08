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
- **An SMTP submission listener in postbud.** regnid talks SMTP to the
  relay directly. Writing a submission server here would only be worth it
  to give SMTP callers the suppression list and the delivery record; if
  that day comes, it is a component, not a redesign.
- **Templates, scheduled sending, open/click tracking.** The applications
  own their content. Tracking pixels in particular are a reputation and
  privacy cost with no upside for transactional mail.
- **Multiple relays / failover.** One relay, one IP, one reputation. Adding
  a second IP splits reputation at exactly the volume where it is already
  thin.
