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

## 5. Throughput, and where the queue actually is

**Postgres is the queue.** Not a stage in front of one: the row in
`message` is the only thing that decides what gets sent. That is forced
rather than chosen — the accepting transaction must consult the
suppression list, dedup on the idempotency key and record the delivery
anyway, so any separate broker would be a second write of the same fact,
with the classic failure of a commit whose publish then fails. A message
queued but never announced is invisible mail.

The pieces that make Postgres enough:

- **Claiming is `for update skip locked`.** Any number of workers may run
  at once; they take disjoint batches with no coordination. That is
  work-stealing, deliberately not round-robin — a partition assigned up
  front leaves one worker stuck behind a slow receiver while its
  neighbours idle.
- **`NOTIFY` inside the accepting transaction** wakes a worker in
  milliseconds instead of at the next poll. It cannot arrive before the
  row it refers to is visible, and cannot arrive at all if the
  transaction rolls back. It is only a wake-up: losing it costs latency
  and nothing else.
- **The poll stays, and is load-bearing.** A retry becomes due at a time
  in the future that nothing can announce when it arrives, so
  `WORKER_IDLE_MS` remains the floor under everything.
- **`WORKER_CONCURRENCY` deliveries in flight per worker.** A batch used
  to be relayed strictly one message at a time, so claiming twenty bought
  nothing; concurrency, not batch size, is what makes a burst drain.
  Attachments for a whole batch load in one query for the same reason.
  The SMTP connection pool is sized to the same number, or the queueing
  simply moves one layer down where nothing can see it.

Sizing is a chain, and every link has to clear the next: workers ×
concurrency must stay under Postfix's per-client connection limit;
`DATABASE_MAX_CONNECTIONS` must clear `WORKER_CONCURRENCY + 1` (the extra
one is held permanently by the notification listener); and workers ×
`DATABASE_MAX_CONNECTIONS`, plus the API's and the purge job's, must stay
under Postgres's own `max_connections`.

**The ceiling above all of it is the relay.** One Postfix, one IP, by
design (section 9). Postfix owns per-destination concurrency and rate
limiting; past a certain rate, pushing harder only moves mail into its
queue, which is what its queue is for. Tuning postbud past that point
optimises the wrong hop.

## 6. Suppression semantics

**Only a permanent failure about the recipient suppresses.** The asymmetry
is deliberate and runs through the whole codebase: a needless retry costs a
connection, a wrong "permanent" costs an invoice and a customer who quietly
stops hearing from you. A full mailbox is `4.2.2` and must never suppress —
it is the most common way a naive suppression list starts silently dropping
real mail.

Permanence alone is not the test, because a 5xx answers "will retrying
help?" rather than "does this mailbox exist?". `5.7.x` is the security and
policy class: a sending domain at DMARC `p=reject` whose SPF and DKIM both
break earns one for every message it sends, each naming a recipient who is
perfectly fine. Reading those as hard bounces would suppress every address
mailed during an outage on postbud's own side of the wire — globally, for
every tenant, recoverable only by a human lifting them one at a time.
`should_suppress` is therefore an allowlist of the codes that name the
address: `5.1.1`, `5.1.2`, `5.1.3`, `5.1.6`, `5.1.10` and `5.2.1`.
`5.1.7`/`5.1.8` are excluded because they name the *sender's* address,
`5.2.3` because an oversized message proves the mailbox works, and `5.0.0`
because a code carrying no information must not be read as bad news.
Everything else is still permanent, still recorded, still never retried —
it just costs nobody their mail.

The code is not always the truth, though, which is why the receiver's own
words are a second signal. Sendmail-derived servers answer a nonexistent
mailbox with `553 5.3.0 ... No such user here` — a dead address filed
under MAIL SYSTEM, a class where nothing may suppress and nothing should.
A short list of unambiguous phrases (`no such user`, `user unknown`,
`recipient not found`, `mailbox not found`, `no mailbox here`) rescues
exactly that case. It is short on purpose: every phrase names the
RECIPIENT as missing, and none can be produced by a full mailbox, a policy
rejection or a broken relay. "does not exist" is deliberately absent,
because a missing domain says it too. Both signals sit behind the
permanence check — a receiver that defers while saying "user unknown" is
contradicting itself, and the safe reading of a contradiction is the one
that keeps writing to the address.

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

## 7. Where each piece runs

| | Runs on | Holds |
| --- | --- | --- |
| postbud + Postgres | wherever the apps run | queue, suppression list, delivery history, message bodies |
| Postfix + OpenDKIM + queue reporter | three containers in one pod on the relay node, `hostNetwork` for port 25 | the IP reputation |

The relay holds no application credentials. It DOES now hold the DKIM
private key as a mounted Secret rather than a file on a host -- the
trade is discoverability over at-rest protection, since a key on a
filesystem is invisible to `kubectl` and forgotten when the node is
rebuilt. It is never in this repository either way.

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

## 8. Message bodies are personal data

Invoices carry names, addresses and amounts. The **delivery record** is
operational history and is kept; the **content** has no reason to outlive
the delivery it existed for. `postbud purge` blanks bodies and attachments
of finished messages after `BODY_RETENTION_DAYS` (default 30), leaving the
delivery attempts, the queue id and the bounce reports intact.

## 9. Deliberately not built

- **Inbound mail.** The relay accepts a short RCPT allowlist — bounces,
  `abuse@`, `postmaster@`, DMARC reports — and rejects everything else
  before any content is accepted, which is what keeps it free of a
  filtering stack and comfortable in 2 GB. A real inbound MX means either
  a larger relay VM or content scanning next to the applications, and the
  second is the better answer.
- **An SMTP submission listener in postbud.** The API is the only way in;
  the relay accepts submission from nowhere but the delivery worker
  (section 7). Writing a submission server here would only be worth it to
  give SMTP callers the suppression list and the delivery record; if that
  day comes, it is a component, not a redesign.
- **Templates, scheduled sending, open/click tracking.** The applications
  own their content. Tracking pixels in particular are a reputation and
  privacy cost with no upside for transactional mail.
- **Multiple relays / failover.** One relay, one IP, one reputation. Adding
  a second IP splits reputation at exactly the volume where it is already
  thin.

## 10. The admin surface

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

## 11. Domain verification

The Domains section holds the sending-domain registry: for each domain,
the expected SPF record, the DKIM selector and public key the relay
signs with, and the MX that routes bounces home. The UI renders these as
paste-ready DNS rows; the worker then checks reality against them —
every 15 minutes while anything is wrong (an operator mid-setup should
get feedback in minutes), daily once everything is green, because DNS
does not only start wrong, it also breaks later. Checks are insert-only
history: "when did it break, and for how long" is answerable.

The rules are pure (`postbud-core::dnscheck`) and encode two failures
that actually happened rather than hypotheticals: a SECOND SPF record on
the same name is reported as a PermError even when one of the two is
exactly right (RFC 7208 — receivers treat the domain as having no SPF at
all), and a published DKIM record is compared to the signing key
byte-for-byte, because a record with the wrong key looks fine to the eye
and fails at every receiver. DMARC follows the inheritance walk toward
the organizational domain, and a resolver failure SKIPS the check rather
than recording it — an outage at our resolver must not be written down
as every domain suddenly losing its DNS.

Checks use PUBLIC resolvers (Cloudflare, then Google), not the host's
own — found the hard way. A relay's ISP resolver had cached NXDOMAIN for
a name from before its records were published and kept serving that
negative answer, so the checker reported "missing" for records that were
live and correct everywhere else. The verdict must not depend on which
resolver the relay happens to be configured with; the question is what
the world's receivers see. `DNS_RESOLVERS` overrides (comma-separated
IPs, or `system` to restore the old behaviour).

**The relay's own identity is checked too**, on the same cadence and
shown above the domain list. A sending domain can have perfect SPF, DKIM
and DMARC and still be scored down, because receivers also judge the
machine mail came from on a three-way agreement: the host resolves
forward to the sending address, that address resolves back to the host
(the PTR), and the SMTP greeting announces the same host. Two of those
three rot silently — a provider hands out a generic PTR unless asked, and
a relay rebuilt from a fresh image greets as `localhost.localdomain`
until `myhostname` is set. Neither breaks a test send; both cost
reputation at the receivers that matter most.

`RELAY_PUBLIC_HOST` names what the relay should be called, deliberately
separate from `RELAY_HOST` (the private address mail is submitted
through). Unset means the check is off, and the UI says so rather than
showing a tick for a question nobody asked. The greeting is read straight
off the socket; a relay that cannot be reached records `unknown` rather
than a failure, because that is our outage and writing it down as a
misconfiguration would leave a lie in the history that outlives it.
There is one relay by design, so the expected host is configuration and
only the evidence is a table — `relay_check`, insert-only, migration
0005.
