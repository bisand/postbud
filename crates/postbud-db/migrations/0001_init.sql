-- postbud schema v1.
--
-- Two disciplines are carried over from regnmed, for the same reasons:
--
--   * Rows that are EVIDENCE are insert-only. A delivery attempt, a bounce
--     report and a suppression decision are all statements about something
--     that happened; they are superseded, never rewritten.
--   * Rows that are STATE are kept to a minimum. A queue genuinely needs
--     mutable state (status, next_attempt_at), so `message` has it -- but
--     every transition that state goes through also leaves an insert-only
--     `delivery_attempt` row behind, so the history is reconstructible even
--     though the current status is a single column.
--
-- The one identifier that matters most is `relay_queue_id`: the queue id
-- Postfix returns in "250 2.0.0 Ok: queued as 4XyZ...". It is the ONLY
-- thing that joins a message we sent to a bounce that comes back days
-- later. Everything else about correlation follows from capturing it.

create extension if not exists pgcrypto;

-- ----------------------------------------------------------------- tenant

-- One row per sending system: regnmed, networco, and whatever comes later.
--
-- The API key itself is never stored. A key is 32 random bytes, so plain
-- SHA-256 is the right function here -- there is no low-entropy guess for
-- a password hash to slow down, and a constant-time comparison against a
-- unique index is what we actually need.
create table tenant (
    id           uuid primary key default gen_random_uuid(),
    name         text        not null unique,
    api_key_hash bytea       not null unique,
    -- A leaked regnmed key must not be able to send as networco. Enforced
    -- on every accept, not only at registration.
    from_domains text[]      not null,
    active       boolean     not null default true,
    created_at   timestamptz not null default now(),
    note         text
);

-- ---------------------------------------------------------------- message

-- Accepted mail. Content is written once at accept time and never edited;
-- only the queue state below the line changes.
create table message (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid        not null references tenant (id),

    -- Supplied by the caller. regnmed passes its own `utsendelse` id here,
    -- which is what makes a retry of the same business event a no-op
    -- rather than a second invoice in the customer's inbox.
    idempotency_key text        not null,

    -- Content (immutable).
    mail_from       text        not null,
    from_name       text,
    rcpt_to         text        not null,
    reply_to        text,
    subject         text        not null,
    body_text       text,
    body_html       text,

    -- Queue state (mutable, deliberately small).
    status          text        not null default 'queued'
                    check (status in ('queued', 'sent', 'failed', 'suppressed')),
    attempts        int         not null default 0,
    next_attempt_at timestamptz not null default now(),
    -- Set by a worker while a batch is in flight; cleared on completion.
    -- Lets a crashed worker's claims be reclaimed by age instead of
    -- staying stuck forever.
    claimed_at      timestamptz,
    claimed_by      text,

    -- Postfix's queue id, captured from the 250 response. Null until the
    -- relay accepts the message.
    relay_queue_id  text,
    last_error      text,

    created_at      timestamptz not null default now(),
    completed_at    timestamptz,
    -- Set when the body columns have been blanked by the retention job.
    body_purged_at  timestamptz,

    unique (tenant_id, idempotency_key)
);

-- The worker's hot path: oldest due message first.
create index message_due on message (next_attempt_at)
    where status = 'queued';

-- Bounce correlation.
create index message_relay_queue_id on message (relay_queue_id)
    where relay_queue_id is not null;

create index message_tenant_created on message (tenant_id, created_at desc);

create table message_attachment (
    id           uuid primary key default gen_random_uuid(),
    message_id   uuid  not null references message (id),
    filename     text  not null,
    content_type text  not null,
    content      bytea not null,
    -- Recorded so a stored attachment can be proven identical to the one
    -- the caller submitted, the same property regnmed's bilagsvedlegg has.
    sha256       bytea not null
);

create index message_attachment_message on message_attachment (message_id);

-- ------------------------------------------------------- delivery_attempt

-- Insert-only. One row per handoff attempt to the relay.
create table delivery_attempt (
    id             bigserial primary key,
    message_id     uuid        not null references message (id),
    attempt        int         not null,
    started_at     timestamptz not null default now(),
    finished_at    timestamptz not null default now(),
    -- accepted: the relay took it (and gave us a queue id)
    -- transient: 4xx, or the relay was unreachable -- try again
    -- permanent: 5xx -- never try again, and suppress the address
    outcome        text        not null
                   check (outcome in ('accepted', 'transient', 'permanent')),
    smtp_code      int,
    relay_queue_id text,
    detail         text
);

create index delivery_attempt_message on delivery_attempt (message_id, attempt);

-- ------------------------------------------------------------ suppression

-- The list Postfix cannot keep for us. An address lands here on a hard
-- bounce or a complaint and stays until someone explicitly lifts it.
--
-- Lifting is a soft delete (`removed_at`) rather than a real one, because
-- "we suppressed this address on the 3rd and someone un-suppressed it on
-- the 9th" is exactly the history you want when a customer says they
-- stopped receiving invoices.
create table suppression (
    id         bigserial primary key,
    -- Null means global: it applies to every tenant. A hard bounce is a
    -- fact about the mailbox, not about who was writing to it, so bounce-
    -- driven suppressions are global by default.
    tenant_id  uuid        references tenant (id),
    address    text        not null,
    reason     text        not null
               check (reason in ('hard_bounce', 'complaint', 'manual', 'invalid')),
    source     text        not null,
    detail     text,
    created_at timestamptz not null default now(),
    removed_at timestamptz,
    removed_by text
);

-- `nulls not distinct` (PG15+) is what makes the global row unique too;
-- without it Postgres would treat every null tenant_id as its own value
-- and happily store the same global suppression a hundred times.
create unique index suppression_active
    on suppression (tenant_id, lower(address)) nulls not distinct
    where removed_at is null;

-- ---------------------------------------------------------- bounce_report

-- Insert-only. The raw DSN as Postfix handed it to us, kept whether or not
-- we managed to parse it -- an unparsed bounce is a bug report, and
-- throwing away the evidence would mean never being able to fix it.
create table bounce_report (
    id             bigserial primary key,
    received_at    timestamptz not null default now(),
    raw            text        not null,
    -- Everything below is what parsing made of `raw`, and is null when
    -- parsing failed.
    relay_queue_id text,
    message_id     uuid references message (id),
    final_rcpt     text,
    status_code    text,
    diagnostic     text,
    classification text check (classification in ('permanent', 'transient', 'unknown'))
);

create index bounce_report_queue_id on bounce_report (relay_queue_id)
    where relay_queue_id is not null;

create index bounce_report_unparsed on bounce_report (received_at)
    where message_id is null;
