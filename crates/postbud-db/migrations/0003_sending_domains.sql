-- Sending domains, verified continuously.
--
-- A tenant names the domains it may send as; this table holds what DNS
-- must SAY for those domains to authenticate: the expected SPF record,
-- the DKIM selector and public key the relay signs with, and the MX that
-- routes bounces home. The admin UI renders these as paste-ready
-- records, and the worker checks reality against them — every ~15
-- minutes while anything is wrong, daily once everything is right,
-- because DNS does not only start wrong, it also breaks later.
--
-- Checks are EVIDENCE, so domain_check is insert-only: "when did it
-- break" and "how long was it broken" are questions the history answers
-- and a mutable status column never could.

create table sending_domain (
    id              bigserial primary key,
    domain          text        not null,
    -- What must be published. The DKIM public key is the p= value the
    -- relay's private key corresponds to — a published record with the
    -- WRONG key is indistinguishable from no record at verification
    -- time, which is why the check compares byte-for-byte.
    spf_expected    text        not null,
    dkim_selector   text        not null,
    dkim_public_key text        not null,
    -- Null = no MX required (a domain that never receives bounces).
    mx_expected     text,
    created_at      timestamptz not null default now(),
    created_by      text        not null,
    ended_at        timestamptz,
    ended_by        text
);

create unique index sending_domain_active
    on sending_domain (lower(domain))
    where ended_at is null;

create table domain_check (
    id             bigserial   primary key,
    domain_id      bigint      not null references sending_domain (id),
    checked_at     timestamptz not null default now(),
    -- Per record: ok | missing | mismatch. Observed carries what DNS
    -- actually said, so a mismatch is diagnosable from the UI alone.
    spf_status     text        not null check (spf_status   in ('ok','missing','mismatch')),
    spf_observed   text,
    dkim_status    text        not null check (dkim_status  in ('ok','missing','mismatch')),
    dkim_observed  text,
    dmarc_status   text        not null check (dmarc_status in ('ok','missing','mismatch')),
    dmarc_observed text,
    -- Null when no MX is expected.
    mx_status      text        check (mx_status in ('ok','missing','mismatch')),
    mx_observed    text,
    valid          boolean     not null
);

create index domain_check_latest on domain_check (domain_id, id desc);
