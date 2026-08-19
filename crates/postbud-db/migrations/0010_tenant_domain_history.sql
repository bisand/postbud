-- Who was allowed to send as what, and since when.
--
-- The tenant -> sending-domain binding is the boundary that makes
-- per-tenant keys worth having: a leaked key for one product must not be
-- able to send as another. Every other record of comparable weight here
-- keeps its history -- admin grants are soft-ended and never deleted,
-- suppressions are soft-deleted so "suppressed on the 3rd, lifted on the
-- 9th" stays answerable, domain and relay checks are insert-only. This
-- one binding was a destructive UPDATE with no actor and no before-value,
-- so after a change nobody could say what it used to be or who changed it.
--
-- That gap was found the way such gaps usually are: a tenant had sent as
-- a domain it is no longer allowed to use, and answering "was this a
-- misconfiguration or a bypass?" took inference from message timestamps
-- because the direct evidence did not exist. The answer was innocent.
-- The next one might not be.
--
-- The LIVE list stays on tenant.from_domains, exactly where the send path
-- reads it. Moving authorization to a join would put a second query in
-- front of every accepted message and rework the one boundary that must
-- not be got wrong, to buy something a separate log buys just as well.
-- So this is insert-only history beside it, like domain_check, and
-- nothing reads it to make a decision.

create table tenant_domain_change (
    id             bigserial   primary key,
    tenant_id      uuid        not null references tenant (id),
    changed_at     timestamptz not null default now(),
    -- The admin actor, or 'cli' when a tenant is created from the host.
    changed_by     text        not null,
    -- Empty on the row that records a tenant's creation, so the history
    -- is complete from the beginning rather than starting at the first
    -- edit -- which would leave the ORIGINAL grant just as unknowable as
    -- before.
    domains_before text[]      not null,
    domains_after  text[]      not null
);

create index tenant_domain_change_tenant
    on tenant_domain_change (tenant_id, id desc);
