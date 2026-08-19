-- What the receivers concluded.
--
-- The sending-domain registry (0003) says what DNS ought to carry and the
-- checks record what it does carry. Neither answers the question a DMARC
-- aggregate report answers: what did the receiver DECIDE when the mail
-- actually arrived. That is the one outcome postbud cannot observe for
-- itself. A message quarantined at the far end is still a clean
-- "250 Ok: queued as ..." from the relay, so it lands in delivery_attempt
-- as a success and never appears in bounce_report at all. Only the
-- receiver can tell us, and this is the only channel it uses.
--
-- Insert-only, like domain_check and relay_check: every report is a
-- distinct fact about a distinct window, and the whole value is in the
-- series -- one day from one receiver says very little. That is the
-- opposite of the relay queue state in 0007, where "still deferred"
-- repeated every five seconds was one fact and belonged in mutable
-- columns.
--
-- Reports are EVIDENCE, never instructions. The address in a rua= tag is
-- public, so anyone on the internet can send a report claiming anything
-- about any domain. Nothing here may drive suppression, domain status, or
-- any other automatic action, and org_name is stored precisely so the UI
-- can attribute a claim to whoever made it rather than restate it as
-- fact.

create table dmarc_report (
    id            bigserial   primary key,
    -- The reporting organisation's own name for itself. Untrusted.
    org_name      text        not null,
    report_id     text        not null,
    email         text,
    -- The window the reporter says it covered.
    period_start  timestamptz not null,
    period_end    timestamptz not null,
    -- The domain whose policy was applied, folded to lower case.
    policy_domain text        not null,
    policy_p      text,
    policy_sp     text,
    policy_pct    int,
    policy_adkim  text,
    policy_aspf   text,
    -- Kept whole because it costs a kilobyte and buys a re-parse: a parser
    -- bug fixed next year can be applied to every report already received,
    -- which is impossible once the XML is discarded. Aggregate reports
    -- carry no recipient addresses and no message content, so unlike
    -- message bodies they are not personal data and are never purged.
    raw           text        not null,
    received_at   timestamptz not null default now()
);

-- The dedupe key, and the reason ingestion can be run twice over the same
-- mailbox without counting anything twice. Reporters redeliver: a retried
-- handoff, a replayed mailbox, the same file imported from two archives.
create unique index dmarc_report_identity
    on dmarc_report (org_name, report_id);

create index dmarc_report_domain_period
    on dmarc_report (policy_domain, period_start desc);

create table dmarc_record (
    id            bigserial   primary key,
    report        bigint      not null references dmarc_report (id) on delete cascade,
    -- Text rather than inet on purpose. A single unparseable address in
    -- one row would fail the insert and cost the whole report, and losing
    -- a receiver's day of history is a far worse trade than losing subnet
    -- queries on a diagnostic table.
    source_ip     text        not null,
    message_count bigint      not null,
    disposition   text        not null,
    -- The ALIGNED results: the DMARC verdict, not the bare mechanism
    -- check. A message can carry a perfectly valid signature for someone
    -- else's domain and still fail here, which is exactly the case an
    -- operator needs to see.
    dkim_aligned  text        not null,
    spf_aligned   text        not null,
    header_from   text        not null,
    -- The raw per-mechanism results. Display-only, variable cardinality,
    -- and nothing aggregates them -- columns would mean a third table
    -- earning nothing. When an aligned result is "fail" while the raw one
    -- passed, this names the domain that actually authenticated, which is
    -- the whole diagnosis for a third-party sender.
    auth_results  jsonb       not null default '{}'::jsonb,
    reasons       jsonb       not null default '[]'::jsonb
);

create index dmarc_record_report on dmarc_record (report);
