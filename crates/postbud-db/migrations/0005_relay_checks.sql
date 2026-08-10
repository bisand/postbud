-- The relay's own identity, verified continuously.
--
-- The sending-domain checks (0003) answer "may this domain authenticate?"
-- Nothing answered "does the machine mail actually leaves from say the
-- same thing three ways?" — forward DNS, the PTR, and the SMTP greeting.
-- Receivers test that agreement, and two thirds of it rot silently: a
-- provider hands out a generic PTR unless asked, and a relay rebuilt from
-- a fresh image greets as localhost.localdomain until myhostname is set.
-- Neither breaks a test send; both cost reputation at the receivers that
-- matter most.
--
-- There is exactly ONE relay by design (one IP, one reputation — adding a
-- second splits reputation at the volume where it is already thin), so
-- the host it should be is configuration, not a registry table. Only the
-- evidence lives here, and like domain_check it is insert-only: "when did
-- it break, and for how long" is the question the history answers.

create table relay_check (
    id              bigserial   primary key,
    checked_at      timestamptz not null default now(),
    -- The name the relay was expected to answer to, stored per row rather
    -- than assumed: a check from before a rename must stay readable as a
    -- statement about the name in force at the time.
    expected_host   text        not null,

    forward_status  text        not null check (forward_status in ('ok','missing','mismatch')),
    forward_observed text,
    ptr_status      text        not null check (ptr_status     in ('ok','missing','mismatch')),
    ptr_observed    text,
    -- Null when the greeting could not be read at all. That is OUR outage,
    -- never the relay's configuration, so it is recorded as unknown rather
    -- than as a failure that would outlive the outage.
    helo_status     text        check (helo_status in ('ok','missing','mismatch')),
    helo_observed   text,

    valid           boolean     not null
);

create index relay_check_latest on relay_check (id desc);
