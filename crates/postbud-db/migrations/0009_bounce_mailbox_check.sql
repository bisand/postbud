-- Whether the relay will actually take a bounce for a sending domain.
--
-- 0008's envelope-sender change made every message leave with
-- `bounces@<sending domain>` as its MAIL FROM, because a DSN comes back
-- to the envelope sender and never to the From: header. That turned one
-- address per domain into a dependency nothing was watching: if the relay
-- does not accept it, delivery status notifications are discarded in
-- silence, and a receiver that verifies the envelope sender before
-- accepting mail may refuse the original message outright.
--
-- Nullable like mx_status, and for the same reason: a domain with no
-- expected MX is one that never receives bounces, so there is nothing to
-- check and a verdict would be an invention.
--
-- Deliberately NOT part of `valid`, on the same reasoning as
-- report_auth_status. `valid` drives the recheck cadence, and a domain
-- whose records authenticate perfectly must not be pushed into
-- fifteen-minute rechecks for ever over a mailbox that has no bearing on
-- whether its mail passes SPF, DKIM or DMARC.

alter table domain_check
    add column bounce_status   text check (bounce_status in ('ok','missing','mismatch')),
    add column bounce_observed text;
