-- DMARC aggregate reports sent to an address outside the publishing
-- domain's organizational domain require that other domain to publish
-- `<domain>._report._dmarc.<host>` (RFC 7489 §7.1). Without it every
-- receiver silently sends nothing -- no error, no bounce, and a DMARC
-- record that still looks perfectly valid to every other check here.
--
-- Nullable, and null on every row written before this: no external
-- report destination means there is nothing to authorize, which is a
-- different thing from "checked and missing".
--
-- Deliberately NOT part of `valid`. `valid` drives the recheck cadence
-- (15 minutes until green, then daily), and where reports are delivered
-- has no bearing on whether mail authenticates -- a domain must not be
-- rechecked every 15 minutes forever over a reporting address.
alter table domain_check
    add column report_auth_status   text
        check (report_auth_status in ('ok','missing','mismatch')),
    add column report_auth_observed text;
