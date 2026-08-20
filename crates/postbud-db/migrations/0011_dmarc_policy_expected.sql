-- The enforcement level a domain is meant to publish.
--
-- The DMARC check has always been presence-only: any record beginning
-- `v=DMARC1` counted as OK. That is enough to answer "is there a policy",
-- and not enough to answer the question that matters once a domain is at
-- `p=reject` -- whether it still IS.
--
-- Two ways it went wrong silently. A domain edited back down to `p=none`
-- kept its green badge, because the prefix still matched. And a typo'd
-- tag (`p=quarantne`) kept it too, which is worse: DMARC fails OPEN, so a
-- receiver that cannot read the policy falls back to no enforcement. The
-- record looks valid, the check says valid, and the domain is protecting
-- nothing.
--
-- The syntax half needs no configuration and now applies to every domain.
-- This column is the other half: null means nobody has stated a level, so
-- only the syntax is checked. Set, it is compared -- and only DOWNWARD
-- drift is a fault. Publishing something stricter than recorded is
-- somebody tightening their policy, and a red badge for that teaches an
-- operator to ignore red badges.

alter table sending_domain
    add column dmarc_policy_expected text
        check (dmarc_policy_expected in ('none','quarantine','reject'));
