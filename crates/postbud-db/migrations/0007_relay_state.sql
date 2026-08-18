-- What the relay did with a message AFTER it accepted it.
--
-- `status = 'sent'` means the smarthost took the message and returned a
-- queue id. It has never meant the mail arrived, and it cannot: Postfix
-- owns delivery and only reports back when it gives up, via a bounce. A
-- 4xx deferral produces no bounce at all, so a destination that blocked
-- us for two hours left every message sitting in the relay's queue while
-- this table said nothing was wrong.
--
-- These three columns are the missing half, filled from `postqueue -j`.
-- Mutable and deliberately small, like the queue state above them: the
-- history worth keeping is already in `delivery_attempt` (the handoff)
-- and `bounce_report` (the terminal failure). A row per poll saying
-- "still deferred" would be thousands of rows carrying one fact.
--
-- Null means nothing has been observed yet -- honest for a message the
-- relay reporter has not covered, and the state every row starts in.
alter table message
    add column relay_state        text
        check (relay_state in ('active', 'deferred', 'delivered')),
    add column relay_state_detail text,
    add column relay_state_at     timestamptz;

-- The reconciliation joins queue ids to messages; `message_relay_queue_id`
-- from 0001 already covers that lookup.
