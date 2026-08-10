-- Attachments keep the order the caller submitted them in.
--
-- They never did. The loader ordered by `id`, which reads like insertion
-- order and is not: the column is `uuid default gen_random_uuid()`, so the
-- ordering was random and could differ between two claims of the SAME
-- message. A two-attachment invoice went out with its pages in whichever
-- order Postgres happened to return.
--
-- Existing rows all take position 0 and keep their previous
-- arbitrary-but-stable order behind it; they are historical, and most are
-- already purged by the body-retention job.
alter table message_attachment
    add column position integer not null default 0;

create index message_attachment_order
    on message_attachment (message_id, position);
