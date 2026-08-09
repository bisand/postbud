-- Admin users for the /admin surface.
--
-- Who may administer postbud, decided by postbud -- the OIDC issuer only
-- proves identity. Rows follow the same discipline as the suppression
-- list: removal is a soft end (`ended_at`), never a delete, because "who
-- had admin access in March" is exactly the question an audit asks. A
-- role change is an end plus a new row, so the history reads as what it
-- is: one grant ending, another beginning.
--
-- While this table has no active rows at all, the ADMIN_OIDC_USERS
-- environment allowlist governs (bootstrap); the first row makes the
-- table authoritative and the environment variable inert.

create table admin_user (
    id         bigserial primary key,
    -- An email (matched case-insensitively against the id_token's
    -- `email`) or an OIDC subject id (matched exactly against `sub`).
    identifier text        not null,
    -- admin: everything. viewer: sees everything, changes nothing.
    role       text        not null check (role in ('admin', 'viewer')),
    note       text,
    created_at timestamptz not null default now(),
    -- The actor who granted this: an email, or 'admin-token'.
    created_by text        not null,
    ended_at   timestamptz,
    ended_by   text
);

-- One active grant per identity; history rows may repeat freely.
create unique index admin_user_active
    on admin_user (lower(identifier))
    where ended_at is null;
