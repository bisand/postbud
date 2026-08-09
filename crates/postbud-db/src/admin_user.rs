//! Admin users: who may operate the admin surface, and as what.
//!
//! The OIDC issuer proves identity; this table decides authorization.
//! Rows end, they are never deleted, and a role change is an end plus a
//! new row — the history stays readable as a sequence of grants.

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminUser {
    pub id: i64,
    pub identifier: String,
    pub role: String,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub ended_at: Option<DateTime<Utc>>,
    pub ended_by: Option<String>,
}

fn row_to_user(r: sqlx::postgres::PgRow) -> AdminUser {
    AdminUser {
        id: r.get("id"),
        identifier: r.get("identifier"),
        role: r.get("role"),
        note: r.get("note"),
        created_at: r.get("created_at"),
        created_by: r.get("created_by"),
        ended_at: r.get("ended_at"),
        ended_by: r.get("ended_by"),
    }
}

pub async fn list(pool: &PgPool, include_ended: bool) -> anyhow::Result<Vec<AdminUser>> {
    let rows = sqlx::query(
        "select id, identifier, role, note, created_at, created_by, ended_at, ended_by
           from admin_user
          where $1 or ended_at is null
          order by (ended_at is not null), lower(identifier), id desc
          limit 500",
    )
    .bind(include_ended)
    .fetch_all(pool)
    .await
    .context("listing admin users")?;
    Ok(rows.into_iter().map(row_to_user).collect())
}

/// Grant access. Refuses a duplicate active grant by name rather than by
/// constraint error.
pub async fn add(
    pool: &PgPool,
    identifier: &str,
    role: &str,
    note: Option<&str>,
    created_by: &str,
) -> anyhow::Result<AdminUser> {
    let row = sqlx::query(
        "insert into admin_user (identifier, role, note, created_by)
              values ($1, $2, $3, $4)
           returning id, identifier, role, note, created_at, created_by,
                     ended_at, ended_by",
    )
    .bind(identifier)
    .bind(role)
    .bind(note)
    .bind(created_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            anyhow!("'{identifier}' already has an active grant")
        }
        _ => anyhow::Error::new(e).context("adding admin user"),
    })?;
    Ok(row_to_user(row))
}

/// End a grant. The last active admin cannot be ended — the check and
/// the end run in one transaction with the active rows locked, so two
/// concurrent removals cannot each see "there is another admin left".
pub async fn end(pool: &PgPool, id: i64, ended_by: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;

    let target = sqlx::query(
        "select role from admin_user where id = $1 and ended_at is null for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .context("locking admin user")?;
    let Some(target) = target else {
        return Ok(false);
    };

    if target.get::<String, _>("role") == "admin" {
        let admins: i64 = sqlx::query(
            "select count(*) as n from (
                 select id from admin_user
                  where ended_at is null and role = 'admin' for update
             ) locked",
        )
        .fetch_one(&mut *tx)
        .await
        .context("counting active admins")?
        .get("n");
        if admins <= 1 {
            return Err(anyhow!(
                "cannot remove the last admin — grant someone else the admin role first"
            ));
        }
    }

    sqlx::query("update admin_user set ended_at = now(), ended_by = $2 where id = $1")
        .bind(id)
        .bind(ended_by)
        .execute(&mut *tx)
        .await
        .context("ending admin user")?;
    tx.commit().await?;
    Ok(true)
}

/// Change a role: end the old grant and write the new one, in one
/// transaction, under the same last-admin rule as [`end`].
pub async fn set_role(pool: &PgPool, id: i64, role: &str, actor: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;

    let target = sqlx::query(
        "select identifier, role, note from admin_user
          where id = $1 and ended_at is null for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .context("locking admin user")?;
    let Some(target) = target else {
        return Ok(false);
    };
    let old_role: String = target.get("role");
    if old_role == role {
        return Ok(true);
    }

    if old_role == "admin" {
        let admins: i64 = sqlx::query(
            "select count(*) as n from (
                 select id from admin_user
                  where ended_at is null and role = 'admin' for update
             ) locked",
        )
        .fetch_one(&mut *tx)
        .await
        .context("counting active admins")?
        .get("n");
        if admins <= 1 {
            return Err(anyhow!(
                "cannot demote the last admin — grant someone else the admin role first"
            ));
        }
    }

    sqlx::query("update admin_user set ended_at = now(), ended_by = $2 where id = $1")
        .bind(id)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .context("ending old grant")?;
    sqlx::query(
        "insert into admin_user (identifier, role, note, created_by)
              values ($1, $2, $3, $4)",
    )
    .bind(target.get::<String, _>("identifier"))
    .bind(role)
    .bind(target.get::<Option<String>, _>("note"))
    .bind(actor)
    .execute(&mut *tx)
    .await
    .context("writing new grant")?;
    tx.commit().await?;
    Ok(true)
}

/// Resolve an authenticated identity to a role, plus whether the table
/// holds any active rows at all (the bootstrap question: an empty table
/// hands the decision to the environment allowlist).
pub async fn resolve(
    pool: &PgPool,
    sub: &str,
    email: Option<&str>,
) -> anyhow::Result<(Option<String>, bool)> {
    let row = sqlx::query(
        "select
           (select role from admin_user
             where ended_at is null
               and (identifier = $1
                    or ($2::text is not null and lower(identifier) = lower($2)))
             limit 1) as role,
           exists (select 1 from admin_user where ended_at is null) as any_active",
    )
    .bind(sub)
    .bind(email)
    .fetch_one(pool)
    .await
    .context("resolving admin role")?;
    Ok((row.get("role"), row.get("any_active")))
}
