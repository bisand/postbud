//! Tenants: one per sending system.

use anyhow::Context;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub from_domains: Vec<String>,
    pub active: bool,
}

/// Resolve a presented API key to a tenant.
///
/// The key is hashed and looked up; the plaintext is never stored, never
/// logged, and never compared directly. An inactive tenant resolves to
/// `None` — deactivating is immediate, with no cache to wait out.
pub async fn by_api_key(pool: &PgPool, presented_key: &str) -> anyhow::Result<Option<Tenant>> {
    let hash = postbud_core::apikey::hash(presented_key);
    let row = sqlx::query(
        "select id, name, from_domains, active
           from tenant
          where api_key_hash = $1 and active",
    )
    .bind(hash.as_slice())
    .fetch_optional(pool)
    .await
    .context("looking up tenant by api key")?;

    Ok(row.map(|r| Tenant {
        id: r.get("id"),
        name: r.get("name"),
        from_domains: r.get("from_domains"),
        active: r.get("active"),
    }))
}

/// Register a tenant. Returns the generated key, which is shown exactly
/// once — postbud stores only its digest and cannot recover it later.
pub async fn create(
    pool: &PgPool,
    name: &str,
    from_domains: &[String],
    note: Option<&str>,
) -> anyhow::Result<(Tenant, String)> {
    let key = postbud_core::apikey::generate();
    let hash = postbud_core::apikey::hash(&key);

    let row = sqlx::query(
        "insert into tenant (name, api_key_hash, from_domains, note)
              values ($1, $2, $3, $4)
           returning id, name, from_domains, active",
    )
    .bind(name)
    .bind(hash.as_slice())
    .bind(from_domains)
    .bind(note)
    .fetch_one(pool)
    .await
    .context("creating tenant")?;

    Ok((
        Tenant {
            id: row.get("id"),
            name: row.get("name"),
            from_domains: row.get("from_domains"),
            active: row.get("active"),
        },
        key,
    ))
}

pub async fn list(pool: &PgPool) -> anyhow::Result<Vec<Tenant>> {
    let rows = sqlx::query("select id, name, from_domains, active from tenant order by created_at")
        .fetch_all(pool)
        .await
        .context("listing tenants")?;

    Ok(rows
        .into_iter()
        .map(|r| Tenant {
            id: r.get("id"),
            name: r.get("name"),
            from_domains: r.get("from_domains"),
            active: r.get("active"),
        })
        .collect())
}
