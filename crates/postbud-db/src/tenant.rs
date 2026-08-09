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

/// Replace the tenant's key. The old key stops working in the same
/// statement the new one starts — there is no window with two valid keys,
/// which is the property that makes rotating a leaked key an actual fix.
///
/// Returns the new key (shown once) or `None` for an unknown tenant.
pub async fn rotate_key(pool: &PgPool, id: Uuid) -> anyhow::Result<Option<String>> {
    let key = postbud_core::apikey::generate();
    let hash = postbud_core::apikey::hash(&key);

    let result = sqlx::query("update tenant set api_key_hash = $2 where id = $1")
        .bind(id)
        .bind(hash.as_slice())
        .execute(pool)
        .await
        .context("rotating tenant key")?;

    Ok((result.rows_affected() > 0).then_some(key))
}

/// Deactivation is immediate: `by_api_key` filters on `active`, and there
/// is no cache to wait out. Reactivating is the same switch back.
pub async fn set_active(pool: &PgPool, id: Uuid, active: bool) -> anyhow::Result<bool> {
    let result = sqlx::query("update tenant set active = $2 where id = $1")
        .bind(id)
        .bind(active)
        .execute(pool)
        .await
        .context("setting tenant active")?;
    Ok(result.rows_affected() > 0)
}

/// Replace the sending domains. Exact list, no merging — what you see in
/// the admin UI after saving is exactly what the tenant may send as.
pub async fn set_domains(pool: &PgPool, id: Uuid, from_domains: &[String]) -> anyhow::Result<bool> {
    let result = sqlx::query("update tenant set from_domains = $2 where id = $1")
        .bind(id)
        .bind(from_domains)
        .execute(pool)
        .await
        .context("setting tenant domains")?;
    Ok(result.rows_affected() > 0)
}

/// Tenant rows as the admin surface sees them: including the audit-ish
/// fields (`created_at`, `note`) the sending path has no use for.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminTenant {
    pub id: Uuid,
    pub name: String,
    pub from_domains: Vec<String>,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub note: Option<String>,
    pub messages_7d: i64,
    pub messages_total: i64,
}

pub async fn admin_list(pool: &PgPool) -> anyhow::Result<Vec<AdminTenant>> {
    let rows = sqlx::query(
        "select t.id, t.name, t.from_domains, t.active, t.created_at, t.note,
                count(m.id) filter (where m.created_at > now() - interval '7 days')
                    as messages_7d,
                count(m.id) as messages_total
           from tenant t left join message m on m.tenant_id = t.id
          group by t.id order by t.created_at",
    )
    .fetch_all(pool)
    .await
    .context("listing tenants for admin")?;

    Ok(rows
        .into_iter()
        .map(|r| AdminTenant {
            id: r.get("id"),
            name: r.get("name"),
            from_domains: r.get("from_domains"),
            active: r.get("active"),
            created_at: r.get("created_at"),
            note: r.get("note"),
            messages_7d: r.get("messages_7d"),
            messages_total: r.get("messages_total"),
        })
        .collect())
}
