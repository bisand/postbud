//! The queue: accept, claim, and record what happened.

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::suppression;

#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NewMessage {
    pub tenant_id: Uuid,
    pub idempotency_key: String,
    pub mail_from: String,
    pub from_name: Option<String>,
    pub rcpt_to: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone)]
pub struct Accepted {
    pub id: Uuid,
    pub status: String,
    /// True when this exact idempotency key had already been accepted, so
    /// nothing new was queued. The caller gets the original id back.
    pub deduplicated: bool,
}

/// Accept a message.
///
/// Three things happen in one transaction, and the order matters:
///
/// 1. The suppression list is consulted. A suppressed recipient is still
///    RECORDED — with status `suppressed` — rather than rejected outright.
///    "We deliberately did not send this, and here is why" is an answer;
///    a 4xx from the API that leaves no trace is not.
/// 2. The row is inserted, or not, on the idempotency key. This is what
///    makes a caller's retry safe: regnmed passing its `utsendelse` id
///    cannot turn one invoice into two.
/// 3. Attachments are stored with their digest.
pub async fn accept(pool: &PgPool, msg: &NewMessage) -> anyhow::Result<Accepted> {
    let mut tx = pool.begin().await.context("beginning accept transaction")?;

    let suppressed = suppression::is_suppressed_tx(&mut tx, msg.tenant_id, &msg.rcpt_to).await?;
    let status = if suppressed { "suppressed" } else { "queued" };

    let inserted = sqlx::query(
        "insert into message (
             tenant_id, idempotency_key, mail_from, from_name, rcpt_to,
             reply_to, subject, body_text, body_html, status, completed_at
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                   case when $10 = 'suppressed' then now() end)
         on conflict (tenant_id, idempotency_key) do nothing
         returning id, status",
    )
    .bind(msg.tenant_id)
    .bind(&msg.idempotency_key)
    .bind(&msg.mail_from)
    .bind(&msg.from_name)
    .bind(&msg.rcpt_to)
    .bind(&msg.reply_to)
    .bind(&msg.subject)
    .bind(&msg.body_text)
    .bind(&msg.body_html)
    .bind(status)
    .fetch_optional(&mut *tx)
    .await
    .context("inserting message")?;

    let Some(row) = inserted else {
        // Already accepted under this key. Return the original, unchanged.
        let existing = sqlx::query(
            "select id, status from message
              where tenant_id = $1 and idempotency_key = $2",
        )
        .bind(msg.tenant_id)
        .bind(&msg.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .context("loading deduplicated message")?;
        tx.commit().await?;
        return Ok(Accepted {
            id: existing.get("id"),
            status: existing.get("status"),
            deduplicated: true,
        });
    };

    let id: Uuid = row.get("id");

    for attachment in &msg.attachments {
        let digest = sha256(&attachment.content);
        sqlx::query(
            "insert into message_attachment
                 (message_id, filename, content_type, content, sha256)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(&attachment.filename)
        .bind(&attachment.content_type)
        .bind(&attachment.content)
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await
        .context("storing attachment")?;
    }

    tx.commit().await.context("committing accept")?;

    Ok(Accepted {
        id,
        status: row.get("status"),
        deduplicated: false,
    })
}

#[derive(Debug, Clone)]
pub struct Claimed {
    pub id: Uuid,
    pub attempts: i32,
    pub mail_from: String,
    pub from_name: Option<String>,
    pub rcpt_to: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<Attachment>,
}

/// How long a claim may sit before another worker may take it. A worker
/// that is killed mid-batch must not park its messages forever.
const CLAIM_TIMEOUT_MINUTES: i64 = 10;

/// Claim up to `batch` due messages for this worker.
///
/// `for update skip locked` is what makes running several workers safe:
/// each takes a disjoint set, and none blocks on another's rows.
pub async fn claim(pool: &PgPool, worker: &str, batch: i64) -> anyhow::Result<Vec<Claimed>> {
    let rows = sqlx::query(
        "update message
            set claimed_at = now(), claimed_by = $1
          where id in (
                select id from message
                 where status = 'queued'
                   and next_attempt_at <= now()
                   and (claimed_at is null
                        or claimed_at < now() - make_interval(mins => $3))
                 order by next_attempt_at
                   for update skip locked
                 limit $2
          )
      returning id, attempts, mail_from, from_name, rcpt_to, reply_to,
                subject, body_text, body_html",
    )
    .bind(worker)
    .bind(batch)
    .bind(CLAIM_TIMEOUT_MINUTES as i32)
    .fetch_all(pool)
    .await
    .context("claiming messages")?;

    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        claimed.push(Claimed {
            id,
            attempts: row.get("attempts"),
            mail_from: row.get("mail_from"),
            from_name: row.get("from_name"),
            rcpt_to: row.get("rcpt_to"),
            reply_to: row.get("reply_to"),
            subject: row.get("subject"),
            body_text: row.get("body_text"),
            body_html: row.get("body_html"),
            attachments: attachments_for(pool, id).await?,
        });
    }
    Ok(claimed)
}

async fn attachments_for(pool: &PgPool, message_id: Uuid) -> anyhow::Result<Vec<Attachment>> {
    let rows = sqlx::query(
        "select filename, content_type, content
           from message_attachment where message_id = $1 order by id",
    )
    .bind(message_id)
    .fetch_all(pool)
    .await
    .context("loading attachments")?;

    Ok(rows
        .into_iter()
        .map(|r| Attachment {
            filename: r.get("filename"),
            content_type: r.get("content_type"),
            content: r.get("content"),
        })
        .collect())
}

/// The relay took the message. `relay_queue_id` is Postfix's own queue id,
/// parsed out of its 250 response — the only handle a future bounce will
/// carry, so losing it here means losing bounce correlation entirely.
pub async fn record_accepted(
    pool: &PgPool,
    id: Uuid,
    attempt: i32,
    relay_queue_id: Option<&str>,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "update message
            set status = 'sent', attempts = $2, relay_queue_id = $3,
                claimed_at = null, claimed_by = null,
                completed_at = now(), last_error = null
          where id = $1",
    )
    .bind(id)
    .bind(attempt)
    .bind(relay_queue_id)
    .execute(&mut *tx)
    .await
    .context("marking message sent")?;

    log_attempt(
        &mut tx,
        id,
        attempt,
        "accepted",
        Some(250),
        relay_queue_id,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The relay refused temporarily, or was unreachable. Schedule the retry.
pub async fn record_transient(
    pool: &PgPool,
    id: Uuid,
    attempt: i32,
    smtp_code: Option<i32>,
    detail: &str,
    retry_in: std::time::Duration,
) -> anyhow::Result<()> {
    let next = Utc::now() + Duration::from_std(retry_in).unwrap_or_else(|_| Duration::minutes(5));
    let mut tx = pool.begin().await?;
    sqlx::query(
        "update message
            set attempts = $2, next_attempt_at = $3, last_error = $4,
                claimed_at = null, claimed_by = null
          where id = $1",
    )
    .bind(id)
    .bind(attempt)
    .bind(next)
    .bind(detail)
    .execute(&mut *tx)
    .await
    .context("rescheduling message")?;

    log_attempt(
        &mut tx,
        id,
        attempt,
        "transient",
        smtp_code,
        None,
        Some(detail),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// A permanent failure, or the retry schedule ran out. Either way the
/// message is done, and `last_error` says which — a failed message is
/// always visible, never silently dropped.
pub async fn record_failed(
    pool: &PgPool,
    id: Uuid,
    attempt: i32,
    smtp_code: Option<i32>,
    detail: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "update message
            set status = 'failed', attempts = $2, last_error = $3,
                claimed_at = null, claimed_by = null, completed_at = now()
          where id = $1",
    )
    .bind(id)
    .bind(attempt)
    .bind(detail)
    .execute(&mut *tx)
    .await
    .context("marking message failed")?;

    log_attempt(
        &mut tx,
        id,
        attempt,
        "permanent",
        smtp_code,
        None,
        Some(detail),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn log_attempt(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    attempt: i32,
    outcome: &str,
    smtp_code: Option<i32>,
    relay_queue_id: Option<&str>,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "insert into delivery_attempt
             (message_id, attempt, outcome, smtp_code, relay_queue_id, detail)
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(attempt)
    .bind(outcome)
    .bind(smtp_code)
    .bind(relay_queue_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .context("logging delivery attempt")?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Status {
    pub id: Uuid,
    pub status: String,
    pub attempts: i32,
    pub rcpt_to: String,
    pub subject: String,
    pub relay_queue_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Status of one message, scoped to the tenant that sent it — a tenant can
/// never read another's mail by guessing an id.
pub async fn status(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> anyhow::Result<Option<Status>> {
    let row = sqlx::query(
        "select id, status, attempts, rcpt_to, subject, relay_queue_id,
                last_error, created_at, completed_at
           from message where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("loading message status")?;

    Ok(row.map(|r| Status {
        id: r.get("id"),
        status: r.get("status"),
        attempts: r.get("attempts"),
        rcpt_to: r.get("rcpt_to"),
        subject: r.get("subject"),
        relay_queue_id: r.get("relay_queue_id"),
        last_error: r.get("last_error"),
        created_at: r.get("created_at"),
        completed_at: r.get("completed_at"),
    }))
}

/// Blank the bodies and attachments of finished messages older than
/// `days`.
///
/// Message bodies are personal data: invoices carry names, addresses and
/// amounts. The DELIVERY RECORD is kept forever — that is the operational
/// history, and it holds no content. The content itself has no reason to
/// outlive the delivery it existed for.
pub async fn purge_bodies(pool: &PgPool, days: i64) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "delete from message_attachment
          where message_id in (
                select id from message
                 where completed_at is not null
                   and completed_at < now() - make_interval(days => $1)
                   and body_purged_at is null)",
    )
    .bind(days as i32)
    .execute(&mut *tx)
    .await
    .context("purging attachments")?;

    let result = sqlx::query(
        "update message
            set body_text = null, body_html = null, body_purged_at = now()
          where completed_at is not null
            and completed_at < now() - make_interval(days => $1)
            and body_purged_at is null",
    )
    .bind(days as i32)
    .execute(&mut *tx)
    .await
    .context("purging bodies")?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
