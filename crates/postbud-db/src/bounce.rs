//! Bounce ingestion.
//!
//! Postfix pipes a DSN in on stdin; this turns it into suppression
//! decisions. Two rules govern the whole module:
//!
//! * The raw DSN is stored FIRST, always, parsed or not. A bounce we
//!   cannot read is a bug report, and discarding the evidence would mean
//!   never being able to fix the parser.
//! * Only a permanent failure suppresses. A transient one — a full
//!   mailbox, a greylisting deferral — must never take an address out of
//!   circulation, or a customer silently stops receiving invoices.

use anyhow::Context;
use postbud_core::{Classification, dsn};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct Ingested {
    pub reports: usize,
    pub suppressed: usize,
    /// Reports whose queue id matched no message we have. Not an error —
    /// it is what a re-imported old bounce or a purged message looks like —
    /// but worth watching, since a persistently high count means the queue
    /// id is not being captured on the way out.
    pub unmatched: usize,
}

/// Ingest one raw DSN.
pub async fn ingest(pool: &PgPool, raw: &str) -> anyhow::Result<Ingested> {
    let reports = dsn::parse(raw);

    if reports.is_empty() {
        sqlx::query("insert into bounce_report (raw) values ($1)")
            .bind(raw)
            .execute(pool)
            .await
            .context("storing unparsed bounce")?;
        return Ok(Ingested::default());
    }

    let mut out = Ingested::default();

    for report in reports {
        out.reports += 1;

        // Join back to the message we sent via Postfix's queue id.
        let message_id: Option<Uuid> = match &report.relay_queue_id {
            Some(qid) => sqlx::query("select id from message where relay_queue_id = $1")
                .bind(qid)
                .fetch_optional(pool)
                .await
                .context("matching bounce to message")?
                .map(|r| r.get("id")),
            None => None,
        };

        if message_id.is_none() {
            out.unmatched += 1;
        }

        let classification = match report.classification {
            Classification::Permanent => "permanent",
            Classification::Transient => "transient",
            _ => "unknown",
        };

        sqlx::query(
            "insert into bounce_report
                 (raw, relay_queue_id, message_id, final_rcpt, status_code,
                  diagnostic, classification)
             values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(raw)
        .bind(&report.relay_queue_id)
        .bind(message_id)
        .bind(&report.final_recipient)
        .bind(&report.status)
        .bind(&report.diagnostic)
        .bind(classification)
        .execute(pool)
        .await
        .context("storing bounce report")?;

        if report.should_suppress()
            && let Some(address) = &report.final_recipient
        {
            // Global (null tenant): the mailbox is gone for everyone.
            crate::suppression::add(
                pool,
                None,
                address,
                "hard_bounce",
                "dsn",
                report.diagnostic.as_deref(),
            )
            .await?;
            out.suppressed += 1;
        }
    }

    Ok(out)
}
