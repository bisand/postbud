//! Reconciling the relay's queue against what we think happened.
//!
//! Two facts come out of one snapshot. A queue id PRESENT in the report is
//! still with the relay, and the receiver's own words say why. A queue id
//! ABSENT from it has left -- which means delivered, unless a bounce says
//! otherwise, because those are the only two ways out of a Postfix queue
//! that we can observe.
//!
//! The absence half is the one to be careful with, since it is an
//! inference rather than an observation:
//!
//! * A message handed over AFTER the snapshot was taken cannot be in it,
//!   and must not be read as delivered. `taken_at` guards that, with a
//!   grace for the seconds between `postqueue` running and the POST
//!   arriving.
//! * A message that bounced also left the queue. `bounce_report` is
//!   checked so a hard failure is never relabelled as a success.

use anyhow::Context;
use postbud_core::relayqueue::Queued;
use sqlx::PgPool;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Messages the relay still holds.
    pub queued: usize,
    /// Messages newly concluded to have left the queue cleanly.
    pub delivered: usize,
    /// Queue ids in the report matching no message we hold. Expected for
    /// mail this postbud did not send (the relay may carry other traffic);
    /// a persistently high count means queue ids are not being captured.
    pub unmatched: usize,
}

/// Apply one `postqueue -j` snapshot.
///
/// `grace_secs` covers the gap between the snapshot being taken on the
/// relay and this call: anything handed over inside that window is left
/// alone rather than guessed at.
pub async fn reconcile(
    pool: &PgPool,
    entries: &[Queued],
    grace_secs: i64,
) -> anyhow::Result<Reconciled> {
    let mut tx = pool.begin().await.context("beginning reconcile")?;
    let mut out = Reconciled::default();

    let ids: Vec<String> = entries.iter().map(|e| e.queue_id.clone()).collect();

    // Present: record what the relay is saying, only where it changed, so
    // a stuck message does not get a fresh timestamp every few seconds.
    for entry in entries {
        let state = match entry.queue_name.as_str() {
            "active" | "incoming" | "maildrop" => "active",
            _ => "deferred",
        };
        let updated = sqlx::query(
            "update message
                set relay_state = $2,
                    relay_state_detail = $3,
                    relay_state_at = now()
              where relay_queue_id = $1
                and (relay_state is distinct from $2
                     or relay_state_detail is distinct from $3)",
        )
        .bind(&entry.queue_id)
        .bind(state)
        .bind(&entry.reason)
        .execute(&mut *tx)
        .await
        .context("recording queued message")?;
        if updated.rows_affected() == 0 {
            // Either unchanged, or no such message. Distinguish, because
            // the second is a correlation failure worth surfacing.
            let known: i64 =
                sqlx::query_scalar("select count(*) from message where relay_queue_id = $1")
                    .bind(&entry.queue_id)
                    .fetch_one(&mut *tx)
                    .await
                    .context("checking queue id")?;
            if known == 0 {
                out.unmatched += 1;
            }
        }
        out.queued += 1;
    }

    // Absent: handed over, not in the queue, never bounced -- delivered.
    let delivered = sqlx::query(
        "update message m
            set relay_state = 'delivered',
                relay_state_detail = null,
                relay_state_at = now()
          where m.relay_queue_id is not null
            and m.status = 'sent'
            and m.relay_state is distinct from 'delivered'
            and m.completed_at < now() - make_interval(secs => $2::double precision)
            and not (m.relay_queue_id = any($1))
            and not exists (
                select 1 from bounce_report b
                 where b.relay_queue_id = m.relay_queue_id)",
    )
    .bind(&ids)
    .bind(grace_secs as f64)
    .execute(&mut *tx)
    .await
    .context("concluding delivery")?;
    out.delivered = delivered.rows_affected() as usize;

    tx.commit().await.context("committing reconcile")?;
    Ok(out)
}
