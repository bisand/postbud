//! The worker loop: claim, relay, record.
//!
//! Every path through `deliver_one` ends in a write. There is no branch
//! where a message is handed to the relay and nothing is recorded — that
//! is the shape of bug that makes a mail system untrustworthy, because the
//! message is neither sent nor retryable and nobody can tell which.

use anyhow::Context;
use postbud_core::retry;
use postbud_db::message::{self, Claimed};
use sqlx::PgPool;
use std::time::Duration;

use crate::{Outcome, Relay};

pub struct Config {
    pub worker_name: String,
    pub batch: i64,
    pub idle: Duration,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let worker_name = std::env::var("WORKER_NAME").unwrap_or_else(|_| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "postbud-worker".into())
        });
        let batch = std::env::var("WORKER_BATCH")
            .unwrap_or_else(|_| "20".into())
            .parse()
            .context("WORKER_BATCH must be a number")?;
        let idle_ms: u64 = std::env::var("WORKER_IDLE_MS")
            .unwrap_or_else(|_| "2000".into())
            .parse()
            .context("WORKER_IDLE_MS must be a number")?;
        Ok(Config {
            worker_name,
            batch,
            idle: Duration::from_millis(idle_ms),
        })
    }
}

/// Run until cancelled. Several instances may run at once: claiming uses
/// `for update skip locked`, so they take disjoint batches.
pub async fn run(pool: PgPool, relay: Relay, config: Config) -> anyhow::Result<()> {
    loop {
        let claimed = message::claim(&pool, &config.worker_name, config.batch).await?;
        if claimed.is_empty() {
            tokio::time::sleep(config.idle).await;
            continue;
        }
        for msg in claimed {
            if let Err(err) = deliver_one(&pool, &relay, &msg).await {
                // Recording failed, not delivery. Leave the claim to time
                // out and be retried rather than pretending anything.
                eprintln!("postbud: recording outcome for {} failed: {err:#}", msg.id);
            }
        }
    }
}

/// One message, start to finish.
pub async fn deliver_one(pool: &PgPool, relay: &Relay, msg: &Claimed) -> anyhow::Result<()> {
    let attempt = msg.attempts + 1;

    match relay.send(msg).await {
        Outcome::Accepted { queue_id } => {
            if queue_id.is_none() {
                eprintln!(
                    "postbud: {} accepted without a queue id — bounces for it \
                     cannot be correlated",
                    msg.id
                );
            }
            message::record_accepted(pool, msg.id, attempt, queue_id.as_deref()).await
        }
        Outcome::Permanent { code, detail } => {
            message::record_failed(pool, msg.id, attempt, code, &detail).await
        }
        Outcome::Transient { code, detail } => match retry::backoff(attempt as u32) {
            Some(delay) => {
                message::record_transient(pool, msg.id, attempt, code, &detail, delay).await
            }
            // The schedule ran out — roughly two days of trying. The
            // message becomes a visible failure, never a silent drop.
            None => {
                let detail = format!("giving up after {attempt} attempts: {detail}");
                message::record_failed(pool, msg.id, attempt, code, &detail).await
            }
        },
    }
}
