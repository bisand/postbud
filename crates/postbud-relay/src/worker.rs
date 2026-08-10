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
use sqlx::postgres::PgListener;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::{Outcome, Relay};

/// Deliveries in flight at once, per worker process.
///
/// Eight, not one: a batch used to be relayed strictly one message at a
/// time, so a batch of twenty was twenty sequential SMTP conversations and
/// the batching bought nothing. Eight is comfortable against a Postfix
/// whose own per-client connection limit defaults to 50 — raise it if the
/// relay's limits and the pool below are raised with it, and remember that
/// the true ceiling is the relay, not this number.
const DEFAULT_CONCURRENCY: usize = 8;

/// Read the in-flight limit. Shared with [`crate::Relay`], which sizes its
/// SMTP connection pool from the same number — a pool smaller than the
/// concurrency would just move the queueing one layer down.
pub fn concurrency_from_env() -> anyhow::Result<usize> {
    let concurrency: usize = std::env::var("WORKER_CONCURRENCY")
        .unwrap_or_else(|_| DEFAULT_CONCURRENCY.to_string())
        .parse()
        .context("WORKER_CONCURRENCY must be a number")?;
    if concurrency == 0 {
        anyhow::bail!("WORKER_CONCURRENCY must be at least 1");
    }
    Ok(concurrency)
}

pub struct Config {
    pub worker_name: String,
    pub batch: i64,
    pub concurrency: usize,
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
            concurrency: concurrency_from_env()?,
            idle: Duration::from_millis(idle_ms),
        })
    }
}

/// Run until cancelled.
///
/// Several instances may run at once: claiming uses `for update skip
/// locked`, so they take disjoint batches with no coordination between
/// them. That is work-stealing rather than round-robin, and deliberately
/// so — a partition assigned up front leaves a worker stuck behind one
/// slow receiver while its neighbours sit idle.
pub async fn run(pool: PgPool, relay: Relay, config: Config) -> anyhow::Result<()> {
    // Domain verification rides in the worker process: it is the
    // long-lived non-API process, and a DNS check is the same kind of
    // background duty as delivery. With several workers the checks
    // duplicate harmlessly (insert-only history, identical answers).
    tokio::spawn(crate::dnscheck::run(pool.clone()));

    let relay = Arc::new(relay);
    let wake = spawn_wake_listener(&pool);

    loop {
        let claimed = message::claim(&pool, &config.worker_name, config.batch).await?;
        if claimed.is_empty() {
            wait_for_work(&wake, config.idle).await;
            continue;
        }

        // The batch is relayed concurrently, bounded. The whole batch is
        // drained before the next claim: one slow message can hold up its
        // own batch's tail, which is a fair trade for a loop that cannot
        // claim more than it is about to deliver — and the claim timeout
        // is measured in minutes, far above any healthy handoff.
        let mut deliveries: JoinSet<()> = JoinSet::new();
        for msg in claimed {
            while deliveries.len() >= config.concurrency {
                join_one(&mut deliveries).await;
            }
            let pool = pool.clone();
            let relay = Arc::clone(&relay);
            deliveries.spawn(async move {
                if let Err(err) = deliver_one(&pool, &relay, &msg).await {
                    // Recording failed, not delivery. Leave the claim to
                    // time out and be retried rather than pretending
                    // anything.
                    eprintln!("postbud: recording outcome for {} failed: {err:#}", msg.id);
                }
            });
        }
        while !deliveries.is_empty() {
            join_one(&mut deliveries).await;
        }
    }
}

/// Reap one finished delivery. A panic in one message must never take the
/// worker down: its claim times out and another attempt picks it up, which
/// is exactly the behaviour the claim timeout exists for.
async fn join_one(deliveries: &mut JoinSet<()>) {
    if let Some(Err(err)) = deliveries.join_next().await {
        eprintln!("postbud: a delivery task did not finish cleanly: {err}");
    }
}

/// How long to wait before rebuilding a listener that gave up.
const LISTENER_RETRY: Duration = Duration::from_secs(30);

/// Listen for accept notifications in a task of its own, and turn them
/// into a flag the delivery loop can wait on.
///
/// The task exists to keep `PgListener::recv` out of the delivery loop.
/// sqlx does not document it as cancel-safe, and the loop would have to
/// abandon it on every idle timeout — a dropped notification would cost
/// only latency, but a hot loop is no place for that question. `Notify`
/// answers it: waiting on it IS cancel-safe, and a wake-up arriving while
/// the worker is busy is remembered rather than lost.
///
/// Failure is not fatal. Without a listener the flag simply never fires
/// and the worker polls, exactly as it did before any of this existed.
fn spawn_wake_listener(pool: &PgPool) -> Arc<Notify> {
    let wake = Arc::new(Notify::new());
    let signal = Arc::clone(&wake);
    let pool = pool.clone();

    tokio::spawn(async move {
        loop {
            match subscribe(&pool).await {
                Some(mut listener) => {
                    // recv() reconnects transparently; returning at all
                    // means the subscription is beyond saving.
                    while listener.recv().await.is_ok() {
                        signal.notify_one();
                    }
                    eprintln!("postbud: queue notifications dropped out; will resubscribe");
                }
                None => {
                    eprintln!("postbud: queue notifications unavailable; polling meanwhile");
                }
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    });

    wake
}

async fn subscribe(pool: &PgPool) -> Option<PgListener> {
    let mut listener = PgListener::connect_with(pool)
        .await
        .inspect_err(|err| eprintln!("postbud: listener connection failed: {err}"))
        .ok()?;
    listener
        .listen(message::QUEUE_CHANNEL)
        .await
        .inspect_err(|err| {
            eprintln!(
                "postbud: could not listen on {}: {err}",
                message::QUEUE_CHANNEL
            )
        })
        .ok()?;
    Some(listener)
}

/// Wait for something to do: a notification, or `idle` elapsing.
///
/// The timeout is not a fallback for lost notifications alone — a retry
/// becomes due at a time in the future that nothing can NOTIFY about when
/// it arrives, so the poll is load-bearing and stays.
async fn wait_for_work(wake: &Notify, idle: Duration) {
    let _ = tokio::time::timeout(idle, wake.notified()).await;
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
