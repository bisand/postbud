//! Reporting the relay's queue to postbud, in Rust and with no Postfix
//! binaries beside it.
//!
//! Reads `showq` directly (see `postbud_core::showq`) and posts the same
//! JSON shape `postqueue -j` produces, so the ingest endpoint has one
//! wire format regardless of which side produced it.
//!
//! THE FAILURE MODE THAT MATTERS: an empty report is what tells postbud
//! every outstanding message left the queue, i.e. was delivered. So a
//! read that FAILED must never be posted as though the queue were empty.
//! Every error path here skips the post entirely and leaves the previous
//! state standing -- stale is recoverable, a false "delivered" is not.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

pub struct Config {
    pub socket: String,
    pub postbud_url: String,
    pub token: String,
    pub interval: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            socket: std::env::var("SHOWQ_SOCKET")
                .unwrap_or_else(|_| "/var/spool/postfix/public/showq".into()),
            postbud_url: std::env::var("POSTBUD_URL")
                .context("POSTBUD_URL is required for queue-report")?,
            token: std::env::var("BOUNCE_INGEST_TOKEN")
                .context("BOUNCE_INGEST_TOKEN is required for queue-report")?,
            interval: Duration::from_secs(
                std::env::var("QUEUE_REPORT_INTERVAL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5),
            ),
        })
    }
}

/// Read one complete showq response.
///
/// Completeness is the whole point: showq hangs up when it has finished,
/// so reaching EOF is the proof that what we hold is the entire queue and
/// not a truncated prefix. A timeout or a read error returns Err, and the
/// caller posts nothing.
async fn read_showq(path: &str) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting {path}"))?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .context("showq read timed out")?
        .context("reading showq")?;
    Ok(buf)
}

/// Re-emit as `postqueue -j` would, one JSON object per line.
fn as_ndjson(entries: &[postbud_core::relayqueue::Queued]) -> String {
    let mut out = String::new();
    for e in entries {
        let recipients = match &e.reason {
            Some(reason) => serde_json::json!([{ "delay_reason": reason }]),
            None => serde_json::json!([{}]),
        };
        let line = serde_json::json!({
            "queue_name": e.queue_name,
            "queue_id": e.queue_id,
            "recipients": recipients,
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

pub async fn run(config: Config) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building http client")?;
    let url = format!(
        "{}/v1/relay/queue",
        config.postbud_url.trim_end_matches('/')
    );

    loop {
        match read_showq(&config.socket).await {
            Ok(bytes) => {
                let entries = postbud_core::showq::parse(&bytes);
                let body = as_ndjson(&entries);
                if let Err(e) = client
                    .post(&url)
                    .bearer_auth(&config.token)
                    .header("content-type", "application/x-ndjson")
                    .body(body)
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                {
                    eprintln!("postbud: queue report post failed: {e}");
                }
            }
            // Deliberately silent about the queue: reporting nothing is
            // safe, reporting "empty" would not be.
            Err(e) => eprintln!("postbud: showq unreadable, not reporting: {e:#}"),
        }
        tokio::time::sleep(config.interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postbud_core::relayqueue::Queued;

    #[test]
    fn ndjson_round_trips_through_the_ingest_parser() {
        let entries = vec![
            Queued {
                queue_id: "AAAA1111".into(),
                queue_name: "deferred".into(),
                reason: Some("451 4.7.7 rate limited".into()),
            },
            Queued {
                queue_id: "BBBB2222".into(),
                queue_name: "active".into(),
                reason: None,
            },
        ];
        let back = postbud_core::relayqueue::parse(&as_ndjson(&entries));
        assert_eq!(back, entries);
    }
}
