//! Fetching DMARC aggregate reports from a mailbox.
//!
//! The RULES live in [`postbud_core::dmarc`] — unwrapping, parsing, and
//! every bound on hostile input. This module only fetches messages and
//! hands over the bytes, the same split as [`crate::dnscheck`].
//!
//! **This does not make postbud an MTA**, and does not revisit "postbud
//! never delivers mail itself". It opens one outbound client connection to
//! one configured mailbox. No port is listened on, no MX is resolved,
//! nothing is queued for anybody. Inbound mail in the sense the README
//! means it — receiving for a domain — is still not built.
//!
//! **It never affects sending.** The poller is a task of its own beside
//! the delivery loop. An unreachable mailbox, a server that has forgotten
//! MOVE, or a report that will not parse are logged and retried later; a
//! failure here must never slow or stop a message going out.

use anyhow::{Context, anyhow};
use futures::StreamExt as _;
use mail_parser::{MessageParser, PartType};
use postbud_core::dmarc;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Messages to take in one pass. Reports arrive daily, a few per domain
/// per day, so this is a bound against a mailbox that has gone unread for
/// a year rather than a throughput setting.
const BATCH: usize = 200;

type Session = async_imap::Session<TlsStream<TcpStream>>;

pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// Where reports arrive.
    pub mailbox: String,
    /// Where they go once stored.
    pub archive: String,
    pub interval: Duration,
}

impl Config {
    /// `Ok(None)` when the feature is switched off, which is the normal
    /// state for an installation that does not collect reports.
    ///
    /// A HALF-configured mailbox is an error rather than a silent
    /// no-op — the same call the admin surface makes, where neither
    /// credential set is an honest 503 but half an OIDC setup fails at
    /// startup. A host with no password is somebody's half-finished
    /// deploy, and discovering it from an empty reports page months later
    /// is the worst way to find out.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(host) = std::env::var("DMARC_EMAIL_IMAP") else {
            return Ok(None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return Ok(None);
        }

        let required = |name: &str| -> anyhow::Result<String> {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("DMARC_EMAIL_IMAP is set but {name} is not"))
        };

        Ok(Some(Config {
            user: required("DMARC_EMAIL_USERNAME")?,
            password: required("DMARC_EMAIL_PASSWORD")?,
            port: parsed("DMARC_EMAIL_PORT", 993)?,
            mailbox: optional("DMARC_EMAIL_MAILBOX", "INBOX"),
            archive: optional("DMARC_EMAIL_ARCHIVE", "Archive"),
            interval: Duration::from_secs(parsed("DMARC_EMAIL_INTERVAL", 3600)?),
            host,
        }))
    }
}

fn optional(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn parsed<T: std::str::FromStr>(name: &str, fallback: T) -> anyhow::Result<T> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse()
            .map_err(|_| anyhow!("{name} is not a number: {value}")),
        _ => Ok(fallback),
    }
}

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub examined: usize,
    pub stored: usize,
    pub duplicates: usize,
    pub unreadable: usize,
}

impl Outcome {
    fn quiet(&self) -> bool {
        self.examined == 0
    }
}

/// Poll forever. Never returns an error: a mailbox that is down is a
/// reason to try again in an hour, not a reason to take the worker with
/// it.
pub async fn run(pool: PgPool, config: Config) {
    println!(
        "postbud dmarc poller reading {}:{} {} every {}s",
        config.host,
        config.port,
        config.mailbox,
        config.interval.as_secs()
    );
    loop {
        match poll_once(&pool, &config).await {
            Ok(outcome) if outcome.quiet() => {}
            Ok(outcome) => println!(
                "dmarc: {} examined, {} stored, {} duplicate, {} unreadable",
                outcome.examined, outcome.stored, outcome.duplicates, outcome.unreadable
            ),
            Err(err) => eprintln!("dmarc poll failed: {err:#}"),
        }
        tokio::time::sleep(config.interval).await;
    }
}

/// One pass over the mailbox.
pub async fn poll_once(pool: &PgPool, config: &Config) -> anyhow::Result<Outcome> {
    let mut session = connect(config).await?;
    let result = drain_mailbox(pool, config, &mut session).await;
    // Log out even when the pass failed: a session left open holds a
    // connection slot on a shared mail server for as long as the server
    // decides to wait.
    let _ = session.logout().await;
    result
}

async fn drain_mailbox(
    pool: &PgPool,
    config: &Config,
    session: &mut Session,
) -> anyhow::Result<Outcome> {
    session
        .select(&config.mailbox)
        .await
        .with_context(|| format!("selecting {}", config.mailbox))?;

    // UNSEEN rather than ALL: a report that could not be parsed is marked
    // read and left where it is, so it stays visible to a human without
    // being retried into the log every hour for ever.
    let mut uids: Vec<u32> = session
        .uid_search("UNSEEN")
        .await
        .context("searching for unread reports")?
        .into_iter()
        .collect();
    uids.sort_unstable();
    uids.truncate(BATCH);

    let mut outcome = Outcome::default();
    for uid in uids {
        outcome.examined += 1;
        // One message at a time. A single unreadable report must not take
        // the rest of the batch with it.
        match handle_one(pool, session, uid).await {
            Ok(stored) => {
                if stored {
                    outcome.stored += 1;
                } else {
                    outcome.duplicates += 1;
                }
                if let Err(err) = archive(session, uid, &config.archive).await {
                    // Stored but not moved -- usually an archive folder
                    // that does not exist, or is called something else on
                    // this server. Marking it read instead is what stops
                    // an hourly re-fetch of a report already held: the
                    // dedupe key means nothing would be stored twice, but
                    // "harmless forever" is still forever.
                    eprintln!("dmarc: uid {uid} stored but not archived: {err:#}");
                    if let Err(err) = mark_seen(session, uid).await {
                        eprintln!("dmarc: uid {uid} could not be marked read: {err:#}");
                    }
                }
            }
            Err(err) => {
                outcome.unreadable += 1;
                eprintln!("dmarc: uid {uid} unreadable: {err:#}");
                if let Err(err) = mark_seen(session, uid).await {
                    eprintln!("dmarc: uid {uid} could not be marked read: {err:#}");
                }
            }
        }
    }
    Ok(outcome)
}

/// Fetch one message and store whatever reports it carried. Returns
/// whether anything new was stored.
async fn handle_one(pool: &PgPool, session: &mut Session, uid: u32) -> anyhow::Result<bool> {
    let raw = {
        let mut fetches = session
            .uid_fetch(uid.to_string(), "RFC822")
            .await
            .context("fetching message")?;
        let mut body = None;
        while let Some(fetch) = fetches.next().await {
            let fetch = fetch.context("reading fetch response")?;
            if let Some(bytes) = fetch.body() {
                body = Some(bytes.to_vec());
                break;
            }
        }
        body.ok_or_else(|| anyhow!("message has no body"))?
    };

    let candidates = candidates(&raw);
    if candidates.is_empty() {
        return Err(anyhow!("no report attachment in the message"));
    }

    let mut stored = false;
    let mut failures = Vec::new();
    for candidate in candidates {
        let documents = match dmarc::extract(&candidate) {
            Ok(documents) => documents,
            Err(err) => {
                failures.push(err.to_string());
                continue;
            }
        };
        for document in documents {
            match dmarc::parse(&document) {
                Ok(report) => {
                    let text = String::from_utf8_lossy(&document);
                    if postbud_db::dmarc::store(pool, &report, &text).await? {
                        stored = true;
                    }
                }
                Err(err) => failures.push(err.to_string()),
            }
        }
    }

    // Nothing usable AND something went wrong: report the first reason
    // rather than a bare "no reports", which says nothing an operator can
    // act on. A message whose every part simply was not a report reaches
    // here with no failures and is treated the same way.
    if !stored && !failures.is_empty() {
        return Err(anyhow!("{}", failures.remove(0)));
    }
    Ok(stored)
}

/// Every part of the message that might be a report.
///
/// Parts are taken by SHAPE, not by declared content type: reporters label
/// the same gzip as application/gzip, application/x-gzip,
/// application/octet-stream and occasionally text/plain, and
/// [`dmarc::extract`] sniffs the bytes anyway. A text part is only offered
/// when it looks like XML, so a covering note is not mistaken for a
/// report.
fn candidates(raw: &[u8]) -> Vec<Vec<u8>> {
    let Some(message) = MessageParser::default().parse(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for part in message.parts.iter() {
        match &part.body {
            PartType::Binary(data) | PartType::InlineBinary(data) => out.push(data.to_vec()),
            PartType::Text(text) => {
                let head = text.trim_start();
                if head.starts_with("<?xml") || head.starts_with("<feedback") {
                    out.push(text.as_bytes().to_vec());
                }
            }
            _ => {}
        }
    }
    out
}

/// Move a processed message out of the way.
///
/// MOVE (RFC 6851) is one round trip and atomic; not every server has it,
/// so the fallback spells it out. COPY comes first in that fallback and
/// the order is not cosmetic: the message must exist in the archive before
/// it is marked deleted here, never the other way round.
async fn archive(session: &mut Session, uid: u32, mailbox: &str) -> anyhow::Result<()> {
    let set = uid.to_string();
    if session.uid_mv(&set, mailbox).await.is_ok() {
        return Ok(());
    }
    session
        .uid_copy(&set, mailbox)
        .await
        .with_context(|| format!("copying uid {uid} to {mailbox}"))?;
    {
        let mut updates = session
            .uid_store(&set, "+FLAGS (\\Deleted)")
            .await
            .context("flagging as deleted")?;
        while updates.next().await.is_some() {}
    }
    // expunge's stream is the one here that is not Unpin, so it is
    // pinned rather than held by value.
    let expunged = session.expunge().await.context("expunging")?;
    futures::pin_mut!(expunged);
    while expunged.next().await.is_some() {}
    Ok(())
}

async fn mark_seen(session: &mut Session, uid: u32) -> anyhow::Result<()> {
    let mut updates = session
        .uid_store(uid.to_string(), "+FLAGS (\\Seen)")
        .await
        .context("flagging as read")?;
    while updates.next().await.is_some() {}
    Ok(())
}

/// Connect and log in over TLS.
///
/// rustls with webpki-roots, like every other outbound client here, which
/// is what lets the runtime image stay `FROM scratch` with no CA bundle.
/// The provider is named explicitly rather than left to the process
/// default: that default depends on which crate in the tree installed one
/// first, and a mail poller is a poor place to discover the answer changed.
async fn connect(config: &Config) -> anyhow::Result<Session> {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let tls = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("building TLS configuration")?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(config.host.clone())
        .with_context(|| format!("{} is not a valid server name", config.host))?;

    let tcp = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .with_context(|| format!("connecting to {}:{}", config.host, config.port))?;

    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .context("TLS handshake")?;

    async_imap::Client::new(stream)
        .login(&config.user, &config.password)
        .await
        // The error carries the client back so a caller can retry; we
        // cannot, and it must not be printed — it is holding the password.
        .map_err(|(err, _)| err)
        .context("logging in")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const REPORT: &str = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>reporter.example</org_name><report_id>mime-1</report_id>
    <date_range><begin>1787011200</begin><end>1787097599</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>198.51.100.7</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

    /// The shape every reporter actually sends: a human-readable note
    /// with the report hung off it as an attachment.
    #[test]
    fn a_report_attached_to_a_covering_note_is_found() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(REPORT);
        let raw = format!(
            "From: noreply@reporter.example\r\n\
             To: dmarc@example.com\r\n\
             Subject: Report Domain: example.com\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"XX\"\r\n\
             \r\n\
             --XX\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             This is a DMARC aggregate report for example.com.\r\n\
             \r\n\
             --XX\r\n\
             Content-Type: application/xml; name=\"report.xml\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-Disposition: attachment; filename=\"report.xml\"\r\n\
             \r\n\
             {encoded}\r\n\
             --XX--\r\n"
        );

        let found = candidates(raw.as_bytes());
        // The covering note is prose, not a report, and offering it would
        // turn every report mail into a parse failure in the log.
        assert_eq!(found.len(), 1, "only the attachment should be offered");

        let documents = dmarc::extract(&found[0]).expect("unwraps");
        let report = dmarc::parse(&documents[0]).expect("parses");
        assert_eq!(report.domain, "example.com");
        assert_eq!(report.records[0].count, 3);
    }

    /// Some reporters skip the attachment and send the document itself.
    #[test]
    fn a_report_sent_as_the_body_is_found() {
        let raw = format!(
            "From: noreply@reporter.example\r\n\
             Subject: report\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/xml; charset=utf-8\r\n\
             \r\n\
             {REPORT}\r\n"
        );
        let found = candidates(raw.as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(dmarc::parse(&found[0]).unwrap().domain, "example.com");
    }

    /// A message carrying nothing report-shaped offers nothing, rather
    /// than offering prose for the parser to choke on.
    #[test]
    fn a_message_with_no_report_offers_nothing() {
        let raw = "From: someone@example.net\r\n\
                   Subject: hello\r\n\
                   Content-Type: text/plain\r\n\
                   \r\n\
                   Just writing to say hello.\r\n";
        assert!(candidates(raw.as_bytes()).is_empty());
    }

    /// Binary parts are handed over untouched: the bytes are sniffed by
    /// postbud_core::dmarc, and guessing here would only get in the way.
    #[test]
    fn a_binary_attachment_arrives_verbatim() {
        let blob: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let raw = format!(
            "MIME-Version: 1.0\r\n\
             Content-Type: application/octet-stream; name=\"r.gz\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-Disposition: attachment; filename=\"r.xml.gz\"\r\n\
             \r\n\
             {encoded}\r\n"
        );
        assert_eq!(candidates(raw.as_bytes()), vec![blob]);
    }
}
