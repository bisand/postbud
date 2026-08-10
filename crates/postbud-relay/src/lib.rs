//! The handoff to Postfix.
//!
//! postbud is not an MTA and must never become one. It does not resolve MX
//! records, hold per-destination queues, negotiate TLS with strangers or
//! generate DSNs. It builds a MIME message, hands it to one smarthost, and
//! writes down what the smarthost said.
//!
//! The DKIM private key is deliberately absent from this crate and from
//! this repository: signing happens in OpenDKIM on the relay host, so the
//! key exists in exactly one place.

pub mod dnscheck;
pub mod worker;

use anyhow::{Context, anyhow};
use lettre::message::{Attachment, MultiPart, SinglePart, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use postbud_db::message::Claimed;

/// What the relay said about one handoff.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Taken. `queue_id` is Postfix's own id for the message, and is the
    /// only handle a bounce arriving days later will carry.
    Accepted { queue_id: Option<String> },
    /// 4xx, unreachable, or a timeout — try again on the schedule.
    Transient { code: Option<i32>, detail: String },
    /// 5xx — stop, and record why.
    Permanent { code: Option<i32>, detail: String },
}

pub struct Relay {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl Relay {
    /// Build from the environment: `RELAY_HOST`, `RELAY_PORT`, `RELAY_TLS`
    /// (`starttls` | `tls` | `none`) and optional `RELAY_USERNAME` /
    /// `RELAY_PASSWORD`.
    ///
    /// `none` is not a lapse: in production the relay is reached over the
    /// tailnet, which is already authenticated and encrypted, and it is the
    /// tailnet address — never the public one — that belongs in
    /// `RELAY_HOST`. A hostname that resolves differently inside and
    /// outside the cluster is how mail quietly starts leaving by the wrong
    /// door.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("RELAY_HOST").context("RELAY_HOST is required")?;
        let port: u16 = std::env::var("RELAY_PORT")
            .unwrap_or_else(|_| "25".into())
            .parse()
            .context("RELAY_PORT must be a port number")?;
        let mode = std::env::var("RELAY_TLS").unwrap_or_else(|_| "starttls".into());

        let mut builder = match mode.as_str() {
            "starttls" => {
                let params = TlsParameters::new(host.clone())?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                    .tls(Tls::Required(params))
            }
            "tls" => {
                let params = TlsParameters::new(host.clone())?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                    .tls(Tls::Wrapper(params))
            }
            "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host),
            other => {
                return Err(anyhow!(
                    "RELAY_TLS must be starttls, tls or none (got {other:?})"
                ));
            }
        }
        .port(port);

        if let (Ok(user), Ok(password)) = (
            std::env::var("RELAY_USERNAME"),
            std::env::var("RELAY_PASSWORD"),
        ) {
            builder = builder.credentials(Credentials::new(user, password));
        }

        Ok(Relay {
            transport: builder.build(),
        })
    }

    /// Hand one message over.
    ///
    /// A message we cannot even build is `Permanent` — retrying malformed
    /// input forever would hide the bug instead of surfacing it.
    pub async fn send(&self, claimed: &Claimed) -> Outcome {
        let message = match build(claimed) {
            Ok(message) => message,
            Err(err) => {
                return Outcome::Permanent {
                    code: None,
                    detail: format!("could not build message: {err:#}"),
                };
            }
        };

        match self.transport.send(message).await {
            Ok(response) => Outcome::Accepted {
                queue_id: queue_id_from(&response.message().collect::<Vec<_>>().join(" ")),
            },
            Err(err) => {
                let code = err.status().map(|c| {
                    let s = c.to_string();
                    s.split_whitespace()
                        .next()
                        .and_then(|d| d.parse::<i32>().ok())
                        .unwrap_or(0)
                });
                let detail = format!("{err}");
                if err.is_permanent() {
                    Outcome::Permanent { code, detail }
                } else {
                    // Everything not certainly permanent is retried. The
                    // asymmetry is deliberate: a needless retry costs a
                    // connection, a wrong "permanent" costs an invoice.
                    Outcome::Transient { code, detail }
                }
            }
        }
    }
}

/// Pull the queue id out of Postfix's acceptance line, which reads
/// `2.0.0 Ok: queued as 4bXlNq2Qh8z1Yk`.
///
/// Absence is tolerated — a relay that phrases it differently still
/// delivered the mail — but it costs bounce correlation for that message,
/// which is why the format is pinned by a test.
fn queue_id_from(response: &str) -> Option<String> {
    let (_, rest) = response.split_once("queued as ")?;
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    (!id.is_empty()).then_some(id)
}

fn build(claimed: &Claimed) -> anyhow::Result<Message> {
    let from = match &claimed.from_name {
        Some(name) => format!("{name} <{}>", claimed.mail_from),
        None => claimed.mail_from.clone(),
    };

    // The Message-ID's right-hand side is the SENDER's domain, not any
    // hostname of this installation: it is already validated against the
    // tenant's allowed domains, it aligns with everything else the
    // receiver sees, and it keeps installation names out of the code.
    let message_id_domain = claimed
        .mail_from
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or("postbud.invalid");

    let mut builder = Message::builder()
        .from(from.parse().context("parsing From address")?)
        .to(claimed.rcpt_to.parse().context("parsing To address")?)
        // Set explicitly, for two reasons. A message with no Message-ID is
        // a spam signal at every large receiver, and Postfix does not add
        // one unless told to. Deriving it from our own id also makes it a
        // third correlation handle: given a Message-ID from a recipient's
        // headers, the message row is a single lookup.
        // The angle brackets are REQUIRED by RFC 5322, and lettre takes this
        // value verbatim rather than adding them. Without them Gmail treats
        // the header as malformed, discards it and stamps its own
        // `SMTPIN_ADDED_BROKEN` id -- which is both a spam signal and a
        // silent loss of the correlation handle. Found in production.
        .message_id(Some(format!("<{}@{message_id_domain}>", claimed.id)))
        .subject(&claimed.subject);

    if let Some(reply_to) = &claimed.reply_to {
        builder = builder.reply_to(reply_to.parse().context("parsing Reply-To address")?);
    }

    let body = match (&claimed.body_text, &claimed.body_html) {
        (Some(text), Some(html)) => MultiPart::alternative_plain_html(text.clone(), html.clone()),
        (None, Some(html)) => MultiPart::mixed().singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html.clone()),
        ),
        (Some(text), None) => MultiPart::mixed().singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text.clone()),
        ),
        (None, None) => return Err(anyhow!("message has neither a text nor an html body")),
    };

    let body = if claimed.attachments.is_empty() {
        body
    } else {
        let mut mixed = MultiPart::mixed().multipart(body);
        for attachment in &claimed.attachments {
            let content_type = header::ContentType::parse(&attachment.content_type)
                .unwrap_or(header::ContentType::TEXT_PLAIN);
            mixed = mixed.singlepart(
                Attachment::new(attachment.filename.clone())
                    .body(attachment.content.clone(), content_type),
            );
        }
        mixed
    };

    builder.multipart(body).context("assembling MIME message")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The join key for every future bounce. If Postfix ever changes this
    /// wording, this test is where it shows up — rather than in a silent
    /// loss of bounce correlation months later.
    #[test]
    fn queue_id_is_read_from_the_postfix_acceptance_line() {
        assert_eq!(
            queue_id_from("2.0.0 Ok: queued as 4bXlNq2Qh8z1Yk").as_deref(),
            Some("4bXlNq2Qh8z1Yk")
        );
    }

    fn claimed(id: uuid::Uuid) -> Claimed {
        Claimed {
            id,
            attempts: 0,
            mail_from: "invoice@sender.example".into(),
            from_name: Some("Sender".into()),
            rcpt_to: "customer@example.net".into(),
            reply_to: None,
            subject: "Invoice 1001".into(),
            body_text: Some("Attached.".into()),
            body_html: None,
            attachments: Vec::new(),
        }
    }

    /// RFC 5322 requires the angle brackets, and lettre does not add them.
    /// Emitting a bare id made Gmail discard the header and substitute
    /// `SMTPIN_ADDED_BROKEN` -- a spam signal, and the loss of the handle
    /// that ties a delivered message back to its row.
    ///
    /// The right-hand side is the sender's own domain -- no installation
    /// hostname is baked into the binary.
    #[test]
    fn message_id_is_bracketed_and_uses_the_senders_domain() {
        let id = uuid::Uuid::new_v4();
        let message = build(&claimed(id)).expect("building the message");
        let raw = String::from_utf8_lossy(&message.formatted()).to_string();
        assert!(
            raw.contains(&format!("Message-ID: <{id}@sender.example>")),
            "Message-ID must be bracketed and carry the sender domain; got:\n{}",
            raw.lines()
                .find(|l| l.starts_with("Message-ID"))
                .unwrap_or("(absent)")
        );
    }

    #[test]
    fn a_response_without_a_queue_id_is_not_invented() {
        assert_eq!(queue_id_from("2.0.0 Ok"), None);
        assert_eq!(queue_id_from(""), None);
    }
}
