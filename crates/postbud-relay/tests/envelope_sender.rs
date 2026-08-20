//! The envelope sender, checked on the wire.
//!
//! This is the one thing that cannot be verified by reading the message:
//! the `From:` header and the SMTP `MAIL FROM` are different values with
//! different jobs, and the bug this pins was that they were the same. A
//! DSN comes back to `MAIL FROM`, so when it followed `From:` -- an
//! address aliased to a person, because that is what replies need -- every
//! bounce went to a human inbox and the suppression list was never fed.
//! Nothing failed visibly, which is why only the wire can prove it.

use postbud_db::message::Claimed;
use postbud_relay::{Outcome, Relay};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Just enough SMTP to accept one message, recording every line the
/// client sent.
async fn fake_relay(listener: TcpListener, seen: Arc<Mutex<Vec<String>>>) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let (read_half, mut write) = socket.split();
    let mut reader = BufReader::new(read_half);

    write.write_all(b"220 test ESMTP\r\n").await.expect("greet");

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.expect("read") == 0 {
            break;
        }
        seen.lock().unwrap().push(line.trim_end().to_string());
        let upper = line.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            write
                .write_all(b"250-test\r\n250 SIZE 10485760\r\n")
                .await
                .expect("ehlo");
        } else if upper.starts_with("DATA") {
            write.write_all(b"354 End data\r\n").await.expect("354");
            loop {
                line.clear();
                if reader.read_line(&mut line).await.expect("read data") == 0 {
                    break;
                }
                seen.lock().unwrap().push(line.trim_end().to_string());
                if line == ".\r\n" {
                    break;
                }
            }
            write
                .write_all(b"250 2.0.0 Ok: queued as TESTQUEUE1\r\n")
                .await
                .expect("accept");
        } else if upper.starts_with("QUIT") {
            write.write_all(b"221 Bye\r\n").await.expect("bye");
            break;
        } else {
            write.write_all(b"250 2.1.0 Ok\r\n").await.expect("ok");
        }
    }
}

fn claimed() -> Claimed {
    Claimed {
        id: uuid::Uuid::nil(),
        attempts: 0,
        mail_from: "no-reply@mail.example.com".into(),
        from_name: Some("Example".into()),
        rcpt_to: "customer@recipient.example".into(),
        reply_to: None,
        subject: "Invoice".into(),
        body_text: Some("hello".into()),
        body_html: None,
        attachments: Vec::new(),
    }
}

/// Run one handoff against a fresh fake relay and return every line the
/// client sent. `mailbox` is what BOUNCE_MAILBOX is set to, or None to
/// leave it unset.
async fn handoff(mailbox: Option<&str>) -> Vec<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(fake_relay(listener, seen.clone()));

    // SAFETY: one test, run to completion in order, so nothing else in
    // this binary is reading the environment while it changes.
    unsafe {
        std::env::set_var("RELAY_HOST", "127.0.0.1");
        std::env::set_var("RELAY_PORT", port.to_string());
        std::env::set_var("RELAY_TLS", "none");
        match mailbox {
            Some(name) => std::env::set_var("BOUNCE_MAILBOX", name),
            None => std::env::remove_var("BOUNCE_MAILBOX"),
        }
    }

    let relay = Relay::from_env().expect("relay");
    match relay.send(&claimed()).await {
        Outcome::Accepted { queue_id } => {
            // The queue id must survive whatever the envelope is doing.
            assert_eq!(queue_id.as_deref(), Some("TESTQUEUE1"));
        }
        other => panic!("expected acceptance, got {other:?}"),
    }

    // No waiting on the server: the transport pools connections, so it
    // never sends QUIT and the task would sit until the test timed out.
    // Every client line is already recorded -- `send` only returned
    // because the server had read the final `.` and answered it.
    server.abort();
    seen.lock().unwrap().clone()
}

fn mail_from(lines: &[String]) -> &str {
    lines
        .iter()
        .find(|l| l.to_ascii_uppercase().starts_with("MAIL FROM"))
        .unwrap_or_else(|| panic!("no MAIL FROM in {lines:#?}"))
}

#[tokio::test]
async fn the_envelope_sender_is_the_bounce_mailbox_not_the_from_header() {
    // Unset: the documented default.
    let lines = handoff(None).await;
    assert!(
        mail_from(&lines).contains("<bounces@mail.example.com>"),
        "envelope sender must default to the bounce mailbox, got {}",
        mail_from(&lines)
    );

    // The header is untouched: replies still reach a person, which is the
    // whole reason the two must differ.
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("From:") && l.contains("no-reply@mail.example.com")),
        "From: header must keep the sending address, got {lines:#?}"
    );
    // ...and the recipient is unchanged by any of it.
    assert!(
        lines.iter().any(|l| {
            l.to_ascii_uppercase().starts_with("RCPT TO")
                && l.contains("<customer@recipient.example>")
        }),
        "recipient must be unchanged, got {lines:#?}"
    );

    // Configured: the variable must actually reach the wire. It did not
    // reach the DOMAIN CHECKER once, which kept its own copy of the name
    // and so went on probing bounces@ while mail left as something else --
    // reporting a healthy bounce path for notifications being discarded.
    // Both now read one accessor; this pins the half a test can see.
    let lines = handoff(Some("return-path")).await;
    assert!(
        mail_from(&lines).contains("<return-path@mail.example.com>"),
        "BOUNCE_MAILBOX must decide the envelope sender, got {}",
        mail_from(&lines)
    );

    // Empty: the escape hatch, where the envelope goes back to following
    // `From:` for a relay that cannot accept a bounces@ address.
    let lines = handoff(Some("")).await;
    assert!(
        mail_from(&lines).contains("<no-reply@mail.example.com>"),
        "an empty BOUNCE_MAILBOX must leave the envelope on the From address, got {}",
        mail_from(&lines)
    );
}
