//! The queue's two throughput properties, against a real Postgres.
//!
//! Both regress SILENTLY, which is why they are worth a test. Drop the
//! NOTIFY and mail still goes out — just up to a poll interval later,
//! with nothing in any log to say so. Get the attachment grouping wrong
//! and every message still sends, carrying somebody else's invoice.
//!
//! Skips politely when DATABASE_URL is unset; runs for real in CI. One
//! sequential test on purpose: "no OTHER notification arrived" is a claim
//! about the whole channel, and a second test accepting messages in
//! parallel would refute it without anything being wrong.

use postbud_db::message::{self, Attachment, NewMessage};
use sqlx::postgres::PgListener;
use std::time::Duration;
use uuid::Uuid;

async fn pool() -> Option<sqlx::PgPool> {
    dotenvy::dotenv().ok();
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL is not set");
        return None;
    };
    let pool = postbud_db::connect(&url).await.expect("connecting");
    postbud_db::migrate(&pool).await.expect("migrating");
    Some(pool)
}

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    let (tenant, _key) = postbud_db::tenant::create(
        pool,
        &format!("queue-test-{}", Uuid::new_v4()),
        &["queue.test".into()],
        Some("created by queue_db.rs"),
    )
    .await
    .expect("creating tenant");
    tenant.id
}

fn draft(tenant_id: Uuid, rcpt: &str) -> NewMessage {
    NewMessage {
        tenant_id,
        idempotency_key: Uuid::new_v4().to_string(),
        mail_from: "sender@queue.test".into(),
        from_name: None,
        rcpt_to: rcpt.into(),
        reply_to: None,
        subject: "queue test".into(),
        body_text: Some("body".into()),
        body_html: None,
        attachments: Vec::new(),
    }
}

/// Claim until every id has been seen, or give up.
///
/// A development database carries a backlog of queued messages from
/// earlier runs, and claiming is ordered by due time — so the messages
/// this test just accepted are at the BACK. Claiming in rounds walks
/// through whatever is ahead of them instead of assuming an empty queue.
async fn claim_until_found(pool: &sqlx::PgPool, ids: &[Uuid]) -> Vec<message::Claimed> {
    let mut found: Vec<message::Claimed> = Vec::new();
    for _ in 0..50 {
        let batch = message::claim(pool, "queue-db-test", 100)
            .await
            .expect("claiming");
        if batch.is_empty() {
            break;
        }
        found.extend(batch.into_iter().filter(|c| ids.contains(&c.id)));
        if ids.iter().all(|id| found.iter().any(|c| c.id == *id)) {
            break;
        }
    }
    found
}

/// The two properties, in sequence.
#[tokio::test]
async fn the_queue_notifies_only_for_real_work_and_claims_keep_their_attachments() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant(&pool).await;

    notifications_are_only_for_queued_messages(&pool, tenant_id).await;
    a_claimed_batch_keeps_each_message_with_its_own_attachments(&pool, tenant_id).await;
}

/// A notification must arrive for work a worker can actually do, and for
/// nothing else. Waking workers for a deduplicated resubmission or a
/// suppressed address would be a poll that always finds an empty queue.
async fn notifications_are_only_for_queued_messages(pool: &sqlx::PgPool, tenant_id: Uuid) {
    let pool = pool.clone();

    let mut listener = PgListener::connect_with(&pool).await.expect("listener");
    listener
        .listen(message::QUEUE_CHANNEL)
        .await
        .expect("subscribing");

    // The ordinary case: something queued, so somebody should wake up.
    let queued = draft(tenant_id, "recipient@example.net");
    message::accept(&pool, &queued).await.expect("accepting");
    tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("a queued message must notify the workers")
        .expect("receiving the notification");

    // The same business event again. It queues nothing, so it must wake
    // nobody -- the caller still gets its original id back.
    let again = message::accept(&pool, &queued).await.expect("re-accepting");
    assert!(again.deduplicated, "the second accept must deduplicate");

    // A suppressed recipient is recorded and finished on the spot; there
    // is no delivery for a worker to attempt.
    postbud_db::suppression::add(
        &pool,
        None,
        "dead@example.net",
        "hard_bounce",
        "queue_db test",
        None,
    )
    .await
    .expect("suppressing");
    let suppressed = message::accept(&pool, &draft(tenant_id, "dead@example.net"))
        .await
        .expect("accepting a suppressed recipient");
    assert_eq!(suppressed.status, "suppressed");

    // Neither of those two may have produced a wake-up.
    let stray = tokio::time::timeout(Duration::from_millis(500), listener.recv()).await;
    assert!(
        stray.is_err(),
        "only a queued message may notify; got a wake-up for a \
         deduplicated or suppressed accept"
    );
}

/// Attachments are loaded for the whole batch in one query and then
/// grouped back per message. If that grouping ever slips, mail still goes
/// out — carrying the wrong file, to the wrong recipient.
async fn a_claimed_batch_keeps_each_message_with_its_own_attachments(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
) {
    let mut first = draft(tenant_id, "first@example.net");
    first.attachments = vec![Attachment {
        filename: "first.pdf".into(),
        content_type: "application/pdf".into(),
        content: b"first-bytes".to_vec(),
    }];

    // Deliberately two, and deliberately in the middle position: a
    // grouping bug that merely shifts by one row would still pass with a
    // single attachment each.
    let mut second = draft(tenant_id, "second@example.net");
    second.attachments = vec![
        Attachment {
            filename: "second-a.pdf".into(),
            content_type: "application/pdf".into(),
            content: b"second-a-bytes".to_vec(),
        },
        Attachment {
            filename: "second-b.pdf".into(),
            content_type: "application/pdf".into(),
            content: b"second-b-bytes".to_vec(),
        },
    ];

    // And one with none at all, which must come back with none rather
    // than inheriting a neighbour's.
    let third = draft(tenant_id, "third@example.net");

    let ids = [
        message::accept(pool, &first).await.expect("accepting").id,
        message::accept(pool, &second).await.expect("accepting").id,
        message::accept(pool, &third).await.expect("accepting").id,
    ];

    let claimed = claim_until_found(pool, &ids).await;

    let find = |id: Uuid| {
        claimed
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("message {id} was not in the claimed batch"))
    };

    let one = find(ids[0]);
    assert_eq!(one.attachments.len(), 1);
    assert_eq!(one.attachments[0].filename, "first.pdf");
    assert_eq!(one.attachments[0].content, b"first-bytes");

    let two = find(ids[1]);
    assert_eq!(two.attachments.len(), 2);
    assert_eq!(
        two.attachments
            .iter()
            .map(|a| a.filename.as_str())
            .collect::<Vec<_>>(),
        vec!["second-a.pdf", "second-b.pdf"],
        "attachment order within a message is the order they were stored"
    );

    assert!(
        find(ids[2]).attachments.is_empty(),
        "a message with no attachments must not inherit a neighbour's"
    );
}
