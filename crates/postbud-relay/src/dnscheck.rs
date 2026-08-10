//! The domain-verification fetch loop.
//!
//! The RULES live in `postbud_core::dnscheck` (pure, unit-tested); this
//! module only asks DNS the questions and hands over the answers. It
//! runs inside the worker process — the long-lived non-API process —
//! and paces itself: a domain that is not yet valid is re-checked every
//! [`RECHECK_MINUTES`] (an operator mid-setup should get feedback in
//! minutes), a valid one every [`REVALIDATE_HOURS`] (DNS also breaks
//! later, and a green badge that cannot turn red again is a lie).

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use postbud_core::dnscheck::{self, Expected, Observed};
use sqlx::PgPool;
use std::time::Duration;

pub const RECHECK_MINUTES: i64 = 15;
pub const REVALIDATE_HOURS: i64 = 24;
const TICK: Duration = Duration::from_secs(60);

/// "No such records" is an ANSWER (the record is missing); a resolver
/// or network failure is NOT (checking must be skipped, or an outage
/// would be recorded as every domain suddenly losing its DNS).
fn empty_if_absent<T>(result: Result<T, ResolveError>) -> Result<Option<T>, ResolveError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

async fn txt(resolver: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, ResolveError> {
    let lookup = empty_if_absent(resolver.txt_lookup(name).await)?;
    Ok(lookup
        .map(|l| {
            l.iter()
                .map(|record| {
                    // A long TXT record arrives as 255-byte chunks; the
                    // split is wire format, not content.
                    record
                        .txt_data()
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<Vec<_>>()
                        .concat()
                })
                .collect()
        })
        .unwrap_or_default())
}

async fn mx(resolver: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, ResolveError> {
    let lookup = empty_if_absent(resolver.mx_lookup(name).await)?;
    Ok(lookup
        .map(|l| l.iter().map(|r| r.exchange().to_string()).collect())
        .unwrap_or_default())
}

/// Fetch everything the evaluation needs for one domain.
pub async fn observe(
    resolver: &TokioAsyncResolver,
    domain: &str,
    dkim_selector: &str,
) -> Result<Observed, ResolveError> {
    let domain_txt = txt(resolver, domain).await?;
    let dkim_txt = txt(resolver, &format!("{dkim_selector}._domainkey.{domain}")).await?;

    // DMARC inherits from the organizational domain: walk toward it and
    // keep the first name that answers with anything.
    let mut dmarc_txt = Vec::new();
    let mut dmarc_found_at = None;
    for name in dnscheck::dmarc_names(domain) {
        let records = txt(resolver, &name).await?;
        if records.iter().any(|r| {
            r.trim_start()
                .get(..8)
                .is_some_and(|p| p.eq_ignore_ascii_case("v=DMARC1"))
        }) {
            dmarc_txt = records;
            dmarc_found_at = Some(name);
            break;
        }
    }

    let mx = mx(resolver, domain).await?;

    Ok(Observed {
        domain_txt,
        dkim_txt,
        dmarc_txt,
        dmarc_found_at,
        mx,
    })
}

/// Check every due domain once. Returns how many were checked.
pub async fn run_due_checks(pool: &PgPool, resolver: &TokioAsyncResolver) -> anyhow::Result<usize> {
    let due = postbud_db::domain::due_for_check(pool, RECHECK_MINUTES, REVALIDATE_HOURS).await?;
    let mut checked = 0;
    for d in due {
        let observed = match observe(resolver, &d.domain, &d.dkim_selector).await {
            Ok(o) => o,
            Err(e) => {
                // Resolver trouble is OUR trouble, never the domain's.
                eprintln!("postbud: dns check for {} skipped: {e}", d.domain);
                continue;
            }
        };
        let expected = Expected {
            spf: d.spf_expected.clone(),
            dkim_public_key: d.dkim_public_key.clone(),
            mx: d.mx_expected.clone(),
        };
        let result = dnscheck::evaluate(&expected, &observed);
        postbud_db::domain::record_check(pool, d.id, &result).await?;
        checked += 1;
    }
    Ok(checked)
}

/// The background loop, spawned by the worker alongside delivery.
pub async fn run(pool: PgPool) {
    // The container's resolv.conf when it has one (Kubernetes always
    // provides it); public resolvers otherwise. Never silently off.
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        eprintln!("postbud: no system resolver config ({e}); using public resolvers");
        TokioAsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::google(),
            hickory_resolver::config::ResolverOpts::default(),
        )
    });
    loop {
        if let Err(e) = run_due_checks(&pool, &resolver).await {
            eprintln!("postbud: domain check round failed: {e:#}");
        }
        tokio::time::sleep(TICK).await;
    }
}
