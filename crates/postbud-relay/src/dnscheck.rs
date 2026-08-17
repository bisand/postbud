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
use postbud_core::rdns;
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

    // A `rua` pointing at another domain is only honoured if that domain
    // publishes its consent. Nothing else in the check would notice it
    // missing: the DMARC record itself stays perfectly valid while every
    // receiver quietly stops sending reports.
    let mut report_auth = Vec::new();
    if let (Some(found_at), Some(record)) = (
        dmarc_found_at.as_deref(),
        dmarc_txt.iter().find(|r| {
            r.trim_start()
                .get(..8)
                .is_some_and(|p| p.eq_ignore_ascii_case("v=DMARC1"))
        }),
    ) {
        let publishing = found_at.strip_prefix("_dmarc.").unwrap_or(found_at);
        for name in dnscheck::report_auth_names(publishing, record) {
            let records = txt(resolver, &name).await?;
            report_auth.push((name, records));
        }
    }

    Ok(Observed {
        domain_txt,
        dkim_txt,
        dmarc_txt,
        dmarc_found_at,
        mx,
        report_auth,
    })
}

/// Read the hostname the relay announces in its SMTP greeting.
///
/// `220 mail.example.com ESMTP` — the second field is the name the
/// relay calls itself, and it is what a receiver compares against the
/// PTR. Read straight off the socket rather than through the SMTP
/// client, which parses the greeting and throws the text away.
///
/// Every failure returns None: an unreachable relay is our outage, and
/// recording it as a bad identity would leave a lie in the history.
async fn smtp_banner_host(host: &str, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpStream;

    let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host, port)));
    let stream = connect.await.ok()?.ok()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .ok()?
        .ok()?;

    // "220 <host> ESMTP ..." — anything else is not a greeting we can
    // read a name out of, and guessing would be worse than not checking.
    let mut fields = line.split_whitespace();
    if fields.next()? != "220" {
        return None;
    }
    let name = fields.next()?.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// Look up the relay's identity: forward addresses, their PTR names, and
/// the greeting it answers with.
pub async fn observe_relay(
    resolver: &TokioAsyncResolver,
    host: &str,
    smtp_host: &str,
    smtp_port: u16,
) -> Result<rdns::Observed, ResolveError> {
    let forward_ips: Vec<std::net::IpAddr> = empty_if_absent(resolver.lookup_ip(host).await)?
        .map(|l| l.iter().collect())
        .unwrap_or_default();

    let mut ptr_names = Vec::new();
    for ip in &forward_ips {
        if let Some(lookup) = empty_if_absent(resolver.reverse_lookup(*ip).await)? {
            for name in lookup.iter() {
                let name = name.to_string().trim_end_matches('.').to_ascii_lowercase();
                if !ptr_names.contains(&name) {
                    ptr_names.push(name);
                }
            }
        }
    }

    Ok(rdns::Observed {
        forward_ips: forward_ips.iter().map(|ip| ip.to_string()).collect(),
        ptr_names,
        banner_host: smtp_banner_host(smtp_host, smtp_port).await,
    })
}

/// Check the relay's identity when due. Silent no-op when
/// `RELAY_PUBLIC_HOST` is unset — an installation that has not told us
/// what its relay should be called cannot be told it is wrong.
async fn run_relay_check(pool: &PgPool, resolver: &TokioAsyncResolver) -> anyhow::Result<()> {
    let Ok(host) = std::env::var("RELAY_PUBLIC_HOST") else {
        return Ok(());
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Ok(());
    }

    if !postbud_db::relay::due(pool, RECHECK_MINUTES, REVALIDATE_HOURS).await? {
        return Ok(());
    }

    // The SMTP hop is the one the worker actually submits through, which
    // on this deployment is a private address; the PUBLIC name is what
    // DNS is asked about. They are deliberately separate inputs.
    let smtp_host = std::env::var("RELAY_HOST").unwrap_or_else(|_| host.clone());
    let smtp_port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(25);

    let observed = match observe_relay(resolver, &host, &smtp_host, smtp_port).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("postbud: relay identity check skipped: {e}");
            return Ok(());
        }
    };

    let result = rdns::evaluate(&host, &observed);
    postbud_db::relay::record_check(pool, &host, &result).await?;
    Ok(())
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

/// Build the resolver the checks use.
///
/// PUBLIC resolvers by default, NOT the system's — found the hard way.
/// A host's ISP resolver had cached NXDOMAIN for a name from before its
/// records were published and kept serving that negative answer, so the
/// checker reported "missing" for records that were live and correct
/// everywhere else. The verdict must not depend on which resolver the
/// relay happens to be configured with.
///
/// The question this feature answers is "what does the world see?", and
/// the world's receivers query the authoritative servers through
/// well-behaved resolvers. Cloudflare and Google are that, and they
/// honour the zone's own negative TTLs instead of inventing longer ones.
/// `DNS_RESOLVERS` overrides with a comma-separated list of IPs for
/// installations that run their own; `DNS_RESOLVERS=system` restores the
/// old behaviour deliberately.
fn build_resolver() -> TokioAsyncResolver {
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

    match std::env::var("DNS_RESOLVERS").ok().as_deref() {
        Some("system") => match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => return r,
            Err(e) => eprintln!("postbud: DNS_RESOLVERS=system but no system config ({e})"),
        },
        Some(list) if !list.trim().is_empty() => {
            let ips: Vec<std::net::IpAddr> = list
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !ips.is_empty() {
                let group = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
                return TokioAsyncResolver::tokio(
                    ResolverConfig::from_parts(None, Vec::new(), group),
                    ResolverOpts::default(),
                );
            }
            eprintln!("postbud: DNS_RESOLVERS held no usable IPs; using the public default");
        }
        _ => {}
    }

    // Cloudflare first, Google as the second name server: two operators,
    // so one having a bad day does not stall verification.
    let mut group = NameServerConfigGroup::cloudflare();
    group.merge(NameServerConfigGroup::google());
    TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(None, Vec::new(), group),
        ResolverOpts::default(),
    )
}

/// The background loop, spawned by the worker alongside delivery.
pub async fn run(pool: PgPool) {
    let resolver = build_resolver();
    loop {
        if let Err(e) = run_due_checks(&pool, &resolver).await {
            eprintln!("postbud: domain check round failed: {e:#}");
        }
        // The relay's own identity, on the same cadence. Separate from the
        // domain loop because it is not a property of any one domain: it
        // is the machine every domain's mail leaves from.
        if let Err(e) = run_relay_check(&pool, &resolver).await {
            eprintln!("postbud: relay identity check failed: {e:#}");
        }
        tokio::time::sleep(TICK).await;
    }
}
