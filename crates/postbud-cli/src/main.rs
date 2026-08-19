//! The `postbud` binary.
//!
//! `serve` and `worker` are separate commands on purpose: the API must stay
//! responsive while the relay is unreachable, and the worker must be able
//! to scale or restart without dropping requests. They share nothing but
//! the database.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "postbud",
    version,
    about = "Self-hosted transactional mail: API in front, Postfix behind"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply database migrations.
    Migrate,
    /// Run the HTTP API.
    Serve,
    /// Run the delivery worker.
    Worker,
    /// Tenant administration.
    #[command(subcommand)]
    Tenant(TenantCommand),
    /// Read a raw DSN on stdin and record it. This is what Postfix pipes
    /// bounces into; see docs/postfix/.
    BounceIngest,
    /// Report the relay's queue to postbud, continuously.
    ///
    /// Runs beside Postfix and reads its `showq` socket directly, so it
    /// needs no Postfix binaries -- which is what keeps this image
    /// `FROM scratch`. Separate from `worker` on purpose: the worker is
    /// scaled for throughput, while exactly one reporter per relay
    /// should be reading one queue.
    QueueReport,
    /// Import DMARC aggregate reports from files or directories.
    ///
    /// Reads .xml, .xml.gz, .gz and .zip, recursing into directories, and
    /// is safe to run twice: a report already held is counted as a
    /// duplicate and skipped. Reading files rather than a mailbox keeps
    /// this usable for backfilling an archive that predates postbud.
    DmarcImport {
        /// Files or directories to read.
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
    },
    /// Read the DMARC report mailbox once and exit.
    ///
    /// The same pass the worker makes on a timer. Separate because
    /// checking that a mailbox is reachable should not mean starting a
    /// delivery worker and waiting an hour to find out.
    DmarcFetch,
    /// Blank message bodies that have outlived their delivery.
    Purge {
        /// Override BODY_RETENTION_DAYS.
        #[arg(long)]
        days: Option<i64>,
    },
}

#[derive(Subcommand)]
enum TenantCommand {
    /// Register a sending system and print its API key. The key is shown
    /// once and cannot be recovered — postbud stores only its digest.
    Add {
        #[arg(long)]
        name: String,
        /// Domains this tenant may use in `From:`. Repeatable. Subdomains
        /// are not implied; list each one.
        #[arg(long = "domain", required = true)]
        domains: Vec<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// List tenants.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();

    match cli.command {
        Command::Migrate => {
            let pool = pool().await?;
            postbud_db::migrate(&pool).await?;
            println!("migrations applied");
        }

        Command::Serve => {
            let pool = pool().await?;
            let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let router = postbud_api::router(postbud_api::AppState {
                pool,
                bounce_token: std::env::var("BOUNCE_INGEST_TOKEN").ok(),
                admin_token: std::env::var("ADMIN_TOKEN").ok(),
                admin_oidc: postbud_api::oidc::OidcAdmin::from_env()?,
                spf_default: std::env::var("DNS_SPF_DEFAULT").ok(),
            });
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            println!("postbud api listening on {bind}");
            axum::serve(listener, router).await.context("serving")?;
        }

        Command::Worker => {
            let pool = pool().await?;
            let relay = postbud_relay::Relay::from_env()?;
            let config = postbud_relay::worker::Config::from_env()?;
            println!("postbud worker '{}' started", config.worker_name);
            postbud_relay::worker::run(pool, relay, config).await?;
        }

        Command::Tenant(TenantCommand::Add {
            name,
            domains,
            note,
        }) => {
            let pool = pool().await?;
            let (tenant, key) =
                postbud_db::tenant::create(&pool, &name, &domains, note.as_deref()).await?;
            println!("tenant {} created ({})", tenant.name, tenant.id);
            println!("domains: {}", tenant.from_domains.join(", "));
            println!();
            println!("API key (shown once, store it now):");
            println!("  {key}");
        }

        Command::Tenant(TenantCommand::List) => {
            let pool = pool().await?;
            for tenant in postbud_db::tenant::list(&pool).await? {
                let state = if tenant.active { "active" } else { "inactive" };
                println!(
                    "{}  {:<20} {:<8} {}",
                    tenant.id,
                    tenant.name,
                    state,
                    tenant.from_domains.join(", ")
                );
            }
        }

        Command::BounceIngest => {
            use std::io::Read as _;
            let pool = pool().await?;
            let mut raw = String::new();
            std::io::stdin()
                .read_to_string(&mut raw)
                .context("reading DSN from stdin")?;
            let result = postbud_db::bounce::ingest(&pool, &raw).await?;
            // Printed rather than silent: this runs under Postfix, whose
            // log is where an operator will look for it.
            println!(
                "bounce ingested: {} report(s), {} suppressed, {} unmatched",
                result.reports, result.suppressed, result.unmatched
            );
        }

        Command::QueueReport => {
            let config = postbud_relay::queuereport::Config::from_env()?;
            println!(
                "postbud queue-report reading {} every {}s",
                config.socket,
                config.interval.as_secs()
            );
            postbud_relay::queuereport::run(config).await?;
        }

        Command::DmarcImport { paths } => {
            let pool = pool().await?;
            let outcome = dmarc_import(&pool, &paths).await?;
            println!(
                "dmarc import: {} report(s) stored, {} duplicate(s), {} record(s)",
                outcome.stored, outcome.duplicates, outcome.records
            );
            println!();
            for row in postbud_db::dmarc::summary(&pool).await? {
                let rate = if row.messages > 0 {
                    100.0 * row.passed as f64 / row.messages as f64
                } else {
                    0.0
                };
                println!(
                    "{:<40} {:>4} report(s) {:>8} msg  {:>6.1}% pass",
                    row.domain, row.reports, row.messages, rate
                );
            }
        }

        Command::DmarcFetch => {
            let Some(config) = postbud_relay::dmarc::Config::from_env()? else {
                anyhow::bail!("DMARC_EMAIL_IMAP is not set; nothing to read");
            };
            let pool = pool().await?;
            let outcome = postbud_relay::dmarc::poll_once(&pool, &config).await?;
            println!(
                "dmarc fetch: {} examined, {} stored, {} duplicate, {} unreadable",
                outcome.examined, outcome.stored, outcome.duplicates, outcome.unreadable
            );
        }

        Command::Purge { days } => {
            let pool = pool().await?;
            let days = match days {
                Some(days) => days,
                None => std::env::var("BODY_RETENTION_DAYS")
                    .unwrap_or_else(|_| "30".into())
                    .parse()
                    .context("BODY_RETENTION_DAYS must be a number")?,
            };
            let purged = postbud_db::message::purge_bodies(&pool, days).await?;
            println!("purged bodies of {purged} message(s) older than {days} days");
        }
    }

    Ok(())
}

/// Import every report found under `paths`.
///
/// Nothing here stops on a bad file. A directory of reports routinely
/// contains one that is truncated, or a stray non-report, and refusing the
/// whole run over it would mean the archive never imports at all. Each
/// failure is named on stderr and the run continues -- the same bargain
/// the DSN parser makes, where an unreadable input is a bug report rather
/// than a fatal error.
async fn dmarc_import(
    pool: &sqlx::PgPool,
    paths: &[std::path::PathBuf],
) -> Result<postbud_db::dmarc::Ingested> {
    let mut outcome = postbud_db::dmarc::Ingested::default();
    for path in collect_report_files(paths) {
        let blob = match std::fs::read(&path) {
            Ok(blob) => blob,
            Err(err) => {
                eprintln!("skipped {}: {err}", path.display());
                continue;
            }
        };
        let documents = match postbud_core::dmarc::extract(&blob) {
            Ok(documents) => documents,
            Err(err) => {
                eprintln!("skipped {}: {err}", path.display());
                continue;
            }
        };
        for document in documents {
            let report = match postbud_core::dmarc::parse(&document) {
                Ok(report) => report,
                Err(err) => {
                    eprintln!("skipped {}: {err}", path.display());
                    continue;
                }
            };
            let raw = String::from_utf8_lossy(&document);
            let records = report.records.len();
            if postbud_db::dmarc::store(pool, &report, &raw).await? {
                outcome.stored += 1;
                outcome.records += records;
            } else {
                outcome.duplicates += 1;
            }
        }
    }
    Ok(outcome)
}

/// Every file under `paths` that looks like a report, directories walked
/// depth-first and in a stable order so two runs read the same way.
fn collect_report_files(paths: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
    fn looks_like_report(path: &std::path::Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        name.ends_with(".xml")
            || name.ends_with(".xml.gz")
            || name.ends_with(".gz")
            || name.ends_with(".zip")
    }

    fn walk(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if path.is_dir() {
            let mut entries: Vec<_> = match std::fs::read_dir(path) {
                Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(err) => {
                    eprintln!("skipped {}: {err}", path.display());
                    return;
                }
            };
            entries.sort();
            for entry in entries {
                walk(&entry, out);
            }
        } else if path.is_file() && looks_like_report(path) {
            out.push(path.to_path_buf());
        }
    }

    let mut out = Vec::new();
    for path in paths {
        if path.is_file() {
            // Named explicitly, so honour it whatever it is called.
            out.push(path.clone());
        } else {
            walk(path, &mut out);
        }
    }
    out
}

async fn pool() -> Result<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    postbud_db::connect(&url).await
}
