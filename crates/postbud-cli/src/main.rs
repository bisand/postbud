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

async fn pool() -> Result<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    postbud_db::connect(&url).await
}
