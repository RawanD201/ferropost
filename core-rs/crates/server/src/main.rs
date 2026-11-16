//! `ferropost`: the Ferropost front server.
//!
//! Terminates HTTP/HTTPS on the console ports, serves ported routes natively
//! and proxies everything else to the Go core running in internal mode.

mod listener;
mod tls;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ferropost_api::AppState;
use ferropost_common::Config;
use ferropost_store::Store;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("ferropost {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let config = match Config::load() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("ferropost: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    let _log_file = init_logging(&config);

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(%err, "cannot start runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "fatal");
            ExitCode::FAILURE
        }
    }
}

/// Logs to standard output and to `logs/core/out/<date>.log`, which the
/// console's output log page reads (Go's logger wrote there).
fn init_logging(config: &Config) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let dir = config.root.join("../logs/core/out");
    let appender = std::fs::create_dir_all(&dir).ok().and_then(|()| {
        tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_suffix("log")
            .build(&dir)
            .ok()
    });
    let stdout = tracing_subscriber::fmt::layer().with_filter(filter());
    match appender {
        Some(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let file = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(filter());
            tracing_subscriber::registry()
                .with(stdout)
                .with(file)
                .init();
            Some(guard)
        }
        None => {
            tracing_subscriber::registry().with(stdout).init();
            tracing::warn!(dir = %dir.display(), "output log folder not writable; logging to stdout only");
            None
        }
    }
}

async fn run(config: Config) -> Result<()> {
    // Several dependencies enable rustls; pick the provider explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing::info!(
        root = %config.root.display(),
        env_file = %config.env.path().display(),
        upstream = %config.go_upstream,
        http_port = config.http_port,
        https_port = config.https_port,
        "starting ferropost"
    );

    let store = Store::connect(&config).await?;
    ferropost_store::migrate(&store.pg).await?;
    let certs = Arc::new(tls::CertStore::new(
        config.ssl_dir.clone(),
        store.pg.clone(),
    )?);
    let state = AppState::new(config.clone(), store.clone())?;
    ferropost_api::bootstrap::before_serving(&state).await;
    ferropost_api::bootstrap::soon(&state);
    let app = ferropost_api::app(state.clone());

    let http = listener::bind(config.http_port).await?;
    let https = listener::bind(config.https_port).await?;
    tracing::info!(http = %http.local_addr()?, https = %https.local_addr()?, "listening");

    let graceful = Arc::new(GracefulShutdown::new());
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut jobs = ferropost_jobs::spawn(&config, &store, stop_rx.clone());
    jobs.extend(ferropost_api::campaigns::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::api_mail::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::mailbox_jobs::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::relay::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::postfix::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::mail_tls::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::multi_ip::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::blocklist::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::domains::spawn(&state, stop_rx.clone()));
    jobs.extend(ferropost_api::askai::crawl::spawn(&state, stop_rx.clone()));
    let watcher = {
        let graceful = graceful.clone();
        move || graceful.watcher()
    };
    let http_task = tokio::spawn(listener::serve(
        http,
        app.clone(),
        None,
        watcher.clone(),
        stop_rx.clone(),
    ));
    let https_task = tokio::spawn(listener::serve(https, app, Some(certs), watcher, stop_rx));

    shutdown_signal().await;
    tracing::info!("shutting down");
    let _ = stop_tx.send(true);
    let _ = tokio::join!(http_task, https_task);
    for job in jobs {
        let _ = tokio::time::timeout(SHUTDOWN_GRACE, job).await;
    }

    let graceful = Arc::try_unwrap(graceful).unwrap_or_else(|_| GracefulShutdown::new());
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("connections still open after grace period; exiting");
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
