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

const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("ferropost {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(%err, "cannot start runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "fatal");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    // Several dependencies enable rustls; pick the provider explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::load()?;
    tracing::info!(
        root = %config.root.display(),
        env_file = %config.env.path().display(),
        upstream = %config.go_upstream,
        http_port = config.http_port,
        https_port = config.https_port,
        "starting ferropost"
    );

    let store = Store::connect(&config).await?;
    let certs = Arc::new(tls::CertStore::new(
        config.ssl_dir.clone(),
        store.pg.clone(),
    )?);
    let app = ferropost_api::app(AppState::new(config.clone(), store)?);

    let http = listener::bind(config.http_port).await?;
    let https = listener::bind(config.https_port).await?;
    tracing::info!(http = %http.local_addr()?, https = %https.local_addr()?, "listening");

    let graceful = Arc::new(GracefulShutdown::new());
    let (stop_tx, stop_rx) = watch::channel(false);
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
