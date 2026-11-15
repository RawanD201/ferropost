//! TCP accept loops for HTTP and HTTPS.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use ferropost_api::ConnInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::Watcher;
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::LazyConfigAcceptor;
use tower::ServiceExt;

use crate::tls::CertStore;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Binds dual-stack when IPv6 is available, IPv4 otherwise.
pub async fn bind(port: u16) -> Result<TcpListener> {
    match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await {
        Ok(listener) => Ok(listener),
        Err(err) => {
            tracing::debug!(port, %err, "IPv6 bind failed; falling back to IPv4");
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
                .await
                .with_context(|| format!("bind port {port}"))
        }
    }
}

/// Accepts connections until `shutdown` flips. Each connection is registered
/// with the graceful-shutdown watcher produced by `watcher`.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    certs: Option<Arc<CertStore>>,
    watcher: impl Fn() -> Watcher,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let app = app.clone();
                    let certs = certs.clone();
                    let watcher = watcher();
                    tokio::spawn(async move { handle(stream, peer, app, certs, watcher).await });
                }
                Err(err) => {
                    // Usually EMFILE; back off instead of spinning.
                    tracing::warn!(%err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            _ = shutdown.changed() => break,
        }
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    certs: Option<Arc<CertStore>>,
    watcher: Watcher,
) {
    let _ = stream.set_nodelay(true);
    let info = ConnInfo {
        peer,
        tls: certs.is_some(),
    };
    let service =
        TowerToHyperService::new(tower::service_fn(move |req: hyper::Request<Incoming>| {
            let mut req = req.map(Body::new);
            req.extensions_mut().insert(info);
            app.clone().oneshot(req)
        }));

    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder.http2().timer(TokioTimer::new());

    let result = match certs {
        None => {
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            watcher.watch(conn.into_owned()).await
        }
        Some(certs) => {
            let Some(tls) = handshake(stream, &certs).await else {
                return;
            };
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            watcher.watch(conn.into_owned()).await
        }
    };
    if let Err(err) = result {
        tracing::debug!(%peer, error = %err, "connection closed with error");
    }
}

async fn handshake(
    stream: TcpStream,
    certs: &CertStore,
) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
    let accept = async {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
        let sni = start.client_hello().server_name().map(str::to_owned);
        let config = certs.config_for(sni.as_deref()).await;
        start.into_stream(config).await
    };
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, accept).await {
        Ok(Ok(tls)) => Some(tls),
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "TLS handshake failed");
            None
        }
        Err(_) => {
            tracing::debug!("TLS handshake timed out");
            None
        }
    }
}
