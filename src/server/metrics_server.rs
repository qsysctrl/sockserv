//! HTTP server for exposing Prometheus metrics endpoint.

use crate::server::metrics::MetricsManager;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Metrics HTTP server configuration.
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    /// Address to bind the metrics server to.
    pub listen_addr: SocketAddr,
    /// Enable/disable the metrics server.
    pub enabled: bool,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9090".parse().unwrap(),
            enabled: true,
        }
    }
}

/// Handle HTTP requests for the metrics server.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    metrics: Arc<MetricsManager>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Only accept GET requests to /metrics
    if req.method() == Method::GET && req.uri().path() == "/metrics" {
        match metrics.encode() {
            Ok(encoded) => {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    .body(Full::new(Bytes::from(encoded)))
                    .unwrap();
                Ok(response)
            }
            Err(e) => {
                error!("Failed to encode metrics: {}", e);
                let response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Failed to encode metrics")))
                    .unwrap();
                Ok(response)
            }
        }
    } else if req.method() == Method::GET && req.uri().path() == "/health" {
        // Health check endpoint
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .unwrap();
        Ok(response)
    } else {
        // 404 for everything else
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap();
        Ok(response)
    }
}

/// Run the metrics HTTP server.
pub async fn run_metrics_server(
    config: MetricsServerConfig,
    metrics: Arc<MetricsManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !config.enabled {
        info!("Metrics server disabled");
        return Ok(());
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!("Metrics server listening on http://{}", config.listen_addr);
    info!("Metrics endpoint: http://{}/metrics", config.listen_addr);
    info!("Health check endpoint: http://{}/health", config.listen_addr);

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let metrics = Arc::clone(&metrics);
                handle_request(req, metrics)
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                warn!("Error serving connection from {}: {}", remote_addr, e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = MetricsServerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listen_addr.port(), 9090);
    }
}
