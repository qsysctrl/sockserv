//! Prometheus metrics collection and export.
//!
//! Provides OpenMetrics-compatible metrics for monitoring:
//! - Connection counters (active, total, rejected)
//! - Bytes transferred (RX/TX histograms)
//! - Error rates by type
//! - Request statistics

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::{
    counter::Counter,
    family::Family,
    gauge::Gauge,
    histogram::Histogram,
};
use prometheus_client::registry::Registry;
use std::fmt::Write;
use std::sync::Arc;

/// Label set for connection metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectionLabels {
    pub remote_ip: String,
}

/// Label set for error metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabels {
    pub error_type: String,
}

/// Label set for request metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub command: String,
}

/// Label set for bytes transferred metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BytesLabels {
    pub direction: String,
}

/// Custom label value for ACL decision.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AclDecisionLabel {
    Allow,
    Deny,
}

impl EncodeLabelValue for AclDecisionLabel {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        match self {
            AclDecisionLabel::Allow => encoder.write_str("allow"),
            AclDecisionLabel::Deny => encoder.write_str("deny"),
        }
    }
}

/// Label set for ACL metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AclLabels {
    pub decision: AclDecisionLabel,
    pub rule_type: String,
}

/// Main metrics collector for the SOCKS5 server.
pub struct MetricsCollector {
    registry: Registry,
    
    // Connection counters
    connections_total: Family<ConnectionLabels, Counter>,
    connections_active: Gauge,
    connections_rejected: Family<ConnectionLabels, Counter>,
    
    // ACL metrics
    acl_decisions: Family<AclLabels, Counter>,
    
    // Bytes transferred
    bytes_transferred: Family<BytesLabels, Histogram>,
    
    // Error tracking
    errors_total: Family<ErrorLabels, Counter>,
    
    // Request statistics
    requests_total: Family<RequestLabels, Counter>,
    request_duration: Family<RequestLabels, Histogram>,
    
    // Authentication metrics
    auth_attempts: Counter,
    auth_success: Counter,
    auth_failure: Counter,
}

impl MetricsCollector {
    /// Create a new metrics collector with registered metrics.
    pub fn new() -> Self {
        let mut registry = Registry::default();
        
        // Connection metrics
        let connections_total = Family::<ConnectionLabels, Counter>::default();
        registry.register(
            "connections_total",
            "Total number of connections accepted",
            connections_total.clone(),
        );
        
        let connections_active = Gauge::default();
        registry.register(
            "connections_active",
            "Current number of active connections",
            connections_active.clone(),
        );
        
        let connections_rejected = Family::<ConnectionLabels, Counter>::default();
        registry.register(
            "connections_rejected_total",
            "Total number of connections rejected",
            connections_rejected.clone(),
        );
        
        // ACL metrics
        let acl_decisions = Family::<AclLabels, Counter>::default();
        registry.register(
            "acl_decisions_total",
            "Total number of ACL decisions by type and result",
            acl_decisions.clone(),
        );
        
        // Bytes transferred histograms
        // Buckets: 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 1GB
        let bytes_transferred = Family::<BytesLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(
                [1024.0, 10240.0, 102400.0, 1048576.0, 10485760.0, 104857600.0, 1073741824.0]
                    .into_iter()
            )
        });
        registry.register(
            "bytes_transferred_total",
            "Total bytes transferred (RX/TX)",
            bytes_transferred.clone(),
        );
        
        // Error metrics
        let errors_total = Family::<ErrorLabels, Counter>::default();
        registry.register(
            "errors_total",
            "Total number of errors by type",
            errors_total.clone(),
        );
        
        // Request metrics
        let requests_total = Family::<RequestLabels, Counter>::default();
        registry.register(
            "requests_total",
            "Total number of SOCKS requests by command",
            requests_total.clone(),
        );
        
        // Request duration histograms (in seconds)
        // Buckets: 1ms, 10ms, 100ms, 1s, 10s, 60s, 300s
        let request_duration = Family::<RequestLabels, Histogram>::new_with_constructor(|| {
            Histogram::new([0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 300.0].into_iter())
        });
        registry.register(
            "request_duration_seconds",
            "SOCKS request duration in seconds",
            request_duration.clone(),
        );
        
        // Authentication metrics
        let auth_attempts = Counter::default();
        registry.register(
            "auth_attempts_total",
            "Total number of authentication attempts",
            auth_attempts.clone(),
        );
        
        let auth_success = Counter::default();
        registry.register(
            "auth_success_total",
            "Total number of successful authentications",
            auth_success.clone(),
        );
        
        let auth_failure = Counter::default();
        registry.register(
            "auth_failure_total",
            "Total number of failed authentications",
            auth_failure.clone(),
        );
        
        Self {
            registry,
            connections_total,
            connections_active,
            connections_rejected,
            acl_decisions,
            bytes_transferred,
            errors_total,
            requests_total,
            request_duration,
            auth_attempts,
            auth_success,
            auth_failure,
        }
    }
    
    /// Get a reference to the metrics registry.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    
    // ========================================================================
    // Connection metrics
    // ========================================================================
    
    /// Record a new connection.
    pub fn record_connection(&self, remote_ip: &str) {
        let labels = ConnectionLabels {
            remote_ip: remote_ip.to_string(),
        };
        self.connections_total.get_or_create(&labels).inc();
        self.connections_active.inc();
    }
    
    /// Record connection close.
    pub fn record_connection_close(&self) {
        self.connections_active.dec();
    }
    
    /// Record a rejected connection.
    pub fn record_connection_reject(&self, remote_ip: &str) {
        let labels = ConnectionLabels {
            remote_ip: remote_ip.to_string(),
        };
        self.connections_rejected.get_or_create(&labels).inc();
    }
    
    // ========================================================================
    // ACL metrics
    // ========================================================================
    
    /// Record an ACL decision.
    pub fn record_acl_decision(&self, decision: AclDecisionLabel, rule_type: &str) {
        let labels = AclLabels {
            decision,
            rule_type: rule_type.to_string(),
        };
        self.acl_decisions.get_or_create(&labels).inc();
    }
    
    // ========================================================================
    // Bytes transferred metrics
    // ========================================================================
    
    /// Record bytes transferred.
    pub fn record_bytes(&self, bytes: u64, direction: &str) {
        let labels = BytesLabels {
            direction: direction.to_string(),
        };
        self.bytes_transferred
            .get_or_create(&labels)
            .observe(bytes as f64);
    }
    
    // ========================================================================
    // Error metrics
    // ========================================================================
    
    /// Record an error.
    pub fn record_error(&self, error_type: &str) {
        let labels = ErrorLabels {
            error_type: error_type.to_string(),
        };
        self.errors_total.get_or_create(&labels).inc();
    }
    
    // ========================================================================
    // Request metrics
    // ========================================================================
    
    /// Record a SOCKS request.
    pub fn record_request(&self, command: &str) {
        let labels = RequestLabels {
            command: command.to_string(),
        };
        self.requests_total.get_or_create(&labels).inc();
    }
    
    /// Record request duration.
    pub fn record_request_duration(&self, command: &str, duration_secs: f64) {
        let labels = RequestLabels {
            command: command.to_string(),
        };
        self.request_duration
            .get_or_create(&labels)
            .observe(duration_secs);
    }
    
    // ========================================================================
    // Authentication metrics
    // ========================================================================
    
    /// Record an authentication attempt.
    pub fn record_auth_attempt(&self) {
        self.auth_attempts.inc();
    }
    
    /// Record successful authentication.
    pub fn record_auth_success(&self) {
        self.auth_success.inc();
    }
    
    /// Record failed authentication.
    pub fn record_auth_failure(&self) {
        self.auth_failure.inc();
    }
    
    // ========================================================================
    // Metrics export
    // ========================================================================
    
    /// Encode metrics in OpenMetrics format.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(
            &mut encoded,
            &self.registry,
        )?;
        Ok(encoded)
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for the metrics collector.
#[derive(Clone)]
pub struct MetricsManager {
    collector: Arc<MetricsCollector>,
}

impl MetricsManager {
    /// Create a new metrics manager.
    pub fn new() -> Self {
        Self {
            collector: Arc::new(MetricsCollector::new()),
        }
    }
    
    /// Get a reference to the underlying collector.
    pub fn collector(&self) -> &MetricsCollector {
        &self.collector
    }
    
    // Delegate all methods to the collector for convenience
    
    pub fn registry(&self) -> &Registry {
        self.collector.registry()
    }
    
    pub fn record_connection(&self, remote_ip: &str) {
        self.collector.record_connection(remote_ip);
    }
    
    pub fn record_connection_close(&self) {
        self.collector.record_connection_close();
    }
    
    pub fn record_connection_reject(&self, remote_ip: &str) {
        self.collector.record_connection_reject(remote_ip);
    }
    
    pub fn record_acl_decision(&self, decision: AclDecisionLabel, rule_type: &str) {
        self.collector.record_acl_decision(decision, rule_type);
    }
    
    pub fn record_bytes(&self, bytes: u64, direction: &str) {
        self.collector.record_bytes(bytes, direction);
    }
    
    pub fn record_error(&self, error_type: &str) {
        self.collector.record_error(error_type);
    }
    
    pub fn record_request(&self, command: &str) {
        self.collector.record_request(command);
    }
    
    pub fn record_request_duration(&self, command: &str, duration_secs: f64) {
        self.collector.record_request_duration(command, duration_secs);
    }
    
    pub fn record_auth_attempt(&self) {
        self.collector.record_auth_attempt();
    }
    
    pub fn record_auth_success(&self) {
        self.collector.record_auth_success();
    }
    
    pub fn record_auth_failure(&self) {
        self.collector.record_auth_failure();
    }

    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        self.collector.encode()
    }
}

impl Default for MetricsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.encode().is_ok());
    }
    
    #[test]
    fn test_connection_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_connection("192.168.1.1");
        collector.record_connection("192.168.1.2");
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("connections_total"));
        assert!(encoded.contains("connections_active"));
    }
    
    #[test]
    fn test_connection_close() {
        let collector = MetricsCollector::new();
        
        collector.record_connection("192.168.1.1");
        collector.record_connection_close();
        
        let encoded = collector.encode().unwrap();
        // Active should be back to 0
        assert!(encoded.contains("connections_active 0"));
    }
    
    #[test]
    fn test_rejected_connection() {
        let collector = MetricsCollector::new();
        
        collector.record_connection_reject("10.0.0.1");
        collector.record_connection_reject("10.0.0.2");
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("connections_rejected_total"));
    }
    
    #[test]
    fn test_acl_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_acl_decision(AclDecisionLabel::Allow, "ip");
        collector.record_acl_decision(AclDecisionLabel::Deny, "domain");
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("acl_decisions_total"));
        assert!(encoded.contains("decision=\"allow\""));
        assert!(encoded.contains("decision=\"deny\""));
    }
    
    #[test]
    fn test_bytes_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_bytes(1024, "rx");
        collector.record_bytes(2048, "tx");
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("bytes_transferred_total"));
    }
    
    #[test]
    fn test_error_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_error("connection_refused");
        collector.record_error("timeout");
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("errors_total"));
    }
    
    #[test]
    fn test_request_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_request("CONNECT");
        collector.record_request("BIND");
        collector.record_request_duration("CONNECT", 0.5);
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("requests_total"));
        assert!(encoded.contains("request_duration_seconds"));
    }
    
    #[test]
    fn test_auth_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_auth_attempt();
        collector.record_auth_success();
        collector.record_auth_failure();
        
        let encoded = collector.encode().unwrap();
        assert!(encoded.contains("auth_attempts_total"));
        assert!(encoded.contains("auth_success_total"));
        assert!(encoded.contains("auth_failure_total"));
    }
    
    #[test]
    fn test_metrics_manager() {
        let manager = MetricsManager::new();
        
        manager.record_connection("1.2.3.4");
        manager.record_request("CONNECT");
        manager.record_auth_attempt();
        
        let encoded = manager.encode().unwrap();
        assert!(encoded.contains("connections_total"));
        assert!(encoded.contains("requests_total"));
    }
    
    #[test]
    fn test_metrics_manager_clone() {
        let manager = MetricsManager::new();
        let clone = manager.clone();
        
        manager.record_connection("1.2.3.4");
        clone.record_request("BIND");
        
        // Both should see the same metrics
        let encoded = manager.encode().unwrap();
        assert!(encoded.contains("connections_total"));
        assert!(encoded.contains("requests_total"));
    }
}
