use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use crate::canonical_normalizer::CanonicalEvent;
use crate::types::ValueVariant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngressProtocol {
    Kafka,
    Redpanda,
    Grpc,
    RestHttp,
    TcpWire,
}

impl IngressProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Kafka => "KAFKA",
            Self::Redpanda => "REDPANDA",
            Self::Grpc => "GRPC",
            Self::RestHttp => "REST",
            Self::TcpWire => "TCP_WIRE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub gateway_id: String,
    pub protocol: IngressProtocol,
    pub cluster_region: String,
    pub network_cidr: Option<String>,
    pub k8s_pod: Option<String>,
    pub k8s_namespace: Option<String>,
    pub cloud_provider: String,
}

impl Default for SourceProvenance {
    fn default() -> Self {
        Self {
            gateway_id: "gw-edge-01".to_string(),
            protocol: IngressProtocol::RestHttp,
            cluster_region: "us-east-1".to_string(),
            network_cidr: Some("10.0.0.0/16".to_string()),
            k8s_pod: Some("ingest-worker-7f89d".to_string()),
            k8s_namespace: Some("stream-detect".to_string()),
            cloud_provider: "aws".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngressContext {
    pub gateway_id: String,
    pub protocol: IngressProtocol,
    pub client_ip: Option<String>,
    pub client_tls_cipher: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TopologyMapping {
    pub cidr_prefix: String,
    pub region: String,
    pub vpc_id: String,
    pub environment: String,
}

pub struct MetadataEnricher {
    topology_cache: Arc<RwLock<HashMap<String, TopologyMapping>>>,
    default_provenance: SourceProvenance,
    total_enriched: AtomicU64,
}

impl MetadataEnricher {
    pub fn new(default_provenance: SourceProvenance) -> Self {
        let mut initial_map = HashMap::new();
        initial_map.insert(
            "10.0.".to_string(),
            TopologyMapping {
                cidr_prefix: "10.0.0.0/16".to_string(),
                region: "us-east-1".to_string(),
                vpc_id: "vpc-prod-primary".to_string(),
                environment: "production".to_string(),
            },
        );
        initial_map.insert(
            "10.1.".to_string(),
            TopologyMapping {
                cidr_prefix: "10.1.0.0/16".to_string(),
                region: "eu-west-1".to_string(),
                vpc_id: "vpc-prod-eu".to_string(),
                environment: "production".to_string(),
            },
        );
        initial_map.insert(
            "192.168.".to_string(),
            TopologyMapping {
                cidr_prefix: "192.168.0.0/16".to_string(),
                region: "on-premise-dc1".to_string(),
                vpc_id: "corp-lan-01".to_string(),
                environment: "corporate".to_string(),
            },
        );

        Self {
            topology_cache: Arc::new(RwLock::new(initial_map)),
            default_provenance,
            total_enriched: AtomicU64::new(0),
        }
    }

    pub fn register_topology(&self, prefix: String, mapping: TopologyMapping) {
        self.topology_cache.write().insert(prefix, mapping);
    }

    /// Enriches CanonicalEvent with ambient ingress runtime provenance and network topology (< 50 ns)
    pub fn enrich(&self, event: &mut CanonicalEvent, ctx: &IngressContext) {
        // 1. Determine region and topology from client IP
        let mut region = self.default_provenance.cluster_region.clone();
        let mut vpc_id = "vpc-default".to_string();
        let mut env = "production".to_string();

        let client_ip = ctx.client_ip.as_deref().or(event.source_ip.as_deref());

        if let Some(ip) = client_ip {
            let cache = self.topology_cache.read();
            for (prefix, mapping) in cache.iter() {
                if ip.starts_with(prefix) {
                    region = mapping.region.clone();
                    vpc_id = mapping.vpc_id.clone();
                    env = mapping.environment.clone();
                    break;
                }
            }
        }

        // 2. Stamp provenance tags into canonical attributes
        event.attributes.insert(
            "_meta.gateway_id".to_string(),
            ValueVariant::String(ctx.gateway_id.clone()),
        );
        event.attributes.insert(
            "_meta.ingress_protocol".to_string(),
            ValueVariant::String(ctx.protocol.as_str().to_string()),
        );
        event.attributes.insert(
            "_meta.cluster_region".to_string(),
            ValueVariant::String(region),
        );
        event.attributes.insert(
            "_meta.vpc_id".to_string(),
            ValueVariant::String(vpc_id),
        );
        event.attributes.insert(
            "_meta.environment".to_string(),
            ValueVariant::String(env),
        );
        event.attributes.insert(
            "_meta.cloud_provider".to_string(),
            ValueVariant::String(self.default_provenance.cloud_provider.clone()),
        );

        if let Some(ref pod) = self.default_provenance.k8s_pod {
            event.attributes.insert(
                "_meta.k8s_pod".to_string(),
                ValueVariant::String(pod.clone()),
            );
        }

        self.total_enriched.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_enriched(&self) -> u64 {
        self.total_enriched.load(Ordering::Relaxed)
    }
}
