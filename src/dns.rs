use crate::config::DnsDomainConfig;
use crate::model::DomainPattern;
use anyhow::Context;
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct DnsGroup {
    pub name: String,
    pub patterns: Vec<DomainPattern>,
    pub servers: Vec<SocketAddr>,
}

pub fn parse_dns_groups(cfg: &[DnsDomainConfig]) -> anyhow::Result<Vec<DnsGroup>> {
    cfg.iter()
        .map(|g| {
            let patterns = crate::model::parse_domain_patterns(g.domains.as_deref().unwrap_or(""))?;
            let mut servers = Vec::new();
            for s in &g.servers {
                let addr: SocketAddr = s.parse().with_context(|| format!("invalid dns server: {s}"))?;
                servers.push(addr);
            }
            Ok(DnsGroup {
                name: g.name.clone(),
                patterns,
                servers,
            })
        })
        .collect()
}

pub struct DnsManager {
    groups: Vec<DnsGroup>,
    resolvers: HashMap<String, TokioAsyncResolver>,
}

impl DnsManager {
    pub fn new(groups: Vec<DnsGroup>) -> anyhow::Result<Self> {
        let mut resolvers = HashMap::new();
        for g in &groups {
            if g.servers.is_empty() {
                continue;
            }
            let mut nsg = NameServerConfigGroup::new();
            for s in &g.servers {
                nsg.push(NameServerConfig::new(*s, Protocol::Udp));
            }
            let rc = ResolverConfig::from_parts(None, vec![], nsg);
            let ro = ResolverOpts::default();
            let resolver = TokioAsyncResolver::tokio(rc, ro);
            resolvers.insert(g.name.clone(), resolver);
        }
        Ok(Self { groups, resolvers })
    }

    pub fn pick_group(&self, host: &str) -> Option<&DnsGroup> {
        let host_lc = host.to_ascii_lowercase();
        self.groups.iter().find(|g| {
            g.patterns.iter().any(|p| p.matches_host(&host_lc))
        })
    }

    pub async fn resolve_ip(&self, host: &str) -> anyhow::Result<Option<IpAddr>> {
        let group = match self.pick_group(host) {
            Some(g) if !g.servers.is_empty() => g,
            _ => return Ok(None),
        };
        let resolver = self
            .resolvers
            .get(&group.name)
            .context("resolver not found")?;

        // Prefer A then AAAA.
        if let Ok(lookup) = resolver.lookup_ip(host).await {
            if let Some(ip) = lookup.iter().next() {
                return Ok(Some(ip));
            }
        }
        Ok(None)
    }
}

