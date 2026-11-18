use crate::config::{HeaderConfig, RuleConfig, RuleWssEchYaml, UserConfig};
use anyhow::Context;
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub password: String,
    pub is_admin: bool,
    pub allowed_rules: HashSet<String>,
}

impl User {
    pub fn from_cfg(u: &UserConfig) -> Self {
        let allowed_rules = u
            .auth_rules
            .as_deref()
            .unwrap_or("")
            .split(|c| c == ',' || c == '\n' || c == '\r')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();
        Self {
            name: u.name.clone(),
            password: u.password.clone(),
            is_admin: u.is_admin,
            allowed_rules,
        }
    }
}

#[derive(Debug, Clone)]
pub enum UpstreamTarget {
    /// Forward via an upstream HTTP proxy at host:port
    HttpProxy { host: String, port: u16 },
    /// Forward via an upstream SOCKS5 proxy at host:port (no-auth)
    Socks5Proxy { host: String, port: u16 },
    /// Forward via websocket(s) proxy. `{domain}` will be replaced with `host:port`.
    WsProxy {
        url_template: String,
        headers: BTreeMap<String, String>,
        /// Encrypted Client Hello for `wss://` upstream when set.
        wss_ech: Option<WssEchSettings>,
    },
}

/// Resolved from rule `wss-ech` YAML for WSS upstream.
#[derive(Debug, Clone)]
pub struct WssEchSettings {
    pub inner_hostname: String,
    pub connect_host: Option<String>,
    pub ech_config_file: Option<String>,
    pub ech_doh_lookup: bool,
    pub ech_doh_cloudflare: bool,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub target: UpstreamTarget,
    pub patterns: Vec<DomainPattern>,
}

#[derive(Debug, Clone)]
pub enum DomainPattern {
    Wildcard(String),
    Cidr(IpNet),
    Ip(IpAddr),
    Exact(String),
    /// host:port 精确匹配，用于同一 host 不同 port 走不同代理
    ExactHostPort(String, u16),
}

impl DomainPattern {
    /// 规则匹配已由 DomainTree 负责；此方法供 dns 等按 host 匹配用。
    pub fn matches_host(&self, host: &str) -> bool {
        let host_norm = host.trim_end_matches('.');
        match self {
            DomainPattern::Wildcard(p) => {
                let suffix = p.trim_start_matches('+').trim_start_matches('*').trim_start_matches('.');
                if !suffix.is_empty() && (host_norm.eq_ignore_ascii_case(suffix) || host_norm.ends_with(&format!(".{}", suffix))) {
                    return true;
                }
                false
            }
            DomainPattern::Exact(s) => s.eq_ignore_ascii_case(host_norm),
            DomainPattern::ExactHostPort(_, _) => false,
            DomainPattern::Cidr(_) | DomainPattern::Ip(_) => false,
        }
    }
}

/// 域名树：按标签从右到左（TLD → 二级 → …）建树，子节点用 BTreeMap 实现有序查找。
/// 每层：未找到下一段或当前节点标记为 *（任意子域）则视为匹配。
struct DomainTreeNode {
    children: BTreeMap<String, Box<DomainTreeNode>>,
    best_apex: Option<usize>,
    best_wildcard: Option<usize>,
    /// host:port 精确匹配（仅域名类 host）时，port -> 最小规则下标
    port_map: BTreeMap<u16, usize>,
}

impl DomainTreeNode {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            best_apex: None,
            best_wildcard: None,
            port_map: BTreeMap::new(),
        }
    }

    fn add_apex(&mut self, rule_idx: usize) {
        self.best_apex = Some(self.best_apex.map_or(rule_idx, |v| v.min(rule_idx)));
    }
    fn add_wildcard(&mut self, rule_idx: usize) {
        self.best_wildcard = Some(self.best_wildcard.map_or(rule_idx, |v| v.min(rule_idx)));
    }
    fn add_port(&mut self, port: u16, rule_idx: usize) {
        self.port_map
            .entry(port)
            .and_modify(|v| *v = (*v).min(rule_idx))
            .or_insert(rule_idx);
    }
}

/// 域名树：根节点，标签从右到左（如 huggingface.co → ["co", "huggingface"]）。
pub struct DomainTree {
    root: DomainTreeNode,
}

impl DomainTree {
    pub fn from_rules(rules: &[Rule]) -> Self {
        let mut tree = DomainTree {
            root: DomainTreeNode::new(),
        };
        for (rule_idx, r) in rules.iter().enumerate() {
            for p in &r.patterns {
                match p {
                    DomainPattern::Exact(domain) => {
                        tree.add_exact(domain, rule_idx);
                    }
                    DomainPattern::Wildcard(pat) => {
                        tree.add_wildcard_pattern(pat, rule_idx);
                    }
                    _ => {}
                }
            }
        }
        tree
    }

    /// 将域名按 '.' 拆成标签，从右到左（TLD 在前）。
    fn domain_labels(domain: &str) -> Vec<String> {
        domain
            .trim()
            .trim_end_matches('.')
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .rev()
            .collect()
    }

    fn add_exact(&mut self, domain: &str, rule_idx: usize) {
        let labels = Self::domain_labels(domain);
        if labels.is_empty() {
            return;
        }
        let mut cur = &mut self.root;
        for (i, label) in labels.iter().enumerate() {
            let is_last = i == labels.len() - 1;
            cur = cur
                .children
                .entry(label.clone())
                .or_insert_with(|| Box::new(DomainTreeNode::new()))
                .as_mut();
            if is_last {
                cur.add_apex(rule_idx);
            }
        }
    }

    /// 支持 "*.domain" 与 "+*.domain"：apex "domain" 与任意子域都匹配。
    fn add_wildcard_pattern(&mut self, pat: &str, rule_idx: usize) {
        let suffix = pat
            .trim_start_matches('+')
            .trim_start_matches('*')
            .trim_start_matches('.');
        let labels = Self::domain_labels(suffix);
        if labels.is_empty() {
            return;
        }
        let mut cur = &mut self.root;
        for (i, label) in labels.iter().enumerate() {
            let is_last = i == labels.len() - 1;
            cur = cur
                .children
                .entry(label.clone())
                .or_insert_with(|| Box::new(DomainTreeNode::new()))
                .as_mut();
            if is_last {
                cur.add_apex(rule_idx);
                cur.add_wildcard(rule_idx);
            }
        }
    }

    /// 查找 (host, port) 在树中的最小匹配规则下标。host 为 IP 时按 '.' 四段正向匹配，否则按域名反向匹配。
    pub fn lookup(&self, host: &str, port: u16) -> Option<usize> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Some(idx) = self.lookup_ip(ip, port) {
                return Some(idx);
            }
        }
        let labels = Self::domain_labels(host);
        if labels.is_empty() {
            return None;
        }
        let mut best = None;
        DomainTree::lookup_rec(&self.root, &labels[..], 0, port, &mut best);
        best
    }

    /// IPv4 按 4 段正向走树，考虑 wildcard、port_map(port)、port_map(0)、apex。
    fn lookup_ip(&self, ip: IpAddr, port: u16) -> Option<usize> {
        let labels = match Self::ipv4_labels(&ip) {
            Some(l) => l,
            None => return None,
        };
        let mut best = None;
        let mut cur = &self.root;
        for label in &labels {
            if let Some(w) = cur.best_wildcard {
                best = Some(best.map_or(w, |b: usize| b.min(w)));
            }
            match cur.children.get(label) {
                Some(child) => cur = child,
                None => break,
            }
        }
        if let Some(apex) = cur.best_apex {
            best = Some(best.map_or(apex, |b| b.min(apex)));
        }
        if let Some(&p) = cur.port_map.get(&port) {
            best = Some(best.map_or(p, |b| b.min(p)));
        }
        if port != 0 {
            if let Some(&p) = cur.port_map.get(&0) {
                best = Some(best.map_or(p, |b| b.min(p)));
            }
        }
        best
    }

    fn lookup_rec(
        node: &DomainTreeNode,
        labels: &[String],
        i: usize,
        port: u16,
        best: &mut Option<usize>,
    ) {
        if i == labels.len() {
            if let Some(apex) = node.best_apex {
                *best = Some(best.map_or(apex, |b| b.min(apex)));
            }
            if let Some(&p) = node.port_map.get(&port) {
                *best = Some(best.map_or(p, |b| b.min(p)));
            }
            if port != 0 {
                if let Some(&p) = node.port_map.get(&0) {
                    *best = Some(best.map_or(p, |b| b.min(p)));
                }
            }
            return;
        }
        if let Some(w) = node.best_wildcard {
            *best = Some(best.map_or(w, |b| b.min(w)));
        }
        if let Some(child) = node.children.get(&labels[i]) {
            Self::lookup_rec(child, labels, i + 1, port, best);
        }
    }

    /// ExactHostPort(host, port)：仅当 host 非 IP 时调用，将 port 记到该 host 路径末端。
    fn add_exact_host_port(&mut self, host: &str, port: u16, rule_idx: usize) {
        if host.parse::<IpAddr>().is_ok() {
            return;
        }
        let labels = Self::domain_labels(host);
        if labels.is_empty() {
            return;
        }
        let mut cur = &mut self.root;
        for label in &labels {
            cur = cur
                .children
                .entry(label.clone())
                .or_insert_with(|| Box::new(DomainTreeNode::new()))
                .as_mut();
        }
        cur.add_port(port, rule_idx);
    }

    /// IPv4 按 '.' 拆成 4 段，正向路径（与域名反向区分开，同树共存）。
    fn ipv4_labels(ip: &IpAddr) -> Option<Vec<String>> {
        match ip {
            IpAddr::V4(a) => {
                let o = a.octets();
                Some(vec![
                    o[0].to_string(),
                    o[1].to_string(),
                    o[2].to_string(),
                    o[3].to_string(),
                ])
            }
            IpAddr::V6(_) => None,
        }
    }

    /// 精确 IP 或 ip:port：路径为 ip 的 4 段，末端记 port（0 表示任意端口，同时写 apex）。
    fn add_ip_exact(&mut self, ip: IpAddr, port: u16, rule_idx: usize) {
        let Some(labels) = Self::ipv4_labels(&ip) else { return };
        let mut cur = &mut self.root;
        for label in &labels {
            cur = cur
                .children
                .entry(label.clone())
                .or_insert_with(|| Box::new(DomainTreeNode::new()))
                .as_mut();
        }
        cur.add_port(port, rule_idx);
        if port == 0 {
            cur.add_apex(rule_idx);
        }
    }

    /// CIDR 如 192.168.1.0/24：路径为前缀段（/24 为 3 段），该层设 wildcard。
    fn add_ip_cidr(&mut self, net: &IpNet, rule_idx: usize) {
        let IpAddr::V4(a) = net.network() else { return };
        let o = a.octets();
        let prefix_len = net.prefix_len();
        let segments = match prefix_len {
            0..=8 => 1,
            9..=16 => 2,
            17..=24 => 3,
            25..=32 => 4,
            _ => return,
        };
        let labels: Vec<String> = (0..segments).map(|i| o[i].to_string()).collect();
        let mut cur = &mut self.root;
        for label in &labels {
            cur = cur
                .children
                .entry(label.clone())
                .or_insert_with(|| Box::new(DomainTreeNode::new()))
                .as_mut();
        }
        cur.add_wildcard(rule_idx);
    }
}

pub fn parse_rules(rules: &[RuleConfig]) -> anyhow::Result<Vec<Rule>> {
    rules
        .iter()
        .map(|r| {
            let target = parse_target(&r.target, r.headers.as_ref(), r.wss_ech.as_ref())?;
            let patterns = parse_domains(r.domains.as_deref().unwrap_or(""))?;
            Ok(Rule {
                name: r.name.clone(),
                target,
                patterns,
            })
        })
        .collect()
}

pub fn parse_users(users: &[UserConfig]) -> Vec<User> {
    users.iter().map(User::from_cfg).collect()
}

pub fn parse_domain_patterns(domains: &str) -> anyhow::Result<Vec<DomainPattern>> {
    parse_domains(domains)
}

/// 直连白名单条目：网段 + 可选端口约束（无则任意端口）
#[derive(Debug, Clone)]
struct DirectAccessEntry {
    net: IpNet,
    ports: Option<Vec<PortAllow>>,
}

#[derive(Debug, Clone)]
enum PortAllow {
    Single(u16),
    Range(u16, u16),
}

impl DirectAccessEntry {
    fn allows(&self, ip: IpAddr, port: u16) -> bool {
        if !self.net.contains(&ip) {
            return false;
        }
        let Some(ref ports) = self.ports else {
            return true;
        };
        ports.iter().any(|p| match p {
            PortAllow::Single(a) => *a == port,
            PortAllow::Range(lo, hi) => port >= *lo && port <= *hi,
        })
    }
}

/// 编译后的直连白名单；空列表在调用方表示为 None（不限制）。
#[derive(Debug, Clone)]
pub struct DirectAccessWhitelist {
    entries: Vec<DirectAccessEntry>,
}

impl DirectAccessWhitelist {
    pub fn allows(&self, ip: IpAddr, port: u16) -> bool {
        self.entries.iter().any(|e| e.allows(ip, port))
    }
}

/// 解析 direct_access_white_list 配置。单条格式：CIDR、CIDR:port、CIDR:[port,range,...]、IP:port、IP:[port,range,...]。
pub fn parse_direct_access_white_list(raw: &[String]) -> anyhow::Result<DirectAccessWhitelist> {
    let mut entries = Vec::new();
    for s in raw {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        // 从最后一个 ':' 分开，区分 "host" 与 "port 部分"（port 可能是 80 或 [80,443,30000-39999]）
        let (host_part, port_part) = if let Some(idx) = s.rfind(':') {
            let (h, p) = s.split_at(idx);
            (h.trim(), p.trim().trim_start_matches(':'))
        } else {
            (s, "")
        };
        let net = if host_part.contains('/') {
            host_part.parse::<IpNet>().context("invalid direct_access cidr")?
        } else {
            let ip = host_part.parse::<IpAddr>().context("invalid direct_access ip/host")?;
            IpNet::from(ip)
        };
        let ports = if port_part.is_empty() {
            None
        } else {
            let inner = port_part
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .unwrap_or(port_part);
            let mut list = Vec::new();
            for token in inner.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
                if let Some((a, b)) = token.split_once('-') {
                    let lo = a.trim().parse::<u16>().context("invalid port range low")?;
                    let hi = b.trim().parse::<u16>().context("invalid port range high")?;
                    if lo <= hi {
                        list.push(PortAllow::Range(lo, hi));
                    }
                } else {
                    list.push(PortAllow::Single(
                        token.parse::<u16>().context("invalid port in direct_access list")?,
                    ));
                }
            }
            if list.is_empty() {
                None
            } else {
                Some(list)
            }
        };
        entries.push(DirectAccessEntry { net, ports });
    }
    Ok(DirectAccessWhitelist { entries })
}

fn parse_target(
    target: &str,
    headers: Option<&Vec<HeaderConfig>>,
    wss_ech_yaml: Option<&RuleWssEchYaml>,
) -> anyhow::Result<UpstreamTarget> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix("HTTP ") {
        let (host, port) = split_host_port(rest.trim())?;
        return Ok(UpstreamTarget::HttpProxy { host, port });
    }

    if let Some(rest) = target.strip_prefix("SOCKS5 ") {
        let (host, port) = split_host_port(rest.trim())?;
        return Ok(UpstreamTarget::Socks5Proxy { host, port });
    }

    if target.starts_with("ws://") || target.starts_with("wss://") {
        let _ = Url::parse(target).context("invalid ws/wss url")?;
        let mut hdrs = BTreeMap::new();
        if let Some(list) = headers {
            for h in list {
                match h {
                    HeaderConfig::Map(m) => {
                        for (k, v) in m {
                            hdrs.insert(k.clone(), v.clone());
                        }
                    }
                    HeaderConfig::Line(line) => {
                        if let Some((k, v)) = line.split_once(':') {
                            hdrs.insert(k.trim().to_string(), v.trim().to_string());
                        }
                    }
                }
            }
        }
        let wss_ech = if let Some(y) = wss_ech_yaml {
            if !y.enable {
                None
            } else {
                let host_from_hdr = hdrs
                    .get("Host")
                    .or_else(|| hdrs.get("host"))
                    .map(|s| {
                        s.split(':')
                            .next()
                            .unwrap_or(s.as_str())
                            .trim()
                            .to_string()
                    })
                    .filter(|s| !s.is_empty());
                let url_host = Url::parse(target)
                    .ok()
                    .and_then(|u| u.host_str().map(|s| s.to_string()));
                let inner = y
                    .inner_hostname
                    .clone()
                    .or(host_from_hdr)
                    .or(url_host)
                    .filter(|s| !s.is_empty())
                    .context("wss-ech enable: set inner_hostname, or Host header, or use a domain in wss URL")?;
                if y.ech_config_file.is_none() && !y.ech_doh_lookup {
                    anyhow::bail!("wss-ech: set ech-config-file or ech-doh-lookup: true");
                }
                Some(WssEchSettings {
                    inner_hostname: inner,
                    connect_host: y.connect_host.clone(),
                    ech_config_file: y.ech_config_file.clone(),
                    ech_doh_lookup: y.ech_doh_lookup,
                    ech_doh_cloudflare: y.ech_doh_cloudflare,
                })
            }
        } else {
            None
        };
        return Ok(UpstreamTarget::WsProxy {
            url_template: target.to_string(),
            headers: hdrs,
            wss_ech,
        });
    }

    anyhow::bail!("unsupported rule target: {target}");
}

fn split_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    let s = s.trim();
    let mut parts = s.rsplitn(2, ':');
    let port = parts
        .next()
        .context("missing port")?
        .parse::<u16>()
        .context("invalid port")?;
    let host = parts.next().context("missing host")?.trim().to_string();
    Ok((host, port))
}

fn parse_domains(domains: &str) -> anyhow::Result<Vec<DomainPattern>> {
    let mut out = Vec::new();
    for raw in domains
        .split(|c| c == ',' || c == '\n' || c == '\r')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        // host:port 精确匹配（先于 Cidr/Ip，避免 "192.168.10.20:32567" 被当纯 IP）
        if let Some((host_part, port_str)) = raw.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                let host = host_part.trim().to_ascii_lowercase();
                if !host.is_empty() {
                    out.push(DomainPattern::ExactHostPort(host, port));
                    continue;
                }
            }
        }
        if let Ok(net) = raw.parse::<IpNet>() {
            out.push(DomainPattern::Cidr(net));
            continue;
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            out.push(DomainPattern::Ip(ip));
            continue;
        }
        if raw.contains('*') || raw.contains('?') {
            out.push(DomainPattern::Wildcard(raw.to_ascii_lowercase()));
        } else {
            out.push(DomainPattern::Exact(raw.to_ascii_lowercase()));
        }
    }
    Ok(out)
}

/// 规范化 host：去首尾空白、若带端口则去掉、去尾部点、转小写。
pub fn normalize_host_for_match(host: &str) -> String {
    let s = host.trim().trim_end_matches('.');
    let (h, _) = s
        .rsplit_once(':')
        .filter(|(_, port_str)| port_str.trim().parse::<u16>().is_ok())
        .map(|(a, _)| (a.trim().trim_end_matches('.'), ()))
        .unwrap_or((s, ()));
    h.to_ascii_lowercase()
}

/// 编译后的规则：规则列表 + 统一树（域名按反向标签，IP 按 '.' 四段正向，ip:0/ip:port/CIDR 均入树）。
pub struct CompiledRules {
    pub rules: Vec<Rule>,
    domain_tree: DomainTree,
}

impl CompiledRules {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut domain_tree = DomainTree::from_rules(&rules);

        for (rule_idx, r) in rules.iter().enumerate() {
            for p in &r.patterns {
                match p {
                    DomainPattern::Ip(addr) => {
                        domain_tree.add_ip_exact(*addr, 0, rule_idx);
                    }
                    DomainPattern::Cidr(net) => {
                        domain_tree.add_ip_cidr(net, rule_idx);
                    }
                    DomainPattern::ExactHostPort(host, port) => {
                        if let Ok(addr) = host.trim().parse::<IpAddr>() {
                            domain_tree.add_ip_exact(addr, *port, rule_idx);
                        } else {
                            domain_tree.add_exact_host_port(host, *port, rule_idx);
                        }
                    }
                    _ => {}
                }
            }
        }

        Self { rules, domain_tree }
    }

    /// 统一走树：先按 host 查（IP 则四段正向，否则域名反向），若有解析出的 ip 再按 ip 查，取最小规则下标。
    pub fn select_rule<'a>(&'a self, host: &str, port: u16, ip: Option<IpAddr>) -> Option<&'a Rule> {
        let host_lc = normalize_host_for_match(host);
        let mut best = self.domain_tree.lookup(&host_lc, port);
        if let Some(addr) = ip {
            if let Some(idx) = self.domain_tree.lookup_ip(addr, port) {
                best = Some(best.map_or(idx, |b| b.min(idx)));
            }
        }
        best.map(|i| &self.rules[i])
    }
}

pub fn users_by_name(users: Vec<User>) -> HashMap<String, User> {
    users.into_iter().map(|u| (u.name.clone(), u)).collect()
}

