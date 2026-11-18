use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// 版本号，用于 ws-proxy 同协议透传：握手头 ws-proxy 与此一致时做底层流 relay。格式建议 年月日时分 如 202603161336。
    #[serde(default)]
    pub version: Option<String>,
    pub proxy_server: ProxyServerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyServerConfig {
    pub http_proxy_enable: bool,
    pub https_proxy_enable: bool,
    pub socks5_proxy_enable: bool,

    pub ws_proxy: Option<WsProxyConfig>,
    pub web_ui: Option<WebUiConfig>,

    pub allow_anonymous: bool,
    pub no_tls_enable: bool,
    #[serde(default)]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub bind_port: Option<u16>,

    pub tls_enable: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    /// Optional TLS listener port for Web UI and WS proxy.
    /// If not set and `tls_enable=true`, default is `bind_port + 1`.
    pub tls_bind_port: Option<u16>,

    pub log: Option<LogConfig>,

    /// 是否允许本地直连：匹配不上规则时是否允许直接连接目标。为 false 时禁止直连。
    #[serde(default = "default_true")]
    pub allow_direct_access: bool,
    /// 直连白名单：仅当 allow_direct_access=true 时生效。格式：CIDR 或 CIDR:port 或 IP:port 或 IP:[port,range,...]，如 10.20.0.0/24、192.168.1.1:80、192.168.1.1:[80,443,30000-39999]。空列表表示不限制（全部允许）。
    #[serde(default)]
    pub direct_access_white_list: Vec<String>,

    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub dns_domains: Vec<DnsDomainConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WsProxyConfig {
    pub enable: bool,
    pub path: String,
    pub token: String,
    /// 每分钟请求限制（按客户端 IP）。0 表示不限制；1 表示每分钟最多 1 次，以此类推。超限返回 429。
    #[serde(default)]
    pub rate_limit_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebUiConfig {
    pub enable: bool,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    pub enable: bool,
    pub level: String,
    pub path: String,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserConfig {
    pub name: String,
    pub password: String,
    pub auth_rules: Option<String>,
    #[serde(default)]
    pub is_admin: bool,
}

/// 隧道类型：ssh = WebSSH 协议；tcp = 本地绑定端口，经代理转发到 target。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    Ssh,
    Tcp,
}

impl Default for TunnelType {
    fn default() -> Self {
        TunnelType::Ssh
    }
}

/// 隧道端点：WebSSH 或 TCP 隧道，tunnel_name 每条 rule 内唯一。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketTunnelEndpoint {
    pub tunnel_name: String,
    pub name: String,
    pub target: String,
    /// ssh = WebSSH；tcp = TCP 隧道，需配置 bind_address。
    #[serde(default, rename = "type")]
    pub type_: TunnelType,
    /// TCP 类型时必填：本地监听地址，如 127.0.0.1:18889。
    #[serde(default, rename = "bind_address")]
    pub bind_address: Option<String>,
    /// SSH 登录用户名，密码不配置，需在终端中手动输入。
    #[serde(default)]
    pub user: Option<String>,
    /// 是否在访问时自动连接并尝试使用记录的握手信息。
    #[serde(default, rename = "auto_connect")]
    pub auto_connect: Option<bool>,
}

/// Optional Encrypted Client Hello (ECH) for rules whose target is `wss://...`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuleWssEchYaml {
    #[serde(default)]
    pub enable: bool,
    /// Inner TLS hostname (ECH + DoH query). Defaults to `Host` header hostname or URL host.
    #[serde(default)]
    pub inner_hostname: Option<String>,
    /// TCP connect target when split from URL (e.g. outer CDN name). Defaults to URL host.
    #[serde(default, rename = "connect-host")]
    pub connect_host: Option<String>,
    /// Raw ECHConfigList (TLS binary). If set, DoH lookup is skipped.
    #[serde(default, rename = "ech-config-file")]
    pub ech_config_file: Option<String>,
    /// When no `ech-config-file`, fetch `echconfig` via DNS-over-HTTPS (default true).
    #[serde(default = "default_true")]
    pub ech_doh_lookup: bool,
    /// Use Cloudflare DoH (`1.1.1.1`); if false use Google.
    #[serde(default = "default_true", rename = "ech-doh-cloudflare")]
    pub ech_doh_cloudflare: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfig {
    pub name: String,
    pub target: String,
    pub domains: Option<String>,
    pub headers: Option<Vec<HeaderConfig>>,
    #[serde(default, rename = "websocket-tunnel")]
    pub websocket_tunnel: Option<Vec<WebsocketTunnelEndpoint>>,
    #[serde(default, rename = "wss-ech")]
    pub wss_ech: Option<RuleWssEchYaml>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HeaderConfig {
    Map(BTreeMap<String, String>),
    Line(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsDomainConfig {
    pub name: String,
    pub domains: Option<String>,
    #[serde(default)]
    pub servers: Vec<String>,
}

pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let cfg: Config = serde_yaml::from_str(&content)?;
    Ok(cfg)
}

pub fn save_config(path: &str, cfg: &Config) -> anyhow::Result<()> {
    let yaml = serde_yaml::to_string(cfg)?;
    std::fs::write(path, yaml)?;
    Ok(())
}

