mod auth;
mod config;
mod dns;
mod model;
mod proxy;
mod socks5;
mod socks5_upstream;
mod tls;
mod ws_rate_limit;
mod ws_upstream_raw;
mod wss_ech;
mod ui;
mod ws_server;
mod webssh_ssh;
mod stats;

use crate::config::{load_config, TunnelType};
use crate::dns::{parse_dns_groups, DnsManager};
use crate::model::{parse_rules, parse_users, users_by_name, CompiledRules};
use anyhow::Context;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::header::AUTHORIZATION;
use hyper::service::service_fn;
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use std::convert::Infallible;
use hyper_tungstenite::is_upgrade_request as is_ws_upgrade_request;
use hyper_util::rt::tokio::TokioIo;
use tokio_rustls::TlsAcceptor;

const CONFIG_PATH: &str = "config.yaml";

#[derive(Clone)]
pub(crate) struct AppStateInner {
    pub config_path: String,
    pub cfg: Arc<config::Config>,
    pub users: Arc<std::collections::HashMap<String, model::User>>,
    pub rules: Arc<CompiledRules>,
    pub dns: Option<Arc<DnsManager>>,
    pub stats: Arc<stats::DailyStats>,
    /// 直连白名单（仅当 direct_access_white_list 非空时存在）；与 allow_direct_access 配合限制本地直连目标。
    pub direct_whitelist: Option<Arc<model::DirectAccessWhitelist>>,
    /// ws_proxy 请求频率限制状态（按 IP 每分钟计数）。
    pub ws_proxy_rate_limiter: Arc<ws_rate_limit::WsProxyRateLimiter>,
}

/// Shared state: UI can replace cfg/users/rules/dns on save; workers read via clone.
pub(crate) type AppState = Arc<RwLock<AppStateInner>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = load_config(CONFIG_PATH).context("read config.yaml")?;

    init_logging(&cfg)?;

    let users = users_by_name(parse_users(&cfg.proxy_server.users));
    let rules = CompiledRules::new(parse_rules(&cfg.proxy_server.rules)?);
    let dns = if cfg.proxy_server.dns_domains.is_empty() {
        None
    } else {
        Some(Arc::new(DnsManager::new(parse_dns_groups(
            &cfg.proxy_server.dns_domains,
        )?)?))
    };

    let mut has_endpoint = false;

    // TCP tunnel listeners (type=tcp): bind bind_address, forward to target via rule. Spawn before moving rules into state.
    for rule_cfg in &cfg.proxy_server.rules {
        let Some(ref endpoints) = rule_cfg.websocket_tunnel else { continue };
        for ep in endpoints {
            if ep.type_ != TunnelType::Tcp {
                continue;
            }
            let Some(ref bind_addr_str) = ep.bind_address else {
                tracing::warn!("tcp tunnel {} missing bind_address", ep.tunnel_name);
                continue;
            };
            let bind_addr: SocketAddr = match bind_addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        "tcp tunnel {} invalid bind_address {}: {}",
                        ep.tunnel_name,
                        bind_addr_str,
                        e
                    );
                    continue;
                }
            };
            let (target_host, target_port) = match ep.target.rfind(':') {
                Some(i) => {
                    let host = ep.target[..i].to_string();
                    let port: u16 = ep.target[i + 1..].parse().unwrap_or(22);
                    (host, port)
                }
                None => (ep.target.clone(), 22u16),
            };
            let Some(compiled_rule) = rules.rules.iter().find(|r| r.name == rule_cfg.name).cloned() else {
                continue;
            };
            let rule_name = rule_cfg.name.clone();
            let tunnel_name = ep.tunnel_name.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    run_tcp_tunnel_listener(bind_addr, compiled_rule, target_host, target_port).await
                {
                    tracing::warn!("tcp tunnel {}:{} error: {e:#}", rule_name, tunnel_name);
                }
            });
        }
        if endpoints.len() > 0 {
            has_endpoint = true;
        }
    }

    let direct_whitelist = if cfg.proxy_server.direct_access_white_list.is_empty() {
        None
    } else {
        Some(Arc::new(model::parse_direct_access_white_list(
            &cfg.proxy_server.direct_access_white_list,
        )?))
    };
    let inner = AppStateInner {
        config_path: CONFIG_PATH.to_string(),
        cfg: Arc::new(cfg.clone()),
        users: Arc::new(users),
        rules: Arc::new(rules),
        dns,
        stats: Arc::new(stats::DailyStats::default()),
        direct_whitelist,
        ws_proxy_rate_limiter: Arc::new(ws_rate_limit::WsProxyRateLimiter::new()),
    };
    let state: AppState = Arc::new(RwLock::new(inner));

    let bind_address = cfg.proxy_server.bind_address.unwrap_or("0.0.0.0".to_string());
    // Optional TLS listener for Web UI + WS proxy (on a separate port).
    if cfg.proxy_server.tls_enable {
        if let (Some(cert), Some(key)) = (
            cfg.proxy_server.tls_cert_file.as_deref(),
            cfg.proxy_server.tls_key_file.as_deref(),
        ) {
            let tls_port = cfg
                .proxy_server
                .tls_bind_port
                .unwrap_or(cfg.proxy_server.bind_port.unwrap_or(1081).saturating_add(1));
            let tls_bind: SocketAddr = format!("{}:{}", bind_address, tls_port)
                .parse()
                .context("invalid tls bind address/port")?;
            let tls_listener = TcpListener::bind(tls_bind).await?;
            let tls_cfg = tls::load_rustls_config(cert, key)?;
            let acceptor = TlsAcceptor::from(tls_cfg);
            let st = state.clone();
            tokio::spawn(async move {
                tracing::info!(%tls_bind, "tls listening for /ui and /ws");
                loop {
                    let (tcp, addr) = match tls_listener.accept().await {
                        Ok(x) => x,
                        Err(e) => {
                            tracing::warn!("tls accept error: {e}");
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let st2 = st.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp).await {
                            Ok(tls_stream) => {
                                let (cfg, users, rules, dns, stats, direct_whitelist) = {
                                    let g = st2.read().await;
                                    (
                                        g.cfg.clone(),
                                        g.users.clone(),
                                        g.rules.clone(),
                                        g.dns.clone(),
                                        g.stats.clone(),
                                        g.direct_whitelist.clone(),
                                    )
                                };
                                if let Err(e) = serve_http_tls(
                                    tls_stream, addr, st2, cfg, users, rules, dns, stats, direct_whitelist,
                                )
                                .await
                                {
                                    tracing::debug!(%addr, "tls http error: {e:#}");
                                }
                            }
                            Err(e) => tracing::debug!(%addr, "tls handshake error: {e}"),
                        }
                    });
                }
            });
        } else {
            tracing::warn!("tls_enable=true but tls_cert_file/tls_key_file not set; tls listener disabled");
        }
    }
    
    if !cfg.proxy_server.no_tls_enable && (cfg.proxy_server.http_proxy_enable
    || cfg.proxy_server.https_proxy_enable
    || cfg.proxy_server.socks5_proxy_enable) {
        tracing::warn!("no_tls_enable is false but http/https/socks5 dependency, update your config to enable no_tls_enable");
    }

    // no_tls_enable=true 时在 bind_port 上监听不安全的 TCP；否则仅靠 TLS 监听 / TCP tunnel 等，需阻塞 main 以免进程退出
    if cfg.proxy_server.no_tls_enable {
        let bind: SocketAddr = format!(
            "{}:{}",
            bind_address, cfg.proxy_server.bind_port.unwrap_or(1081) 
        )
        .parse()
        .context("invalid bind address/port")?;
        let listener = TcpListener::bind(bind).await?;
        tracing::info!(%bind, "listening");
        loop {
            let (stream, addr) = listener.accept().await?;
            let st = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, addr, st).await {
                    tracing::debug!(%addr, "conn error: {e:#}");
                }
            });
        }
    } else if has_endpoint {
        // 无明文监听时等待 Ctrl+C，避免 main 返回导致进程退出、spawn 的 TLS / TCP tunnel 等被杀死
        tokio::signal::ctrl_c().await.context("ctrl_c")?;
        tracing::info!("shutting down");
    }
    Ok(())
}

fn init_logging(cfg: &config::Config) -> anyhow::Result<()> {
    let log_cfg = match &cfg.proxy_server.log {
        Some(l) if l.enable => l,
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter("info")
                .with_target(false)
                .init();
            return Ok(());
        }
    };

    let level = log_cfg.level.clone();
    let filter = tracing_subscriber::EnvFilter::try_new(level).unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info")
    });

    let log_path = std::path::Path::new(&log_cfg.path);
    let (dir, file) = match (log_path.parent(), log_path.file_name()) {
        (Some(d), Some(f)) => (d, f.to_string_lossy().to_string()),
        _ => (std::path::Path::new("."), "proxy.log".to_string()),
    };
    if !dir.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(dir);
    }

    let file_appender = tracing_appender::rolling::never(dir, file);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive forever by leaking it. (Simple service-style process.)
    std::mem::forget(_guard);

    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false);

    if log_cfg.encoding.as_deref().unwrap_or("text") == "json" {
        fmt.json().init();
    } else {
        fmt.init();
    }
    Ok(())
}

/// 在 bind_addr 上监听，每接受一个连接则经 rule 代理连到 target，并双向转发。
async fn run_tcp_tunnel_listener(
    bind_addr: SocketAddr,
    rule: model::Rule,
    target_host: String,
    target_port: u16,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "tcp tunnel listening");
    loop {
        let (mut client_stream, client_addr) = listener.accept().await?;
        let rule = rule.clone();
        let target_host = target_host.clone();
        tokio::spawn(async move {
            const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
            let connect_result = tokio::time::timeout(
                UPSTREAM_CONNECT_TIMEOUT,
                proxy::connect_tcp_via_rule(&rule, &target_host, target_port, None),
            )
            .await;

            let remote = match connect_result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%client_addr, "tcp tunnel upstream connect error: {e:#}");
                    let _ = client_stream.shutdown().await;
                    return;
                }
                Err(_) => {
                    tracing::warn!(%client_addr, "tcp tunnel upstream connect timeout after {:?}", UPSTREAM_CONNECT_TIMEOUT);
                    let _ = client_stream.shutdown().await;
                    return;
                }
            };

            if let Err(e) = remote.run_tunnel(client_stream).await {
                tracing::debug!(%client_addr, "tcp tunnel bridge error: {e:#}");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let (cfg, users, rules, dns, stats, direct_whitelist) = {
        let g = state.read().await;
        (
            g.cfg.clone(),
            g.users.clone(),
            g.rules.clone(),
            g.dns.clone(),
            g.stats.clone(),
            g.direct_whitelist.clone(),
        )
    };
    // Peek first byte to detect SOCKS5.
    let mut buf = [0u8; 1];
    let n = stream.peek(&mut buf).await?;
    if n == 1 && buf[0] == 0x05 {
        if !cfg.proxy_server.socks5_proxy_enable {
            anyhow::bail!("socks5 disabled");
        }
        return socks5::handle_socks5(
            stream,
            addr,
            cfg.proxy_server.allow_anonymous,
            &users,
            rules.as_ref(),
            dns.as_deref(),
            Some(&stats),
            cfg.proxy_server.allow_direct_access,
            direct_whitelist.as_deref(),
        )
        .await;
    }

    let ws_enabled = cfg.proxy_server.ws_proxy.as_ref().map_or(false, |c| c.enable);
    if !(cfg.proxy_server.http_proxy_enable || cfg.proxy_server.https_proxy_enable || ws_enabled) {
        anyhow::bail!("http/https proxy disabled");
    }

    serve_http(stream, addr, state, cfg, users, rules, dns, stats, direct_whitelist).await
}

async fn serve_http(
    stream: TcpStream,
    client_addr: SocketAddr,
    state: AppState,
    cfg: Arc<config::Config>,
    users: Arc<std::collections::HashMap<String, model::User>>,
    rules: Arc<CompiledRules>,
    dns: Option<Arc<DnsManager>>,
    stats: Arc<stats::DailyStats>,
    direct_whitelist: Option<Arc<model::DirectAccessWhitelist>>,
) -> anyhow::Result<()> {
    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
        let st = state.clone();
        let cfg = cfg.clone();
        let users = users.clone();
        let rules = rules.clone();
        let dns = dns.clone();
        let stats = stats.clone();
        let direct_whitelist = direct_whitelist.clone();
        async move { route_http(req, client_addr, st, cfg, users, rules, dns, stats, direct_whitelist).await }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await?;

    Ok(())
}

async fn serve_http_tls(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    client_addr: SocketAddr,
    state: AppState,
    cfg: Arc<config::Config>,
    users: Arc<std::collections::HashMap<String, model::User>>,
    rules: Arc<CompiledRules>,
    dns: Option<Arc<DnsManager>>,
    stats: Arc<stats::DailyStats>,
    direct_whitelist: Option<Arc<model::DirectAccessWhitelist>>,
) -> anyhow::Result<()> {
    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
        let st = state.clone();
        let cfg = cfg.clone();
        let users = users.clone();
        let rules = rules.clone();
        let dns = dns.clone();
        let stats = stats.clone();
        let direct_whitelist = direct_whitelist.clone();
        async move { route_http(req, client_addr, st, cfg, users, rules, dns, stats, direct_whitelist).await }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await?;
    Ok(())
}


async fn route_http(
    req: Request<hyper::body::Incoming>,
    client_addr: SocketAddr,
    state: AppState,
    cfg: Arc<config::Config>,
    users: Arc<std::collections::HashMap<String, model::User>>,
    rules: Arc<CompiledRules>,
    dns: Option<Arc<DnsManager>>,
    stats: Arc<stats::DailyStats>,
    direct_whitelist: Option<Arc<model::DirectAccessWhitelist>>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let ws_cfg = cfg.proxy_server.ws_proxy.as_ref().filter(|c| c.enable);
    let ui_cfg = cfg.proxy_server.web_ui.as_ref().filter(|c| c.enable);

    if let Some(ws_cfg) = ws_cfg {
        if path == ws_cfg.path && ws_server::is_ws_upgrade(&req) {
            if !proxy::ws_proxy_token_ok(&req, &ws_cfg.token) {
                return Ok(ws_server::plain_response(
                    hyper::StatusCode::UNAUTHORIZED,
                    "invalid token",
                ));
            }
            if ws_cfg.rate_limit_per_minute > 0 {
                let limiter = {
                    let g = state.read().await;
                    g.ws_proxy_rate_limiter.clone()
                };
                if !limiter.try_allow(client_addr.ip(), ws_cfg.rate_limit_per_minute) {
                    tracing::warn!(%client_addr, "ws proxy rate limit exceeded");
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::TOO_MANY_REQUESTS,
                        "rate limit exceeded",
                    ));
                }
            }
            let proxy_target = match ws_server::parse_query_param(req.uri(), "proxy") {
                Some(v) => v,
                None => {
                    tracing::warn!(%client_addr, "missing proxy param");
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "missing proxy param",
                    ))
                }
            };
            let (host, port) = match proxy_target.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(port) => (h.to_string(), port),
                    _ => {
                        return Ok(ws_server::plain_response(
                            hyper::StatusCode::BAD_REQUEST,
                            "invalid proxy param (host:port)",
                        ));
                    }
                },
                None => {
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "invalid proxy param (host:port)",
                    ));
                }
            };
            // 先按规则匹配；命中则经代理转发，未命中再走本地直连并做直连/白名单校验
            let mut ip = host.parse::<std::net::IpAddr>().ok();
            let mut chosen = rules.select_rule(&host, port, ip);
            if chosen.is_none() {
                if let Some(ref d) = dns {
                    if let Ok(Some(resolved)) = d.resolve_ip(&host).await {
                        tracing::info!("resolve domain {} to ip {}", host, resolved);
                        ip = Some(resolved);
                        chosen = rules.select_rule(&host, port, Some(resolved));
                        tracing::info!("chosen rule: {:?}", chosen);
                    }
                }
            }
            let chosen_rule = chosen.cloned();
            if chosen_rule.is_none() {
                if !cfg.proxy_server.allow_direct_access {
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::FORBIDDEN,
                        "direct access disabled by config",
                    ));
                }
                if let Some(ref w) = direct_whitelist {
                    let check_ip = match ip {
                        Some(i) => i,
                        None => {
                            match dns.as_ref() {
                                Some(d) => match d.resolve_ip(&host).await {
                                    Ok(Some(addr)) => addr,
                                    _ => {
                                        return Ok(ws_server::plain_response(
                                            hyper::StatusCode::FORBIDDEN,
                                            "could not resolve host for direct whitelist",
                                        ));
                                    }
                                },
                                None => {
                                    return Ok(ws_server::plain_response(
                                        hyper::StatusCode::FORBIDDEN,
                                        "direct whitelist requires resolvable host",
                                    ));
                                }
                            }
                        }
                    };
                    if !w.allows(check_ip, port) {
                        return Ok(ws_server::plain_response(
                            hyper::StatusCode::FORBIDDEN,
                            "direct access not in whitelist",
                        ));
                    }
                }
            }
            let ws_proxy_header = req
                .headers()
                .get("ws-proxy")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string());
            let same_protocol_downstream = cfg
                .version
                .as_ref()
                .zip(ws_proxy_header.as_ref())
                .map_or(false, |(a, b)| a == b);
            let version_for_tunnel = cfg.version.clone();
            // Manual upgrade so we get the raw stream for same-protocol raw relay.
            match ws_server::websocket_upgrade_manual(req) {
                Ok((resp, on_upgrade)) => {
                    let host = host.clone();
                    tokio::spawn(async move {
                        let upgraded = match on_upgrade.await {
                            Ok(u) => u,
                            Err(e) => {
                                tracing::warn!(%client_addr, "ws upgrade failed: {}", e);
                                return;
                            }
                        };
                        let stream = hyper_util::rt::TokioIo::new(upgraded);
                        if let Err(e) = ws_server::serve_ws_tunnel_via_rule_or_direct_with_upgraded(
                            stream,
                            client_addr,
                            host,
                            port,
                            proxy_target,
                            chosen_rule,
                            same_protocol_downstream,
                            version_for_tunnel,
                        )
                        .await
                        {
                            tracing::warn!(%client_addr, "ws tunnel error: {e:#}");
                        }
                    });
                    return Ok(resp.map(|b| b.boxed()));
                }
                Err(e) => {
                    tracing::debug!("ws upgrade error: {e:#}");
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "ws upgrade failed",
                    ));
                }
            }
        }
    }

    if let Some(ui_cfg) = ui_cfg {
        if path.starts_with(&ui_cfg.path) {
            // WebSSH WebSocket upgrade: {path}/webssh/{rule_name}/{tunnel_name}
            let rest = path.strip_prefix(&ui_cfg.path).unwrap_or("").trim_start_matches('/');
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 3 && parts[0] == "webssh" && is_ws_upgrade_request(&req) {
                let rule_name = parts[1];
                let tunnel_name = parts[2];
                let auth_header = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok());
                let Some(current_user) = ui::current_ui_user(auth_header, &users) else {
                    let mut r = ws_server::plain_response(hyper::StatusCode::UNAUTHORIZED, "auth required");
                    r.headers_mut().insert(
                        hyper::header::WWW_AUTHENTICATE,
                        hyper::header::HeaderValue::from_static("Basic realm=\"p-proxy\""),
                    );
                    return Ok(r);
                };
                if !current_user.is_admin && !current_user.allowed_rules.contains(rule_name) {
                    return Ok(ws_server::plain_response(hyper::StatusCode::FORBIDDEN, "rule not allowed"));
                }
                let rule_cfg = cfg.proxy_server.rules.iter().find(|r| r.name == rule_name);
                let endpoint = rule_cfg
                    .and_then(|r| r.websocket_tunnel.as_ref())
                    .and_then(|eps| eps.iter().find(|e| e.tunnel_name == tunnel_name));
                let Some(endpoint) = endpoint else {
                    return Ok(ws_server::plain_response(hyper::StatusCode::NOT_FOUND, "tunnel not found"));
                };
                if endpoint.type_ != TunnelType::Ssh {
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::NOT_FOUND,
                        "tunnel is tcp type, use bind_address to connect",
                    ));
                }
                let (target_host, target_port) = match endpoint.target.rfind(':') {
                    Some(i) => {
                        let host = endpoint.target[..i].to_string();
                        let port: u16 = endpoint.target[i + 1..].parse().unwrap_or(22);
                        (host, port)
                    }
                    None => (endpoint.target.clone(), 22u16),
                };
                let compiled_rule = match rules.rules.iter().find(|r| r.name == rule_name) {
                    Some(r) => r.clone(),
                    None => return Ok(ws_server::plain_response(hyper::StatusCode::BAD_REQUEST, "rule not compiled")),
                };
                let username = endpoint.user.as_deref().unwrap_or("root").to_string();
                match ws_server::websocket_upgrade(req) {
                    Ok((resp, ws)) => {
                                tokio::spawn(async move {
                                    if let Err(e) = ws_server::serve_webssh_with_connect(
                                        ws,
                                        compiled_rule,
                                        target_host,
                                        target_port,
                                        username,
                                    )
                                    .await
                                    {
                                        tracing::info!("webssh error: {e:#}");
                                    }
                                });
                        return Ok(resp.map(|b| b.boxed()));
                    }
                    Err(e) => {
                        tracing::debug!("webssh ws upgrade error: {e:#}");
                        return Ok(ws_server::plain_response(
                            hyper::StatusCode::BAD_REQUEST,
                            "ws upgrade failed",
                        ));
                    }
                }
            }

            match ui::handle_ui(req, state, &cfg, rules.as_ref(), &users, dns.as_deref(), &stats).await
            {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::debug!("ui error: {e:#}");
                    return Ok(ws_server::plain_response(
                        hyper::StatusCode::INTERNAL_SERVER_ERROR,
                        "ui error",
                    ));
                }
            }
        }
    }

    match proxy::handle_http_request(
        req,
        client_addr,
        cfg.proxy_server.allow_anonymous,
        &users,
        rules.as_ref(),
        dns.as_deref(),
        Some(&stats),
        cfg.proxy_server.http_proxy_enable,
        cfg.proxy_server.https_proxy_enable,
        cfg.proxy_server.allow_direct_access,
        direct_whitelist.as_deref(),
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => {
            tracing::debug!("proxy err: {e:#}");
            let msg = format!("proxy error: {e:#}");
            Ok(ws_server::plain_response(hyper::StatusCode::BAD_GATEWAY, &msg))
        }
    }
}
