use crate::auth::is_rule_allowed;
use crate::model::{CompiledRules, UpstreamTarget};
use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::ext::ReasonPhrase;
use hyper::{Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use hyper_util::rt::tokio::TokioIo;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
pub async fn handle_http_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    allow_anonymous: bool,
    users: &HashMap<String, crate::model::User>,
    rules: &CompiledRules,
    dns: Option<&crate::dns::DnsManager>,
    stats: Option<&crate::stats::DailyStats>,
    http_enabled: bool,
    https_enabled: bool,
    allow_direct_access: bool,
    direct_whitelist: Option<&crate::model::DirectAccessWhitelist>,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    if req.method() == Method::CONNECT {
        if !https_enabled {
            return Ok(simple_response(
                StatusCode::FORBIDDEN,
                "https proxy disabled by config",
            ));
        }
        return handle_connect(
            req,
            client_addr,
            allow_anonymous,
            users,
            rules,
            dns,
            stats,
            allow_direct_access,
            direct_whitelist,
        )
        .await;
    }

    // Regular HTTP proxy request (absolute-form usually).
    if !http_enabled {
        return Ok(simple_response(
            StatusCode::FORBIDDEN,
            "http proxy disabled by config",
        ));
    }

    handle_forward_http(
        req,
        allow_anonymous,
        users,
        rules,
        dns,
        stats,
        allow_direct_access,
        direct_whitelist,
    )
    .await
}

fn simple_response(code: StatusCode, msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    let full = Full::new(Bytes::from(msg.to_string()));
    Response::builder().status(code).body(full.boxed()).unwrap()
}

fn proxy_auth_required() -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = simple_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED, "auth required");
    resp.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"p-proxy\""),
    );
    resp
}

async fn handle_forward_http(
    req: Request<Incoming>,
    allow_anonymous: bool,
    users: &HashMap<String, crate::model::User>,
    rules: &CompiledRules,
    dns: Option<&crate::dns::DnsManager>,
    stats: Option<&crate::stats::DailyStats>,
    allow_direct_access: bool,
    direct_whitelist: Option<&crate::model::DirectAccessWhitelist>,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    let proxy_auth = req
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let auth = match crate::auth::authenticate_http(allow_anonymous, proxy_auth, users) {
        Ok(a) => a,
        Err(_) => return Ok(proxy_auth_required()),
    };
    if let Some(s) = stats {
        s.incr(crate::auth::username_for_stats(&auth)).await;
    }

    let (host, port, ip) = infer_destination_for_http(&req)?;
    let mut chosen = rules.select_rule(&host, port, ip);
    let mut resolved_ip = ip;
    if chosen.is_none() {
        if let Some(dns) = dns {
            if let Ok(Some(resolved)) = dns.resolve_ip(&host).await {
                resolved_ip = Some(resolved);
                chosen = rules.select_rule(&host, port, Some(resolved));
            }
        }
    }

    if let Some(rule) = chosen {
        if !is_rule_allowed(&auth, &rule.name) {
            return Ok(simple_response(StatusCode::FORBIDDEN, "rule not allowed"));
        }
        match &rule.target {
            UpstreamTarget::HttpProxy { host: up_host, port: up_port } => {
                return forward_via_upstream_http_proxy(req, up_host, *up_port).await;
            }
            UpstreamTarget::Socks5Proxy { host: up_host, port: up_port } => {
                return forward_via_upstream_socks5_proxy(req, up_host, *up_port).await;
            }
            UpstreamTarget::WsProxy { .. } => {
                return Ok(simple_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "ws upstream only supported for CONNECT/SOCKS5 tunnels",
                ));
            }
        }
    }

    // No matching rule -> direct connect; 需通过直连开关与白名单校验
    if !allow_direct_access {
        return Ok(simple_response(
            StatusCode::FORBIDDEN,
            "direct access disabled by config",
        ));
    }
    if let Some(w) = direct_whitelist {
        let ip = match resolved_ip {
            Some(i) => i,
            None => {
                if let Some(dns) = dns {
                    match dns.resolve_ip(&host).await {
                        Ok(Some(addr)) => addr,
                        _ => {
                            return Ok(simple_response(
                                StatusCode::FORBIDDEN,
                                "could not resolve host for direct whitelist",
                            ));
                        }
                    }
                } else {
                    return Ok(simple_response(
                        StatusCode::FORBIDDEN,
                        "direct whitelist requires resolvable host",
                    ));
                }
            }
        };
        if !w.allows(ip, port) {
            return Ok(simple_response(
                StatusCode::FORBIDDEN,
                "direct access not in whitelist",
            ));
        }
    }
    forward_direct_http(req).await
}

async fn forward_direct_http(req: Request<Incoming>) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    let (mut parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();

    let (host, port, _ip) = {
        if let Some(auth) = parts.uri.authority() {
            let host = auth.host().to_string();
            let port = auth.port_u16().unwrap_or(80);
            (host.clone(), port, host.parse::<IpAddr>().ok())
        } else if let Some(h) = parts.headers.get(HOST).and_then(|v| v.to_str().ok()) {
            let (h, p) = split_host_port_default(h, 80).unwrap();
            (h.to_string(), p, h.parse::<IpAddr>().ok())
        } else {
            anyhow::bail!("unable to infer destination for direct http");
        }
    };

    strip_hop_by_hop_headers(&mut parts.headers);
    let origin_path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let uri: hyper::Uri = format!("http://{host}:{port}{origin_path}").parse()?;
    let mut out_req = Request::from_parts(parts, Full::new(bytes));
    *out_req.uri_mut() = uri;

    let stream = TcpStream::connect(format!("{host}:{port}")).await?;
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("direct http conn error: {e}");
        }
    });

    let resp = sender.send_request(out_req).await?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let resp = Response::from_parts(parts, Full::new(bytes));
    Ok(resp.map(|b| b.boxed()))
}

fn infer_destination_for_http(req: &Request<Incoming>) -> anyhow::Result<(String, u16, Option<IpAddr>)> {
    // For proxy requests, destination is usually in absolute-form URI, or in Host header.
    let uri = req.uri();
    if let Some(auth) = uri.authority() {
        let host = auth.host().to_string();
        let port = auth.port_u16().unwrap_or(80);
        let ip = host.parse::<IpAddr>().ok();
        return Ok((host, port, ip));
    }
    if let Some(h) = req.headers().get(HOST).and_then(|v| v.to_str().ok()) {
        if let Some((host, port)) = split_host_port_default(h, 80) {
            let ip = host.parse::<IpAddr>().ok();
            return Ok((host.to_string(), port, ip));
        }
    }
    anyhow::bail!("unable to infer http destination")
}

pub(crate) fn split_host_port_default(s: &str, default_port: u16) -> Option<(&str, u16)> {
    let s = s.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h, port));
        }
    }
    Some((s, default_port))
}

/// Remove hop-by-hop headers before forwarding to upstream so connection lifecycle is not tied to client.
fn strip_hop_by_hop_headers(headers: &mut hyper::http::HeaderMap) {
    let hop_names = [
        CONNECTION,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ];
    for name in &hop_names {
        headers.remove(name);
    }
}

async fn forward_via_upstream_http_proxy(
    req: Request<Incoming>,
    upstream_host: &str,
    upstream_port: u16,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    let addr = format!("{upstream_host}:{upstream_port}");
    let stream = TcpStream::connect(addr).await?;
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("upstream http conn error: {e}");
        }
    });

    // Buffer request body to make life simpler (good enough for a first cut).
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let mut out_parts = parts;
    strip_hop_by_hop_headers(&mut out_parts.headers);
    let out_req = Request::from_parts(out_parts, Full::new(bytes));

    let resp = sender.send_request(out_req).await?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let resp = Response::from_parts(parts, Full::new(bytes));
    Ok(resp.map(|b| b.boxed()))
}

async fn forward_via_upstream_socks5_proxy(
    req: Request<Incoming>,
    upstream_host: &str,
    upstream_port: u16,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    // Establish SOCKS5 tunnel to origin, then send origin-form HTTP request.
    let (host, port, _ip) = infer_destination_for_http(&req)?;
    let (mut parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();

    let origin_path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    strip_hop_by_hop_headers(&mut parts.headers);
    let uri: hyper::Uri = origin_path.parse()?;
    let mut out_req = Request::from_parts(parts, Full::new(bytes));
    *out_req.uri_mut() = uri;

    let stream = crate::socks5_upstream::connect_via_socks5_with_context(
        upstream_host,
        upstream_port,
        &host,
        port,
    )
    .await?;
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("upstream socks5 http conn error: {e}");
        }
    });

    let resp = sender.send_request(out_req).await?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let resp = Response::from_parts(parts, Full::new(bytes));
    Ok(resp.map(|b| b.boxed()))
}

async fn handle_connect(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    allow_anonymous: bool,
    users: &HashMap<String, crate::model::User>,
    rules: &CompiledRules,
    dns: Option<&crate::dns::DnsManager>,
    stats: Option<&crate::stats::DailyStats>,
    allow_direct_access: bool,
    direct_whitelist: Option<&crate::model::DirectAccessWhitelist>,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    let proxy_auth = req
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let auth = match crate::auth::authenticate_http(allow_anonymous, proxy_auth, users) {
        Ok(a) => a,
        Err(_) => return Ok(proxy_auth_required()),
    };
    if let Some(s) = stats {
        // Count CONNECT as one request when accepted.
        s.incr(crate::auth::username_for_stats(&auth)).await;
    }

    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .context("missing CONNECT authority")?;
    let (host, port) = parse_connect_authority(&authority)?;
    let mut ip = host.parse::<IpAddr>().ok();

    // CONNECT supports: rule match -> upstream tunnel, else (after DNS fallback) -> direct tunnel.
    let mut chosen = rules.select_rule(&host, port, ip);
    if chosen.is_none() {
        if let Some(dns) = dns {
            if let Ok(Some(resolved)) = dns.resolve_ip(&host).await {
                ip = Some(resolved);
                chosen = rules.select_rule(&host, port, Some(resolved));
            }
        }
    }

    // 直连前校验：未命中规则且走直连时，检查 allow_direct_access 与白名单
    if chosen.is_none() {
        if !allow_direct_access {
            return Ok(simple_response(
                StatusCode::FORBIDDEN,
                "direct access disabled by config",
            ));
        }
        if let Some(w) = direct_whitelist {
            let check_ip = match ip {
                Some(i) => i,
                None => {
                    if let Some(dns) = dns {
                        match dns.resolve_ip(&host).await {
                            Ok(Some(addr)) => addr,
                            _ => {
                                return Ok(simple_response(
                                    StatusCode::FORBIDDEN,
                                    "could not resolve host for direct whitelist",
                                ));
                            }
                        }
                    } else {
                        return Ok(simple_response(
                            StatusCode::FORBIDDEN,
                            "direct whitelist requires resolvable host",
                        ));
                    }
                }
            };
            if !w.allows(check_ip, port) {
                return Ok(simple_response(
                    StatusCode::FORBIDDEN,
                    "direct access not in whitelist",
                ));
            }
        }
    }

    let host_cloned = host.clone();
    let target_cloned = chosen.map(|r| r.target.clone());
    let wss_ech_ref = target_cloned.as_ref().and_then(|t| match t {
        UpstreamTarget::WsProxy { wss_ech, .. } => wss_ech.as_ref(),
        _ => None,
    });
    if let Some(rule) = chosen {
        if !is_rule_allowed(&auth, &rule.name) {
            return Ok(simple_response(StatusCode::FORBIDDEN, "rule not allowed"));
        }
    }
    let on_upgrade = hyper::upgrade::on(req);

    // 参考实现：CONNECT 且 WsProxy 时先连上 WSS 再给客户端 200，避免浏览器先发 ClientHello 后长时间等 ServerHello 导致超时。
    if let Some(UpstreamTarget::WsProxy { url_template, headers, .. }) = &target_cloned {
        const WSS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
        let connect_fut = connect_ws_proxy_upstream(
            &host_cloned,
            port,
            url_template,
            headers,
            wss_ech_ref,
            None,
        );
        let conn_result = match tokio::time::timeout(WSS_CONNECT_TIMEOUT, connect_fut).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                tracing::warn!(%client_addr, "wss upstream connect timed out after {:?}", WSS_CONNECT_TIMEOUT);
                Err(anyhow::anyhow!("wss upstream connect timed out"))
            }
        };
        match conn_result {
            Ok((remote_r, remote_w)) => {
                tokio::spawn(async move {
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let client = TokioIo::new(upgraded);
                            if let Err(e) = tunnel_ws_proxy_loop(client, &host_cloned, port, remote_r, remote_w).await {
                                tracing::warn!(%client_addr, "tunnel error: {e:#}");
                            }
                        }
                        Err(e) => tracing::debug!(%client_addr, "upgrade error: {e}"),
                    }
                });
                let full = Full::new(Bytes::new());
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONNECTION, "keep-alive")
                    .header(hyper::header::HeaderName::from_static("proxy-agent"), "p-proxy")
                    .body(full.boxed())
                    .unwrap();
                resp.extensions_mut()
                    .insert(ReasonPhrase::from_static(b"Connection Established"));
                return Ok(resp);
            }
            Err(e) => {
                tracing::warn!(%client_addr, "wss upstream connect failed: {e:#}");
                return Ok(simple_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream wss connect failed",
                ));
            }
        }
    }

    tokio::spawn(async move {
        let result = match on_upgrade.await {
            Ok(upgraded) => {
                if let Some(target) = target_cloned {
                    tunnel_upgraded_stream(upgraded, &host_cloned, port, &target).await
                } else {
                    tunnel_direct_upgraded_stream(upgraded, &host_cloned, port).await
                }
            }
            Err(e) => {
                tracing::debug!("upgrade error: {e}");
                Err(e.into())
            }
        };
        if let Err(e) = result {
            tracing::warn!(%client_addr, "tunnel error: {e:#}");
        }
    });

    let full = Full::new(Bytes::new());
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONNECTION, "keep-alive")
        .body(full.boxed())
        .unwrap();
    resp.extensions_mut()
        .insert(ReasonPhrase::from_static(b"Connection Established"));
    Ok(resp)
}

async fn tunnel_direct_upgraded_stream(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let mut client = TokioIo::new(upgraded);
    let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
    let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn parse_connect_authority(s: &str) -> anyhow::Result<(String, u16)> {
    let mut parts = s.rsplitn(2, ':');
    let port = parts
        .next()
        .context("missing port")?
        .parse::<u16>()
        .context("invalid port")?;
    let host = parts.next().context("missing host")?.to_string();
    Ok((host, port))
}

pub async fn tunnel_upgraded_stream(
    client: hyper::upgrade::Upgraded,
    host: &str,
    port: u16,
    upstream: &UpstreamTarget,
) -> anyhow::Result<()> {
    let client = TokioIo::new(client);
    match upstream {
        UpstreamTarget::HttpProxy { host: up_host, port: up_port } => {
            tunnel_via_http_proxy(client, host, port, up_host, *up_port).await
        }
        UpstreamTarget::Socks5Proxy { host: up_host, port: up_port } => {
            tunnel_via_socks5_proxy(client, host, port, up_host, *up_port).await
        }
        UpstreamTarget::WsProxy {
            url_template,
            headers,
            wss_ech,
        } => tunnel_via_ws_proxy(client, host, port, url_template, headers, wss_ech.as_ref()).await,
    }
}

pub type WsRemoteReader = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
pub type WsRemoteWriter = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// Connect to WSS/WS upstream only (no tunnel). Used to overlap with on_upgrade so browser doesn't timeout.
/// If `version` is Some, adds header "ws-proxy: <version>" for same-protocol relay identification.
async fn connect_ws_proxy_upstream(
    host: &str,
    port: u16,
    url_template: &str,
    headers: &std::collections::BTreeMap<String, String>,
    wss_ech: Option<&crate::model::WssEchSettings>,
    version: Option<&str>,
) -> anyhow::Result<(WsRemoteReader, WsRemoteWriter)> {
    let dest = format!("{host}:{port}");
    let url = url_template.replace("{domain}", &dest);
    let parsed = url::Url::parse(&url).map_err(|e| anyhow::anyhow!("invalid ws url: {}", e))?;
    let ws_host = parsed.host_str().context("url has no host")?;
    let ws_port = parsed.port_or_known_default().unwrap_or(if url.starts_with("wss://") { 443 } else { 80 });
    let path = parsed.path();
    let path_and_query = if path.is_empty() { "/".to_string() } else { path.to_string() };
    let path_and_query = if let Some(q) = parsed.query() {
        format!("{}?{}", path_and_query, q)
    } else {
        path_and_query
    };
    let host_header = headers
        .get("Host")
        .or_else(|| headers.get("host"))
        .map(|s| s.as_str())
        .unwrap_or("");
    let host_header = if host_header.is_empty() {
        format!("{}:{}", ws_host, ws_port)
    } else {
        host_header.to_string()
    };
    let mut headers_with_version = headers.clone();
    if let Some(v) = version {
        headers_with_version.insert("ws-proxy".to_string(), v.to_string());
    }
    let headers_to_use = &headers_with_version;

    if url.starts_with("wss://") {
        let (tls_cfg, tls_sni, tcp_host) = if let Some(ech) = wss_ech {
            let mode = crate::wss_ech::build_ech_mode_from_settings(
                ech.inner_hostname.as_str(),
                ws_port,
                ech.ech_config_file.as_deref(),
                ech.ech_doh_lookup,
                ech.ech_doh_cloudflare,
            )
            .await
            .map_err(|e| {
                tracing::warn!(url = %url, "wss ECH setup failed: {e:#}");
                e
            })?;
            let cfg = crate::tls::rustls_client_config_insecure_ech(mode).map_err(|e| {
                tracing::warn!(url = %url, "wss ECH tls config: {e:#}");
                e
            })?;
            let tcp_host = ech.connect_host.as_deref().unwrap_or(ws_host);
            (cfg, ech.inner_hostname.clone(), tcp_host.to_string())
        } else {
            let host_part = host_header
                .split(':')
                .next()
                .unwrap_or(host_header.as_str())
                .trim()
                .to_string();
            (
                crate::tls::rustls_client_config_insecure(),
                host_part,
                ws_host.to_string(),
            )
        };
        let (r, w) = crate::ws_upstream_raw::connect_wss_raw(
            tcp_host.as_str(),
            ws_port,
            &path_and_query,
            &host_header,
            headers_to_use,
            tls_sni.as_str(),
            tls_cfg,
        )
        .await
        .map_err(|e| {
            tracing::warn!(url = %url, "wss raw upstream failed: {}", e);
            e
        })?;
        Ok((Box::new(r), Box::new(w)))
    } else {
        let (r, w) = crate::ws_upstream_raw::connect_ws_raw(
            ws_host,
            ws_port,
            &path_and_query,
            &host_header,
            headers_to_use,
        )
        .await
        .map_err(|e| {
            tracing::warn!(url = %url, "ws raw upstream failed: {}", e);
            e
        })?;
        Ok((Box::new(r), Box::new(w)))
    }
}

/// Tunnel client <-> already-connected WSS upstream (so we can overlap WSS connect with CONNECT upgrade).
/// 参考实现：CONNECT(https_proxy) 时 body 为空，不向上游发首帧，目标已在 URL proxy={domain} 中；仅 http_proxy(GET) 才发首帧(body=请求内容)。
async fn tunnel_ws_proxy_loop(
    client: TokioIo<hyper::upgrade::Upgraded>,
    _host: &str,
    _port: u16,
    mut remote_r: WsRemoteReader,
    remote_w: WsRemoteWriter,
) -> anyhow::Result<()> {
    let remote_w = std::sync::Arc::new(tokio::sync::Mutex::new(remote_w));
    let (mut cr, mut cw) = tokio::io::split(client);

    let c2w = {
        let remote_w = std::sync::Arc::clone(&remote_w);
        async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let mut w = remote_w.lock().await;
                crate::ws_upstream_raw::write_ws_binary_masked_zero(&mut *w, &buf[..n]).await?;
            }
            anyhow::Ok(())
        }
    };

    let w2c = {
        let remote_w = std::sync::Arc::clone(&remote_w);
        async move {
            loop {
                match crate::ws_upstream_raw::read_ws_frame_payload(&mut *remote_r).await? {
                    Some(crate::ws_upstream_raw::WsFrameResult::Binary(p)) if !p.is_empty() => {
                        cw.write_all(&p).await?;
                    }
                    Some(crate::ws_upstream_raw::WsFrameResult::Ping(p)) => {
                        let mut w = remote_w.lock().await;
                        crate::ws_upstream_raw::write_ws_pong(&mut *w, &p).await?;
                    }
                    Some(crate::ws_upstream_raw::WsFrameResult::Close) | None => break,
                    _ => {}
                }
            }
            anyhow::Ok(())
        }
    };

    tokio::select! {
        r = c2w => r?,
        r = w2c => r?,
    }
    Ok(())
}

/// TCP 隧道经 WS 上游时需按 WebSocket 帧读写，不能裸写字节（否则对端 tungstenite 会解析到 invalid opcode）。
async fn tunnel_tcp_to_ws_upstream(
    client: TcpStream,
    mut remote_r: WsRemoteReader,
    remote_w: WsRemoteWriter,
) -> anyhow::Result<()> {
    let remote_w = std::sync::Arc::new(tokio::sync::Mutex::new(remote_w));
    let (mut cr, mut cw) = tokio::io::split(client);

    let c2w = {
        let remote_w = std::sync::Arc::clone(&remote_w);
        async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let mut w = remote_w.lock().await;
                crate::ws_upstream_raw::write_ws_binary_masked_zero(&mut *w, &buf[..n]).await?;
            }
            anyhow::Ok(())
        }
    };

    let w2c = {
        let remote_w = std::sync::Arc::clone(&remote_w);
        async move {
            loop {
                match crate::ws_upstream_raw::read_ws_frame_payload(&mut *remote_r).await? {
                    Some(crate::ws_upstream_raw::WsFrameResult::Binary(p)) if !p.is_empty() => {
                        cw.write_all(&p).await?;
                    }
                    Some(crate::ws_upstream_raw::WsFrameResult::Ping(p)) => {
                        let mut w = remote_w.lock().await;
                        crate::ws_upstream_raw::write_ws_pong(&mut *w, &p).await?;
                    }
                    Some(crate::ws_upstream_raw::WsFrameResult::Close) | None => break,
                    _ => {}
                }
            }
            anyhow::Ok(())
        }
    };

    tokio::select! {
        r = c2w => r?,
        r = w2c => r?,
    }
    Ok(())
}

async fn tunnel_via_http_proxy(
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    upstream_host: &str,
    upstream_port: u16,
) -> anyhow::Result<()> {
    let mut upstream = TcpStream::connect(format!("{upstream_host}:{upstream_port}")).await?;
    let connect_req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    upstream.write_all(connect_req.as_bytes()).await?;
    upstream.flush().await?;

    // Read until end of headers.
    let mut buf = vec![0u8; 4096];
    let mut total = Vec::new();
    loop {
        let n = upstream.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("upstream closed during CONNECT");
        }
        total.extend_from_slice(&buf[..n]);
        if total.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total.len() > 64 * 1024 {
            anyhow::bail!("upstream CONNECT response too large");
        }
    }
    let resp_txt = String::from_utf8_lossy(&total);
    if !resp_txt.starts_with("HTTP/1.1 200") && !resp_txt.starts_with("HTTP/1.0 200") {
        anyhow::bail!("upstream CONNECT failed: {}", resp_txt.lines().next().unwrap_or(""));
    }

    let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn tunnel_via_ws_proxy(
    client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    url_template: &str,
    headers: &std::collections::BTreeMap<String, String>,
    wss_ech: Option<&crate::model::WssEchSettings>,
) -> anyhow::Result<()> {
    let (remote_r, remote_w) =
        connect_ws_proxy_upstream(host, port, url_template, headers, wss_ech, None).await?;
    tunnel_ws_proxy_loop(client, host, port, remote_r, remote_w).await
}

async fn tunnel_via_socks5_proxy(
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    upstream_host: &str,
    upstream_port: u16,
) -> anyhow::Result<()> {
    let mut upstream = crate::socks5_upstream::connect_via_socks5_with_context(
        upstream_host,
        upstream_port,
        host,
        port,
    )
    .await?;
    let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Connect to target_host:target_port via HTTP CONNECT proxy; returns the tunnelled stream.
pub async fn connect_tcp_via_http_proxy(
    upstream_host: &str,
    upstream_port: u16,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<TcpStream> {
    let mut upstream = TcpStream::connect(format!("{upstream_host}:{upstream_port}")).await?;
    let connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    upstream.write_all(connect_req.as_bytes()).await?;
    upstream.flush().await?;

    let mut buf = vec![0u8; 4096];
    let mut total = Vec::new();
    loop {
        let n = upstream.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("upstream closed during CONNECT");
        }
        total.extend_from_slice(&buf[..n]);
        if total.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total.len() > 64 * 1024 {
            anyhow::bail!("upstream CONNECT response too large");
        }
    }
    let resp_txt = String::from_utf8_lossy(&total);
    if !resp_txt.starts_with("HTTP/1.1 200") && !resp_txt.starts_with("HTTP/1.0 200") {
        anyhow::bail!("upstream CONNECT failed: {}", resp_txt.lines().next().unwrap_or(""));
    }
    Ok(upstream)
}

/// Stream that can be either a TCP connection or a WS upstream tunnel (both AsyncRead + AsyncWrite).
pub enum TunnelStream {
    Tcp(TcpStream),
    Ws(WsTunnelStream),
}

/// Wraps WS upstream (reader + writer). For TCP tunnel over WS use `TunnelStream::run_tunnel`, not copy_bidirectional.
pub struct WsTunnelStream {
    read: WsRemoteReader,
    write: WsRemoteWriter,
}

impl WsTunnelStream {
    pub fn into_inner(self) -> (WsRemoteReader, WsRemoteWriter) {
        (self.read, self.write)
    }
}

impl AsyncRead for WsTunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsTunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TunnelStream::Ws(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TunnelStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TunnelStream::Ws(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            TunnelStream::Ws(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TunnelStream::Ws(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl TunnelStream {
    /// 双向桥接：Tcp 直连用 copy_bidirectional；Ws 上游用 WebSocket 帧封装/解析，避免对端收到裸字节报 invalid opcode。
    pub async fn run_tunnel(self, mut client: TcpStream) -> anyhow::Result<()> {
        match self {
            TunnelStream::Tcp(mut tcp) => {
                let _ = copy_bidirectional(&mut client, &mut tcp).await;
                Ok(())
            }
            TunnelStream::Ws(ws) => {
                let (r, w) = ws.into_inner();
                tunnel_tcp_to_ws_upstream(client, r, w).await
            }
        }
    }
}

/// Connect to target_host:target_port via the given rule's upstream (HTTP, SOCKS5, or WS/WSS).
/// For WsProxy, `version` is sent as header "ws-proxy" for same-protocol relay.
pub async fn connect_tcp_via_rule(
    rule: &crate::model::Rule,
    target_host: &str,
    target_port: u16,
    version: Option<&str>,
) -> anyhow::Result<TunnelStream> {
    match &rule.target {
        UpstreamTarget::HttpProxy { host: up_host, port: up_port } => {
            let tcp = connect_tcp_via_http_proxy(up_host, *up_port, target_host, target_port).await?;
            Ok(TunnelStream::Tcp(tcp))
        }
        UpstreamTarget::Socks5Proxy { host: up_host, port: up_port } => {
            let tcp = crate::socks5_upstream::connect_via_socks5_with_context(
                up_host,
                *up_port,
                target_host,
                target_port,
            )
            .await?;
            Ok(TunnelStream::Tcp(tcp))
        }
        UpstreamTarget::WsProxy {
            url_template,
            headers,
            wss_ech,
        } => {
            let (read, write) = connect_ws_proxy_upstream(
                target_host,
                target_port,
                url_template,
                headers,
                wss_ech.as_ref(),
                version,
            )
            .await?;
            Ok(TunnelStream::Ws(WsTunnelStream { read, write }))
        }
    }
}

pub fn ws_proxy_token_ok(req: &Request<Incoming>, expected: &str) -> bool {
    let qs = req.uri().query().unwrap_or("");
    qs.split('&').any(|kv| kv == format!("token={expected}"))
}

