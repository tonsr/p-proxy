use crate::auth::{authenticate_socks5, is_rule_allowed, username_for_stats};
use crate::model::{CompiledRules, DirectAccessWhitelist, UpstreamTarget};
use anyhow::Context;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn handle_socks5(
    mut client: TcpStream,
    client_addr: SocketAddr,
    allow_anonymous: bool,
    users: &HashMap<String, crate::model::User>,
    rules: &CompiledRules,
    dns: Option<&crate::dns::DnsManager>,
    stats: Option<&crate::stats::DailyStats>,
    allow_direct_access: bool,
    direct_whitelist: Option<&DirectAccessWhitelist>,
) -> anyhow::Result<()> {
    // RFC1928 + RFC1929 (username/password).
    let ver = client.read_u8().await?;
    if ver != 0x05 {
        anyhow::bail!("not socks5");
    }
    let nmethods = client.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    let supports_no_auth = methods.contains(&0x00);
    let supports_user_pass = methods.contains(&0x02);

    let chosen = if allow_anonymous && supports_no_auth {
        0x00
    } else if supports_user_pass {
        0x02
    } else if allow_anonymous && supports_no_auth {
        0x00
    } else {
        0xFF
    };

    client.write_all(&[0x05, chosen]).await?;
    client.flush().await?;
    if chosen == 0xFF {
        anyhow::bail!("no acceptable auth method");
    }

    let auth = if chosen == 0x02 {
        // Username/password subnegotiation
        let subver = client.read_u8().await?;
        if subver != 0x01 {
            anyhow::bail!("invalid socks5 auth version");
        }
        let ulen = client.read_u8().await? as usize;
        let mut ub = vec![0u8; ulen];
        client.read_exact(&mut ub).await?;
        let plen = client.read_u8().await? as usize;
        let mut pb = vec![0u8; plen];
        client.read_exact(&mut pb).await?;
        let u = String::from_utf8_lossy(&ub).to_string();
        let p = String::from_utf8_lossy(&pb).to_string();

        match authenticate_socks5(allow_anonymous, Some((u, p)), users) {
            Ok(a) => {
                client.write_all(&[0x01, 0x00]).await?; // success
                a
            }
            Err(_) => {
                client.write_all(&[0x01, 0x01]).await?; // failure
                client.flush().await?;
                anyhow::bail!("auth failed");
            }
        }
    } else {
        authenticate_socks5(allow_anonymous, None, users)?
    };

    // Request
    let ver = client.read_u8().await?;
    if ver != 0x05 {
        anyhow::bail!("invalid socks5 req ver");
    }
    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    if cmd != 0x01 {
        // CONNECT only
        reply_socks5(&mut client, 0x07, "0.0.0.0", 0).await?;
        anyhow::bail!("unsupported socks5 cmd");
    }

    let (host, ip) = match atyp {
        0x01 => {
            // IPv4
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            let ip = IpAddr::from(b);
            (ip.to_string(), Some(ip))
        }
        0x04 => {
            // IPv6
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            let ip = IpAddr::from(b);
            (ip.to_string(), Some(ip))
        }
        0x03 => {
            let len = client.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            client.read_exact(&mut b).await?;
            let host = String::from_utf8_lossy(&b).to_string();
            // 若 host 为 IP 字符串（如 "192.168.128.221"、"192.168.57.100"），解析为 ip 供规则匹配；
            // domains 里纯 IP 为 Ip 模式、网段为 Cidr 模式，都只走 matches_ip(ip)，否则会误走直连。
            let ip = host.parse::<IpAddr>().ok();
            (host, ip)
        }
        _ => {
            reply_socks5(&mut client, 0x08, "0.0.0.0", 0).await?;
            anyhow::bail!("invalid atyp");
        }
    };
    let port = client.read_u16().await?;

    if let Some(s) = stats {
        s.incr(username_for_stats(&auth)).await;
    }

    let mut chosen = rules.select_rule(&host, port, ip);
    let mut resolved_ip = None;
    if chosen.is_none() {
        if let Some(dns) = dns {
            if let Ok(Some(resolved)) = dns.resolve_ip(&host).await {
                chosen = rules.select_rule(&host, port, Some(resolved));
                resolved_ip = Some(String::from(resolved.to_string().clone()));
            }
        }
    }

    if let Some(rule) = chosen {
        if !is_rule_allowed(&auth, &rule.name) {
            reply_socks5(&mut client, 0x02, "0.0.0.0", 0).await?;
            anyhow::bail!("rule not allowed");
        }

        // 先连上游再回复 0x00，避免首包积压；上游建连加超时，超时则回 SOCKS5 错误避免浏览器一直等。
        const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
        match &rule.target {
            UpstreamTarget::HttpProxy { host: up_host, port: up_port } => {
                let connect_fut = async {
                    TcpStream::connect(format!("{up_host}:{up_port}")).await
                };
                let mut upstream = match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect_fut).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::warn!(%client_addr, upstream = %format!("{}:{}", up_host, up_port), "http upstream connect failed: {e:#}");
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream connect failed: {e:#}");
                    }
                    Err(_) => {
                        tracing::warn!(%client_addr, upstream = %format!("{}:{}", up_host, up_port), "http upstream connect timed out after {:?}", UPSTREAM_CONNECT_TIMEOUT);
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream connect timed out");
                    }
                };
                let connect_req = format!(
                    "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
                );
                upstream.write_all(connect_req.as_bytes()).await?;
                upstream.flush().await?;
                let mut buf = vec![0u8; 4096];
                let mut total = Vec::new();
                loop {
                    let n = upstream.read(&mut buf).await?;
                    if n == 0 {
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream closed during CONNECT");
                    }
                    total.extend_from_slice(&buf[..n]);
                    if total.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if total.len() > 64 * 1024 {
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream CONNECT response too large");
                    }
                }
                let resp_txt = String::from_utf8_lossy(&total);
                if !resp_txt.starts_with("HTTP/1.1 200") && !resp_txt.starts_with("HTTP/1.0 200") {
                    reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                    anyhow::bail!("upstream CONNECT failed: {}", resp_txt.lines().next().unwrap_or(""));
                }
                reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
                let _ = copy_bidirectional(&mut client, &mut upstream).await?;
                Ok(())
            }
            UpstreamTarget::Socks5Proxy { host: up_host, port: up_port } => {
                let connect_fut = crate::socks5_upstream::connect_via_socks5_with_context(
                    up_host,
                    *up_port,
                    &host,
                    port,
                );
                let mut upstream = match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect_fut).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::warn!(%client_addr, upstream = %format!("{}:{}", up_host, up_port), "socks5 upstream connect failed: {e:#}");
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream connect failed: {e:#}");
                    }
                    Err(_) => {
                        tracing::warn!(%client_addr, upstream = %format!("{}:{}", up_host, up_port), "socks5 upstream connect timed out after {:?}", UPSTREAM_CONNECT_TIMEOUT);
                        reply_socks5(&mut client, 0x05, "0.0.0.0", 0).await?;
                        anyhow::bail!("upstream connect timed out");
                    }
                };
                reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
                let _ = copy_bidirectional(&mut client, &mut upstream).await?;
                Ok(())
            }
            UpstreamTarget::WsProxy {
                url_template,
                headers,
                wss_ech,
            } => {
                tunnel_via_ws_proxy(client, &host, port, url_template, headers, wss_ech.as_ref())
                    .await
            }
        }
        .with_context(|| format!("socks5 tunnel to {host}:{port} for {client_addr}"))?;
    } else {
        // Direct connect fallback：需通过直连开关与白名单校验
        if !allow_direct_access {
            reply_socks5(&mut client, 0x02, "0.0.0.0", 0).await?;
            anyhow::bail!("direct access disabled by config");
        }
        if let Some(w) = direct_whitelist {
            let check_ip = match ip {
                Some(i) => i,
                None => {
                    if let Some(dns) = dns {
                        match dns.resolve_ip(&host).await {
                            Ok(Some(addr)) => addr,
                            _ => {
                                reply_socks5(&mut client, 0x02, "0.0.0.0", 0).await?;
                                anyhow::bail!("could not resolve host for direct whitelist");
                            }
                        }
                    } else {
                        reply_socks5(&mut client, 0x02, "0.0.0.0", 0).await?;
                        anyhow::bail!("direct whitelist requires resolvable host");
                    }
                }
            };
            if !w.allows(check_ip, port) {
                reply_socks5(&mut client, 0x02, "0.0.0.0", 0).await?;
                anyhow::bail!("direct access not in whitelist");
            }
        }
        if let Some(resolved_ip) = resolved_ip {
            tracing::info!("direct connect resolved host: {} ip: {}", host, resolved_ip);
            let mut upstream = TcpStream::connect(format!("{resolved_ip}:{port}")).await?;
            reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
            let _ = copy_bidirectional(&mut client, &mut upstream).await?;
        } else {
            let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
            reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
            let _ = copy_bidirectional(&mut client, &mut upstream).await?;
        }
        // Direct connect fallback：先连目标再回复
        // let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
        // reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
        // let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    }

    Ok(())
}

async fn reply_socks5(
    client: &mut TcpStream,
    rep: u8,
    bind_addr: &str,
    bind_port: u16,
) -> anyhow::Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let mut out = Vec::new();
    out.push(0x05);
    out.push(rep);
    out.push(0x00);
    // Always reply IPv4 0.0.0.0
    out.push(0x01);
    out.extend_from_slice(&[0, 0, 0, 0]);
    let _ = bind_addr; // reserved for later
    out.extend_from_slice(&bind_port.to_be_bytes());
    client.write_all(&out).await?;
    client.flush().await?;
    Ok(())
}

async fn tunnel_via_ws_proxy(
    mut client: TcpStream,
    host: &str,
    port: u16,
    url_template: &str,
    headers: &std::collections::BTreeMap<String, String>,
    wss_ech: Option<&crate::model::WssEchSettings>,
) -> anyhow::Result<()> {
    // URL 保持 wss://IP/... 或 wss://域名/...，不把地址里的 host 替换成 Host 头，避免上游解析到别的 IP
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

    type RemoteReader = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    type RemoteWriter = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
    let conn_result: anyhow::Result<(RemoteReader, RemoteWriter)> = if url.starts_with("wss://") {
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
        crate::ws_upstream_raw::connect_wss_raw(
            tcp_host.as_str(),
            ws_port,
            &path_and_query,
            &host_header,
            headers,
            tls_sni.as_str(),
            tls_cfg,
        )
        .await
        .map(|(r, w)| (Box::new(r) as RemoteReader, Box::new(w) as RemoteWriter))
        .map_err(|e| {
            tracing::warn!(url = %url, "wss raw upstream failed: {}", e);
            e
        })
    } else {
        crate::ws_upstream_raw::connect_ws_raw(
            ws_host,
            ws_port,
            &path_and_query,
            &host_header,
            headers,
        )
        .await
        .map(|(r, w)| (Box::new(r) as RemoteReader, Box::new(w) as RemoteWriter))
        .map_err(|e| {
            tracing::warn!(url = %url, "ws raw upstream failed: {}", e);
            e
        })
    };

    let (mut remote_r, remote_w) = match conn_result {
        Ok(conn) => conn,
        Err(e) => {
            let _ = reply_socks5(&mut client, 0x01, "0.0.0.0", 0).await;
            return Err(e);
        }
    };

    reply_socks5(&mut client, 0x00, "0.0.0.0", 0).await?;
    let remote_w = std::sync::Arc::new(tokio::sync::Mutex::new(remote_w));
    let (mut cr, mut cw) = client.into_split();

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

