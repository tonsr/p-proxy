//! Raw WSS upstream: HTTP upgrade + WebSocket binary frames with mask_key=0 (零拷贝).
//! 连接目标始终为 wss:// 或 ws:// 后的 host：若为 IP 则直接连，若为域名则先解析再连；
//! 请求头 Host 使用配置中的值（如 socks5.example.com），不参与连接目标解析。

use anyhow::{Context, Result};
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

const MASK_KEY_ZERO: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Build HTTP/1.1 WebSocket upgrade request (GET path?query, Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version).
/// Host 必须使用配置中的内容，否则连接会失败；Sec-WebSocket-Key / Sec-WebSocket-Version 固定即可。
fn build_upgrade_request(
    path_and_query: &str,
    host_header: &str,
    extra_headers: &[(String, String)],
) -> String {
    // Host: 优先使用配置(extra_headers)里的值
    let host_value = extra_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .unwrap_or(host_header);

    const WS_KEY: &str = "E61fBLH3DHj3ONVTnJZ/XA==";
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        path_and_query,
        host_value,
        WS_KEY,
    );
    for (k, v) in extra_headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("sec-websocket-key")
            || k.eq_ignore_ascii_case("sec-websocket-version")
        {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req
}

/// 解析连接目标：URL 里是 IP 则直接连该 IP；是域名则先解析再连解析出的 IP。不解析 Host 头。
async fn resolve_connect_addr(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    if host.parse::<IpAddr>().is_ok() {
        let addr = (host.parse::<IpAddr>().unwrap(), port).into();
        tracing::info!(
            connect = %addr,
            "wss upstream: URL host is IP, connecting directly (Host header from config)"
        );
        Ok(addr)
    } else {
        let addrs: Vec<std::net::SocketAddr> =
            tokio::net::lookup_host((host, port)).await.context("dns lookup")?.collect();
        let first = addrs.into_iter().next().context("domain resolved to no address")?;
        tracing::info!(
            connect = %first,
            url_domain = %host,
            "wss upstream: resolved URL domain to IP, connecting (Host header from config)"
        );
        Ok(first)
    }
}

/// Connect to wss: TCP resolves `tcp_connect_host` (URL host or ECH `connect-host`); TLS uses
/// `tls_sni_hostname` (inner name for ECH); HTTP `Host` uses `host_header`.
pub async fn connect_wss_raw(
    tcp_connect_host: &str,
    port: u16,
    path_and_query: &str,
    host_header: &str,
    extra_headers: &std::collections::BTreeMap<String, String>,
    tls_sni_hostname: &str,
    tls_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<(
    tokio::io::ReadHalf<TlsStream<TcpStream>>,
    tokio::io::WriteHalf<TlsStream<TcpStream>>,
)> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;
    let connect_addr = resolve_connect_addr(tcp_connect_host, port).await?;
    let tcp = TcpStream::connect(connect_addr)
        .await
        .with_context(|| format!("tcp connect {}", connect_addr))?;
    tracing::info!(addr = %connect_addr, tcp_host = %tcp_connect_host, "wss upstream: tcp connected");

    // let sni_name = if tls_sni_hostname.ends_with(".workers.dev") {
    //     "cloudfleare-ech.com"
    // } else {
    //     tls_sni_hostname.trim()
    // };
    let sni_name = tls_sni_hostname.trim();
    let sni = ServerName::try_from(sni_name)
        .map_err(|_| anyhow::anyhow!("invalid TLS server name / SNI: {}", sni_name))?
        .to_owned();
    tracing::info!(tls_sni = %sni_name, addr = %connect_addr, host_header = %host_header, "wss upstream: TLS ServerName and HTTP Host");

    let connector = TlsConnector::from(tls_config);
    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("tls connect: {}", e))?;

    let request = build_upgrade_request(
        path_and_query,
        host_header,
        &extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
    );
    let first_line = request.lines().next().unwrap_or("");
    tracing::info!(request_line = %first_line, host_in_request = %host_header, "wss upstream: sending upgrade request");
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut buf = [0u8; 4096];
    let mut n = 0;
    loop {
        if n >= 4 {
            break;
        }
        if n >= buf.len() {
            anyhow::bail!("upgrade response too large");
        }
        let read = reader.read(&mut buf[n..]).await?;
        if read == 0 {
            anyhow::bail!("upstream closed before 101");
        }
        n += read;
    }
    tracing::info!("read end");
    let head = std::str::from_utf8(&buf[..n]).context("upgrade response not utf8")?;
    let status_line = head.lines().next().unwrap_or("");
    if head.starts_with("HTTP/1.1 429") || head.starts_with("HTTP/1.0 429") {
        tracing::warn!(response_status = %status_line, "wss upstream: 429 Too Many Requests (rate limit)");
        anyhow::bail!("upstream returned 429 Too Many Requests (rate limit)");
    }
    if !head.starts_with("HTTP/1.1 101") && !head.starts_with("HTTP/1.0 101") {
        tracing::error!(
            response_status = %status_line,
            response_head = %head,
            "wss upstream: upgrade failed, not 101"
        );
        anyhow::bail!("upstream did not return 101 Switching Protocols: {}", status_line);
    }
    tracing::info!(response_status = %status_line, "wss upstream: upgrade ok, 101 Switching Protocols");

    Ok((reader, writer))
}

/// 同 wss：仅连接 ws:// 后的 host（IP 直连，域名先解析），请求头 Host 用配置值。
pub async fn connect_ws_raw(
    host: &str,
    port: u16,
    path_and_query: &str,
    host_header: &str,
    extra_headers: &std::collections::BTreeMap<String, String>,
) -> Result<(
    tokio::net::tcp::OwnedReadHalf,
    tokio::net::tcp::OwnedWriteHalf,
)> {
    let connect_addr = resolve_connect_addr(host, port).await?;
    let mut tcp = TcpStream::connect(connect_addr)
        .await
        .with_context(|| format!("tcp connect {}", connect_addr))?;
    tracing::info!(addr = %connect_addr, "ws upstream: tcp connected");

    let request = build_upgrade_request(
        path_and_query,
        host_header,
        &extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
    );
    let first_line = request.lines().next().unwrap_or("");
    tracing::info!(request_line = %first_line, host_in_request = %host_header, "ws upstream: sending upgrade request");

    tcp.write_all(request.as_bytes()).await?;
    tcp.flush().await?;

    let mut buf = [0u8; 4096];
    let mut n = 0;
    loop {
        if n >= 4 && buf.get(n - 4..n) == Some(b"\r\n\r\n") {
            break;
        }
        if n >= buf.len() {
            anyhow::bail!("upgrade response too large");
        }
        let read = tcp.read(&mut buf[n..]).await?;
        if read == 0 {
            anyhow::bail!("upstream closed before 101");
        }
        n += read;
    }

    let head = std::str::from_utf8(&buf[..n]).context("upgrade response not utf8")?;
    let status_line = head.lines().next().unwrap_or("");
    if head.starts_with("HTTP/1.1 429") || head.starts_with("HTTP/1.0 429") {
        tracing::warn!(response_status = %status_line, "ws upstream: 429 Too Many Requests (rate limit)");
        anyhow::bail!("upstream returned 429 Too Many Requests (rate limit)");
    }
    if !head.starts_with("HTTP/1.1 101") && !head.starts_with("HTTP/1.0 101") {
        tracing::error!(
            response_status = %status_line,
            response_head = %head,
            "ws upstream: upgrade failed, not 101"
        );
        anyhow::bail!("upstream did not return 101: {}", status_line);
    }
    tracing::info!(response_status = %status_line, "ws upstream: upgrade ok, 101 Switching Protocols");

    let (r, w) = tcp.into_split();
    Ok((r, w))
}

/// Result of reading one WebSocket frame: binary/continuation payload, ping payload (caller should send Pong), or close.
#[derive(Debug)]
pub enum WsFrameResult {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Close,
}

/// Write a WebSocket Pong frame with mask_key = 0 (reply to Ping).
pub async fn write_ws_pong<W: AsyncWriteExt + Unpin + ?Sized>(
    w: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    if len < 126 {
        w.write_all(&[0x8A, 0x80 | len as u8]).await?;
    } else if len < 65536 {
        w.write_all(&[0x8A, 0xFE, (len >> 8) as u8, len as u8]).await?;
    } else {
        w.write_all(&[
            0x8A, 0xFF,
            (len >> 56) as u8, (len >> 48) as u8, (len >> 40) as u8, (len >> 32) as u8,
            (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8,
        ]).await?;
    }
    w.write_all(&MASK_KEY_ZERO).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Write a WebSocket binary frame with mask_key = 0 (零拷贝: payload sent as-is).
pub async fn write_ws_binary_masked_zero<W: AsyncWriteExt + Unpin + ?Sized>(
    w: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    if len < 126 {
        w.write_all(&[0x82, 0x80 | len as u8]).await?;
    } else if len < 65536 {
        w.write_all(&[0x82, 0xFE, (len >> 8) as u8, len as u8]).await?;
    } else {
        w.write_all(&[
            0x82, 0xFF,
            (len >> 56) as u8, (len >> 48) as u8, (len >> 40) as u8, (len >> 32) as u8,
            (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8,
        ]).await?;
    }
    w.write_all(&MASK_KEY_ZERO).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one WebSocket frame (server -> client), return typed result; supports binary, continuation, ping, pong, close.
pub async fn read_ws_frame_payload<R: AsyncReadExt + Unpin + ?Sized>(r: &mut R) -> io::Result<Option<WsFrameResult>> {
    let mut hdr = [0u8; 2];
    if r.read_exact(&mut hdr).await.is_err() {
        return Ok(None);
    }
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let mut len = (hdr[1] & 0x7F) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }
    if len > 4 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ws frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    if masked {
        for i in 0..payload.len() {
            payload[i] ^= mask[i % 4];
        }
    }

    match opcode {
        0x2 => Ok(Some(WsFrameResult::Binary(payload))), // binary
        0x8 => Ok(Some(WsFrameResult::Close)),          // close
        0x9 => Ok(Some(WsFrameResult::Ping(payload))), // ping: caller must send Pong
        0xA => Ok(Some(WsFrameResult::Binary(vec![]))), // pong, ignore
        _ => Ok(Some(WsFrameResult::Binary(payload))),
    }
}
