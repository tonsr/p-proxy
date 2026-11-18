use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use hyper::body::Bytes;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_tungstenite::tungstenite::{handshake::derive_accept_key, protocol::Role};
use hyper_tungstenite::{tungstenite::Message, HyperWebsocket, WebSocketStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;

pub fn is_ws_upgrade(req: &Request<hyper::body::Incoming>) -> bool {
    hyper_tungstenite::is_upgrade_request(req)
}

#[cfg_attr(not(feature = "webssh"), allow(dead_code))]
pub fn websocket_upgrade(
    req: Request<hyper::body::Incoming>,
) -> anyhow::Result<(Response<http_body_util::Full<bytes::Bytes>>, HyperWebsocket)> {
    let (resp, ws) = hyper_tungstenite::upgrade(req, None)?;
    Ok((resp, ws))
}

/// Manual WebSocket upgrade that returns the raw upgraded stream (for same-protocol raw relay).
/// Caller must await `on_upgrade` and then use the stream.
pub fn websocket_upgrade_manual(
    req: Request<hyper::body::Incoming>,
) -> anyhow::Result<(
    Response<Full<Bytes>>,
    hyper::upgrade::OnUpgrade,
)> {
    use hyper_tungstenite::tungstenite::error::ProtocolError;
    let key = req
        .headers()
        .get("Sec-WebSocket-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(ProtocolError::MissingSecWebSocketKey)?;
    if req.headers().get("Sec-WebSocket-Version").map(|v| v.as_bytes()) != Some(b"13") {
        anyhow::bail!("missing or invalid Sec-WebSocket-Version");
    }
    let accept = derive_accept_key(key.as_bytes());
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Accept", accept)
        .body(Full::from(Bytes::from("switching to websocket protocol")))
        .map_err(|e| anyhow::anyhow!("build response: {}", e))?;
    let on_upgrade = hyper::upgrade::on(req);
    Ok((response, on_upgrade))
}

/// WebSSH: upgrade first, then connect via rule; on failure send error to client. Then wait password, SSH shell, bridge.
#[cfg(feature = "webssh")]
pub async fn serve_webssh_with_connect(
    ws: HyperWebsocket,
    compiled_rule: crate::model::Rule,
    target_host: String,
    target_port: u16,
    username: String,
) -> anyhow::Result<()> {
    use hyper_tungstenite::tungstenite::Message;
    let ws = ws.await.context("ws upgrade await")?;
    let (ws_sink, mut ws_stream) = ws.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));

    let tcp_stream = match crate::proxy::connect_tcp_via_rule(
        &compiled_rule,
        &target_host,
        target_port,
        None,
    )
    .await
    {
        Ok(crate::proxy::TunnelStream::Tcp(s)) => s,
        Ok(crate::proxy::TunnelStream::Ws(_)) => {
            let msg = "\r\nWebSSH 不支持经 WS/WSS 上游连接，请使用 TCP 类型隧道。\r\n";
            let _ = ws_sink.lock().await.send(Message::Text(msg.to_string())).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            return Err(anyhow::anyhow!("WebSSH over WS upstream not supported"));
        }
        Err(e) => {
            let msg = format!("\r\n连接代理/目标失败: {}\r\n", e);
            let _ = ws_sink.lock().await.send(Message::Text(msg)).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            return Err(e.context("connect_tcp_via_rule"));
        }
    };

    // Push password prompt so user types password in terminal (hidden); wait for next message as password.
    let prompt = format!("{}@{}'s password: ", username, target_host);
    let _ = ws_sink.lock().await.send(Message::Text(prompt)).await;

    let password = match ws_stream.next().await {
        Some(Ok(Message::Text(p))) => p,
        Some(Ok(Message::Binary(b))) => String::from_utf8_lossy(&b).into_owned(),
        Some(Err(e)) => return Err(e.into()),
        Some(Ok(Message::Close(_))) => anyhow::bail!("client closed before sending password"),
        _ => anyhow::bail!("send password in terminal and press Enter"),
    };

    let _ = ws_sink.lock().await.send(Message::Text("connecting ...\r\n".to_string())).await;
    let (tx_control, mut rx_control) = tokio::sync::mpsc::channel::<String>(2);
    let (tx_ws_to_ssh, mut rx_ssh_to_ws) = match crate::webssh_ssh::run_ssh_shell(tcp_stream, &username, &password, Some(tx_control)).await {
        Ok(x) => x,
        Err(e) => {
            let _ = ws_sink.lock().await.send(Message::Text(format!("\r\nSSH 登录失败: {}\r\n", e))).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            return Err(e.context("SSH handshake/auth"));
        }
    };

    // Drain control (FILE_LIST) and send SSH_READY, then run bridge.
    let ws_sink_ctrl = ws_sink.clone();
    let ctrl_done = async move {
        while let Some(payload) = rx_control.recv().await {
            let _ = ws_sink_ctrl.lock().await.send(Message::Text(format!("FILE_LIST:{}", payload))).await;
        }
        let _ = ws_sink_ctrl.lock().await.send(Message::Text("SSH_READY".to_string())).await;
    };
    ctrl_done.await;

    let ws_sink_for_ping = ws_sink.clone();
    let w2ssh = async move {
        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(b) => {
                    if tx_ws_to_ssh.send(b).is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                Message::Ping(p) => {
                    let mut sink = ws_sink_for_ping.lock().await;
                    sink.send(Message::Pong(p)).await?;
                }
                Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
            }
        }
        anyhow::Ok(())
    };

    let ws_sink_for_ssh = ws_sink.clone();
    let ssh2w = async move {
        while let Some(data) = rx_ssh_to_ws.recv().await {
            let mut sink = ws_sink_for_ssh.lock().await;
            if sink.send(Message::Binary(data)).await.is_err() {
                break;
            }
        }
        anyhow::Ok(())
    };

    tokio::select! {
        r = w2ssh => r?,
        r = ssh2w => r?,
    }
    Ok(())
}

/// Bridge WebSocket to an existing TCP stream (e.g. from connect_tcp_via_rule).
#[allow(dead_code)]
pub async fn serve_ws_tunnel_with_stream(
    ws: HyperWebsocket,
    tcp: TcpStream,
) -> anyhow::Result<()> {
    let ws = ws.await.context("ws upgrade await")?;
    bridge_ws_to_tcp(ws, tcp).await
}

/// Same as serve_ws_tunnel_with_stream but starting from raw upgraded stream (for manual upgrade path).
pub async fn serve_ws_tunnel_with_stream_from_raw(
    down_stream: TokioIo<hyper::upgrade::Upgraded>,
    tcp: TcpStream,
) -> anyhow::Result<()> {
    let ws = WebSocketStream::from_raw_socket(down_stream, Role::Server, None).await;
    bridge_ws_to_tcp(ws, tcp).await
}

async fn bridge_ws_to_tcp(
    ws: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    mut tcp: TcpStream,
) -> anyhow::Result<()> {
    let (ws_sink, mut ws_stream) = ws.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let (mut tr, mut tw) = tcp.split();

    let ws_sink_for_ping = ws_sink.clone();
    let w2t = async move {
        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(b) => tw.write_all(&b).await?,
                Message::Close(_) => break,
                Message::Ping(p) => {
                    let mut sink = ws_sink_for_ping.lock().await;
                    sink.send(Message::Pong(p)).await?;
                }
                Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
            }
        }
        anyhow::Ok(())
    };

    let ws_sink_for_tcp = ws_sink.clone();
    let t2w = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut sink = ws_sink_for_tcp.lock().await;
            sink.send(Message::Binary(buf[..n].to_vec())).await?;
        }
        anyhow::Ok(())
    };

    tokio::select! {
        r = w2t => r?,
        r = t2w => r?,
    }
    Ok(())
}

/// 同协议透传：下游与上游均为本服务（ws-proxy 版本一致）时，握手完成后直接底层流双向 copy，不解析/重编码 WS 帧。
/// `down_stream` 为 manual upgrade 得到的原始流（未包装为 WebSocketStream）。
pub async fn serve_ws_tunnel_raw_relay(
    down_stream: TokioIo<hyper::upgrade::Upgraded>,
    mut remote_r: crate::proxy::WsRemoteReader,
    mut remote_w: crate::proxy::WsRemoteWriter,
) -> anyhow::Result<()> {
    let (mut down_r, mut down_w) = tokio::io::split(down_stream);
    let t1 = tokio::spawn(async move { copy(&mut down_r, &mut remote_w).await });
    let t2 = tokio::spawn(async move { copy(&mut remote_r, &mut down_w).await });
    let (a, b) = tokio::join!(t1, t2);
    a.context("raw relay down->up")??;
    b.context("raw relay up->down")??;
    Ok(())
}

/// 客户端 WebSocket 与上游 WS 隧道（binary 帧）双向桥接；用于规则命中且后端为 ws/wss 时。
#[allow(dead_code)]
pub async fn serve_ws_tunnel_with_ws_upstream(
    ws: HyperWebsocket,
    remote_r: crate::proxy::WsRemoteReader,
    remote_w: crate::proxy::WsRemoteWriter,
) -> anyhow::Result<()> {
    let ws = ws.await.context("ws upgrade await")?;
    bridge_ws_to_ws_upstream(ws, remote_r, remote_w).await
}

/// Same as serve_ws_tunnel_with_ws_upstream but starting from raw upgraded stream (for manual upgrade path).
pub async fn serve_ws_tunnel_with_ws_upstream_from_raw(
    down_stream: TokioIo<hyper::upgrade::Upgraded>,
    remote_r: crate::proxy::WsRemoteReader,
    remote_w: crate::proxy::WsRemoteWriter,
) -> anyhow::Result<()> {
    let ws = WebSocketStream::from_raw_socket(down_stream, Role::Server, None).await;
    bridge_ws_to_ws_upstream(ws, remote_r, remote_w).await
}

async fn bridge_ws_to_ws_upstream(
    ws: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    mut remote_r: crate::proxy::WsRemoteReader,
    remote_w: crate::proxy::WsRemoteWriter,
) -> anyhow::Result<()> {
    let (ws_sink, mut ws_stream) = ws.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let remote_w = Arc::new(Mutex::new(remote_w));

    let remote_w_w2r = Arc::clone(&remote_w);
    let w2remote = async move {
        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(b) => {
                    let mut w = remote_w_w2r.lock().await;
                    crate::ws_upstream_raw::write_ws_binary_masked_zero(&mut *w, &b).await?;
                }
                Message::Close(_) => break,
                Message::Ping(p) => {
                    let mut w = remote_w_w2r.lock().await;
                    crate::ws_upstream_raw::write_ws_pong(&mut *w, &p).await?;
                }
                Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
            }
        }
        anyhow::Ok(())
    };

    let ws_sink_for_remote = ws_sink.clone();
    let remote2w = async move {
        loop {
            match crate::ws_upstream_raw::read_ws_frame_payload(&mut *remote_r).await? {
                Some(crate::ws_upstream_raw::WsFrameResult::Binary(p)) if !p.is_empty() => {
                    let mut sink = ws_sink_for_remote.lock().await;
                    sink.send(Message::Binary(p.into())).await?;
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
    };

    tokio::select! {
        r = w2remote => r?,
        r = remote2w => r?,
    }
    Ok(())
}

/// 先按规则匹配；命中则经对应代理协议连目标，未命中则本地直连（调用方已做 allow_direct_access / 白名单校验）。
/// 当 same_protocol_downstream 且上游为 WsProxy 时，做同协议透传：握手完成后底层流双向 copy，不解析 WS 帧。
#[allow(dead_code)]
pub async fn serve_ws_tunnel_via_rule_or_direct(
    ws: HyperWebsocket,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    proxy_target: String,
    chosen_rule: Option<crate::model::Rule>,
    _same_protocol_downstream: bool,
    version: Option<String>,
) -> anyhow::Result<()> {
    if let Some(rule) = chosen_rule {
        tracing::info!(%client_addr, %proxy_target, rule = %rule.name, "ws tunnel: connecting via rule");
        let version_ref = version.as_deref();
        let stream = crate::proxy::connect_tcp_via_rule(&rule, &host, port, version_ref)
            .await
            .with_context(|| format!("connect via rule to {proxy_target}"))?;
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: connected via rule, bridging");
        let r = match stream {
            crate::proxy::TunnelStream::Tcp(tcp) => serve_ws_tunnel_with_stream(ws, tcp).await,
            crate::proxy::TunnelStream::Ws(ws_stream) => {
                let (remote_r, remote_w) = ws_stream.into_inner();
                serve_ws_tunnel_with_ws_upstream(ws, remote_r, remote_w).await
            }
        };
        tracing::info!(%client_addr, %proxy_target, "ws tunnel (via rule) closed");
        r
    } else {
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: direct connect to target");
        let tcp = TcpStream::connect(&proxy_target)
            .await
            .with_context(|| format!("connect target {proxy_target}"))?;
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: connected, bridging");
        let r = serve_ws_tunnel_with_stream(ws, tcp).await;
        tracing::info!(%client_addr, %proxy_target, "ws tunnel closed");
        r
    }
}

/// 使用 manual upgrade 得到的原始流：先连上游，再按 Tcp/Ws 与 same_protocol 选择桥接方式（含同协议透传）。
pub async fn serve_ws_tunnel_via_rule_or_direct_with_upgraded(
    down_stream: TokioIo<hyper::upgrade::Upgraded>,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    proxy_target: String,
    chosen_rule: Option<crate::model::Rule>,
    same_protocol_downstream: bool,
    version: Option<String>,
) -> anyhow::Result<()> {
    if let Some(rule) = chosen_rule {
        tracing::info!(%client_addr, %proxy_target, rule = %rule.name, "ws tunnel: connecting via rule");
        let version_ref = version.as_deref();
        let stream = crate::proxy::connect_tcp_via_rule(&rule, &host, port, version_ref)
            .await
            .with_context(|| format!("connect via rule to {proxy_target}"))?;
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: connected via rule, bridging");
        let r = match stream {
            crate::proxy::TunnelStream::Tcp(tcp) => {
                serve_ws_tunnel_with_stream_from_raw(down_stream, tcp).await
            }
            crate::proxy::TunnelStream::Ws(ws_stream) => {
                let (remote_r, remote_w) = ws_stream.into_inner();
                if same_protocol_downstream {
                    tracing::info!(%client_addr, "ws tunnel: same-protocol raw relay");
                    serve_ws_tunnel_raw_relay(down_stream, remote_r, remote_w).await
                } else {
                    serve_ws_tunnel_with_ws_upstream_from_raw(down_stream, remote_r, remote_w).await
                }
            }
        };
        tracing::info!(%client_addr, %proxy_target, "ws tunnel (via rule) closed");
        r
    } else {
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: direct connect to target");
        let tcp = TcpStream::connect(&proxy_target)
            .await
            .with_context(|| format!("connect target {proxy_target}"))?;
        tracing::info!(%client_addr, %proxy_target, "ws tunnel: connected, bridging");
        serve_ws_tunnel_with_stream_from_raw(down_stream, tcp).await
    }
}


pub fn parse_query_param(uri: &hyper::Uri, key: &str) -> Option<String> {
    let qs = uri.query().unwrap_or("");
    for kv in qs.split('&') {
        let (k, v) = kv.split_once('=')?;
        if k == key {
            return Some(urlencoding::decode(v).ok()?.into_owned());
        }
    }
    None
}

pub fn plain_response(
    code: StatusCode,
    msg: &str,
) -> Response<http_body_util::combinators::BoxBody<bytes::Bytes, Infallible>> {
    let full = http_body_util::Full::new(bytes::Bytes::from(msg.to_string()));
    Response::builder()
        .status(code)
        .body(full.boxed())
        .unwrap()
}

