use anyhow::Context;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn connect_via_socks5(
    upstream_host: &str,
    upstream_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> anyhow::Result<TcpStream> {
    let mut s = TcpStream::connect(format!("{upstream_host}:{upstream_port}")).await?;

    // greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    s.flush().await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        anyhow::bail!("upstream socks5 does not accept no-auth");
    }

    // connect request
    let mut req = Vec::new();
    req.push(0x05); // VER
    req.push(0x01); // CMD=CONNECT
    req.push(0x00); // RSV
    if let Ok(ip) = dest_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let bytes = dest_host.as_bytes();
        if bytes.len() > 255 {
            anyhow::bail!("dest host too long for socks5");
        }
        req.push(0x03);
        req.push(bytes.len() as u8);
        req.extend_from_slice(bytes);
    }
    req.extend_from_slice(&dest_port.to_be_bytes());
    s.write_all(&req).await?;
    s.flush().await?;

    // reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        anyhow::bail!("invalid socks5 reply ver");
    }
    if head[1] != 0x00 {
        anyhow::bail!("upstream socks5 connect failed, rep={}", head[1]);
    }
    let atyp = head[3];
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let len = s.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
        }
        _ => anyhow::bail!("invalid socks5 reply atyp"),
    }
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;

    Ok(s)
}

pub async fn connect_via_socks5_with_context(
    upstream_host: &str,
    upstream_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> anyhow::Result<TcpStream> {
    connect_via_socks5(upstream_host, upstream_port, dest_host, dest_port)
        .await
        .with_context(|| format!("socks5 upstream {upstream_host}:{upstream_port} -> {dest_host}:{dest_port}"))
}

