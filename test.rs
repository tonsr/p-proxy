use anyhow::Context;
use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::EchConfigListBytes;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use tokio::net::TcpStream;
use core::str;
use std::collections::BTreeMap;
use std::sync::Arc;
use rustls::pki_types::{CertificateDer};
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 直接指定 1.1.1.1 UDP
    let tls_sni_hostname = "steep-salad-1699.ak48159.workers.dev";
    let mut out = Vec::new();

    let json = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"steep-salad-1699.ak48159.workers.dev","type":65}],"Answer":[{"name":"steep-salad-1699.ak48159.workers.dev","type":65,"TTL":300,"data":"\\# 136 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68 15 24 d2 ac 43 c7 9b 00 05 00 47 00 45 fe 0d 00 41 c1 00 20 00 20 80 15 e3 7a 9e 41 9f b0 d2 fc c4 fb 18 7f 86 ba 8c 8d 3b c0 80 12 66 d0 5a d1 e3 8d 8c e9 60 4c 00 04 00 01 00 01 00 12 63 6c 6f 75 64 66 6c 61 72 65 2d 65 63 68 2e 63 6f 6d 00 00 00 06 00 20 26 06 47 00 30 33 00 00 00 00 00 00 68 15 24 d2 26 06 47 00 30 33 00 00 00 00 00 00 ac 43 c7 9b"}]}"#;
    let out_res = parse_echconfig_from_doh_json(json).unwrap();
    for res in &out_res {
        out.push(EchConfigListBytes::from(res.clone()));
    }
    
    let ech_config = out
        .into_iter()
        .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
        .context("no ECH config list compatible with supported HPKE suites")?;
    let mode = EchMode::from(ech_config);
    let tls_config = rustls_client_config_insecure_ech(mode).map_err(|e| {
        e
    })?;
    let connect_addr = "108.162.198.56:443";
    let tcp = TcpStream::connect(connect_addr)
        .await
        .with_context(|| format!("tcp connect {}", connect_addr))?; 
    let sni_name = tls_sni_hostname.trim();
    let sni = ServerName::try_from(sni_name)
        .map_err(|_| anyhow::anyhow!("invalid TLS server name / SNI: {}", sni_name))?
        .to_owned();
    tracing::info!(tls_sni = %sni_name, addr = %connect_addr, "wss upstream: TLS ServerName and HTTP Host");

    let connector = TlsConnector::from(tls_config);
    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("tls connect: {}", e))?;
    let mut extra_headers = BTreeMap::new();
    extra_headers.insert(String::from("Host"),String::from("steep-salad-1699.ak48159.workers.dev"));

    let request = build_upgrade_request(
        "/?token=THIS_IS_MY_TOKEN&proxy=github.com:443",
        tls_sni_hostname,
        &extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
    );
    let first_line = request.lines().next().unwrap_or("");
    tracing::info!(request_line = %first_line, "wss upstream: sending upgrade request");
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
    let body = str::from_utf8(&buf).unwrap();
    println!("str:{body}");
    Ok(())
}

use serde::Deserialize;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Vec<DohAnswer>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

/// 从 DoH JSON 响应中提取 ECHConfig 字节
fn parse_echconfig_from_doh_json(json: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let resp: DohResponse = serde_json::from_str(json)?;
    let mut out = Vec::new();

    for answer in &resp.answer {
        if answer.record_type != 65 {
            continue;
        }

        // 解析 RDATA hex 格式: "\# <length> <hex bytes>"
        let data = answer.data.trim();
        if !data.starts_with("\\#") {
            continue;
        }

        // 跳过 "\#" 和长度，取 hex 部分
        let hex_str: String = data
            .split_whitespace()
            .skip(2) // 跳过 "\#" 和长度
            .collect();
        let bytes = hex::decode(&hex_str)?;

        // 解析 HTTPS 记录 RDATA
        // 格式: 2 bytes SvcPriority + TargetName (DNS name) + SvcParams
        if bytes.len() < 3 {
            continue;
        }

        let mut pos = 2; // 跳过 SvcPriority

        // 跳过 TargetName (DNS name: length-prefixed labels, 以 0 结尾)
        while pos < bytes.len() && bytes[pos] != 0 {
            let label_len = bytes[pos] as usize;
            pos += 1 + label_len;
        }
        pos += 1; // 跳过结尾的 0

        // 解析 SvcParams (key: 2 bytes, length: 2 bytes, value: length bytes)
        while pos + 4 <= bytes.len() {
            let key = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
            pos += 4;

            if pos + len > bytes.len() {
                break;
            }

            if key == 0x0005 {
                // echconfig — 这就是 ECHConfigList 的原始字节
                out.push(bytes[pos..pos + len].to_vec());
            }

            pos += len;
        }
    }

    Ok(out)
}


fn build_http_request(
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

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\n",
        path_and_query,
        host_value,
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
    tracing::info!(
        connect = %req,
        "req:"
    );
    req
}

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
    tracing::info!(
        connect = %req,
        "req:"
    );
    req
}


pub fn rustls_client_config_insecure_ech(
    ech_mode: rustls::client::EchMode,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::ServerName;
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    struct InsecureVerifier;

    impl ServerCertVerifier for InsecureVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_ech(ech_mode)
    .map_err(|e| anyhow::anyhow!("rustls with_ech: {e}"))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

