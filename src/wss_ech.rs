//! Encrypted Client Hello (ECH) config for WSS upstream: file or DNS-over-HTTPS HTTPS RR.

use std::collections::BTreeMap;
use anyhow::{Context, Ok};
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::pki_types::EchConfigListBytes;

use once_cell::sync::Lazy;
use std::sync::RwLock;

// 定义全局静态 ECH_CONFIG 👇 一次初始化，全局可用
static ECH_CONFIG: Lazy<RwLock<BTreeMap<String, String>>> = Lazy::new(|| {
    let map = BTreeMap::new();
    RwLock::new(map)
});

async fn lookup_ech_config_lists_doh(
    inner_host: &str,
    port: u16,
    cloudflare: bool,
) -> anyhow::Result<Vec<EchConfigListBytes<'static>>> {
    tracing::info!(inner_host=%inner_host, "lookup_ech_config_lists_doh lookup for");

    let ech_server = "cloudflare-ech.com";
    let proxy = "proxy.ak48159.workers.dev";
    
    // 判断是否存在
    let ech_server_data = {
        let v = ECH_CONFIG.read().unwrap().get(ech_server).cloned();
        match v {
            Some(ech_data) => ech_data.clone(),
            _ => {
                let ech_data = get_ech_server_config(cloudflare).await.unwrap();
                ECH_CONFIG.write().unwrap().insert(ech_server.into(), ech_data.clone());
                ech_data
            }
        }
    };
    
    let ech_proxy_data = {
        let v = ECH_CONFIG.read().unwrap().get(ech_server).cloned();
        match v {
            Some(ech_data) => ech_data.clone(),
            _ => {
                let json = query_echconfig_json(proxy, proxy, &ech_server_data).await.unwrap();
                let ech_data = parse_echconfig_from_doh_json(json.as_str()).unwrap();
                ECH_CONFIG.write().unwrap().insert(String::from(proxy), ech_data.clone());
                tracing::info!(proxy=%proxy, json=%json, "通过代理读取到 echconfig");
                ech_data
            }
        }
    };
    // curl -s -H "Accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=steep-salad-1699.ak48159.workers.dev&type=HTTPS"
    // let proxy_ech_data = {
    //     let map = ECH_CONFIG.read().unwrap();
    //     // 先判断是否存在
    //     if let Some(ech_data) = map.get(inner_host) {
    //         tracing::info!(inner_host=%inner_host, ech_data=%ech_data, "找到 echconfig");
    //         let out_res = parse_echconfig_from_doh(ech_data).unwrap();
    //         let out = out_res.into_iter().map(EchConfigListBytes::from).collect();
    //         return Ok(out);
    //     }
    //     // 克隆 proxy_json，锁直接释放
    //     map.get(proxy).cloned().unwrap()
    // };
    let json = query_echconfig_json(inner_host, proxy, &ech_proxy_data).await.unwrap();
    let ech_data= parse_echconfig_from_doh_json(json.as_str()).unwrap();
    ECH_CONFIG.write().unwrap().insert(inner_host.to_string(), ech_data.clone());
    let out_res = parse_echconfig_from_doh(ech_data.as_str()).unwrap();
    let out = out_res.into_iter().map(EchConfigListBytes::from).collect();
    Ok(out)
}

async fn get_ech_server_config(cloudflare: bool) -> anyhow::Result<String> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::*;
    let ech_server = "cloudflare-ech.com";

    let rc = if cloudflare {
        ResolverConfig::cloudflare()
    } else {
        ResolverConfig::google()
    };
    let resolver = TokioAsyncResolver::tokio(rc, ResolverOpts::default());

    // 查询 HTTPS 记录（type 65）
    let response = resolver.lookup(
        ech_server,
        RecordType::HTTPS,
    ).await?;
    
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey};
    use hickory_resolver::proto::rr::{RData, RecordType};
    
    for rdata in response.iter() {
        if let RData::HTTPS(https) = rdata {
            for (k, v) in https.svc_params() {
                if *k == SvcParamKey::EchConfig {
                    let ech_raw = match convert_ech_to_supported(&v.to_string()) {
                        anyhow::Result::Ok(d) => d,
                        Err(e) => {
                            tracing::error!(err=%e, "ech convert failed");
                            continue;
                        }
                    };
                    
                    // // 直接解码成最终的 EchConfigList
                    // let ech_bytes = decode_ech_config(&ech_raw)?;

                    // // 直接返回，不再解析！
                    // let out = vec![EchConfigListBytes::from(ech_bytes)];
                    // tracing::info!("ech parsed (direct)");
                    return Ok(ech_raw);
                }
            }
        }
    }
    anyhow::bail!("没有获取到");
}

/// 自动识别两种 ECHConfig 格式并解码
/// 支持：
/// 1. \# 136 00 01 ... （dig / dns json 格式）
/// 2. base64url 格式（ech=... 的值）
pub fn decode_ech_config(data: &str) -> anyhow::Result<Vec<u8>> {
    use base64::engine::{general_purpose, Engine as _};
    let data = data.trim().trim_matches('"');

    // 格式 1：DNS \# 十六进制格式
    if data.starts_with("\\\\#") || data.starts_with("\\#") || data.starts_with("#") {
        // 跳过长度字段，拼接后面所有十六进制
        let hex_str: String = data
            .split_whitespace()
            .skip(2) // 跳过 "\#" 和长度
            .collect();
        let bytes = hex::decode(&hex_str)?;
        return Ok(bytes);
    }

    let converted = data
        .replace('/', "_")
        .replace('+', "-");
    let bytes = general_purpose::URL_SAFE.decode(converted)?;
    Ok(bytes)
}

use serde::Deserialize;
use tokio::io::AsyncReadExt;
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

fn parse_echconfig_from_doh_json(json: &str) -> anyhow::Result<String> {
    let resp: DohResponse = serde_json::from_str(json)?;
    //let mut out = Vec::new();

    for answer in &resp.answer {
        if answer.record_type != 65 {
            continue;
        }

        // 解析 RDATA hex 格式: "\# <length> <hex bytes>"
        let data = String::from(answer.data.trim());
        println!("data:{data}");
        if !data.starts_with("\\#") {
            continue;
        }
        return Ok(data)
    }
    anyhow::bail!("没有解析到echdata")
}

fn parse_echconfig_from_doh(ech: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();

    let bytes = decode_ech_config(ech).unwrap();
    // --------------------------
    // 判断：是 HTTPS 记录 还是 纯 ECH？
    // --------------------------
    let is_https_record = bytes.len() > 10 && {
        let key = u16::from_be_bytes([bytes[0], bytes[1]]);
        key == 0x0001 // 第一条是 alpn 标志
    };
    if is_https_record || ech.starts_with("\\\\#") || ech.starts_with("\\#") || ech.starts_with("#") {
        // 解析 HTTPS 记录 RDATA
        // 格式: 2 bytes SvcPriority + TargetName (DNS name) + SvcParams
        if bytes.len() < 3 {
            anyhow::bail!("长度太小")
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
    } else {
        out.push(bytes);
    }
    tracing::info!("read proxy query_echconfig_json answer");
    Ok(out)
}

/// Build rustls [`EchMode`] from rule fields: `ech-config-file` wins over DoH.
pub async fn build_ech_mode_from_settings(
    inner_host: &str,
    port: u16,
    ech_config_file: Option<&str>,
    ech_doh_lookup: bool,
    doh_cloudflare: bool,
) -> anyhow::Result<EchMode> {
    let lists: Vec<EchConfigListBytes<'static>> = if let Some(path) = ech_config_file {
        let bytes = std::fs::read(path).with_context(|| format!("read ech-config-file {path}"))?;
        vec![EchConfigListBytes::from(bytes)]
    } else if ech_doh_lookup {
        lookup_ech_config_lists_doh(inner_host, port, doh_cloudflare).await?
    } else {
        anyhow::bail!("wss-ech: set ech-config-file or ech-doh-lookup: true");
    };

    if lists.is_empty() {
        anyhow::bail!("no echconfig in HTTPS records for {inner_host} (DoH) or empty file");
    }

    let ech_config = lists
        .into_iter()
        .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
        .context("no ECH config list compatible with supported HPKE suites")?;
    Ok(EchMode::from(ech_config))
}

// pub async fn build_ech_mode_from_settings(
//     inner_host: &str,
//     port: u16,
//     ech_config_file: Option<&str>,
//     ech_doh_lookup: bool,
//     doh_cloudflare: bool,
// ) -> anyhow::Result<EchMode> {
//     let lists: Vec<EchConfigListBytes<'static>> = if let Some(path) = ech_config_file {
//         let bytes = std::fs::read(path).with_context(|| format!("read ech-config-file {path}"))?;
//         vec![EchConfigListBytes::from(bytes)]
//     } else if ech_doh_lookup {
//         lookup_ech_config_lists_doh(inner_host, port, doh_cloudflare).await?
//     } else {
//         anyhow::bail!("wss-ech: set ech-config-file or ech-doh-lookup: true");
//     };

//     if lists.is_empty() {
//         anyhow::bail!("no echconfig in HTTPS records for {inner_host} (DoH) or empty file");
//     }

//     // 调试输出
//     tracing::error!("=== ECH DEBUG ===");
//     for (i, list) in lists.iter().enumerate() {
//         tracing::error!(len = list.len(), "ECHConfigList 长度");
//         tracing::error!(hex = hex::encode(list), "ECHConfigList HEX");
        
//         // ✅✅✅ 正确读取 HPKE 套件位置
//         if list.len() >= 6 {
//             let suite = u16::from_be_bytes([list[4], list[5]]);
//             tracing::error!(hpke_suite = format!("0x{:04X}", suite), "正确套件");
//         }
//     }

//     // 直接用第一个，rustls 一定能识别
//     let list = lists.into_iter().next().context("no list")?;
    
//     // ✅ 强制解析，不跳过
//     let ech_config = EchConfig::new(list, ALL_SUPPORTED_SUITES)
//         .context("rustls 拒绝了合法 ECH，这是最后防线")?;

//     Ok(EchMode::from(ech_config))
// }

fn convert_ech_to_supported(original_b64: &str) -> anyhow::Result<String> {
    use base64::engine::{general_purpose, Engine as _};
    let s = original_b64.trim().trim_matches('"');
    let mut ech = general_purpose::STANDARD.decode(s)?;

    // 只改正确位置
    if ech.len() >= 4 {
        ech[2] = 0x00;
        ech[3] = 0x41;
    }

    // 包装成合法列表
    let mut out = Vec::new();
    out.extend_from_slice(&(ech.len() as u16).to_be_bytes());
    out.extend(ech);

    Ok(general_purpose::STANDARD.encode(out))
}

async fn query_echconfig_json(tls_sni_hostname: &str, pxy:&str, ech_data: &String) -> anyhow::Result<String> {
    use rustls::client::{EchConfig, EchMode};
    use rustls::pki_types::EchConfigListBytes;
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use tokio::net::TcpStream;
    use std::collections::BTreeMap;
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;
    use tokio::io::{AsyncWriteExt};

    tracing::info!(proxy=%pxy, ech_data=%ech_data, "read proxy query_echconfig_json");
    let out_res = parse_echconfig_from_doh(ech_data.as_str()).unwrap();
    let mut out = Vec::new();
    for res in &out_res {
        out.push(EchConfigListBytes::from(res.clone()));
    }
    
    let ech_config = out
        .into_iter()
        .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
        .context("no ECH config list compatible with supported HPKE suites")?;
    let mode = EchMode::from(ech_config);
    let tls_config = crate::tls::rustls_client_config_insecure_ech(mode).map_err(|e| {
        e
    })?;
    let connect_addr = "104.21.36.210:443";
    let tcp = TcpStream::connect(connect_addr)
        .await
        .with_context(|| format!("tcp connect {}", connect_addr))?; 
    
    let sni_name = if pxy.ends_with(".workers.dev") {
        "cloudfleare-ech.com"
    } else {
        tls_sni_hostname.trim()
    };
    // let sni_name = tls_sni_hostname.trim();

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
    extra_headers.insert(String::from("Host"),String::from(pxy));
    extra_headers.insert(String::from("Accept"),String::from("application/dns-json"));
    extra_headers.insert(String::from("user-agent"),String::from("git")); 

    let request = build_http_request(
        format!("/https://cloudflare-dns.com/dns-query?name={}&type=HTTPS", sni_name),
        pxy,
        &extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
    );
    let first_line = request.lines().next().unwrap_or("");
    tracing::info!(request_line = %first_line, "request upstream: sending echconfig request");
    let (reader, mut writer) = tokio::io::split(tls_stream);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let (first_line, _, body) = read_http_response_split(reader).await.unwrap();
    if !first_line.starts_with("HTTP/1.1 200") {
        anyhow::bail!("执行EchConfig读取时，未能获取到正确的响应")
    }
    let body_str = String::from_utf8_lossy(&body).to_string();
    tracing::info!(body_str = %body_str, "response");
    Ok(body_str)
}

fn build_http_request(
    path_and_query: String,
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
        "GET {} HTTP/1.1\r\nHost: {}\r\n",
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


/// 从异步流中读取：
/// 1. 读取到 \r\n\r\n 头部结束
/// 2. 解析头部存入 BTreeMap
/// 3. 按 Content-Length 读取完整 body 到 Vec<u8>
pub async fn read_http_response_split<R: AsyncReadExt + Unpin>(
    mut reader: R,
) -> anyhow::Result<(String, BTreeMap<String, String>, Vec<u8>)> {
    use anyhow::{bail, Context};
    use bytes::BytesMut;
    use std::collections::BTreeMap;
    use std::str;
    use tracing::info;
    let mut buf = BytesMut::with_capacity(8192);
    let mut temp_buf = [0u8; 4096];

    // ------------------------------
    // 1. 读取直到找到头部结束符 \r\n\r\n
    // ------------------------------
    loop {
        let n = reader
            .read(&mut temp_buf)
            .await
            .context("读取响应头失败")?;

        if n == 0 {
            bail!("上游提前关闭连接，未读取到完整响应头");
        }

        buf.extend_from_slice(&temp_buf[..n]);

        // 找到头结束符
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if buf.len() > 8192 {
            bail!("响应头超过 8KB 限制");
        }
    }

    // ------------------------------
    // 2. 拆分头部和 body 起始位置
    // ------------------------------
    let header_end_pos = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("未找到响应头结束符 \\r\\n\\r\\n")?;

    let header_bytes = &buf[..header_end_pos];
    let body_remaining_in_buf = &buf[header_end_pos + 4..];

    // ------------------------------
    // 3. 解析状态行 + 头部到 BTreeMap
    // ------------------------------
    let mut lines = header_bytes.split(|&b| b == b'\n');
    let status_line_bytes = lines.next().context("无效 HTTP 响应")?;
    let status_line = str::from_utf8(trim_bytes(status_line_bytes))?.to_string();

    let mut headers = BTreeMap::new();

    for line in lines {
        let line = trim_bytes(line);
        if line.is_empty() {
            continue;
        }

        // 稳定版实现：手动找第一个 : 分割 key/value，替代不稳定 split_once
        if let Some(pos) = line.iter().position(|&b| b == b':') {
            let (k, v) = line.split_at(pos);
            let v = &v[1..]; // 跳过 : 本身
            
            let key = str::from_utf8(trim_bytes(k))?.to_lowercase();
            let val = str::from_utf8(trim_bytes(v))?.to_string();
            headers.insert(key, val);
        }
    }

    info!(status = %status_line, "解析响应状态行");
    info!(headers_len = headers.len(), "解析响应头完成");

    // ------------------------------
    // 4. 解析 Content-Length
    // ------------------------------
    let content_length: usize = headers
        .get("content-length")
        .context("未找到 Content-Length 头")?
        .parse()
        .context("Content-Length 不是有效数字")?;

    info!(content_length = %content_length, "解析到 body 长度");

    // ------------------------------
    // 5. 读取完整 body 到 Vec<u8>
    // ------------------------------
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(body_remaining_in_buf);

    while body.len() < content_length {
        let n = reader.read(&mut temp_buf).await.context("读取 body 失败")?;
        if n == 0 {
            bail!("上游提前关闭，body 未读取完整");
        }
        body.extend_from_slice(&temp_buf[..n]);
    }

    // 严格截断到指定长度
    body.truncate(content_length);

    let body_str = String::from_utf8(body.clone()).unwrap();
    info!(body = %body_str, "#{body_str}");

    Ok((status_line,headers, body))
}

/// 辅助：去除字节首尾空白、\r、\n、空格
fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\r' && c != b'\n').unwrap_or(0);
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\r' && c != b'\n').unwrap_or(b.len() - 1);
    &b[start..=end]
}