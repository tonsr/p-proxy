use crate::config::{save_config, Config, DnsDomainConfig, RuleConfig, TunnelType, UserConfig, WebsocketTunnelEndpoint};
use crate::dns::{parse_dns_groups, DnsManager};
use crate::model::{parse_rules, parse_users, users_by_name, CompiledRules, Rule, UpstreamTarget, User};
use crate::stats::DailyStats;
use crate::AppState;
use bytes::Bytes;
use url::Url;
use http_body_util::combinators::BoxBody;
use http_body_util::Full;
use http_body_util::BodyExt;
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode};
use std::collections::HashMap;
use base64::Engine;
use std::convert::Infallible;

/// 解析 Basic 头并校验用户；返回当前登录用户（用于按 auth_rules 过滤隧道等）。
pub fn current_ui_user<'a>(
    auth_header: Option<&str>,
    users: &'a HashMap<String, crate::model::User>,
) -> Option<&'a crate::model::User> {
    let h = auth_header?;
    let b64 = h.trim().strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    let user = users.get(u)?;
    if user.password != p {
        return None;
    }
    Some(user)
}

fn resp(code: StatusCode, body: String) -> Response<BoxBody<Bytes, Infallible>> {
    let full = Full::new(Bytes::from(body));
    Response::builder()
        .status(code)
        .header("content-type", "text/html; charset=utf-8")
        .body(full.boxed())
        .unwrap()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn form_val(form: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    form.split('&')
        .find(|kv| kv.starts_with(&prefix))
        .and_then(|kv| kv.strip_prefix(&prefix))
        .and_then(|v| urlencoding::decode(v).ok())
        .map(|c| c.to_string())
}

fn resp_unauthorized() -> Response<BoxBody<Bytes, Infallible>> {
    let mut r = resp(StatusCode::UNAUTHORIZED, "unauthorized".to_string());
    r.headers_mut().insert(
        WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Basic realm=\"p-proxy-ui\""),
    );
    r
}

const LAYOUT_CSS: &str = r#"
:root { --bg:#0f0f12; --card:#18181c; --border:#2a2a30; --text:#e4e4e7; --muted:#71717a; --accent:#3b82f6; --hover:#27272a; }
* { box-sizing:border-box; }
body { margin:0; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); min-height:100vh; display:flex; }
.sidebar { width:220px; flex-shrink:0; background: var(--card); border-right:1px solid var(--border); padding:1rem 0; }
.sidebar a { display:block; padding:0.6rem 1.25rem; color: var(--text); text-decoration:none; font-size:0.9rem; }
.sidebar a:hover { background: var(--hover); }
.sidebar a.active { background: var(--accent); color:#fff; }
.main { flex:1; padding:1.5rem 2rem; overflow-auto; }
h1 { font-size:1.5rem; margin:0 0 1rem; font-weight:600; }
.card { background: var(--card); border:1px solid var(--border); border-radius:8px; padding:1.25rem; margin-bottom:1rem; }
.card h2 { font-size:1.1rem; margin:0 0 0.75rem; font-weight:500; }
label { display:block; margin-bottom:0.25rem; font-size:0.875rem; color: var(--muted); }
input, select, textarea { width:100%; max-width:400px; padding:0.5rem 0.75rem; border:1px solid var(--border); border-radius:6px; background: var(--bg); color: var(--text); font-size:0.9rem; }
textarea { min-height:80px; resize:vertical; }
button, .btn { display:inline-block; padding:0.5rem 1rem; background: var(--accent); color:#fff; border:none; border-radius:6px; cursor:pointer; font-size:0.9rem; text-decoration:none; }
button:hover, .btn:hover { opacity:0.9; }
.btn-secondary { background: var(--hover); }
.flash { padding:0.5rem 1rem; border-radius:6px; margin-bottom:1rem; }
.flash.ok { background:#166534; color:#dcfce7; }
.flash.err { background:#991b1b; color:#fecaca; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid var(--border); font-size:0.875rem; }
th { color: var(--muted); font-weight:500; }
.del { color:#f87171; text-decoration:none; font-size:0.85rem; }
.del:hover { text-decoration:underline; }
.edt { color:#3b82f6; text-decoration:none; font-size:0.85rem; margin-right:0.5rem; }
.edt:hover { text-decoration:underline; }
"#;

fn layout(active: &str, title: &str, content: &str, flash: Option<(&str, bool)>) -> String {
    let nav = [
        ("/ui", "基本配置"),
        ("/ui/rules", "规则管理"),
        ("/ui/dns", "域名解析"),
        ("/ui/users", "用户管理"),
        ("/ui/tunnels", "隧道端点"),
        ("/ui/stats", "统计"),
        ("/ui/logs", "日志"),
        ("/ui/check", "检查"),
    ];
    let mut nav_html = String::new();
    for (href, label) in nav {
        let is_active = active == href || (active == "/ui" && href == "/ui");
        nav_html.push_str(&format!(
            r#"<a href="{}" class="{}">{}</a>"#,
            href,
            if is_active { "active" } else { "" },
            label
        ));
    }
    let flash_html = flash.map(|(msg, ok)| {
        format!(
            r#"<div class="flash {}">{}</div>"#,
            if ok { "ok" } else { "err" },
            html_escape(msg)
        )
    }).unwrap_or_default();
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{}</title><style>{}</style></head><body>
<div class="sidebar"><a href="/ui">p-proxy</a>{}</div>
<div class="main"><h1>{}</h1>{}{}</div></body></html>"#,
        html_escape(title),
        LAYOUT_CSS,
        nav_html,
        html_escape(title),
        flash_html,
        content
    )
}

async fn apply_config(state: &AppState, new_cfg: &Config) -> anyhow::Result<()> {
    let path = {
        let g = state.read().await;
        g.config_path.clone()
    };
    save_config(&path, new_cfg)?;
    let loaded = crate::config::load_config(&path)?;
    let users = users_by_name(parse_users(&loaded.proxy_server.users));
    let rules = parse_rules(&loaded.proxy_server.rules)?;
    let dns = if loaded.proxy_server.dns_domains.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(
            DnsManager::new(parse_dns_groups(&loaded.proxy_server.dns_domains)?)?,
        ))
    };
    let direct_whitelist = if loaded.proxy_server.direct_access_white_list.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(
            crate::model::parse_direct_access_white_list(&loaded.proxy_server.direct_access_white_list)?,
        ))
    };
    let mut g = state.write().await;
    g.cfg = std::sync::Arc::new(loaded);
    g.users = std::sync::Arc::new(users);
    g.rules = std::sync::Arc::new(CompiledRules::new(rules));
    g.dns = dns;
    g.direct_whitelist = direct_whitelist;
    Ok(())
}

pub async fn handle_ui(
    req: Request<hyper::body::Incoming>,
    state: AppState,
    cfg: &Config,
    rules: &CompiledRules,
    users: &HashMap<String, crate::model::User>,
    dns: Option<&DnsManager>,
    stats: &DailyStats,
) -> anyhow::Result<Response<BoxBody<Bytes, Infallible>>> {
    let auth_header = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    let current_user = match current_ui_user(auth_header, users) {
        Some(u) => u,
        None => return Ok(resp_unauthorized()),
    };

    let path: String = {
        let p = req.uri().path().trim_end_matches('/');
        if p.is_empty() { "/ui".to_string() } else { p.to_string() }
    };
    let query = req.uri().query().map(|s| s.to_string());

    // POST save handlers (save and apply)
    if req.method() == Method::POST {
        let body = req.collect().await?.to_bytes();
        let form = String::from_utf8_lossy(&body);

        if path == "/ui/basic" || path.as_str() == "/ui" {
            let mut new_cfg = cfg.clone();
            fn has(form: &str, key: &str) -> bool {
                form.split('&').any(|kv| kv == key || kv.starts_with(&format!("{}=", key)))
            }
            new_cfg.proxy_server.http_proxy_enable = has(&form, "http_proxy_enable");
            new_cfg.proxy_server.https_proxy_enable = has(&form, "https_proxy_enable");
            new_cfg.proxy_server.socks5_proxy_enable = has(&form, "socks5_proxy_enable");
            new_cfg.proxy_server.allow_anonymous = has(&form, "allow_anonymous");
            new_cfg.proxy_server.tls_enable = has(&form, "tls_enable");
            new_cfg.proxy_server.ws_proxy = Some(crate::config::WsProxyConfig {
                enable: has(&form, "ws_proxy_enable"),
                path: form_val(&form, "ws_proxy_path").unwrap_or_else(|| "/ws".to_string()),
                token: form_val(&form, "ws_proxy_token").unwrap_or_default(),
                rate_limit_per_minute: form_val(&form, "ws_proxy_rate_limit_per_minute")
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0),
            });
            new_cfg.proxy_server.web_ui = Some(crate::config::WebUiConfig {
                enable: has(&form, "web_ui_enable"),
                path: form_val(&form, "web_ui_path").unwrap_or_else(|| "/ui".to_string()),
            });
            for kv in form.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or(("", ""));
                let v = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v));
                match k {
                    "bind_address" => new_cfg.proxy_server.bind_address = Some(v.into_owned()),
                    "bind_port" => new_cfg.proxy_server.bind_port = v.parse().ok().or(new_cfg.proxy_server.bind_port),
                    "log_path" => {
                        if let Some(ref mut log) = new_cfg.proxy_server.log {
                            log.path = v.to_string();
                        }
                    }
                    "log_level" => {
                        if let Some(ref mut log) = new_cfg.proxy_server.log {
                            log.level = v.to_string();
                        }
                    }
                    _ => {}
                }
            }
            if new_cfg.proxy_server.log.is_none() {
                new_cfg.proxy_server.log = Some(crate::config::LogConfig {
                    enable: true,
                    level: "info".to_string(),
                    path: "proxy.log".to_string(),
                    encoding: None,
                });
            }
            match apply_config(&state, &new_cfg).await {
                Ok(()) => return Ok(resp(StatusCode::OK, layout("/ui", "基本配置", &page_basic(cfg), Some(("已保存并生效", true))))),
                Err(e) => return Ok(resp(StatusCode::OK, layout("/ui", "基本配置", &page_basic(cfg), Some((&e.to_string(), false))))),
            }
        }

        if path.as_str() == "/ui/rules" {
            let action = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "action").map(|(_,v)| v));
            if action == Some("update") {
                let edit_name = form_val(&form, "edit_name");
                let name = form_val(&form, "name").unwrap_or_default();
                let target = form_val(&form, "target").unwrap_or_default();
                let domains = form_val(&form, "domains").unwrap_or_default();
                if let Some(ref key) = edit_name && !name.is_empty() && !target.is_empty() {
                    let mut new_cfg = cfg.clone();
                    if let Some(pos) = new_cfg.proxy_server.rules.iter().position(|r| r.name == *key) {
                        new_cfg.proxy_server.rules[pos] = RuleConfig {
                            name: name.clone(),
                            target,
                            domains: if domains.is_empty() { None } else { Some(domains) },
                            headers: new_cfg.proxy_server.rules[pos].headers.clone(),
                            websocket_tunnel: new_cfg.proxy_server.rules[pos].websocket_tunnel.clone(),
                            wss_ech: new_cfg.proxy_server.rules[pos].wss_ech.clone(),
                        };
                        match apply_config(&state, &new_cfg).await {
                            Ok(()) => {
                                let (cfg2, rules2) = { let g = state.read().await; (g.cfg.clone(), g.rules.clone()) };
                                return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules2.rules, &cfg2, None), Some(("规则已更新并生效", true)))));
                            }
                            Err(e) => return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules.rules, cfg, edit_name.as_deref()), Some((&e.to_string(), false))))),
                        }
                    }
                }
            }
            if action == Some("add") {
                let name = form_val(&form, "name").unwrap_or_default();
                let target = form_val(&form, "target").unwrap_or_default();
                let domains = form_val(&form, "domains").unwrap_or_default();
                if !name.is_empty() && !target.is_empty() {
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.rules.push(RuleConfig {
                        name,
                        target,
                        domains: if domains.is_empty() { None } else { Some(domains) },
                        headers: None,
                        websocket_tunnel: None,
                        wss_ech: None,
                    });
                    match apply_config(&state, &new_cfg).await {
                        Ok(()) => return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules.rules, cfg, None), Some(("规则已添加并生效", true))))),
                        Err(e) => return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules.rules, cfg, None), Some((&e.to_string(), false))))),
                    }
                }
            }
            if let Some(del) = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "delete").map(|(_,v)| urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string())) {
                let mut new_cfg = cfg.clone();
                new_cfg.proxy_server.rules.retain(|r| r.name != del);
                let _ = apply_config(&state, &new_cfg).await;
                let (cfg2, rules2) = { let g = state.read().await; (g.cfg.clone(), g.rules.clone()) };
                return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules2.rules, &cfg2, None), Some(("已删除并生效", true)))));
            }
        }

        if path.as_str() == "/ui/dns" {
            let action = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "action").map(|(_,v)| v));
            if action == Some("update") {
                let edit_name = form_val(&form, "edit_name");
                let name = form_val(&form, "name").unwrap_or_default();
                let domains = form_val(&form, "domains").unwrap_or_default();
                let servers = form_val(&form, "servers").unwrap_or_default();
                if let Some(ref key) = edit_name && !name.is_empty() {
                    let mut new_cfg = cfg.clone();
                    if let Some(pos) = new_cfg.proxy_server.dns_domains.iter().position(|d| d.name == *key) {
                        new_cfg.proxy_server.dns_domains[pos] = DnsDomainConfig {
                            name,
                            domains: if domains.is_empty() { None } else { Some(domains) },
                            servers: servers.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                        };
                        if let Err(e) = apply_config(&state, &new_cfg).await {
                            return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(cfg, edit_name.as_deref()), Some((&e.to_string(), false)))));
                        }
                        let g = state.read().await;
                        return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(&g.cfg, None), Some(("已更新并生效", true)))));
                    }
                }
            }
            if action == Some("add") {
                let name = form_val(&form, "name").unwrap_or_default();
                let domains = form_val(&form, "domains").unwrap_or_default();
                let servers = form_val(&form, "servers").unwrap_or_default();
                if !name.is_empty() {
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.dns_domains.push(DnsDomainConfig {
                        name,
                        domains: if domains.is_empty() { None } else { Some(domains) },
                        servers: servers.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                    });
                    match apply_config(&state, &new_cfg).await {
                        Ok(()) => return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(cfg, None), Some(("已添加并生效", true))))),
                        Err(e) => return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(cfg, None), Some((&e.to_string(), false))))),
                    }
                }
            }
            if let Some(del) = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "delete").map(|(_,v)| urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string())) {
                let mut new_cfg = cfg.clone();
                new_cfg.proxy_server.dns_domains.retain(|d| d.name != del);
                let _ = apply_config(&state, &new_cfg).await;
                let g = state.read().await;
                return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(&g.cfg, None), Some(("已删除并生效", true)))));
            }
        }

        if path.as_str() == "/ui/users" {
            let action = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "action").map(|(_,v)| v));
            if action == Some("update") {
                let edit_name = form_val(&form, "edit_name");
                let name = form_val(&form, "name").unwrap_or_default();
                let password = form_val(&form, "password").unwrap_or_default();
                let auth_rules = form_val(&form, "auth_rules");
                let is_admin = form.split('&').any(|kv| kv == "is_admin=on" || kv == "is_admin=1");
                if let Some(ref key) = edit_name && !name.is_empty() {
                    let mut new_cfg = cfg.clone();
                    if let Some(pos) = new_cfg.proxy_server.users.iter().position(|u| u.name == *key) {
                        new_cfg.proxy_server.users[pos] = UserConfig {
                            name,
                            password: if password.is_empty() { new_cfg.proxy_server.users[pos].password.clone() } else { password },
                            auth_rules,
                            is_admin,
                        };
                        if let Err(e) = apply_config(&state, &new_cfg).await {
                            return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(cfg, edit_name.as_deref()), Some((&e.to_string(), false)))));
                        }
                        let g = state.read().await;
                        return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(&g.cfg, None), Some(("已更新并生效", true)))));
                    }
                }
            }
            if action == Some("add") {
                let name = form_val(&form, "name").unwrap_or_default();
                let password = form_val(&form, "password").unwrap_or_default();
                let auth_rules = form_val(&form, "auth_rules");
                let is_admin = form.split('&').any(|kv| kv == "is_admin=on" || kv == "is_admin=1");
                if !name.is_empty() {
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.users.push(UserConfig {
                        name,
                        password,
                        auth_rules,
                        is_admin,
                    });
                    match apply_config(&state, &new_cfg).await {
                        Ok(()) => return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(cfg, None), Some(("用户已添加并生效", true))))),
                        Err(e) => return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(cfg, None), Some((&e.to_string(), false))))),
                    }
                }
            }
            if let Some(del) = form.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "delete").map(|(_,v)| urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string())) {
                let mut new_cfg = cfg.clone();
                new_cfg.proxy_server.users.retain(|u| u.name != del);
                let _ = apply_config(&state, &new_cfg).await;
                let g = state.read().await;
                return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(&g.cfg, None), Some(("已删除并生效", true)))));
            }
        }
    }

    // GET pages
    if path.as_str() == "/ui/stats" {
        let items = stats.snapshot_today().await;
        let mut list = String::new();
        for (u, c) in items {
            list.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", html_escape(&u), c));
        }
        let content = format!(r#"<div class="card"><h2>今日请求统计 (UTC)</h2><table><tr><th>用户</th><th>次数</th></tr>{}</table></div>"#, list);
        return Ok(resp(StatusCode::OK, layout("/ui/stats", "统计", &content, None)));
    }

    if path.as_str() == "/ui/logs" {
        const MAX_TAIL_LINES: usize = 500;
        let log_path = cfg.proxy_server.log.as_ref().map(|l| l.path.as_str()).unwrap_or("proxy.log");
        let content = match std::fs::read_to_string(log_path) {
            Ok(s) => {
                let lines: Vec<&str> = s.lines().collect();
                let start = lines.len().saturating_sub(MAX_TAIL_LINES);
                lines[start..].join("\n")
            }
            Err(e) => format!("(read error: {})", e),
        };
        let body = format!(
            "<div class=\"card\"><h2>日志 (最近 {} 行)</h2><pre style=\"white-space:pre-wrap;font-size:12px;overflow:auto;max-height:70vh;\">{}</pre><p><a href=\"/ui/logs\" class=\"btn\">刷新</a></p></div>",
            MAX_TAIL_LINES,
            html_escape(&content)
        );
        return Ok(resp(StatusCode::OK, layout("/ui/logs", "日志", &body, None)));
    }

    if path.as_str() == "/ui/tunnels" {
        let body = page_tunnels(cfg, current_user);
        return Ok(resp(StatusCode::OK, layout("/ui/tunnels", "隧道端点", &body, None)));
    }

    // GET /ui/webssh/{rule_name}/{tunnel_name} — WebSSH terminal page (WebSocket upgrade handled in main)
    if path.starts_with("/ui/webssh/") && !path.contains("/webssh-files/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 5 && parts.get(2) == Some(&"webssh") {
            let rule_name = parts[3];
            let tunnel_name = parts[4];
            let allowed = current_user.is_admin || current_user.allowed_rules.contains(rule_name);
            if !allowed {
                return Ok(resp(StatusCode::FORBIDDEN, "无权限访问该隧道".to_string()));
            }
            let rule_cfg = cfg.proxy_server.rules.iter().find(|r| r.name == rule_name);
            let endpoint = rule_cfg
                .and_then(|r| r.websocket_tunnel.as_ref())
                .and_then(|eps| eps.iter().find(|e| e.tunnel_name == tunnel_name));
            if let Some(ep) = endpoint {
                if ep.type_ != TunnelType::Ssh {
                    let body = format!(
                        r#"<div class="card"><h2>隧道类型为 TCP</h2><p>此端点为 TCP 隧道，请使用配置的 bind_address 连接。</p><p><a href="/ui/tunnels">← 隧道端点</a></p></div>"#
                    );
                    return Ok(resp(StatusCode::OK, layout("/ui/tunnels", "TCP 隧道", &body, None)));
                }
                let body = page_webssh(ep);
                return Ok(resp(StatusCode::OK, layout("/ui/tunnels", &ep.name, &body, None)));
            }
        }
    }

    // GET /ui/webssh-files/{rule_name}/{tunnel_name} — 文件上传下载（占位）
    if path.starts_with("/ui/webssh-files/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 5 && parts.get(2) == Some(&"webssh-files") {
            let rule_name = parts[3];
            let tunnel_name = parts[4];
            let allowed = current_user.is_admin || current_user.allowed_rules.contains(rule_name);
            if !allowed {
                return Ok(resp(StatusCode::FORBIDDEN, "无权限访问该隧道".to_string()));
            }
            let rule_cfg = cfg.proxy_server.rules.iter().find(|r| r.name == rule_name);
            let endpoint = rule_cfg
                .and_then(|r| r.websocket_tunnel.as_ref())
                .and_then(|eps| eps.iter().find(|e| e.tunnel_name == tunnel_name));
            if let Some(ep) = endpoint {
                if ep.type_ != TunnelType::Ssh {
                    let body = r#"<div class="card"><h2>隧道类型为 TCP</h2><p>文件管理仅适用于 SSH 类型隧道。</p><p><a href="/ui/tunnels">← 隧道端点</a></p></div>"#;
                    return Ok(resp(StatusCode::OK, layout("/ui/tunnels", "TCP 隧道", body, None)));
                }
                let body = format!(
                    r#"<div class="card"><h2>文件 — {}</h2><p><a href="/ui/tunnels">← 隧道端点</a></p><p>文件上传下载（建设中，将复用当前会话建立 SFTP 通道）。</p></div>"#,
                    html_escape(&ep.name)
                );
                return Ok(resp(StatusCode::OK, layout("/ui/tunnels", "文件", &body, None)));
            }
        }
    }

    if path.as_str() == "/ui/check" {
        let raw = query.as_deref().unwrap_or("").split('&')
            .find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                if k == "url" || k == "host" {
                    urlencoding::decode(v).ok().map(|x| x.into_owned())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let raw = raw.trim().to_string();
        let (host, port) = if raw.contains("://") {
            match Url::parse(&raw) {
                Ok(u) => {
                    let h = u.host_str().map(|s| s.to_string()).unwrap_or_default();
                    let p = u.port().or(u.port_or_known_default()).unwrap_or(443);
                    (h, p)
                }
                _ => (raw.clone(), 443u16),
            }
        } else if raw.is_empty() {
            (String::new(), 443u16)
        } else {
            (raw.clone(), 443u16)
        };
        let mut result = String::new();
        result.push_str(r#"<div class="card"><h2>代理目标检查</h2><form method="GET" action="/ui/check"><label>URL 或 Host</label>"#);
        result.push_str(&format!(r#"<input name="url" placeholder="https://example.com 或 example.com" value="{}" style="width:100%;max-width:32em;" /><button type="submit">检查</button></form>"#, html_escape(&raw)));
        if !host.is_empty() {
            let ip = host.parse().ok();
            let mut chosen = rules.select_rule(&host, port, ip);
            let mut resolved_ip = None;
            if chosen.is_none() {
                if let Some(dns) = dns {
                    if let Ok(Some(resolved)) = dns.resolve_ip(&host).await {
                        resolved_ip = Some(resolved);
                        chosen = rules.select_rule(&host, port, Some(resolved));
                    }
                }
            }
            result.push_str("<h3>结果</h3><pre>");
            if raw != host {
                result.push_str(&format!("url = {}\n", html_escape(&raw)));
            }
            result.push_str(&format!("host = {}\n", host));
            result.push_str(&format!("port = {}\n", port));
            if let Some(ip) = resolved_ip {
                result.push_str(&format!("dns_ip = {}\n", ip));
            }
            match chosen {
                Some(rule) => {
                    result.push_str(&format!("rule = {}\n", rule.name));
                    match &rule.target {
                        UpstreamTarget::HttpProxy { host: h, port: p } => {
                            result.push_str(&format!("target = HTTP {}:{}\n", h, p));
                            let ok = tokio::net::TcpStream::connect(format!("{}:{}", h, p)).await.is_ok();
                            result.push_str(&format!("connect_test = {}\n", if ok { "ok" } else { "fail" }));
                        }
                        UpstreamTarget::Socks5Proxy { host: h, port: p } => {
                            result.push_str(&format!("target = SOCKS5 {}:{}\n", h, p));
                            let ok = tokio::net::TcpStream::connect(format!("{}:{}", h, p)).await.is_ok();
                            result.push_str(&format!("connect_test = {}\n", if ok { "ok" } else { "fail" }));
                        }
                        UpstreamTarget::WsProxy { url_template, .. } => {
                            result.push_str(&format!("target = WS {}\n", url_template));
                            result.push_str("connect_test = (skipped)\n");
                        }
                    }
                }
                None => {
                    result.push_str("rule = (none)\nfallback = direct\n");
                }
            }
            result.push_str("</pre>");
        }
        result.push_str("</div>");
        return Ok(resp(StatusCode::OK, layout("/ui/check", "检查", &result, None)));
    }

    if path.as_str() == "/ui/rules" {
        let edit_name = query.as_deref().and_then(|q| q.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "edit").map(|(_,v)| urlencoding::decode(v).ok().map(|c| c.to_string())))).flatten();
        if let Some(ref q) = query {
            for kv in q.split('&') {
                if let Some(("delete", v)) = kv.split_once('=') {
                    let del = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string();
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.rules.retain(|r| r.name != del);
                    let _ = apply_config(&state, &new_cfg).await;
                    let (cfg2, rules2) = { let g = state.read().await; (g.cfg.clone(), g.rules.clone()) };
                    return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules2.rules, &cfg2, None), Some(("已删除并生效", true)))));
                }
            }
        }
        return Ok(resp(StatusCode::OK, layout("/ui/rules", "规则管理", &page_rules(&rules.rules, cfg, edit_name.as_deref()), None)));
    }

    if path.as_str() == "/ui/dns" {
        let edit_name = query.as_deref().and_then(|q| q.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "edit").map(|(_,v)| urlencoding::decode(v).ok().map(|c| c.to_string())))).flatten();
        if let Some(ref q) = query {
            for kv in q.split('&') {
                if let Some(("delete", v)) = kv.split_once('=') {
                    let del = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string();
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.dns_domains.retain(|d| d.name != del);
                    let _ = apply_config(&state, &new_cfg).await;
                    let g = state.read().await;
                    return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(&g.cfg, None), Some(("已删除并生效", true)))));
                }
            }
        }
        return Ok(resp(StatusCode::OK, layout("/ui/dns", "域名解析", &page_dns(cfg, edit_name.as_deref()), None)));
    }

    if path.as_str() == "/ui/users" {
        let edit_name = query.as_deref().and_then(|q| q.split('&').find_map(|kv| kv.split_once('=').filter(|(k,_)| *k == "edit").map(|(_,v)| urlencoding::decode(v).ok().map(|c| c.to_string())))).flatten();
        if let Some(ref q) = query {
            for kv in q.split('&') {
                if let Some(("delete", v)) = kv.split_once('=') {
                    let del = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string();
                    let mut new_cfg = cfg.clone();
                    new_cfg.proxy_server.users.retain(|u| u.name != del);
                    let _ = apply_config(&state, &new_cfg).await;
                    let g = state.read().await;
                    return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(&g.cfg, None), Some(("已删除并生效", true)))));
                }
            }
        }
        return Ok(resp(StatusCode::OK, layout("/ui/users", "用户管理", &page_users(cfg, edit_name.as_deref()), None)));
    }

    // /ui -> 基本配置
    Ok(resp(StatusCode::OK, layout("/ui", "基本配置", &page_basic(cfg), None)))
}

fn page_basic(cfg: &Config) -> String {
    let ps = &cfg.proxy_server;
    let log_path = ps.log.as_ref().map(|l| l.path.as_str()).unwrap_or("proxy.log");
    let log_level = ps.log.as_ref().map(|l| l.level.as_str()).unwrap_or("info");
    let (ws_enable, ws_path, ws_token, ws_rate_limit) = ps.ws_proxy.as_ref()
        .map(|w| (w.enable, w.path.as_str(), w.token.as_str(), w.rate_limit_per_minute))
        .unwrap_or((false, "/ws", "", 0));
    let (web_ui_enable, web_ui_path) = ps.web_ui.as_ref()
        .map(|w| (w.enable, w.path.as_str()))
        .unwrap_or((true, "/ui"));
    format!(
        r#"<form method="POST" action="/ui">
<div class="card"><h2>监听</h2>
<label>绑定地址</label><input name="bind_address" value="{}" />
<label>绑定端口</label><input name="bind_port" type="number" value="{}" />
</div>
<div class="card"><h2>代理开关</h2>
<label><input type="checkbox" name="http_proxy_enable" {} /> HTTP 代理</label><br/>
<label><input type="checkbox" name="https_proxy_enable" {} /> HTTPS 代理</label><br/>
<label><input type="checkbox" name="socks5_proxy_enable" {} /> SOCKS5 代理</label><br/>
<label><input type="checkbox" name="allow_anonymous" {} /> 允许匿名</label><br/>
<label><input type="checkbox" name="tls_enable" {} /> 启用 TLS（UI/WS）</label>
</div>
<div class="card"><h2>WS 代理服务端</h2>
<label><input type="checkbox" name="ws_proxy_enable" {} /> 启用</label><br/>
<label>路径</label><input name="ws_proxy_path" value="{}" placeholder="/ws" />
<label>token</label><input name="ws_proxy_token" value="{}" placeholder="连接校验 token" />
<label>每分钟请求限制（0 不限制）</label><input name="ws_proxy_rate_limit_per_minute" type="number" min="0" value="{}" placeholder="0" />
</div>
<div class="card"><h2>Web UI</h2>
<label><input type="checkbox" name="web_ui_enable" {} /> 启用</label><br/>
<label>路径</label><input name="web_ui_path" value="{}" placeholder="/ui" />
</div>
<div class="card"><h2>日志</h2>
<label>路径</label><input name="log_path" value="{}" />
<label>级别</label><input name="log_level" value="{}" />
</div>
<button type="submit">保存并应用</button>
</form>"#,
        html_escape(&ps.bind_address.clone().unwrap_or("0.0.0.0".to_string())),
        ps.bind_port.clone().unwrap_or(1081),
        if ps.http_proxy_enable { "checked" } else { "" },
        if ps.https_proxy_enable { "checked" } else { "" },
        if ps.socks5_proxy_enable { "checked" } else { "" },
        if ps.allow_anonymous { "checked" } else { "" },
        if ps.tls_enable { "checked" } else { "" },
        if ws_enable { "checked" } else { "" },
        html_escape(ws_path),
        html_escape(ws_token),
        ws_rate_limit,
        if web_ui_enable { "checked" } else { "" },
        html_escape(web_ui_path),
        html_escape(log_path),
        html_escape(log_level),
    )
}

fn page_tunnels(cfg: &Config, current_user: &User) -> String {
    let mut rows = String::new();
    for rule in &cfg.proxy_server.rules {
        let allowed = current_user.is_admin || current_user.allowed_rules.contains(&rule.name);
        if !allowed {
            continue;
        }
        let Some(ref endpoints) = rule.websocket_tunnel else { continue };
        for ep in endpoints {
            let rule_enc = urlencoding::encode(&rule.name);
            let tunnel_enc = urlencoding::encode(&ep.tunnel_name);
            let type_str = match ep.type_ {
                TunnelType::Ssh => "SSH",
                TunnelType::Tcp => "TCP",
            };
            let action_cell = match ep.type_ {
                TunnelType::Ssh => format!(
                    r#"<a href="/ui/webssh/{}/{}">WebSSH</a> | <a href="/ui/webssh-files/{}/{}">文件</a>"#,
                    rule_enc,
                    tunnel_enc,
                    rule_enc,
                    tunnel_enc,
                ),
                TunnelType::Tcp => {
                    let addr = ep
                        .bind_address
                        .as_deref()
                        .unwrap_or("—")
                        .to_string();
                    format!(r#"<span title="连接此地址访问隧道">{}</span>"#, html_escape(&addr))
                }
            };
            rows.push_str(&format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&rule.name),
                html_escape(&ep.name),
                type_str,
                html_escape(&ep.tunnel_name),
                html_escape(&ep.target),
                action_cell,
            ));
        }
    }
    if rows.is_empty() {
        return r#"<div class="card"><h2>隧道端点</h2><p>暂无可见隧道端点，或当前用户无权限。</p></div>"#.to_string();
    }
    format!(
        r#"<div class="card"><h2>隧道端点</h2><table><thead><tr><th>规则</th><th>名称</th><th>类型</th><th>端点ID</th><th>目标</th><th>操作 / 绑定地址</th></tr></thead><tbody>{}</tbody></table></div>"#,
        rows
    )
}

fn page_webssh(ep: &WebsocketTunnelEndpoint) -> String {
    let display_name_esc = html_escape(&ep.name);
    format!(
        r#"<div class="card"><h2>WebSSH — {}</h2>
<p><a href="/ui/tunnels">← 隧道端点</a> <button type="button" id="webssh-connect">连接</button></p>
<div style="display:flex;gap:12px;margin-top:12px;">
  <div id="webssh-file-tree" style="width:260px;min-width:260px;border:1px solid #2a2a30;border-radius:6px;padding:12px;max-height:75vh;overflow:auto;">
    <div class="webssh-tree-placeholder">等待登录完成后继续</div>
  </div>
  <div style="flex:1;display:flex;flex-direction:column;">
    <div id="terminal" style="flex:1;min-height:400px;background:#1e1e1e;padding:8px;"></div>
    <div id="status" style="margin-top:6px;color:#666;font-size:12px;"></div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css" />
<script>
(function(){{
  var status = document.getElementById('status');
  var treeEl = document.getElementById('webssh-file-tree');
  var term = new Terminal({{ cursorBlink: true, theme: {{ background: '#1e1e1e' }} }});
  term.open(document.getElementById('terminal'));
  term.writeln('点击「连接」后，在终端中根据提示输入密码（输入不显示），按回车登录。');
  var passwordMode = false;
  var passwordBuf = '';
  document.getElementById('webssh-connect').onclick = function() {{
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var wsUrl = proto + '//' + location.host + location.pathname;
    term.writeln('Connecting...');
    status.textContent = '连接中';
    var ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    ws.onopen = function() {{ status.textContent = '已连接，等待密码提示…'; }};
    ws.onclose = function() {{ term.writeln('Connection closed.'); status.textContent = '连接已关闭'; passwordMode = false; }};
    ws.onerror = function() {{ term.writeln('WebSocket error.'); status.textContent = '连接错误'; }};
    ws.onmessage = function(ev) {{
      if (ev.data instanceof ArrayBuffer) {{
        term.write(new Uint8Array(ev.data));
      }} else {{
        var s = ev.data;
        if (s === 'SSH_READY') {{ status.textContent = '已登录'; return; }}
        if (s.indexOf('FILE_LIST:') === 0) {{
          try {{
            var list = JSON.parse(s.slice(10));
            treeEl.innerHTML = '';
            var ul = document.createElement('ul');
            ul.style.cssText = 'list-style:none;margin:0;padding-left:12px;';
            list.forEach(function(e) {{
              var li = document.createElement('li');
              li.textContent = (e.dir ? '📁 ' : '📄 ') + (e.name || e.path || '');
              li.style.cssText = 'padding:2px 0;font-size:13px;';
              ul.appendChild(li);
            }});
            treeEl.appendChild(ul);
          }} catch(ex) {{}}
          return;
        }}
        term.write(s);
        if (s.indexOf("'s password:") !== -1) {{
          passwordMode = true;
          passwordBuf = '';
          status.textContent = '请输入密码（不显示），按回车';
        }}
        var t = s.trim();
        if (t.indexOf('失败') !== -1 || t.indexOf('error') !== -1) status.textContent = t.substring(0, 60);
      }}
    }};
    function isEnter(d) {{
      for (var i = 0; i < d.length; i++) if (d.charCodeAt(i) === 13 || d.charCodeAt(i) === 10) return true;
      return false;
    }}
    function isBackspace(d) {{
      if (d.length !== 1) return false;
      var c = d.charCodeAt(0);
      return c === 127 || c === 8;
    }}
    term.onData(function(data) {{
      if (ws.readyState !== 1) return;
      if (passwordMode) {{
        if (isEnter(data)) {{
          ws.send(passwordBuf);
          passwordBuf = '';
          passwordMode = false;
          term.writeln('');
        }} else if (isBackspace(data)) {{
          if (passwordBuf.length) {{ passwordBuf = passwordBuf.slice(0, -1); term.write('\\b \\b'); }}
        }} else {{
          passwordBuf += data;
          term.write('*');
        }}
      }} else {{
        ws.send(new TextEncoder().encode(data));
      }}
    }});
  }};
}})();
</script></div>"#,
        display_name_esc
    )
}

fn page_rules(rules: &[Rule], cfg: &Config, edit_name: Option<&str>) -> String {
    let mut rows = String::new();
    for r in rules {
        let target_str = match &r.target {
            UpstreamTarget::HttpProxy { host, port } => format!("HTTP {}:{}", host, port),
            UpstreamTarget::Socks5Proxy { host, port } => format!("SOCKS5 {}:{}", host, port),
            UpstreamTarget::WsProxy { url_template, .. } => format!("WS {}", url_template),
        };
        rows.push_str(&format!(
            r#"<tr><td>{}</td><td>{}</td><td><a href="?edit={}" class="edt">编辑</a><a href="?delete={}" class="del" onclick="return confirm('删除?')">删除</a></td></tr>"#,
            html_escape(&r.name),
            html_escape(&target_str),
            urlencoding::encode(&r.name),
            urlencoding::encode(&r.name),
        ));
    }
    let form_title = edit_name.map(|_| "编辑规则").unwrap_or("添加规则");
    let (form_edit_hidden, form_name_val, form_target_val, form_domains_val) = if let Some(name) = edit_name {
        let rc = cfg.proxy_server.rules.iter().find(|r| r.name == name);
        let (target, domains) = rc.map(|r| (r.target.as_str(), r.domains.as_deref().unwrap_or(""))).unwrap_or(("", ""));
        (
            format!(r#"<input type="hidden" name="action" value="update" /><input type="hidden" name="edit_name" value="{}" />"#, html_escape(name)),
            html_escape(name),
            html_escape(target),
            html_escape(domains),
        )
    } else {
        (
            r#"<input type="hidden" name="action" value="add" />"#.to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        )
    };
    format!(
        r#"<div class="card"><h2>现有规则</h2><table><tr><th>名称</th><th>目标</th><th></th></tr>{}</table></div>
<div class="card"><h2>{}</h2><form method="POST" action="/ui/rules">
{}<label>名称</label><input name="name" required placeholder="如 prod" value="{}" {} />
<label>目标 (HTTP 1.2.3.4:8080 / SOCKS5 1.2.3.4:1080 / wss://...)</label><input name="target" required placeholder="SOCKS5 192.168.10.20:1080" value="{}" />
<label>domains (逗号或换行，支持 host:port)</label><textarea name="domains" placeholder="192.168.1.1, *.example.com">{}</textarea>
<button type="submit">{}</button>
</form></div>"#,
        rows,
        form_title,
        form_edit_hidden,
        form_name_val,
        if edit_name.is_some() { "readonly" } else { "" },
        form_target_val,
        form_domains_val,
        if edit_name.is_some() { "更新并应用" } else { "添加并应用" }
    )
}

fn page_dns(cfg: &Config, edit_name: Option<&str>) -> String {
    let mut rows = String::new();
    for d in &cfg.proxy_server.dns_domains {
        let servers = d.servers.join(", ");
        rows.push_str(&format!(
            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td><a href="?edit={}" class="edt">编辑</a> <a href="?delete={}" class="del" onclick="return confirm('删除?')">删除</a></td></tr>"#,
            html_escape(&d.name),
            html_escape(d.domains.as_deref().unwrap_or("")),
            html_escape(&servers),
            urlencoding::encode(&d.name),
            urlencoding::encode(&d.name),
        ));
    }
    let form_title = edit_name.map(|_| "编辑解析组").unwrap_or("添加解析组");
    let (form_edit_hidden, form_name_val, form_domains_val, form_servers_val) = if let Some(name) = edit_name {
        let dc = cfg.proxy_server.dns_domains.iter().find(|d| d.name == name);
        let (domains, servers) = dc.map(|d| (d.domains.as_deref().unwrap_or(""), d.servers.join("\n"))).unwrap_or(("", String::new()));
        (
            format!(r#"<input type="hidden" name="action" value="update" /><input type="hidden" name="edit_name" value="{}" />"#, html_escape(name)),
            html_escape(name),
            html_escape(domains),
            html_escape(&servers),
        )
    } else {
        (
            r#"<input type="hidden" name="action" value="add" />"#.to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        )
    };
    format!(
        r#"<div class="card"><h2>域名解析组</h2><table><tr><th>名称</th><th>domains</th><th>servers</th><th></th></tr>{}</table></div>
<div class="card"><h2>{}</h2><form method="POST" action="/ui/dns">
{}<label>名称</label><input name="name" required value="{}" {} />
<label>domains (一行一个或逗号分隔)</label><textarea name="domains" placeholder="*.example.com">{}</textarea>
<label>servers (一行一个，如 8.8.8.8:53)</label><textarea name="servers" placeholder="8.8.8.8:53">{}</textarea>
<button type="submit">{}</button>
</form></div>"#,
        rows,
        form_title,
        form_edit_hidden,
        form_name_val,
        if edit_name.is_some() { "readonly" } else { "" },
        form_domains_val,
        form_servers_val,
        if edit_name.is_some() { "更新并应用" } else { "添加并应用" }
    )
}

fn page_users(cfg: &Config, edit_name: Option<&str>) -> String {
    let mut rows = String::new();
    for u in &cfg.proxy_server.users {
        rows.push_str(&format!(
            r#"<tr><td>{}</td><td>***</td><td>{}</td><td>{}</td><td><a href="?edit={}" class="edt">编辑</a> <a href="?delete={}" class="del" onclick="return confirm('删除?')">删除</a></td></tr>"#,
            html_escape(&u.name),
            html_escape(u.auth_rules.as_deref().unwrap_or("")),
            if u.is_admin { "是" } else { "否" },
            urlencoding::encode(&u.name),
            urlencoding::encode(&u.name),
        ));
    }
    let form_title = edit_name.map(|_| "编辑用户").unwrap_or("添加用户");
    let (form_edit_hidden, form_name_val, form_auth_rules_val, form_is_admin_checked) = if let Some(name) = edit_name {
        let uc = cfg.proxy_server.users.iter().find(|u| u.name == name);
        let (auth_rules, is_admin) = uc.map(|u| (u.auth_rules.as_deref().unwrap_or(""), u.is_admin)).unwrap_or(("", false));
        (
            format!(r#"<input type="hidden" name="action" value="update" /><input type="hidden" name="edit_name" value="{}" />"#, html_escape(name)),
            html_escape(name),
            html_escape(auth_rules),
            if is_admin { r#" checked="checked""# } else { "" },
        )
    } else {
        (
            r#"<input type="hidden" name="action" value="add" />"#.to_string(),
            "".to_string(),
            "".to_string(),
            "",
        )
    };
    format!(
        r#"<div class="card"><h2>用户列表</h2><table><tr><th>用户名</th><th>密码</th><th>auth_rules</th><th>管理员</th><th></th></tr>{}</table></div>
<div class="card"><h2>{}</h2><form method="POST" action="/ui/users">
{}<label>用户名</label><input name="name" required value="{}" {} />
<label>密码</label><input name="password" type="password" placeholder="{}" {} />
<label>auth_rules (逗号分隔规则名)</label><input name="auth_rules" placeholder="prod, outer" value="{}" />
<label><input type="checkbox" name="is_admin"{} /> 管理员</label><br/>
<button type="submit">{}</button>
</form></div>"#,
        rows,
        form_title,
        form_edit_hidden,
        form_name_val,
        if edit_name.is_some() { "readonly" } else { "" },
        if edit_name.is_some() { "留空不修改" } else { "" },
        if edit_name.is_some() { "" } else { "required" },
        form_auth_rules_val,
        form_is_admin_checked,
        if edit_name.is_some() { "更新并应用" } else { "添加并应用" }
    )
}
