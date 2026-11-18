use base64::Engine;
use std::collections::HashMap;

use crate::model::User;

#[derive(Debug, Clone)]
pub enum AuthResult {
    Anonymous,
    User(User),
}

pub fn username_for_stats(auth: &AuthResult) -> &str {
    match auth {
        AuthResult::Anonymous => "anonymous",
        AuthResult::User(u) => u.name.as_str(),
    }
}

pub fn parse_basic_proxy_authorization(header_value: &str) -> Option<(String, String)> {
    // Expect: "Basic base64(user:pass)"
    let hv = header_value.trim();
    let b64 = hv.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

pub fn authenticate_http(
    allow_anonymous: bool,
    proxy_authorization: Option<&str>,
    users: &HashMap<String, User>,
) -> anyhow::Result<AuthResult> {
    if let Some(h) = proxy_authorization {
        if let Some((u, p)) = parse_basic_proxy_authorization(h) {
            if let Some(user) = users.get(&u) {
                if user.password == p {
                    return Ok(AuthResult::User(user.clone()));
                }
            }
        }
        anyhow::bail!("invalid credentials");
    }
    if allow_anonymous {
        Ok(AuthResult::Anonymous)
    } else {
        anyhow::bail!("authentication required")
    }
}

pub fn authenticate_socks5(
    allow_anonymous: bool,
    user: Option<(String, String)>,
    users: &HashMap<String, User>,
) -> anyhow::Result<AuthResult> {
    if let Some((u, p)) = user {
        if let Some(x) = users.get(&u) {
            if x.password == p {
                return Ok(AuthResult::User(x.clone()));
            }
        }
        anyhow::bail!("invalid credentials");
    }
    if allow_anonymous {
        Ok(AuthResult::Anonymous)
    } else {
        anyhow::bail!("authentication required")
    }
}

pub fn is_rule_allowed(auth: &AuthResult, rule_name: &str) -> bool {
    match auth {
        AuthResult::Anonymous => true,
        AuthResult::User(u) => u.is_admin || u.allowed_rules.contains(rule_name),
    }
}

