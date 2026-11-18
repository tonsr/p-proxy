//! ws_proxy 请求频率限制：按客户端 IP 每分钟最多 N 次，超限返回 429。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const WINDOW_SECS: u64 = 60;

/// 按 IP 的滑动窗口计数，用于 ws_proxy rate_limit_per_minute。
#[derive(Default)]
pub struct WsProxyRateLimiter {
    /// ip -> 该 IP 在窗口内的请求时间戳
    map: RwLock<HashMap<IpAddr, Vec<Instant>>>,
}

impl WsProxyRateLimiter {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// 若 limit 为 0 表示不限制，返回 true。否则在 1 分钟滑动窗口内，该 IP 若已达 limit 次则返回 false，未达则记录本次并返回 true。
    pub fn try_allow(&self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return true;
        }
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        let mut map = match self.map.write() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let vec = map.entry(ip).or_default();
        vec.retain(|t| now.duration_since(*t) < window);
        if vec.len() >= limit as usize {
            return false;
        }
        vec.push(now);
        true
    }
}
