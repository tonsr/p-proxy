use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct DailyStats {
    // key: "YYYY-MM-DD|username"
    inner: Arc<Mutex<HashMap<String, u64>>>,
}

fn today_key_prefix() -> String {
    // Use local date by naive conversion (good enough for in-memory counters).
    // Format: YYYY-MM-DD
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs / 86_400;
    // 1970-01-01 + days; approximate via chrono would be nicer but avoid dependency.
    // We'll just bucket by UTC day to keep deterministic behavior.
    let ymd = utc_ymd_from_days(days);
    format!("{:04}-{:02}-{:02}", ymd.0, ymd.1, ymd.2)
}

fn utc_ymd_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    // Civil-from-days algorithm (Howard Hinnant), days relative to 1970-01-01.
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    let year = (y + (m <= 2) as i64) as i32;
    (year, m as u32, d as u32)
}

impl DailyStats {
    pub async fn incr(&self, username: &str) {
        let day = today_key_prefix();
        let key = format!("{day}|{username}");
        let mut m = self.inner.lock().await;
        *m.entry(key).or_insert(0) += 1;
    }

    pub async fn snapshot_today(&self) -> Vec<(String, u64)> {
        let day = today_key_prefix();
        let m = self.inner.lock().await;
        let mut out = Vec::new();
        for (k, v) in m.iter() {
            if let Some((d, u)) = k.split_once('|') {
                if d == day {
                    out.push((u.to_string(), *v));
                }
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1));
        out
    }
}

