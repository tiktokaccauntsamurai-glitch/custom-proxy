//! Clash API запущенного sing-box: `experimental.clash_api` на 127.0.0.1:<случайный порт> со случайным secret.
//!
//! Включается при каждом `run` (клиент и `--server`, main.rs::build): адрес и secret — `<data>/api.json`
//! (0600, server.rs::write_file), удаляется при выходе. Потребители: `cproxy groups|select|test` (main.rs) и
//! `cproxy server status`. Маршруты sing-box: `experimental/clashapi/proxies.go` (`GET /proxies`,
//! `PUT /proxies/{name}` — только selector, `GET /proxies/{name}/delay`), `api_meta_group.go`
//! (`GET /group/{name}/delay` — задержки всех членов группы; у url-test заодно обновляет выбор),
//! `connections.go`. Адрес `url` с `http://` sing-box заменяет на свой https по умолчанию (proxies.go:215).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

fn api_path(dir: &Path) -> PathBuf {
    dir.join("api.json")
}

pub fn save(addr: &str, secret: &str) -> Result<(), String> {
    crate::server::write_file(&api_path(&crate::store::data_dir()), &json!({"addr": addr, "secret": secret}), true)
}

pub fn remove() {
    let _ = std::fs::remove_file(api_path(&crate::store::data_dir()));
}

pub struct Api {
    pub addr: String,
    secret: String,
}

/// Свой каталог данных, затем каталог службы (Linux, нужен sudo).
pub fn load() -> Result<Api, String> {
    let mut dirs = vec![crate::store::data_dir()];
    if cfg!(target_os = "linux") {
        dirs.push(PathBuf::from(crate::service::HOME));
    }
    let mut denied = None;
    for d in dirs {
        let p = api_path(&d);
        match std::fs::read_to_string(&p) {
            Ok(t) => {
                let v: Value = serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))?;
                let s = |k: &str| v[k].as_str().map(String::from).ok_or(format!("{}: `{k}` missing", p.display()));
                log::debug!(target: "clash", "api from {}", p.display());
                return Ok(Api { addr: s("addr")?, secret: s("secret")? });
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied = Some(p),
            Err(_) => {}
        }
    }
    Err(match denied {
        Some(p) => format!("{}: permission denied — run the command with sudo", p.display()),
        None => "cproxy is not running (no api.json): start it with `cproxy run` / `cproxy run --server`".into(),
    })
}

/// Сегмент пути URL: имена групп и узлов бывают с пробелами, кириллицей, `§`.
pub fn seg(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Api {
    fn agent(timeout: Duration) -> ureq::Agent {
        // Без системных/env-прокси: API на loopback.
        ureq::Agent::config_builder().proxy(None).timeout_global(Some(timeout)).http_status_as_error(false).build().into()
    }

    fn check(path: &str, status: u16, body: &str) -> Result<(), String> {
        if (200..300).contains(&status) {
            return Ok(());
        }
        let msg = serde_json::from_str::<Value>(body).ok().and_then(|v| v["message"].as_str().map(String::from)).unwrap_or_else(|| body.to_string());
        Err(format!("clash api {path}: HTTP {status}: {msg}"))
    }

    pub fn get(&self, path: &str) -> Result<Value, String> {
        self.get_with(path, Duration::from_secs(5))
    }

    pub fn get_with(&self, path: &str, timeout: Duration) -> Result<Value, String> {
        log::debug!(target: "clash", "GET {path}");
        let mut resp = Self::agent(timeout)
            .get(&format!("http://{}{path}", self.addr))
            .header("Authorization", &format!("Bearer {}", self.secret))
            .call()
            .map_err(|e| format!("clash api {path}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
        Self::check(path, status, &body)?;
        serde_json::from_str(&body).map_err(|e| format!("clash api {path}: {e}"))
    }

    pub fn put(&self, path: &str, body: &Value) -> Result<(), String> {
        log::debug!(target: "clash", "PUT {path} {body}");
        let mut resp = Self::agent(Duration::from_secs(5))
            .put(&format!("http://{}{path}", self.addr))
            .header("Authorization", &format!("Bearer {}", self.secret))
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|e| format!("clash api {path}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        Self::check(path, status, &text)
    }
}

/// Группы из `GET /proxies`: (имя, тип Clash `Selector`/`URLTest`, текущий, члены) в порядке конфига
/// (`all` у GLOBAL перечисляет теги по порядку; сам GLOBAL — служебная группа Clash API, её не показываем).
pub fn groups(proxies: &Value) -> Vec<(String, String, String, Vec<String>)> {
    let map = &proxies["proxies"];
    let order: Vec<String> = map["GLOBAL"]["all"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
    let mut names: Vec<String> = order.into_iter().filter(|n| map[n]["all"].is_array()).collect();
    for (k, v) in map.as_object().into_iter().flatten() {
        if v["all"].is_array() && k != "GLOBAL" && !names.contains(k) {
            names.push(k.clone());
        }
    }
    names
        .into_iter()
        .map(|n| {
            let g = &map[&n];
            let all = g["all"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
            (n.clone(), g["type"].as_str().unwrap_or("?").to_string(), g["now"].as_str().unwrap_or("").to_string(), all)
        })
        .collect()
}

/// Имя из ввода пользователя → точное имя (как `canonical()` генератора: точное, иначе без учёта регистра,
/// иначе единственное, начинающееся с введённого, иначе единственное, содержащее его: `vps` → «Дом-VPS»).
pub fn resolve<'a>(names: &'a [String], input: &str) -> Result<&'a str, String> {
    if let Some(n) = names.iter().find(|n| *n == input) {
        return Ok(n);
    }
    let lower = input.to_lowercase();
    if let Some(n) = names.iter().find(|n| n.to_lowercase() == lower) {
        return Ok(n);
    }
    let mut pre: Vec<&String> = names.iter().filter(|n| n.to_lowercase().starts_with(&lower)).collect();
    if pre.is_empty() {
        pre = names.iter().filter(|n| n.to_lowercase().contains(&lower)).collect();
    }
    match pre.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("`{input}` not found; available: {}", names.join(", "))),
        many => Err(format!("`{input}` is ambiguous: {}", many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_and_names() {
        let p = json!({"proxies": {
            "GLOBAL": {"type": "Fallback", "all": ["DIRECT", "NL 1", "AUTO", "PROXY"], "now": "DIRECT"},
            "DIRECT": {"type": "Direct"},
            "NL 1": {"type": "VLESS"},
            "AUTO": {"type": "URLTest", "all": ["NL 1"], "now": "NL 1"},
            "PROXY": {"type": "Selector", "all": ["NL 1", "AUTO"], "now": "AUTO"}}});
        let g = groups(&p);
        assert_eq!(g.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), ["AUTO", "PROXY"]);
        assert_eq!((g[1].1.as_str(), g[1].2.as_str()), ("Selector", "AUTO"));
        let names = vec!["NL 1".to_string(), "NL 2".to_string(), "Дом-VPS".to_string()];
        assert_eq!(resolve(&names, "nl 1"), Ok("NL 1"));
        assert_eq!(resolve(&names, "дом"), Ok("Дом-VPS"));
        assert_eq!(resolve(&names, "vps"), Ok("Дом-VPS"));
        assert!(resolve(&names, "NL").unwrap_err().contains("ambiguous"));
        assert!(resolve(&names, "JP").is_err());
        assert_eq!(seg("NL 1 § 0"), "NL%201%20%C2%A7%200");
    }
}
