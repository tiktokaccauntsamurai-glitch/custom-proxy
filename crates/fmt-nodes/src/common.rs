//! Общие помощники форматов: сборка `Proxy` с ключами Shadowrocket, транспорт, base64, %-декодирование.
//! Ключи — те, что читает `singbox-gen/src/outbound.rs` (и `xray.rs` для xhttp); таблица — docs/MAPPING.md.

use core_model::Proxy;
use serde_json::Value;

/// Построитель узла. Пустые значения не записываются.
pub struct B {
    pub name: String,
    kind: String,
    server: String,
    port: u16,
    params: Vec<(String, String)>,
}

impl B {
    pub fn new(kind: &str, server: &str, port: u16) -> Result<Self, String> {
        if server.is_empty() {
            return Err("missing server".into());
        }
        if port == 0 {
            return Err("missing port".into());
        }
        Ok(B { name: String::new(), kind: kind.into(), server: server.trim_matches(['[', ']']).into(), port, params: Vec::new() })
    }

    pub fn set(&mut self, k: &str, v: impl Into<String>) {
        let v = v.into();
        if !v.is_empty() {
            self.params.retain(|(pk, _)| pk != k);
            self.params.push((k.into(), v));
        }
    }

    pub fn opt(&mut self, k: &str, v: Option<impl Into<String>>) {
        if let Some(v) = v {
            self.set(k, v);
        }
    }

    pub fn flag(&mut self, k: &str, on: bool) {
        if on {
            self.set(k, "true");
        }
    }


    pub fn build(self) -> Proxy {
        let name = if self.name.is_empty() { format!("{} {}:{}", self.kind, self.server, self.port) } else { self.name };
        Proxy { name, kind: self.kind, server: self.server, port: self.port, args: Vec::new(), params: self.params }
    }
}

/// Параметры транспорта в общем виде (ссылки, Clash, Xray называют их по-разному).
#[derive(Default)]
pub struct Transport<'a> {
    pub network: Option<&'a str>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service: Option<String>,
    pub mode: Option<String>,
    pub extra: Option<String>,
    /// `headerType`/`type` для tcp: `http` — обфускация HTTP-заголовком.
    pub header: Option<&'a str>,
}

/// Транспорт → `obfs=` Shadowrocket (+ path / obfs-host / grpc-service-name / mode / xhttp-extra).
pub fn transport(b: &mut B, t: Transport) -> Result<(), String> {
    let net = t.network.unwrap_or("tcp").to_ascii_lowercase();
    let obfs = match net.as_str() {
        "" | "tcp" | "raw" | "none" => {
            if t.header.is_some_and(|h| h.eq_ignore_ascii_case("http")) {
                return Err("tcp with HTTP header obfuscation is not supported".into());
            }
            return Ok(());
        }
        "ws" | "websocket" => "websocket",
        "grpc" | "gun" => "grpc",
        "h2" | "http" => "h2",
        "httpupgrade" => "httpupgrade",
        "xhttp" | "splithttp" => "xhttp",
        "quic" => "quic",
        other => return Err(format!("unsupported transport `{other}`")),
    };
    b.set("obfs", obfs);
    if obfs == "grpc" {
        b.opt("grpc-service-name", t.service.or(t.path));
    } else {
        b.opt("path", t.path);
    }
    b.opt("obfs-host", t.host);
    if obfs == "xhttp" {
        b.opt("mode", t.mode);
        b.opt("xhttp-extra", t.extra);
    }
    Ok(())
}

/// Значение JSON/YAML как строка (числа и bool тоже).
pub fn s(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64() == Some(1),
        Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

pub fn port(v: &Value) -> u16 {
    s(v).and_then(|p| p.parse().ok()).unwrap_or(0)
}

/// Массив строк или строка через запятую → `a|b` (формат alpn в outbound.rs).
pub fn list(v: &Value) -> Option<String> {
    let items: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(s).collect(),
        Value::String(x) => x.split(',').map(|i| i.trim().to_string()).filter(|i| !i.is_empty()).collect(),
        _ => return None,
    };
    (!items.is_empty()).then(|| items.join("|"))
}

/// base64 (стандартный и URL-safe, с паддингом и без, с переводами строк).
pub fn b64(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn b64_str(input: &str) -> Option<String> {
    b64(input).and_then(|b| String::from_utf8(b).ok())
}

/// `%XX` → байт; `+` не трогаем (в fragment/userinfo это буква).
pub fn pct(input: &str) -> String {
    let b = input.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// YAML (yaml-rust2) → serde_json::Value, чтобы Clash разбирался теми же функциями.
pub fn yaml_to_json(y: &yaml_rust2::Yaml) -> Value {
    use yaml_rust2::Yaml;
    match y {
        Yaml::Real(r) => r.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map_or(Value::String(r.clone()), Value::Number),
        Yaml::Integer(i) => Value::from(*i),
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Array(a) => Value::Array(a.iter().map(yaml_to_json).collect()),
        Yaml::Hash(h) => Value::Object(
            h.iter()
                .filter_map(|(k, v)| {
                    let key = match k {
                        Yaml::String(s) => s.clone(),
                        Yaml::Integer(i) => i.to_string(),
                        Yaml::Boolean(b) => b.to_string(),
                        _ => return None,
                    };
                    Some((key, yaml_to_json(v)))
                })
                .collect(),
        ),
        _ => Value::Null,
    }
}
