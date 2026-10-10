//! Xray JSON (`outbounds[]` с `protocol` + `streamSettings`) → `Proxy` с ключами Shadowrocket.
//!
//! Поля — Xray `infra/conf/{vless,vmess,trojan,shadowsocks,socks,http,wireguard}.go` и
//! `transport_internet.go` (StreamConfig: network, security, tls/reality/ws/grpc/httpupgrade/xhttpSettings).
//! Обе формы settings: плоская (`settings.address/port/id`, Xray ≥ 25) и `vnext[0].users[0]` / `servers[0]`.
//! Подписки v2rayN «custom config» — массив полных конфигов: имя узла из `remarks`.
//! Проверено по исходникам v26.3.27 (ARCHITECTURE.md §11). Это ВХОД; генерация для xhttp — singbox-gen/src/xray.rs.

use core_model::Proxy;
use serde_json::Value;

use crate::common::{list, port, s, transport, truthy, Transport, B};

/// Служебные протоколы — не узлы.
const SERVICE: &[&str] = &["freedom", "blackhole", "dns", "loopback"];

/// Узлы одного конфига. `remarks` — имя по умолчанию (если у outbound нет осмысленного тега).
pub fn outbounds(cfg: &Value) -> Vec<Result<Proxy, (String, String)>> {
    let remarks = s(&cfg["remarks"]);
    let items: Vec<&Value> =
        cfg["outbounds"].as_array().into_iter().flatten().filter(|o| !SERVICE.contains(&o["protocol"].as_str().unwrap_or(""))).collect();
    let single = items.len() == 1;
    items
        .into_iter()
        .map(|o| {
            let tag = s(&o["tag"]).unwrap_or_default();
            one(o)
                .map(|mut p| {
                    // Тег вида "proxy" ничего не говорит: при одном узле в конфиге берём remarks.
                    p.name = match (&remarks, single || tag.is_empty() || tag == "proxy") {
                        (Some(r), true) => r.clone(),
                        _ if !tag.is_empty() => tag.clone(),
                        _ => p.name,
                    };
                    p
                })
                .map_err(|e| (tag, e))
        })
        .collect()
}

fn one(o: &Value) -> Result<Proxy, String> {
    let protocol = o["protocol"].as_str().ok_or("missing protocol")?;
    let st = &o["settings"];
    // Цель: vnext[0] / servers[0] / peers[0] или сами settings (плоская форма).
    let target = st["vnext"].get(0).or(st["servers"].get(0)).unwrap_or(st);
    let user = target["users"].get(0).unwrap_or(target);
    let addr = s(&target["address"]).unwrap_or_default();
    let mut b = match protocol {
        "vless" | "vmess" => {
            let mut b = B::new(protocol, &addr, port(&target["port"]))?;
            b.opt("password", s(&user["id"]));
            b.opt("flow", s(&user["flow"]));
            if protocol == "vmess" {
                b.opt("method", s(&user["security"]));
                b.opt("alterId", s(&user["alterId"]).filter(|a| a != "0"));
            } else if s(&user["encryption"]).is_some_and(|e| e != "none") {
                return Err("VLESS encryption (non-`none`) is not supported by sing-box".into());
            }
            b
        }
        "trojan" => {
            let mut b = B::new("trojan", &addr, port(&target["port"]))?;
            b.opt("password", s(&user["password"]));
            b
        }
        "shadowsocks" => {
            let mut b = B::new("ss", &addr, port(&target["port"]))?;
            b.opt("method", s(&user["method"]));
            b.opt("password", s(&user["password"]));
            b
        }
        "socks" | "http" => {
            let mut b = B::new(if protocol == "socks" { "socks5" } else { "http" }, &addr, port(&target["port"]))?;
            b.opt("username", s(&user["user"]));
            b.opt("password", s(&user["pass"]));
            b
        }
        "wireguard" => {
            let peer = &st["peers"][0];
            let ep = s(&peer["endpoint"]).ok_or("wireguard: missing peers[0].endpoint")?;
            let (host, p) = ep.rsplit_once(':').ok_or("wireguard: endpoint without port")?;
            let mut b = B::new("wireguard", host, p.parse().unwrap_or(0))?;
            b.opt("privateKey", s(&st["secretKey"]));
            b.opt("publicKey", s(&peer["publicKey"]));
            b.opt("preSharedKey", s(&peer["preSharedKey"]));
            for a in st["address"].as_array().into_iter().flatten().filter_map(s) {
                b.set(if a.contains(':') { "ipv6" } else { "ip" }, a);
            }
            if let Some(r) = st["reserved"].as_array() {
                b.set("reserved", r.iter().filter_map(s).collect::<Vec<_>>().join("/"));
            }
            b.opt("mtu", s(&st["mtu"]));
            return Ok(b.build());
        }
        other => return Err(format!("unsupported protocol `{other}`")),
    };
    stream(&mut b, &o["streamSettings"], protocol == "trojan")?;
    Ok(b.build())
}

fn stream(b: &mut B, st: &Value, tls_default: bool) -> Result<(), String> {
    let security = s(&st["security"]).unwrap_or_else(|| if tls_default { "tls".into() } else { "none".into() });
    match security.as_str() {
        "tls" => {
            let t = &st["tlsSettings"];
            b.set("tls", "true");
            b.opt("sni", s(&t["serverName"]));
            b.opt("alpn", list(&t["alpn"]));
            b.opt("fp", s(&t["fingerprint"]));
            b.flag("skip-cert-verify", truthy(&t["allowInsecure"]));
        }
        "reality" => {
            let r = &st["realitySettings"];
            b.set("tls", "true");
            b.opt("sni", s(&r["serverName"]));
            b.opt("fp", s(&r["fingerprint"]));
            b.opt("pbk", s(&r["publicKey"]).or(s(&r["password"])));
            b.opt("sid", s(&r["shortId"]));
        }
        "none" | "" => {}
        other => return Err(format!("unsupported security `{other}`")),
    }
    let network = s(&st["network"]);
    let t = match network.as_deref() {
        Some("ws") => {
            let w = &st["wsSettings"];
            Transport { path: s(&w["path"]), host: s(&w["host"]).or(s(&w["headers"]["Host"])), ..Default::default() }
        }
        Some("grpc") => Transport { service: s(&st["grpcSettings"]["serviceName"]), ..Default::default() },
        Some("httpupgrade") => {
            let h = &st["httpupgradeSettings"];
            Transport { path: s(&h["path"]), host: s(&h["host"]), ..Default::default() }
        }
        Some("xhttp") | Some("splithttp") => {
            let x = if st["xhttpSettings"].is_object() { &st["xhttpSettings"] } else { &st["splithttpSettings"] };
            Transport {
                path: s(&x["path"]),
                host: s(&x["host"]),
                mode: s(&x["mode"]),
                extra: x["extra"].is_object().then(|| x["extra"].to_string()),
                ..Default::default()
            }
        }
        Some("h2") | Some("http") => {
            let h = &st["httpSettings"];
            Transport { path: s(&h["path"]), host: h["host"].as_array().and_then(|a| a.first()).and_then(s), ..Default::default() }
        }
        Some("tcp") | Some("raw") => {
            let set = if st["rawSettings"].is_object() { &st["rawSettings"] } else { &st["tcpSettings"] };
            Transport { header: set["header"]["type"].as_str(), ..Default::default() }
        }
        _ => Transport::default(),
    };
    transport(b, Transport { network: network.as_deref(), ..t })
}
