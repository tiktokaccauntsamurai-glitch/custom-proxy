//! Clash / Mihomo YAML (`proxies:`) → `Proxy` с ключами Shadowrocket.
//!
//! YAML читает yaml-rust2 (решение пользователя) и переводит в serde_json::Value (`common::yaml_to_json`).
//! Поля — документация Mihomo «proxies»: name, type, server, port, uuid/password/cipher, tls, sni/servername,
//! skip-cert-verify, alpn, client-fingerprint, reality-opts, network + ws/grpc/h2/http/xhttp-opts,
//! plugin + plugin-opts, hysteria2/tuic/wireguard-специфичные. `proxy-groups` и `rules` Clash не берём:
//! группы и правила задаёт `.conf` Shadowrocket.

use core_model::Proxy;
use serde_json::Value;

use crate::common::{list, port, s, transport, truthy, Transport, B};

/// Узлы из документа (`proxies:`). Ошибка узла → `Err` для этого элемента.
pub fn proxies(doc: &Value) -> Vec<Result<Proxy, (String, String)>> {
    doc["proxies"].as_array().into_iter().flatten().map(|p| one(p).map_err(|e| (s(&p["name"]).unwrap_or_default(), e))).collect()
}

fn one(p: &Value) -> Result<Proxy, String> {
    let g = |k: &str| s(&p[k]);
    let kind = g("type").ok_or("missing type")?.to_ascii_lowercase();
    let server = g("server").unwrap_or_default();
    let mut b = match kind.as_str() {
        "ss" => {
            let mut b = B::new("ss", &server, port(&p["port"]))?;
            b.opt("method", g("cipher"));
            b.opt("password", g("password"));
            match g("plugin").as_deref() {
                Some("obfs") => {
                    let o = &p["plugin-opts"];
                    b.set("obfs", s(&o["mode"]).unwrap_or_else(|| "http".into()));
                    b.opt("obfs-host", s(&o["host"]));
                }
                Some("v2ray-plugin") => {
                    let o = &p["plugin-opts"];
                    b.set("obfs", "websocket");
                    b.opt("obfs-host", s(&o["host"]));
                    b.opt("path", s(&o["path"]));
                    b.flag("tls", truthy(&o["tls"]));
                }
                None => {}
                Some(other) => return Err(format!("unsupported ss plugin `{other}`")),
            }
            b
        }
        "vmess" | "vless" | "trojan" => {
            let mut b = B::new(&kind, &server, port(&p["port"]))?;
            if kind == "trojan" {
                b.opt("password", g("password"));
            } else {
                b.opt("password", g("uuid"));
            }
            if kind == "vmess" {
                b.opt("alterId", g("alterId").filter(|a| a != "0"));
                b.opt("method", g("cipher"));
            }
            b.opt("flow", g("flow"));
            b.opt("packet-encoding", g("packet-encoding"));
            let reality = &p["reality-opts"];
            if kind == "trojan" || truthy(&p["tls"]) || reality.is_object() {
                b.set("tls", "true");
                b.opt("sni", g("servername").or(g("sni")));
                b.opt("alpn", list(&p["alpn"]));
                b.opt("fp", g("client-fingerprint"));
                b.flag("skip-cert-verify", truthy(&p["skip-cert-verify"]));
                b.opt("pbk", s(&reality["public-key"]));
                b.opt("sid", s(&reality["short-id"]));
            }
            net(&mut b, p)?;
            b
        }
        "hysteria2" | "hy2" => {
            let mut b = B::new("hysteria2", &server, port(&p["port"]))?;
            b.opt("password", g("password").or(g("auth")));
            if g("obfs").is_some_and(|o| o == "salamander") {
                b.opt("obfs-password", g("obfs-password"));
            }
            b.opt("upmbps", g("up"));
            b.opt("downmbps", g("down"));
            tls_common(&mut b, p);
            b
        }
        "hysteria" => {
            let mut b = B::new("hysteria", &server, port(&p["port"]))?;
            b.opt("auth", g("auth-str").or(g("auth_str")));
            b.opt("obfsParam", g("obfs"));
            b.opt("upmbps", g("up"));
            b.opt("downmbps", g("down"));
            tls_common(&mut b, p);
            b
        }
        "tuic" => {
            let mut b = B::new("tuic", &server, port(&p["port"]))?;
            b.opt("uuid", g("uuid"));
            b.opt("password", g("password"));
            b.opt("congestion-controller", g("congestion-controller"));
            tls_common(&mut b, p);
            b
        }
        "anytls" => {
            let mut b = B::new("anytls", &server, port(&p["port"]))?;
            b.opt("password", g("password"));
            b.opt("fp", g("client-fingerprint"));
            tls_common(&mut b, p);
            b
        }
        "socks5" | "http" => {
            let tls = truthy(&p["tls"]);
            let k = if kind == "http" && tls { "https" } else { kind.as_str() };
            let mut b = B::new(k, &server, port(&p["port"]))?;
            b.opt("username", g("username"));
            b.opt("password", g("password"));
            if tls {
                tls_common(&mut b, p);
            }
            b
        }
        "wireguard" => {
            let mut b = B::new("wireguard", &server, port(&p["port"]))?;
            b.opt("privateKey", g("private-key"));
            b.opt("publicKey", g("public-key"));
            b.opt("preSharedKey", g("pre-shared-key"));
            b.opt("ip", g("ip"));
            b.opt("ipv6", g("ipv6"));
            b.opt("mtu", g("mtu"));
            if let Some(r) = p["reserved"].as_array() {
                b.set("reserved", r.iter().filter_map(s).collect::<Vec<_>>().join("/"));
            } else {
                b.opt("reserved", g("reserved").map(|r| r.replace(',', "/")));
            }
            b
        }
        "ssr" => return Err("ShadowsocksR is not supported by sing-box".into()),
        other => return Err(format!("unsupported type `{other}`")),
    };
    b.name = g("name").unwrap_or_default();
    Ok(b.build())
}

fn tls_common(b: &mut B, p: &Value) {
    b.opt("sni", s(&p["sni"]).or(s(&p["servername"])));
    b.opt("alpn", list(&p["alpn"]));
    b.flag("skip-cert-verify", truthy(&p["skip-cert-verify"]));
}

/// `network` + `<net>-opts` → транспорт.
fn net(b: &mut B, p: &Value) -> Result<(), String> {
    let network = s(&p["network"]);
    let t = match network.as_deref() {
        Some("ws") => {
            let o = &p["ws-opts"];
            Transport { path: s(&o["path"]), host: s(&o["headers"]["Host"]).or(s(&o["headers"]["host"])), ..Default::default() }
        }
        Some("grpc") => Transport { service: s(&p["grpc-opts"]["grpc-service-name"]), ..Default::default() },
        Some("h2") => {
            let o = &p["h2-opts"];
            Transport { path: s(&o["path"]), host: o["host"].as_array().and_then(|a| a.first()).and_then(s).or(s(&o["host"])), ..Default::default() }
        }
        Some("http") => {
            // Clash `network: http` — это HTTP/1.1-обфускация поверх TCP, не h2.
            return Err("network `http` (HTTP header obfuscation) is not supported".into());
        }
        Some("httpupgrade") => {
            let o = &p["http-upgrade-opts"];
            Transport { path: s(&o["path"]), host: s(&o["host"]), ..Default::default() }
        }
        Some("xhttp") | Some("splithttp") => {
            let o = &p["xhttp-opts"];
            Transport {
                path: s(&o["path"]),
                host: s(&o["host"]),
                mode: s(&o["mode"]),
                extra: o["extra"].is_object().then(|| o["extra"].to_string()),
                ..Default::default()
            }
        }
        _ => Transport::default(),
    };
    transport(b, Transport { network: network.as_deref(), ..t })
}
