//! Режим сервера, сторона cli: ключи, пользователи, ссылки для Shadowrocket (docs/SERVER-MODE.md).
//!
//! Команды `cproxy server init|user|link|show` и подготовка к `run --server` вызываются из `main.rs`;
//! конфиг sing-box собирает `singbox_gen::server` (вход VLESS REALITY + правила `auth_user`).
//! Файлы в каталоге данных (store::data_dir), решения пользователя SERVER-QUESTIONS D1/D2:
//! - `server.json` — без секретов: адрес, порт, маска, устройства и их выходы;
//! - `server-keys.json` — приватный ключ REALITY, short_id, UUID пользователей. Единственное осознанное
//!   исключение из инварианта «секреты не на диске»: серверу ключ нужен после перезагрузки. Unix — права
//!   0600; Windows — профиль пользователя (%APPDATA%) и так закрыт от других.
//! Ключи генерирует сам sing-box (`generate reality-keypair|uuid|rand`, `cmd/sing-box/cmd_generate*.go`):
//! без новых крипто-зависимостей. Сайт-маску проверяет [`check_mask`] (rustls из дерева ureq).
//! `server check` (main.rs::server_check, этап 2): маска, внешний IP против `host`, порт, «взгляд сканера» на
//! сам сервер ([`tls_probe`]) — локально и через внешний адрес (hairpin NAT роутера).

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use singbox_gen::server::{Exit, Server, User};

pub const DEFAULT_PORT: u16 = 443;

/// Кандидаты в маски REALITY: крупные сайты с TLS 1.3 + X25519 + h2, доступные из РФ. `server init`
/// проверяет их с этой машины и берёт самый быстрый рабочий (SERVER-QUESTIONS B2).
pub const MASK_CANDIDATES: &[&str] = &[
    "www.microsoft.com",
    "www.apple.com",
    "dl.google.com",
    "www.samsung.com",
    "www.nvidia.com",
    "www.amd.com",
    "www.intel.com",
    "www.cloudflare.com",
];

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub exits: Vec<Exit>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Адрес для телефона (домен DDNS или IP).
    pub host: String,
    pub listen: String,
    pub port: u16,
    pub mask: String,
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone)]
pub struct Keys {
    pub private_key: String,
    pub public_key: String,
    pub short_id: String,
    /// Имя пользователя (`iphone-ru`) → UUID.
    pub uuids: BTreeMap<String, String>,
}

fn config_path() -> PathBuf {
    crate::store::data_dir().join("server.json")
}

fn keys_path() -> PathBuf {
    crate::store::data_dir().join("server-keys.json")
}

pub fn user_name(device: &str, exit: Exit) -> String {
    format!("{device}-{}", exit.name())
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let p = config_path();
        let text = std::fs::read_to_string(&p).map_err(|_| format!("{} not found: run `cproxy server init` first", p.display()))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        let s = |k: &str| v[k].as_str().map(String::from).ok_or(format!("{}: `{k}` missing", p.display()));
        let mut devices = Vec::new();
        for d in v["devices"].as_array().into_iter().flatten() {
            let name = d["name"].as_str().unwrap_or_default().to_string();
            let mut exits = Vec::new();
            for e in d["exits"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                match Exit::parse(e) {
                    Some(x) => exits.push(x),
                    None => log::warn!(target: "server", "{}: device `{name}`: unknown exit `{e}` ignored", p.display()),
                }
            }
            devices.push(Device { name, exits });
        }
        let c = Config {
            host: s("host")?,
            listen: v["listen"].as_str().unwrap_or("::").into(),
            port: v["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(DEFAULT_PORT),
            mask: s("mask")?,
            devices,
        };
        log::debug!(target: "server", "loaded {}: host {} listen [{}]:{} mask {} devices {:?}", p.display(), c.host, c.listen, c.port, c.mask, c.devices);
        Ok(c)
    }

    pub fn save(&self) -> Result<(), String> {
        let devices: Vec<Value> = self
            .devices
            .iter()
            .map(|d| json!({"name": d.name, "exits": d.exits.iter().map(|e| e.name()).collect::<Vec<_>>()}))
            .collect();
        let v = json!({"host": self.host, "listen": self.listen, "port": self.port, "mask": self.mask, "devices": devices});
        write_file(&config_path(), &v, false)
    }

    /// Пользователи sing-box: по одному на пару устройство × выход.
    pub fn users(&self) -> Vec<(String, Exit)> {
        self.devices.iter().flat_map(|d| d.exits.iter().map(|e| (user_name(&d.name, *e), *e))).collect()
    }
}

impl Keys {
    pub fn load() -> Result<Self, String> {
        let p = keys_path();
        let text = std::fs::read_to_string(&p).map_err(|_| format!("{} not found: run `cproxy server init` first", p.display()))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        let s = |k: &str| v[k].as_str().map(String::from).ok_or(format!("{}: `{k}` missing", p.display()));
        let uuids = v["uuids"].as_object().map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()).unwrap_or_default();
        Ok(Keys { private_key: s("private_key")?, public_key: s("public_key")?, short_id: s("short_id")?, uuids })
    }

    pub fn save(&self) -> Result<(), String> {
        let v = json!({"private_key": self.private_key, "public_key": self.public_key, "short_id": self.short_id, "uuids": self.uuids});
        write_file(&keys_path(), &v, true)
    }
}

/// Запись JSON; `secret` — права 0600 на Unix (создаётся сразу с ними, без окна 0644).
pub(crate) fn write_file(path: &Path, v: &Value, secret: bool) -> Result<(), String> {
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    if secret {
        // Файл мог существовать раньше с другими правами.
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(serde_json::to_string_pretty(v).unwrap().as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    log::info!(target: "server", "saved {}{}", path.display(), if secret { " (secret keys)" } else { "" });
    Ok(())
}

/// `sing-box generate <args>` → stdout. Вывод содержит секреты: в лог не пишется.
fn generate(sing_box: &Path, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(sing_box)
        .arg("generate")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", sing_box.display()))?;
    if !out.status.success() {
        return Err(format!("sing-box generate {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    log::debug!(target: "server", "sing-box generate {} ok", args.join(" "));
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn new_uuid(sing_box: &Path) -> Result<String, String> {
    generate(sing_box, &["uuid"])
}

/// Ключи REALITY: пара X25519 + short_id (8 байт hex).
pub fn new_keys(sing_box: &Path) -> Result<Keys, String> {
    let pair = generate(sing_box, &["reality-keypair"])?;
    let field = |name: &str| {
        pair.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .ok_or(format!("sing-box generate reality-keypair: no `{name}` in output"))
    };
    Ok(Keys {
        private_key: field("PrivateKey:")?,
        public_key: field("PublicKey:")?,
        short_id: generate(sing_box, &["rand", "--hex", "8"])?,
        uuids: BTreeMap::new(),
    })
}

/// Проверка сайта-маски с этой машины: TLS 1.3 + X25519 + h2 и валидный сертификат для имени
/// (требования REALITY: сервер выдаёт себя за этот сайт и пересылает ему чужие рукопожатия).
/// Ok — время рукопожатия.
pub fn check_mask(host: &str, port: u16) -> Result<Duration, String> {
    let addr = (host, port).to_socket_addrs().map_err(|e| format!("resolve: {e}"))?.next().ok_or("resolve: no address")?;
    let took = tls_probe(addr, host)?;
    log::debug!(target: "server", "mask {host}:{port}: TLS 1.3 + X25519 + h2 ok in {took:?} ({addr})");
    Ok(took)
}

/// TLS 1.3 + X25519 + h2 к `addr` с SNI `sni` и проверкой сертификата для `sni`. Для своего сервера это
/// «взгляд сканера»: без ключа REALITY должен ответить сертификатом настоящей маски.
pub fn tls_probe(addr: SocketAddr, sni: &str) -> Result<Duration, String> {
    let provider = rustls::crypto::CryptoProvider {
        kx_groups: vec![rustls::crypto::ring::kx_group::X25519],
        ..rustls::crypto::ring::default_provider()
    };
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|e| format!("bad name: {e}"))?;
    let started = Instant::now();
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| format!("connect {addr}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| format!("TLS 1.3/X25519 handshake: {e}"))?;
    }
    let took = started.elapsed();
    if conn.alpn_protocol() != Some(b"h2") {
        return Err("no HTTP/2 (ALPN h2)".into());
    }
    Ok(took)
}

/// Внешний IP этой машины: Cloudflare `/cdn-cgi/trace` по IP (тот же 1.1.1.1, что DoH сервера). Если на машине
/// работает VPN/TUN, вернётся его IP — `server check` об этом предупреждает.
pub fn public_ip() -> Result<String, String> {
    let body = crate::store::http_get("https://1.1.1.1/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace", None)?;
    let text = String::from_utf8_lossy(&body);
    text.lines().find_map(|l| l.strip_prefix("ip=")).map(str::to_string).ok_or("no ip= in cdn-cgi/trace".into())
}

/// Свободен ли порт для sing-box. Err — занят (тогда sing-box не стартует) или нет прав (Unix, порт < 1024).
/// Сначала подключение к 127.0.0.1:port: на Windows пробный `bind` проходит даже на занятый порт (проверено:
/// слушатель Python на [::]:8443, bind из Rust успешен, sing-box падает), а принятое подключение — точный признак.
pub fn port_check(listen: &str, port: u16) -> Result<(), std::io::Error> {
    let local = SocketAddr::from(([127, 0, 0, 1], port));
    if TcpStream::connect_timeout(&local, Duration::from_millis(300)).is_ok() {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, format!("something already accepts connections on {local}")));
    }
    let addr = if listen.contains(':') { format!("[{listen}]:{port}") } else { format!("{listen}:{port}") };
    std::net::TcpListener::bind(addr).map(drop)
}

/// Самый быстрый рабочий кандидат (печатает результат проверки каждого).
pub fn pick_mask() -> Result<String, String> {
    println!("проверяю сайты-маски (TLS 1.3 + X25519 + HTTP/2) с этой машины:");
    let mut best: Option<(Duration, &str)> = None;
    for &h in MASK_CANDIDATES {
        match check_mask(h, 443) {
            Ok(t) => {
                println!("  ok    {h:<22} {} мс", t.as_millis());
                if best.is_none_or(|(b, _)| t < b) {
                    best = Some((t, h));
                }
            }
            Err(e) => println!("  нет   {h:<22} {e}"),
        }
    }
    best.map(|(_, h)| h.to_string()).ok_or("no mask candidate passed; pass --mask <site>".into())
}

/// LAN-адрес этой машины (маршрут по умолчанию; UDP connect пакетов не шлёт).
pub fn lan_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

/// Сборка `singbox_gen::server::Server`: пользователи с UUID, запрет внешнего IP дома.
pub fn build(cfg: &Config, keys: &Keys) -> Result<Server, String> {
    let mut users = Vec::new();
    for (name, exit) in cfg.users() {
        let uuid = keys.uuids.get(&name).ok_or(format!("no UUID for user `{name}` in server-keys.json: re-add the device"))?;
        users.push(User { name, uuid: uuid.clone(), exit });
    }
    if users.is_empty() {
        return Err("no devices: `cproxy server user add <name>`".into());
    }
    // Внешний адрес дома ведёт в роутер (hairpin NAT): закрыть для выходов в интернет.
    let mut block = Vec::new();
    match (cfg.host.as_str(), cfg.port).to_socket_addrs() {
        Ok(addrs) => {
            for a in addrs.filter(|a| !is_private(a.ip())) {
                let c = if a.is_ipv4() { format!("{}/32", a.ip()) } else { format!("{}/128", a.ip()) };
                if !block.contains(&c) {
                    block.push(c);
                }
            }
        }
        Err(e) => log::warn!(target: "server", "cannot resolve host `{}`: {e}; its public IP is not blocked for phones", cfg.host),
    }
    log::debug!(target: "server", "users {:?}, extra block {block:?}", users.iter().map(|u| &u.name).collect::<Vec<_>>());
    Ok(Server {
        listen: cfg.listen.clone(),
        port: cfg.port,
        mask: cfg.mask.clone(),
        mask_port: 443,
        private_key: keys.private_key.clone(),
        short_ids: vec![keys.short_id.clone()],
        users,
        block,
        clash_api: None,
    })
}

/// Secret для Clash API (clash.rs): 16 случайных байт от sing-box.
pub fn new_secret(sing_box: &Path) -> Result<String, String> {
    generate(sing_box, &["rand", "--hex", "16"])
}

/// Пользователь соединения из текста правила Clash API: `auth_user=iphone-ru ip_is_private=true => reject`.
/// Правила сервера — по одному пользователю (singbox_gen::server), поэтому имя однозначно.
pub fn rule_user(rule: &str) -> Option<&str> {
    let rest = &rule[rule.find("auth_user=")? + "auth_user=".len()..];
    let name = rest.split([' ', ']']).next()?.trim_start_matches('[');
    (!name.is_empty()).then_some(name)
}

/// Активные соединения по пользователю: имя → (число, ↑ байт, ↓ байт).
pub fn per_user(conns: &Value) -> BTreeMap<String, (usize, u64, u64)> {
    let mut m: BTreeMap<String, (usize, u64, u64)> = BTreeMap::new();
    for c in conns["connections"].as_array().into_iter().flatten() {
        let user = c["rule"].as_str().and_then(rule_user).unwrap_or("?").to_string();
        let e = m.entry(user).or_default();
        e.0 += 1;
        e.1 += c["upload"].as_u64().unwrap_or(0);
        e.2 += c["download"].as_u64().unwrap_or(0);
    }
    m
}

pub fn human(bytes: u64) -> String {
    let b = bytes as f64;
    match bytes {
        0..=1023 => format!("{bytes} Б"),
        1024..=1048575 => format!("{:.1} КБ", b / 1024.0),
        1048576..=1073741823 => format!("{:.1} МБ", b / 1048576.0),
        _ => format!("{:.2} ГБ", b / 1073741824.0),
    }
}

pub fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        std::net::IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn pct(s: &str) -> String {
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

/// Ссылка `vless://` для Shadowrocket (формат Xray share link: VLESS + REALITY + Vision).
pub fn link(cfg: &Config, keys: &Keys, device: &str, exit: Exit) -> Option<String> {
    let uuid = keys.uuids.get(&user_name(device, exit))?;
    let host = if cfg.host.contains(':') { format!("[{}]", cfg.host) } else { cfg.host.clone() };
    Some(format!(
        "vless://{uuid}@{host}:{}?encryption=none&flow={}&security=reality&sni={}&fp=chrome&pbk={}&sid={}&type=tcp#{}",
        cfg.port,
        singbox_gen::server::FLOW,
        cfg.mask,
        keys.public_key,
        keys.short_id,
        pct(exit.node_name())
    ))
}

/// Строка `[Proxy]` Shadowrocket для узла «Дом-*» (ключи — docs/MAPPING.md: `password`=uuid, `xtls=2` → Vision,
/// `peer` — SNI, `pbk`/`sid` — REALITY, `fp`). Наш парсер её принимает (тест `phone_conf`), но в самом Shadowrocket
/// синтаксис VLESS REALITY в `.conf` не подтверждён (официальной документации нет) — поэтому только по флагу.
pub fn proxy_line(cfg: &Config, keys: &Keys, device: &str, exit: Exit) -> Option<String> {
    let uuid = keys.uuids.get(&user_name(device, exit))?;
    Some(format!(
        "{} = vless, {}, {}, password={uuid}, tls=true, xtls=2, peer={}, pbk={}, sid={}, fp=chrome",
        exit.node_name(),
        cfg.host,
        cfg.port,
        cfg.mask,
        keys.public_key,
        keys.short_id
    ))
}

/// Узлы-выходы, которые не должны попадать в автогруппы телефона: в url-test «Дом-RU» выиграл бы у VPS
/// (заблокированное пошло бы с домашнего IP), «Дом-LAN» в интернет не выпускает вовсе.
fn not_for_groups() -> Vec<&'static str> {
    Exit::ALL.iter().filter(|e| **e != Exit::Proxy).map(|e| e.node_name()).collect()
}

/// `policy-regex-filter` группы → тот же фильтр, но без «Дом-RU»/«Дом-LAN» (негативный lookahead, Shadowrocket
/// использует NSRegularExpression — lookahead поддерживается, как и в fancy-regex генератора).
pub fn exclude_home_exits(filter: &str) -> String {
    let names: Vec<String> = not_for_groups().iter().map(|n| fancy_regex::escape(n).into_owned()).collect();
    format!("^(?!(?:{})$)(?:{filter})", names.join("|"))
}

/// `.conf` для телефона (SERVER-QUESTIONS, сессия 6): правила пользователя как есть (lossless writer
/// fmt-shadowrocket), DIRECT остаётся прямым с телефона, во всех группах с `policy-regex-filter` исключены
/// «Дом-RU»/«Дом-LAN» — AUTO выбирает из «Дом-VPS» и узлов подписки VPS на телефоне.
/// `with_nodes` — дописать узлы «Дом-*» в `[Proxy]` (тогда в файле секреты). Правила для домашней сети
/// (выход lan) — позже, по решению пользователя: сюда добавится группа/правило.
/// Возвращает текст и список сделанных изменений (для экрана и лога).
pub fn phone_conf(rules: &str, cfg: &Config, keys: &Keys, device: &Device, with_nodes: bool) -> (String, Vec<String>) {
    let mut doc = fmt_shadowrocket::parse(rules);
    let mut changes = Vec::new();
    if let Some(sec) = doc.sections.iter_mut().find(|s| s.name.eq_ignore_ascii_case("Proxy Group")) {
        for line in sec.lines.iter_mut() {
            let Some(pos) = line.find("policy-regex-filter=") else { continue };
            let t = line.trim_start();
            if t.starts_with('#') || t.starts_with("//") || t.starts_with(';') {
                continue;
            }
            let start = pos + "policy-regex-filter=".len();
            let end = line[start..].find(',').map_or(line.len(), |i| start + i);
            let old = line[start..end].trim().to_string();
            if old.contains("(?!(?:Дом-") {
                continue; // уже переписан прошлым запуском
            }
            let new = exclude_home_exits(&old);
            let group = line.split('=').next().unwrap_or("").trim().to_string();
            *line = format!("{}{new}{}", &line[..start], &line[end..]);
            changes.push(format!("group `{group}`: {} excluded from policy-regex-filter", not_for_groups().join(", ")));
        }
    }
    if with_nodes {
        let lines: Vec<String> = device.exits.iter().filter_map(|x| proxy_line(cfg, keys, &device.name, *x)).collect();
        let ours: Vec<&str> = device.exits.iter().map(|x| x.node_name()).collect();
        let is_ours = |l: &str| l.split('=').next().is_some_and(|n| ours.contains(&n.trim()));
        match doc.sections.iter_mut().find(|s| s.name.eq_ignore_ascii_case("Proxy")) {
            Some(sec) => {
                sec.lines.retain(|l| !is_ours(l));
                // Перед хвостом из пустых строк, чтобы не слипнуться со следующей секцией.
                let at = sec.lines.iter().rposition(|l| !l.trim().is_empty()).map_or(0, |i| i + 1);
                sec.lines.splice(at..at, lines.iter().cloned());
            }
            None => {
                let at = doc.sections.iter().position(|s| s.name.eq_ignore_ascii_case("Proxy Group") || s.name.eq_ignore_ascii_case("Rule")).unwrap_or(doc.sections.len());
                let mut body = lines.clone();
                body.push(String::new());
                doc.sections.insert(at, fmt_shadowrocket::Section { name: "Proxy".into(), header_line: 0, lines: body });
            }
        }
        changes.push(format!("[Proxy]: {} (contains secrets)", ours.join(", ")));
    }
    let header = format!("# cproxy server phone-conf: device `{}`, server {}:{}. DIRECT — напрямую с телефона.", device.name, cfg.host, cfg.port);
    if !doc.preamble.first().is_some_and(|l| l.starts_with("# cproxy server phone-conf")) {
        doc.preamble.insert(0, header);
    }
    (fmt_shadowrocket::write(&doc), changes)
}

/// QR-код в терминал (полублоки: две строки модулей на строку текста).
pub fn qr(text: &str) -> Result<String, String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_link() {
        let cfg = Config { host: "home.example.net".into(), listen: "::".into(), port: 443, mask: "www.samsung.com".into(), devices: vec![] };
        let keys = Keys {
            private_key: "x".into(),
            public_key: "PUB".into(),
            short_id: "abcd".into(),
            uuids: BTreeMap::from([("iphone-vps".to_string(), "U".to_string())]),
        };
        assert_eq!(
            link(&cfg, &keys, "iphone", Exit::Proxy).unwrap(),
            "vless://U@home.example.net:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.samsung.com&fp=chrome&pbk=PUB&sid=abcd&type=tcp#%D0%94%D0%BE%D0%BC-VPS"
        );
        assert!(link(&cfg, &keys, "iphone", Exit::Direct).is_none(), "no UUID — no link");
        let v6 = Config { host: "2001:db8::1".into(), ..cfg };
        assert!(link(&v6, &keys, "iphone", Exit::Proxy).unwrap().contains("@[2001:db8::1]:443?"));
        // Ссылка из `server link` разбирается нашим же парсером узлов (тот же путь, что у Shadowrocket-ссылок).
        let l = link(&Config { host: "1.2.3.4".into(), ..v6 }, &keys, "iphone", Exit::Proxy).unwrap();
        assert_eq!(rule_user("auth_user=iphone-ru => route(DIRECT)"), Some("iphone-ru"));
        assert_eq!(rule_user("auth_user=[ipad-vps] ip_is_private=true => reject"), Some("ipad-vps"));
        assert_eq!(rule_user("network=[tcp udp icmp] => reject"), None);
        let conns = serde_json::json!({"connections": [
            {"rule": "auth_user=iphone-ru => route(DIRECT)", "upload": 10, "download": 100},
            {"rule": "auth_user=iphone-ru => route(DIRECT)", "upload": 1, "download": 2},
            {"rule": "auth_user=iphone-vps => route(PROXY)", "upload": 5, "download": 7}]});
        let pu = per_user(&conns);
        assert_eq!((pu["iphone-ru"], pu["iphone-vps"]), ((2, 11, 102), (1, 5, 7)));
        assert_eq!(human(1536), "1.5 КБ");
        let n = fmt_nodes::parse(&l, "link").unwrap().nodes;
        assert_eq!((n[0].proxy.name.as_str(), n[0].proxy.kind.as_str(), n[0].proxy.port), ("Дом-VPS", "vless", 443));
        assert!(!qr(&l).unwrap().is_empty());
    }

    #[test]
    fn phone_conf() {
        // Как у пользователя: без [Proxy], AUTO — url-test по regex «всё, кроме России», CRLF.
        let rules = "[General]\r\ndns-server = system\r\n\r\n[Proxy Group]\r\n# AUTO — автовыбор\r\nAUTO = url-test, policy-regex-filter=^(?!.*(Россия|Russia|🇷🇺)).*, interval=600, timeout=5, url=http://www.gstatic.com/generate_204\r\nMANUAL = select, DIRECT\r\n\r\n[Rule]\r\nDOMAIN-SUFFIX,ru,DIRECT\r\nFINAL,AUTO\r\n";
        let cfg = Config { host: "home.example.net".into(), listen: "::".into(), port: 443, mask: "www.samsung.com".into(), devices: vec![] };
        let keys = Keys {
            private_key: "x".into(),
            public_key: "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON-GwPq7SOV4".into(),
            short_id: "abcd".into(),
            uuids: BTreeMap::from([
                ("iphone-ru".to_string(), "11111111-1111-1111-1111-111111111111".to_string()),
                ("iphone-vps".to_string(), "22222222-2222-2222-2222-222222222222".to_string()),
            ]),
        };
        let dev = Device { name: "iphone".into(), exits: vec![Exit::Direct, Exit::Proxy] };
        let (out, changes) = super::phone_conf(rules, &cfg, &keys, &dev, false);
        assert_eq!(changes.len(), 1, "{changes:?}");
        // Всё, кроме строки AUTO и заголовка, — байт в байт (CRLF, комментарии, MANUAL, правила).
        let auto = out.lines().find(|l| l.starts_with("AUTO")).unwrap();
        assert_eq!(out.replace(auto, "").lines().skip(1).collect::<Vec<_>>(), rules.replace(rules.lines().nth(5).unwrap(), "").lines().collect::<Vec<_>>());
        assert!(out.contains("\r\n") && !out.contains("password="), "CRLF kept, no secrets without --with-nodes");
        assert!(auto.ends_with(", interval=600, timeout=5, url=http://www.gstatic.com/generate_204\r") || auto.ends_with("generate_204"));
        // Новый фильтр: Дом-RU/Дом-LAN исключены, Дом-VPS и узлы подписки остаются, «Россия» — как раньше.
        let g = fmt_shadowrocket::parse(&out).groups().unwrap();
        let re = fancy_regex::Regex::new(g[0].param("policy-regex-filter").unwrap()).unwrap();
        let m = |n: &str| re.is_match(n).unwrap();
        assert!(m("Дом-VPS") && m("NL Amsterdam 1") && m("Дом-RU 2"));
        assert!(!m("Дом-RU") && !m("Дом-LAN") && !m("Россия 1") && !m("🇷🇺 MSK"));
        // Повторный прогон не переписывает фильтр второй раз.
        let (again, ch2) = super::phone_conf(&out, &cfg, &keys, &dev, false);
        assert_eq!((again.as_str(), ch2.len()), (out.as_str(), 0));

        // --with-nodes: [Proxy] перед [Proxy Group]; генератор принимает узлы как VLESS REALITY Vision.
        let (with, _) = super::phone_conf(rules, &cfg, &keys, &dev, true);
        let doc = fmt_shadowrocket::parse(&with);
        let names: Vec<String> = doc.proxies().unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["Дом-RU", "Дом-VPS"]);
        assert!(with.find("[Proxy]").unwrap() < with.find("[Proxy Group]").unwrap());
        let gen = singbox_gen::generate(&doc, &NoRes, &singbox_gen::Options::default()).unwrap();
        let vps = gen.config["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "Дом-VPS").unwrap().clone();
        assert_eq!((vps["type"].as_str(), vps["flow"].as_str()), (Some("vless"), Some("xtls-rprx-vision")));
        assert_eq!(vps["tls"]["reality"]["public_key"], keys.public_key.as_str());
        assert_eq!(vps["tls"]["server_name"], "www.samsung.com");
        // Генератор (как и Shadowrocket) отбирает в AUTO по новому фильтру только Дом-VPS.
        let auto = gen.config["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "AUTO").unwrap().clone();
        assert_eq!(auto["outbounds"], serde_json::json!(["Дом-VPS"]));
    }

    struct NoRes;
    impl singbox_gen::Resources for NoRes {
        fn text(&self, _: &str) -> Option<String> {
            None
        }
        fn path(&self, _: &str) -> Option<String> {
            None
        }
    }
}
