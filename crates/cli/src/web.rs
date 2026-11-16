//! Веб-страница управления (dev-версия): логи, исходящие подключения (узлы, правила, группы) и входящие
//! (режим сервера: адрес, порт, маска, устройства, ссылки/QR). Документация — docs/WEB.md.
//!
//! Запускается командой `cproxy web [--port N]` (main.rs) как отдельный процесс: сама ничего не проксирует,
//! а читает и правит те же файлы, что и CLI (`settings.rs`, `server.rs`, `<data>/logs`, run.json) и ходит
//! в Clash API запущенного экземпляра (`clash.rs`) за живыми данными. Изменения вступают в силу при следующем
//! запуске ядра — как у `cproxy set ...`; для установленной службы они копируются в её каталог
//! (`service::apply`, ARCHITECTURE.md §15).
//!
//! Безопасность (страница показывает ссылки с UUID и правит конфиги):
//! - слушает только 127.0.0.1; чужой `Host` отвергается (защита от DNS rebinding);
//! - для `/api/*` нужен токен в заголовке `X-Token`: он случайный на каждый запуск, печатается в консоль в
//!   адресе после `#` (фрагмент не уходит на сервер и в прокси), поэтому чужая страница в браузере не может
//!   ни прочитать, ни отправить запрос (кросс-доменный запрос с таким заголовком требует CORS preflight — его нет);
//! - секреты в ответах: подписка — `https://host/***`; ссылки vless:// отдаются только по явному запросу.
//! Без зависимостей: `std::net` + поток на соединение. Фронтенд — `web.html` (один файл, без CDN).

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{json, Value};
use singbox_gen::server::Exit;

use crate::settings::{self, Mode, NodesMode, Settings};
use crate::{clash, server, service, store};

const DEFAULT_PORT: u16 = 7899;
const PAGE: &str = include_str!("web.html");
const MAX_BODY: usize = 1 << 20;
/// Сколько байт лога отдаётся за один запрос и сколько хвоста — при первом открытии.
const LOG_CHUNK: u64 = 512 * 1024;
const LOG_TAIL: u64 = 64 * 1024;

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

type ApiResult = Result<Value, (u16, String)>;

fn bad<T>(msg: impl Into<String>) -> Result<T, (u16, String)> {
    Err((400, msg.into()))
}

/// Случайный токен: `RandomState` засеян ОС при создании (без новых зависимостей и без sing-box).
fn new_token() -> String {
    (0..3u64)
        .map(|i| {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u64(i);
            format!("{:016x}", h.finish())
        })
        .collect()
}

pub fn serve(port: Option<u16>) -> Result<ExitCode, String> {
    let port = port.unwrap_or(DEFAULT_PORT);
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("127.0.0.1:{port}: {e} (занят? другой порт: --port N)"))?;
    let token = new_token();
    log::info!(target: "web", "listening on 127.0.0.1:{port}, data dir {}", store::data_dir().display());
    println!("веб-страница: http://127.0.0.1:{port}/#{token}");
    println!("данные: {} (остановка: Ctrl+C)", store::data_dir().display());
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let token = token.clone();
        std::thread::spawn(move || handle(stream, port, &token));
    }
    Ok(ExitCode::SUCCESS)
}

fn handle(mut stream: TcpStream, port: u16, token: &str) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let (status, ctype, body) = match read_request(&stream) {
        Ok(req) => respond(&req, port, token),
        Err((code, msg)) => (code, "application/json; charset=utf-8", json!({"error": msg}).to_string().into_bytes()),
    };
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(&body));
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push((hex(b[i + 1]).unwrap() * 16 + hex(b[i + 2]).unwrap()) as u8);
                i += 3;
                continue;
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_request(stream: &TcpStream) -> Result<Req, (u16, String)> {
    let io = |e: std::io::Error| (400, format!("read: {e}"));
    let mut r = BufReader::new(stream.try_clone().map_err(io)?.take((MAX_BODY + 65536) as u64));
    let mut line = String::new();
    r.read_line(&mut line).map_err(io)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return bad("bad request line") };
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let query = qs.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').unwrap_or((p, ""))).map(|(k, v)| (pct_decode(k), pct_decode(v))).collect();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).map_err(io)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Err((413, "body too large".into()));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).map_err(io)?;
    Ok(Req { method: method.to_string(), path: pct_decode(path), query, headers, body })
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn respond(req: &Req, port: u16, token: &str) -> (u16, &'static str, Vec<u8>) {
    const JSON: &str = "application/json; charset=utf-8";
    let err = |code: u16, msg: &str| (code, JSON, json!({"error": msg}).to_string().into_bytes());
    // DNS rebinding: страница чужого домена, указывающая на 127.0.0.1, пришла бы с чужим Host.
    let host = req.headers.get("host").map(String::as_str).unwrap_or("");
    if ![format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].iter().any(|h| h.eq_ignore_ascii_case(host)) {
        log::warn!(target: "web", "rejected request with Host `{host}`");
        return err(403, "bad Host");
    }
    if !req.path.starts_with("/api/") {
        return match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => (200, "text/html; charset=utf-8", PAGE.as_bytes().to_vec()),
            _ => err(404, "not found"),
        };
    }
    if !ct_eq(req.headers.get("x-token").map(String::as_str).unwrap_or(""), token) {
        log::warn!(target: "web", "{} {}: bad or missing token", req.method, req.path);
        return err(401, "bad token: open the address printed by `cproxy web` (with #token)");
    }
    log::debug!(target: "web", "{} {}", req.method, req.path);
    match api(req) {
        Ok(v) => (200, JSON, v.to_string().into_bytes()),
        Err((code, msg)) => {
            log::warn!(target: "web", "{} {} → {code}: {msg}", req.method, req.path);
            err(code, &msg)
        }
    }
}

fn api(req: &Req) -> ApiResult {
    let body = || -> Result<Value, (u16, String)> { serde_json::from_slice(&req.body).map_err(|e| (400, format!("bad JSON: {e}"))) };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/state") => Ok(state()),
        ("GET", "/api/logs") => logs(req),
        ("GET", "/api/nodes") => nodes(),
        ("GET", "/api/server/link") => link(req),
        ("POST", "/api/settings") => set_settings(&body()?),
        ("POST", "/api/select") => select(&body()?),
        ("POST", "/api/test") => test(&body()?),
        ("POST", "/api/server/init") => server_init(&body()?),
        ("POST", "/api/server/params") => server_params(&body()?),
        ("POST", "/api/server/device") => server_device(&body()?),
        ("POST", "/api/server/device/remove") => server_device_remove(&body()?),
        ("POST", "/api/service/sync") => Ok(json!({"apply": apply_note(true)})),
        ("GET" | "POST", _) => Err((404, "no such endpoint".into())),
        _ => Err((405, "method not allowed".into())),
    }
}

fn settings_json() -> Value {
    let s = Settings::load();
    json!({
        "rules": s.rules,
        "connection": s.connection.as_deref().map(settings::redact_source),
        "connection_is_url": s.connection.as_deref().is_some_and(settings::is_url),
        "nodes": s.nodes.name(),
        "nodes_modes": NodesMode::NAMES,
        "system_proxy": s.system_proxy,
        "tun": s.tun,
        "debug": s.debug,
        "kill_switch": s.kill_switch,
        "mode": s.mode.name(),
        "modes": Mode::NAMES,
        "selections": s.selections,
    })
}

fn server_json() -> Value {
    let protocols = || server::Protocol::ALL.iter().map(|p| json!({"id": p.id(), "title": p.title()})).collect::<Vec<_>>();
    let (Ok(cfg), Ok(keys)) = (server::Config::load(), server::Keys::load()) else { return json!({"configured": false, "protocols": protocols()}) };
    let devices: Vec<Value> = cfg
        .devices
        .iter()
        .map(|d| json!({"name": d.name, "exits": d.exits.iter().map(|e| json!({"id": e.name(), "node": e.node_name()})).collect::<Vec<_>>()}))
        .collect();
    json!({
        "configured": true, "protocol": cfg.protocol.id(), "protocol_title": cfg.protocol.title(), "needs_mask": cfg.protocol.needs_mask(),
        "protocols": protocols(),
        "host": cfg.host, "listen": cfg.listen, "port": cfg.port, "mask": cfg.mask,
        "public_key": keys.public_key, "short_id": keys.short_id, "devices": devices,
        "exits": Exit::ALL.iter().map(|e| json!({"id": e.name(), "node": e.node_name()})).collect::<Vec<_>>(),
    })
}

/// Живые данные из Clash API запущенного экземпляра (клиента или сервера).
fn live() -> Value {
    let api = match clash::load() {
        Ok(a) => a,
        Err(e) => return json!({"error": e}),
    };
    let conns = match api.get("/connections") {
        Ok(c) => c,
        Err(e) => return json!({"error": e}),
    };
    let users: Vec<Value> = server::per_user(&conns).into_iter().map(|(n, (c, u, d))| json!({"name": n, "conns": c, "up": u, "down": d})).collect();
    let groups: Vec<Value> = api
        .get("/proxies")
        .map(|p| clash::groups(&p))
        .unwrap_or_default()
        .into_iter()
        .map(|(name, kind, now, all)| json!({"name": name, "kind": kind, "now": now, "all": all}))
        .collect();
    json!({
        "up": conns["uploadTotal"], "down": conns["downloadTotal"],
        "connections": conns["connections"].as_array().map_or(0, Vec::len),
        "users": users, "groups": groups,
    })
}

fn state() -> Value {
    let run = supervisor::RunState::load(&store::data_dir()).filter(supervisor::RunState::is_running).map(|st| {
        json!({
            "pid": st.pid, "uptime": supervisor::RunState::now_unix().saturating_sub(st.started_unix),
            "listeners": st.listeners, "cores": st.cores.iter().map(|(n, p)| json!({"name": n, "pid": p})).collect::<Vec<_>>(), "log": st.log,
        })
    });
    let live = if run.is_some() { live() } else { Value::Null };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "data_dir": store::data_dir().display().to_string(),
        "run": run,
        "settings": settings_json(),
        "server": server_json(),
        "service": {"systemd": service::has_systemd(), "installed": service::installed()},
        "live": live,
    })
}

// ---- логи ----

/// Файлы логов, новые первыми (имя содержит время запуска).
fn log_files() -> Vec<(String, u64)> {
    let dir = store::data_dir().join("logs");
    let mut v: Vec<(String, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            (n.starts_with("cproxy-") && n.ends_with(".log")).then(|| (n, e.metadata().map_or(0, |m| m.len())))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v
}

/// `?file=<имя>&offset=N&follow=1`: новые строки лога после смещения. Без `offset` (или за концом файла —
/// файл усечён) отдаётся хвост ~64 КБ. `follow` — переходить на более новый файл (ротация, перезапуск).
fn logs(req: &Req) -> ApiResult {
    let files = log_files();
    let list: Vec<Value> = files.iter().map(|(n, s)| json!({"name": n, "size": s})).collect();
    // «Новый» — последний лог работы прокси: собственный лог `cproxy web` (он тоже новее всех при debug)
    // не должен перехватывать слежение.
    let Some(newest) = files.iter().find(|f| !f.0.ends_with("-web.log")).or(files.first()).map(|f| f.0.clone()) else {
        return Ok(json!({"files": list, "file": null, "latest": null, "offset": 0, "text": ""}));
    };
    let mut file = req.query.get("file").filter(|f| !f.is_empty()).cloned();
    let mut offset: Option<u64> = req.query.get("offset").and_then(|o| o.parse().ok());
    let follow = req.query.get("follow").is_some_and(|f| f == "1");
    if file.is_none() {
        let running = supervisor::RunState::load(&store::data_dir()).and_then(|s| s.log).and_then(|p| Some(std::path::Path::new(&p).file_name()?.to_string_lossy().into_owned()));
        file = Some(running.filter(|r| files.iter().any(|f| &f.0 == r)).unwrap_or_else(|| newest.clone()));
    }
    let mut file = file.unwrap();
    let latest = newest.clone();
    if follow && newest > file {
        file = newest;
        offset = None;
    }
    // Только имена из каталога логов: никаких путей из запроса.
    let Some((_, size)) = files.iter().find(|f| f.0 == file) else { return bad(format!("no such log `{file}`")) };
    let path = store::data_dir().join("logs").join(&file);
    let size = std::fs::metadata(&path).map_or(*size, |m| m.len());
    let fresh = offset.is_none_or(|o| o > size);
    let start = if fresh { size.saturating_sub(LOG_TAIL) } else { offset.unwrap() };
    let mut f = std::fs::File::open(&path).map_err(|e| (500, format!("{file}: {e}")))?;
    f.seek(SeekFrom::Start(start)).map_err(|e| (500, e.to_string()))?;
    let mut buf = Vec::new();
    f.take(LOG_CHUNK).read_to_end(&mut buf).map_err(|e| (500, e.to_string()))?;
    // Только целые строки: хвост без \n дочитается следующим запросом (кроме аномально длинной строки).
    let end = match buf.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        None if buf.len() as u64 >= LOG_CHUNK => buf.len(),
        None => 0,
    };
    // С середины файла начинаем с первой целой строки.
    let skip = if fresh && start > 0 { buf.iter().position(|b| *b == b'\n').map_or(end, |i| i + 1).min(end) } else { 0 };
    let text = String::from_utf8_lossy(&buf[skip..end]).into_owned();
    Ok(json!({"files": list, "file": file, "latest": latest, "offset": start + end as u64, "size": size, "reset": fresh, "text": text}))
}

// ---- исходящие: настройки, узлы, группы ----

fn set_settings(b: &Value) -> ApiResult {
    let mut s = Settings::load();
    let text = |k: &str| -> Result<Option<Option<String>>, (u16, String)> {
        match &b[k] {
            Value::Null if b.get(k).is_none() => Ok(None),
            Value::Null => Ok(Some(None)),
            Value::String(v) if v.trim().is_empty() => Ok(Some(None)),
            Value::String(v) => settings::normalize(v).map(|n| Some(Some(n))).map_err(|e| (400, format!("{k}: {e}"))),
            _ => bad(format!("{k}: string expected")),
        }
    };
    if let Some(v) = text("rules")? {
        s.rules = v;
    }
    if let Some(v) = text("connection")? {
        s.connection = v;
    }
    if let Some(m) = b["nodes"].as_str() {
        s.nodes = NodesMode::parse(m).ok_or((400, format!("bad nodes mode `{m}` ({})", NodesMode::NAMES)))?;
    }
    if let Some(m) = b["mode"].as_str() {
        s.mode = Mode::parse(m).ok_or((400, format!("bad mode `{m}` ({})", Mode::NAMES)))?;
    }
    for (key, slot) in [("system_proxy", &mut s.system_proxy), ("tun", &mut s.tun), ("debug", &mut s.debug), ("kill_switch", &mut s.kill_switch)] {
        if let Some(v) = b[key].as_bool() {
            *slot = v;
        }
    }
    s.save().map_err(|e| (500, e))?;
    // Служба держит свою копию settings.json (service::data_steps): без синхронизации она работала бы со старыми.
    let apply = if service::installed() { apply_note(false) } else { String::new() };
    Ok(json!({"settings": settings_json(), "note": "Вступит в силу при следующем запуске cproxy.", "apply": apply}))
}

/// Узлы подключения (с подпиской — скачивает её в память, как и запуск). Секреты узлов не отдаются.
fn nodes() -> ApiResult {
    let args = crate::parse_args(&["check".to_string()]).map_err(|e| (500, e))?;
    let list = crate::server_nodes(&args).map_err(|e| (502, e))?;
    let rows: Vec<Value> = list
        .iter()
        .map(|n| json!({"name": n.proxy.name, "kind": n.proxy.kind, "server": n.proxy.server, "port": n.proxy.port, "xray": singbox_gen::needs_xray(&n.proxy)}))
        .collect();
    Ok(json!({"nodes": rows}))
}

fn select(b: &Value) -> ApiResult {
    let (Some(group), Some(node)) = (b["group"].as_str(), b["node"].as_str()) else { return bad("group and node needed") };
    let api = clash::load().map_err(|e| (409, e))?;
    let list = clash::groups(&api.get("/proxies").map_err(|e| (502, e))?);
    let (_, kind, _, all) = list.iter().find(|g| g.0 == group).ok_or((404, format!("no group `{group}`")))?;
    if kind != "Selector" {
        return bad(format!("`{group}` is {kind}: it picks the node itself"));
    }
    if !all.iter().any(|n| n == node) {
        return bad(format!("no node `{node}` in `{group}`"));
    }
    api.put(&format!("/proxies/{}", clash::seg(group)), &json!({"name": node})).map_err(|e| (502, e))?;
    let mut s = Settings::load();
    s.selections.insert(group.to_string(), node.to_string());
    s.save().map_err(|e| (500, e))?;
    log::info!(target: "web", "select `{group}` → `{node}` (saved)");
    Ok(json!({"group": group, "node": node}))
}

fn test(b: &Value) -> ApiResult {
    let group = b["group"].as_str().ok_or((400, "group needed".to_string()))?;
    let api = clash::load().map_err(|e| (409, e))?;
    let path = format!("/group/{}/delay?url={}&timeout=5000", clash::seg(group), clash::seg("https://www.gstatic.com/generate_204"));
    let res = api.get_with(&path, Duration::from_secs(30)).map_err(|e| (502, e))?;
    Ok(json!({"delays": res}))
}

// ---- входящие: режим сервера ----

/// Что сказать пользователю после изменения устройств/параметров: куда это применилось.
fn apply_note(explicit: bool) -> String {
    match service::apply() {
        Ok(service::Applied::Synced) => "Служба обновлена и перезапущена.".into(),
        Ok(service::Applied::NeedRoot) => "Служба держит свою копию данных: выполните `sudo cproxy service sync`.".into(),
        Ok(service::Applied::NoService) if crate::running() => "cproxy запущен вручную: перезапустите его (cproxy stop, затем cproxy run [--server]).".into(),
        Ok(service::Applied::NoService) if explicit => "Службы нет — применять нечего.".into(),
        Ok(service::Applied::NoService) => String::new(),
        Err(e) => format!("Не удалось обновить службу: {e}"),
    }
}

fn sing_box() -> Result<std::path::PathBuf, (u16, String)> {
    store::find_bin("sing-box", None, "CPROXY_SING_BOX").ok_or((500, "sing-box not found (scripts/fetch-sing-box)".into()))
}

fn port_of(v: &Value) -> Result<Option<u16>, (u16, String)> {
    match v {
        Value::Null => Ok(None),
        v => v.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).map(Some).ok_or((400, "bad port".into())),
    }
}

fn server_init(b: &Value) -> ApiResult {
    let host = b["host"].as_str().map(str::trim).filter(|h| !h.is_empty()).ok_or((400, "host needed".to_string()))?;
    let port = port_of(&b["port"])?.unwrap_or(server::DEFAULT_PORT);
    let mask = b["mask"].as_str().map(str::trim).filter(|m| !m.is_empty()).map(String::from);
    let protocol = match b["protocol"].as_str() {
        None => server::Protocol::DEFAULT,
        Some(p) => server::Protocol::parse(p).ok_or((400, format!("bad protocol `{p}` ({})", server::Protocol::NAMES)))?,
    };
    server::init(protocol, host.to_string(), port, mask, &sing_box()?).map_err(|e| (400, e))?;
    Ok(json!({"server": server_json()}))
}

fn server_params(b: &Value) -> ApiResult {
    let changes = server::set_params(b["host"].as_str().map(String::from), port_of(&b["port"])?, b["mask"].as_str().map(String::from)).map_err(|e| (400, e))?;
    let apply = if changes.is_empty() { String::new() } else { apply_note(false) };
    Ok(json!({"changes": changes, "apply": apply, "server": server_json()}))
}

fn server_device(b: &Value) -> ApiResult {
    let name = b["name"].as_str().ok_or((400, "name needed".to_string()))?;
    let ids: Vec<&str> = b["exits"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let exits = server::parse_exits(ids).map_err(|e| (400, e))?;
    if exits.is_empty() {
        return bad("pick at least one exit (ru|vps|lan)");
    }
    server::set_device(name, exits, true, &sing_box()?).map_err(|e| (400, e))?;
    Ok(json!({"apply": apply_note(false), "server": server_json()}))
}

fn server_device_remove(b: &Value) -> ApiResult {
    let name = b["name"].as_str().ok_or((400, "name needed".to_string()))?;
    server::remove_device(name).map_err(|e| (400, e))?;
    Ok(json!({"apply": apply_note(false), "server": server_json()}))
}

/// Ссылка vless:// и QR одного выхода устройства. Содержит UUID — отдаётся только по этому запросу.
fn link(req: &Req) -> ApiResult {
    let (Some(device), Some(exit)) = (req.query.get("device"), req.query.get("exit")) else { return bad("device and exit needed") };
    let exit = Exit::parse(exit).ok_or((400, format!("bad exit ({})", Exit::NAMES)))?;
    let cfg = server::Config::load().map_err(|e| (409, e))?;
    let keys = server::Keys::load().map_err(|e| (409, e))?;
    let l = server::link(&cfg, &keys, device, exit).ok_or((404, format!("no link for `{device}` / {}", exit.name())))?;
    log::debug!(target: "web", "link for `{device}` / {} shown", exit.name());
    Ok(json!({"link": l, "node": exit.node_name(), "qr_svg": server::qr_svg(&l).map_err(|e| (500, e))?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_token() {
        assert_eq!(pct_decode("cproxy-2026%2D1.log"), "cproxy-2026-1.log");
        assert_eq!(pct_decode("a+b%D0%94%zz%"), "a bД%zz%");
        assert_eq!(new_token().len(), 48);
        assert_ne!(new_token(), new_token());
        assert!(ct_eq("abc", "abc") && !ct_eq("abc", "abd") && !ct_eq("abc", "ab"));
    }

    fn req(method: &str, path: &str, host: &str, token: Option<&str>) -> Req {
        let mut headers = HashMap::from([("host".to_string(), host.to_string())]);
        if let Some(t) = token {
            headers.insert("x-token".into(), t.into());
        }
        Req { method: method.into(), path: path.into(), query: HashMap::new(), headers, body: Vec::new() }
    }

    #[test]
    fn auth_rules() {
        let page = respond(&req("GET", "/", "127.0.0.1:7899", None), 7899, "T");
        assert_eq!(page.0, 200);
        assert!(String::from_utf8(page.2).unwrap().contains("cproxy"));
        // DNS rebinding: чужой Host отвергается, даже на странице.
        assert_eq!(respond(&req("GET", "/", "evil.example:7899", None), 7899, "T").0, 403);
        // API: без токена и с чужим — 401, с верным — работает.
        assert_eq!(respond(&req("GET", "/api/state", "localhost:7899", None), 7899, "T").0, 401);
        assert_eq!(respond(&req("GET", "/api/state", "localhost:7899", Some("X")), 7899, "T").0, 401);
        assert_eq!(respond(&req("GET", "/api/nope", "localhost:7899", Some("T")), 7899, "T").0, 404);
    }

    #[test]
    fn log_name_is_not_a_path() {
        let mut r = req("GET", "/api/logs", "127.0.0.1:1", Some("T"));
        r.query.insert("file".into(), "..\\..\\settings.json".into());
        // Либо нет каталога логов (пустой ответ), либо отказ: путь из запроса до файловой системы не доходит.
        match logs(&r) {
            Ok(v) => assert!(v["file"].is_null()),
            Err((code, _)) => assert_eq!(code, 400),
        }
    }
}
