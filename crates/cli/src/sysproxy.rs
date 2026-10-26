//! Системный прокси ОС: включается на время `cproxy run`, при выходе возвращается как было.
//!
//! - Windows: HKCU `Software\Microsoft\Windows\CurrentVersion\Internet Settings` (WinINet; его читают
//!   Chrome/Edge/Firefox-«системные настройки» и большинство программ) + `InternetSetOptionW`
//!   (SETTINGS_CHANGED, REFRESH), чтобы программы подхватили изменение сразу. FFI без зависимостей.
//! - macOS: `networksetup` для каждой включённой сетевой службы (web, secure web, SOCKS, bypass).
//! - Linux: GNOME (`gsettings`) и KDE Plasma (`kwriteconfig`), см. `mod os` для linux.
//!
//! Откат (решение пользователя: включено по умолчанию, ARCHITECTURE.md §12):
//! 1. снимок прежних значений → `<data>/sysproxy-backup.json` ДО изменения (переживает падение);
//! 2. обычный выход / Ctrl+C → `restore()` (main.rs::run, обработчик ctrlc);
//! 3. закрытие окна / выход из системы (Windows) → свой `SetConsoleCtrlHandler`, восстанавливает
//!    синхронно: обработчик ctrlc на это событие не успевает (процесс завершается сразу после него);
//! 4. процесс убит → при следующем запуске `recover_stale()` восстанавливает из файла.
//! Исключения — `[General] skip-proxy` (как в Shadowrocket) + всегда localhost/локальные адреса.
//! Вызывается из `main.rs` (run, команда `sysproxy`).

use std::sync::Mutex;

use serde_json::Value;

/// Снимок до изменения; `None` — мы ничего не меняли (или уже восстановили).
static SNAPSHOT: Mutex<Option<Value>> = Mutex::new(None);

fn backup_path() -> std::path::PathBuf {
    crate::store::data_dir().join("sysproxy-backup.json")
}

/// Куда направить системный прокси.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub http: Option<(String, u16)>,
    pub socks: Option<(String, u16)>,
}

impl Target {
    /// Из inbound генератора (`singbox_gen::Output::inbounds`). `0.0.0.0`/`::` → 127.0.0.1.
    pub fn from_inbounds(list: &[(String, String, u16)]) -> Option<Self> {
        let local = |h: &str| if h == "0.0.0.0" || h == "::" || h.is_empty() { "127.0.0.1".to_string() } else { h.to_string() };
        let mut t = Target { http: None, socks: None };
        for (kind, host, port) in list {
            let a = Some((local(host), *port));
            match kind.as_str() {
                "mixed" => {
                    t.http = t.http.or(a.clone());
                    t.socks = t.socks.or(a);
                }
                "http" => t.http = t.http.or(a),
                "socks" => t.socks = t.socks.or(a),
                _ => {}
            }
        }
        (t.http.is_some() || t.socks.is_some()).then_some(t)
    }
}

/// Список исключений: `skip-proxy` + обязательные локальные. Разделители — запятая.
pub fn bypass_list(skip_proxy: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = skip_proxy.unwrap_or("").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for must in ["localhost", "127.0.0.0/8"] {
        if !v.iter().any(|x| x.eq_ignore_ascii_case(must)) {
            v.push(must.into());
        }
    }
    v
}

/// Включает системный прокси. Снимок пишется в файл до изменения.
pub fn enable(t: &Target, bypass: &[String], warnings: &mut Vec<String>) -> Result<(), String> {
    // Подсказки ОС ссылаются на `<port>` (Linux без поддерживаемого стола): подставить наш.
    let port = t.http.as_ref().or(t.socks.as_ref()).map(|(_, p)| p.to_string()).unwrap_or_default();
    let snap = os::snapshot().map_err(|e| e.replace("<port>", &port))?;
    std::fs::write(backup_path(), serde_json::to_string_pretty(&snap).unwrap()).map_err(|e| format!("cannot save system proxy backup: {e}"))?;
    log::debug!(target: "sysproxy", "snapshot saved to {}: {snap}", backup_path().display());
    *SNAPSHOT.lock().unwrap() = Some(snap);
    if let Err(e) = os::apply(t, bypass, warnings) {
        restore();
        return Err(e);
    }
    log::info!(target: "sysproxy", "system proxy ON → {}", describe(t));
    Ok(())
}

/// Возвращает прежние настройки (идемпотентно: второй вызов ничего не делает).
pub fn restore() {
    let snap = SNAPSHOT.lock().map(|mut g| g.take()).unwrap_or(None);
    if let Some(snap) = snap {
        match os::restore(&snap) {
            Ok(()) => {
                let _ = std::fs::remove_file(backup_path());
                log::info!(target: "sysproxy", "system proxy restored");
            }
            Err(e) => log::error!(target: "sysproxy", "cannot restore system proxy: {e} (backup kept: {})", backup_path().display()),
        }
    }
}

/// Прошлый запуск не вернул настройки (убит/упал) → вернуть из файла.
pub fn recover_stale() {
    let Ok(text) = std::fs::read_to_string(backup_path()) else { return };
    match serde_json::from_str::<Value>(&text) {
        Ok(snap) => {
            log::warn!(target: "sysproxy", "previous run did not restore the system proxy; restoring from {}", backup_path().display());
            *SNAPSHOT.lock().unwrap() = Some(snap);
            restore();
        }
        Err(e) => log::error!(target: "sysproxy", "{}: {e}", backup_path().display()),
    }
}

pub fn has_backup() -> bool {
    backup_path().exists()
}

pub fn describe(t: &Target) -> String {
    let f = |a: &Option<(String, u16)>| a.as_ref().map(|(h, p)| format!("{h}:{p}"));
    match (f(&t.http), f(&t.socks)) {
        (Some(h), Some(s)) if h == s => format!("HTTP+SOCKS {h}"),
        (h, s) => [h.map(|h| format!("HTTP {h}")), s.map(|s| format!("SOCKS {s}"))].into_iter().flatten().collect::<Vec<_>>().join(", "),
    }
}

/// Переменные окружения прокси, которые читают консольные программы (Claude Code, curl, git, npm).
/// Они важнее системного прокси и TUN: loopback-адрес в TUN не попадает (route_exclude 127.0.0.0/8),
/// поэтому `HTTP_PROXY` на чужой порт (Hiddify 12334) уводит программу мимо cproxy.
const PROXY_ENV: [&str; 6] = ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"];

/// Переменные из `vars`, указывающие не на наш порт: `(имя, значение)`. Наш = loopback + порт из `t`.
pub fn foreign_env_proxies(t: &Target, vars: &[(String, String)]) -> Vec<(String, String)> {
    let ours: Vec<u16> = [&t.http, &t.socks].into_iter().flatten().map(|(_, p)| *p).collect();
    let points_to_us = |v: &str| {
        let rest = v.split_once("://").map_or(v, |(_, r)| r);
        let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
        let hostport = rest.split('/').next().unwrap_or("");
        let Some((host, port)) = hostport.rsplit_once(':') else { return false };
        let local = matches!(host.trim_matches(['[', ']']), "localhost" | "::1") || host.starts_with("127.");
        local && port.parse().is_ok_and(|p: u16| ours.contains(&p))
    };
    vars.iter().filter(|(_, v)| !v.trim().is_empty() && !points_to_us(v.trim())).cloned().collect()
}

/// Предупредить о `HTTP(S)_PROXY`/`ALL_PROXY` мимо cproxy (вызывается из `main.rs::run`). Ничего не меняет.
pub fn warn_env_proxies(t: &Target) {
    let mut vars: Vec<(String, String)> = PROXY_ENV.iter().filter_map(|n| std::env::var(n).ok().map(|v| (n.to_string(), v))).collect();
    // В Windows имена без учёта регистра: http_proxy = HTTP_PROXY, не предупреждать дважды.
    if cfg!(windows) {
        vars.retain(|(n, _)| n.chars().all(|c| !c.is_ascii_lowercase()));
    }
    log::debug!(target: "sysproxy", "proxy env: {}", if vars.is_empty() { "none".into() } else { vars.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join(", ") });
    let ours = t.http.as_ref().or(t.socks.as_ref()).map(|(h, p)| format!("http://{h}:{p}")).unwrap_or_default();
    for (name, value) in foreign_env_proxies(t, &vars) {
        log::warn!(
            target: "sysproxy",
            "env {name}={value} points outside cproxy: console programs (Claude Code, curl, git) will bypass it, even in TUN mode. Fix: set {name}={ours} or remove it"
        );
    }
}

/// Текущее состояние системного прокси (для `cproxy sysproxy status`).
pub fn current() -> Result<Value, String> {
    os::snapshot()
}

/// Закрытие окна / выход из системы / выключение (Windows): восстановить синхронно.
pub fn install_close_handler() {
    os::install_close_handler();
}

/// IPv4 CIDR → маски WinINet (`192.168.*`). Не по границе байта — разворачивается (/12 → 16 масок).
/// `None` — не IPv4 CIDR (оставить как есть); `Some(vec![])` — не переводится (IPv6, слишком широкий).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn cidr_to_wildcards(entry: &str) -> Option<Vec<String>> {
    let (ip, bits) = entry.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    let octets: Vec<u8> = ip.split('.').map(|o| o.parse().ok()).collect::<Option<Vec<u8>>>()?;
    if octets.len() != 4 || bits > 32 {
        return Some(vec![]);
    }
    if bits == 32 {
        return Some(vec![ip.to_string()]);
    }
    if bits < 8 {
        return Some(vec![]);
    }
    let full = bits.div_ceil(8) as usize; // сколько октетов фиксировано после округления вверх
    let base = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]) & (!0u32 << (32 - bits));
    let count = 1u32 << (full as u32 * 8 - bits);
    let step = 1u32 << (32 - full as u32 * 8);
    Some(
        (0..count)
            .map(|i| {
                let b = (base + i * step).to_be_bytes();
                let fixed: Vec<String> = b[..full].iter().map(u8::to_string).collect();
                if full == 4 { fixed.join(".") } else { format!("{}.*", fixed.join(".")) }
            })
            .collect(),
    )
}

#[cfg(windows)]
mod os {
    //! WinINet: advapi32 (реестр) + wininet (уведомление программ).
    use super::Target;
    use serde_json::{json, Map, Value};
    use std::ffi::c_void;

    type Hkey = isize;
    const HKEY_CURRENT_USER: Hkey = 0x8000_0001u32 as i32 as isize;
    const KEY_READ: u32 = 0x20019;
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Значения, которые меняем (и поэтому сохраняем). AutoConfigURL (PAC) имеет приоритет над
    /// ProxyServer — на время работы убираем.
    const NAMES: [&str; 4] = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"];

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: Hkey, sub: *const u16, opts: u32, sam: u32, out: *mut Hkey) -> i32;
        fn RegQueryValueExW(key: Hkey, name: *const u16, reserved: *mut u32, ty: *mut u32, data: *mut u8, len: *mut u32) -> i32;
        fn RegSetValueExW(key: Hkey, name: *const u16, reserved: u32, ty: u32, data: *const u8, len: u32) -> i32;
        fn RegDeleteValueW(key: Hkey, name: *const u16) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(h: *mut c_void, opt: u32, buf: *mut c_void, len: u32) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct Key(Hkey);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: ключ открыт RegOpenKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(sam: u32) -> Result<Key, String> {
        let mut h: Hkey = 0;
        // SAFETY: валидные указатели, строка с нулём на конце.
        let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(KEY).as_ptr(), 0, sam, &mut h) };
        if rc != 0 {
            return Err(format!("RegOpenKeyExW(HKCU\\{KEY}) failed: {rc}"));
        }
        Ok(Key(h))
    }

    fn read(k: &Key, name: &str) -> Result<Value, String> {
        let n = wide(name);
        let (mut ty, mut len) = (0u32, 0u32);
        // SAFETY: первый вызов узнаёт размер (data = null).
        let rc = unsafe { RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null_mut(), &mut ty, std::ptr::null_mut(), &mut len) };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(Value::Null);
        }
        if rc != 0 {
            return Err(format!("RegQueryValueExW({name}) failed: {rc}"));
        }
        let mut buf = vec![0u8; len as usize + 2];
        // SAFETY: буфер на len байт.
        let rc = unsafe { RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null_mut(), &mut ty, buf.as_mut_ptr(), &mut len) };
        if rc != 0 {
            return Err(format!("RegQueryValueExW({name}) failed: {rc}"));
        }
        Ok(match ty {
            REG_DWORD => json!({"dword": u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])}),
            REG_SZ => {
                let w: Vec<u16> = buf[..len as usize].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                json!({"sz": String::from_utf16_lossy(&w).trim_end_matches('\0')})
            }
            other => json!({"unsupported_type": other}),
        })
    }

    fn write(k: &Key, name: &str, v: &Value) -> Result<(), String> {
        let n = wide(name);
        // SAFETY: данные и длина согласованы; строки REG_SZ с завершающим нулём.
        let rc = unsafe {
            if let Some(d) = v["dword"].as_u64() {
                let b = (d as u32).to_le_bytes();
                RegSetValueExW(k.0, n.as_ptr(), 0, REG_DWORD, b.as_ptr(), 4)
            } else if let Some(s) = v["sz"].as_str() {
                let w = wide(s);
                RegSetValueExW(k.0, n.as_ptr(), 0, REG_SZ, w.as_ptr() as *const u8, (w.len() * 2) as u32)
            } else if v.is_null() {
                let rc = RegDeleteValueW(k.0, n.as_ptr());
                if rc == ERROR_FILE_NOT_FOUND { 0 } else { rc }
            } else {
                return Err(format!("{name}: cannot write {v}"));
            }
        };
        if rc != 0 {
            return Err(format!("registry write {name} failed: {rc}"));
        }
        log::trace!(target: "sysproxy", "HKCU\\...\\Internet Settings\\{name} := {v}");
        Ok(())
    }

    /// Уведомить WinINet-программы, что настройки изменились (иначе подхватят не сразу).
    fn notify() {
        // SAFETY: NULL-хэндл и пустой буфер допустимы для этих опций.
        unsafe {
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
        }
    }

    pub fn snapshot() -> Result<Value, String> {
        let k = open(KEY_READ)?;
        let mut m = Map::new();
        for n in NAMES {
            m.insert(n.into(), read(&k, n)?);
        }
        Ok(json!({"os": "windows", "values": m}))
    }

    pub fn apply(t: &Target, bypass: &[String], warnings: &mut Vec<String>) -> Result<(), String> {
        let server = match (&t.http, &t.socks) {
            (Some(h), Some(s)) if h == s => format!("{}:{}", h.0, h.1),
            (h, s) => {
                let mut parts = Vec::new();
                if let Some((host, port)) = h {
                    parts.push(format!("http={host}:{port};https={host}:{port}"));
                }
                if let Some((host, port)) = s {
                    parts.push(format!("socks={host}:{port}"));
                }
                parts.join(";")
            }
        };
        let mut over: Vec<String> = Vec::new();
        for b in bypass {
            match super::cidr_to_wildcards(b) {
                Some(w) if w.is_empty() => warnings.push(format!("skip-proxy `{b}`: not expressible in Windows proxy bypass; ignored")),
                Some(w) => over.extend(w),
                None if b.contains(':') => warnings.push(format!("skip-proxy `{b}`: IPv6 is not supported by Windows proxy bypass; ignored")),
                None => over.push(b.clone()),
            }
        }
        over.push("<local>".into());
        let k = open(KEY_WRITE)?;
        write(&k, "ProxyServer", &json!({"sz": server}))?;
        write(&k, "ProxyOverride", &json!({"sz": over.join(";")}))?;
        write(&k, "AutoConfigURL", &Value::Null)?;
        write(&k, "ProxyEnable", &json!({"dword": 1}))?;
        notify();
        log::debug!(target: "sysproxy", "ProxyServer={server} ProxyOverride has {} entries", over.len());
        Ok(())
    }

    pub fn restore(snap: &Value) -> Result<(), String> {
        let k = open(KEY_WRITE)?;
        for n in NAMES {
            let v = &snap["values"][n];
            if v.get("unsupported_type").is_some() {
                continue;
            }
            write(&k, n, v)?;
        }
        notify();
        Ok(())
    }

    /// CTRL_CLOSE_EVENT (2), CTRL_LOGOFF_EVENT (5), CTRL_SHUTDOWN_EVENT (6): процесс завершится сразу
    /// после возврата из обработчиков — восстанавливаем прямо здесь. Ctrl+C/Break (0, 1) — дальше, к ctrlc.
    unsafe extern "system" fn on_close(ctrl: u32) -> i32 {
        if matches!(ctrl, 2 | 5 | 6) {
            log::warn!(target: "sysproxy", "console event {ctrl} (window closed / logoff / shutdown): restoring system proxy");
            super::restore();
            // Закрытие окна — штатный выход: ядра гибнут вместе с окном (Job Object), защиту тоже снять,
            // иначе без интернета до следующего запуска (killswitch.rs).
            crate::killswitch::disable();
            log::logger().flush();
        }
        0
    }

    pub fn install_close_handler() {
        // SAFETY: регистрируем функцию со статическим временем жизни. Регистрируется после ctrlc,
        // поэтому вызывается первой (обработчики идут в обратном порядке регистрации).
        if unsafe { SetConsoleCtrlHandler(Some(on_close), 1) } == 0 {
            log::warn!(target: "sysproxy", "SetConsoleCtrlHandler failed: closing the window may leave the system proxy on until next start");
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    //! `networksetup` для каждой включённой службы (Wi-Fi, Ethernet, ...).
    use super::Target;
    use serde_json::{json, Value};
    use std::process::Command;

    fn ns(args: &[&str]) -> Result<String, String> {
        let out = Command::new("networksetup").args(args).output().map_err(|e| format!("networksetup: {e}"))?;
        if !out.status.success() {
            return Err(format!("networksetup {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        log::trace!(target: "sysproxy", "networksetup {}", args.join(" "));
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn services() -> Result<Vec<String>, String> {
        // Первая строка — пояснение; `*` в начале — служба отключена.
        Ok(ns(&["-listallnetworkservices"])?.lines().skip(1).filter(|l| !l.starts_with('*') && !l.trim().is_empty()).map(String::from).collect())
    }

    /// `Enabled: Yes / Server: x / Port: n` → {enabled, server, port}.
    fn read_proxy(svc: &str, getter: &str) -> Result<Value, String> {
        let text = ns(&[getter, svc])?;
        let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string())).unwrap_or_default();
        Ok(json!({"enabled": field("Enabled:") == "Yes", "server": field("Server:"), "port": field("Port:")}))
    }

    const KINDS: [(&str, &str, &str, &str); 3] = [
        ("web", "-getwebproxy", "-setwebproxy", "-setwebproxystate"),
        ("secure", "-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"),
        ("socks", "-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
    ];

    pub fn snapshot() -> Result<Value, String> {
        let mut list = Vec::new();
        for svc in services()? {
            let mut s = json!({"service": svc});
            for (k, get, _, _) in KINDS {
                s[k] = read_proxy(&svc, get)?;
            }
            let bypass = ns(&["-getproxybypassdomains", &svc])?;
            let domains: Vec<&str> = bypass.lines().filter(|l| !l.contains("There aren't any")).map(str::trim).filter(|l| !l.is_empty()).collect();
            s["bypass"] = json!(domains);
            list.push(s);
        }
        Ok(json!({"os": "macos", "services": list}))
    }

    pub fn apply(t: &Target, bypass: &[String], _warnings: &mut Vec<String>) -> Result<(), String> {
        for svc in services()? {
            for (k, _, set, state) in KINDS {
                let addr = if k == "socks" { &t.socks } else { &t.http };
                match addr {
                    Some((h, p)) => {
                        ns(&[set, &svc, h, &p.to_string()])?;
                        ns(&[state, &svc, "on"])?;
                    }
                    None => {
                        ns(&[state, &svc, "off"])?;
                    }
                }
            }
            // macOS понимает CIDR и маски в bypass как есть.
            let mut args = vec!["-setproxybypassdomains", svc.as_str()];
            args.extend(bypass.iter().map(String::as_str));
            ns(&args)?;
        }
        Ok(())
    }

    pub fn restore(snap: &Value) -> Result<(), String> {
        for s in snap["services"].as_array().into_iter().flatten() {
            let svc = s["service"].as_str().unwrap_or("");
            for (k, _, set, state) in KINDS {
                let p = &s[k];
                let (server, port) = (p["server"].as_str().unwrap_or(""), p["port"].as_str().unwrap_or(""));
                if !server.is_empty() && port != "0" && !port.is_empty() {
                    ns(&[set, svc, server, port])?;
                }
                ns(&[state, svc, if p["enabled"].as_bool() == Some(true) { "on" } else { "off" }])?;
            }
            let domains: Vec<&str> = s["bypass"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let mut args = vec!["-setproxybypassdomains", svc];
            if domains.is_empty() {
                args.push("Empty");
            } else {
                args.extend(domains);
            }
            ns(&args)?;
        }
        Ok(())
    }

    pub fn install_close_handler() {
        // macOS: закрытие Терминала шлёт SIGHUP — ловит ctrlc с feature `termination` (Cargo.toml).
    }
}

#[cfg(target_os = "linux")]
mod os {
    //! Единого системного прокси в Linux нет: каждый рабочий стол хранит свой.
    //! - GNOME (и Ubuntu, Cinnamon, Budgie, Pantheon): `gsettings` схемы `org.gnome.system.proxy`.
    //!   Его же читают Chrome/Firefox на этих столах. Снимок — значения в формате GVariant, как их
    //!   печатает `gsettings get`; `gsettings set` принимает их обратно без преобразований.
    //! - KDE Plasma 5/6: `kioslaverc`, группа `Proxy Settings` через `kreadconfig{6,5}`/`kwriteconfig{6,5}`,
    //!   затем сигнал D-Bus `org.kde.KIO.Scheduler.reparseSlaveConfiguration`, чтобы KIO перечитал файл.
    //! Включаются все найденные. Нет ни одного (сервер, другой стол, `sudo` без сессии D-Bus) —
    //! ошибка с подсказкой; `run` её только логирует (main.rs::enable_system_proxy).
    use super::Target;
    use serde_json::{json, Map, Value};
    use std::process::Command;

    const GNOME: &str = "org.gnome.system.proxy";
    /// (подсхема, ключ) — всё, что меняем в GNOME и потому сохраняем в снимке.
    const GNOME_KEYS: [(&str, &str); 8] = [
        ("", "mode"),
        ("", "ignore-hosts"),
        (".http", "host"),
        (".http", "port"),
        (".https", "host"),
        (".https", "port"),
        (".socks", "host"),
        (".socks", "port"),
    ];
    const KDE_KEYS: [&str; 5] = ["ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"];

    fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
        let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
        log::trace!(target: "sysproxy", "{cmd} {} → {}", args.join(" "), out.status);
        if !out.status.success() {
            return Err(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// GNOME доступен: есть `gsettings`, схема установлена и есть сессия D-Bus (иначе gsettings
    /// молча пишет в memory-backend, и изменение никуда не попадает).
    fn has_gnome() -> bool {
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() && run("gsettings", &["get", GNOME, "mode"]).is_ok()
    }

    /// KDE: стол Plasma и найден `kwriteconfig6` или `kwriteconfig5`. Возвращает (чтение, запись).
    fn kde_tools() -> Option<(&'static str, &'static str)> {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        if !desktop.split(':').any(|d| d.eq_ignore_ascii_case("KDE")) {
            return None;
        }
        [("kreadconfig6", "kwriteconfig6"), ("kreadconfig5", "kwriteconfig5")]
            .into_iter()
            .find(|(_, w)| Command::new(w).arg("--help").output().is_ok_and(|o| o.status.success()))
    }

    fn kde_read(tool: &str, key: &str) -> Result<String, String> {
        run(tool, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key])
    }

    /// Пустое значение — ключа не было: при откате его удаляем, а не пишем пустую строку.
    fn kde_write(tool: &str, key: &str, value: &str) -> Result<(), String> {
        let mut args = vec!["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key];
        if value.is_empty() {
            args.push("--delete");
        } else {
            args.push(value);
        }
        run(tool, &args).map(drop)
    }

    fn kde_notify() {
        // Без сигнала уже запущенные программы KDE не заметят изменения до перезапуска.
        let _ = run("dbus-send", &["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"]);
    }

    /// Строка GVariant `['a', 'b']` для `ignore-hosts`.
    pub fn gvariant_list(items: &[String]) -> String {
        let quoted: Vec<String> = items.iter().map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))).collect();
        format!("[{}]", quoted.join(", "))
    }

    /// Значения KDE для нашего прокси: адрес в формате `http://host port` (так пишет сама Plasma).
    pub fn kde_values(t: &Target, bypass: &[String]) -> Vec<(&'static str, String)> {
        let addr = |scheme: &str, a: &Option<(String, u16)>| a.as_ref().map(|(h, p)| format!("{scheme}://{h} {p}")).unwrap_or_default();
        vec![
            ("ProxyType", "1".into()),
            ("httpProxy", addr("http", &t.http)),
            ("httpsProxy", addr("http", &t.http)),
            ("socksProxy", addr("socks", &t.socks)),
            ("NoProxyFor", bypass.join(",")),
        ]
    }

    const UNSUPPORTED: &str = "no supported desktop found for the system proxy (GNOME via gsettings, KDE Plasma via kwriteconfig). \
        Use TUN (`cproxy run --tun`) or point programs at the proxy: export HTTP_PROXY=http://127.0.0.1:<port> HTTPS_PROXY=http://127.0.0.1:<port>";

    pub fn snapshot() -> Result<Value, String> {
        let mut snap = Map::new();
        snap.insert("os".into(), "linux".into());
        if has_gnome() {
            let mut g = Map::new();
            for (sub, key) in GNOME_KEYS {
                g.insert(format!("{sub}:{key}"), run("gsettings", &["get", &format!("{GNOME}{sub}"), key])?.into());
            }
            snap.insert("gnome".into(), g.into());
        }
        if let Some((read, _)) = kde_tools() {
            let mut k = Map::new();
            for key in KDE_KEYS {
                k.insert(key.into(), kde_read(read, key)?.into());
            }
            snap.insert("kde".into(), json!({"tool": read, "values": k}));
        }
        if !snap.contains_key("gnome") && !snap.contains_key("kde") {
            return Err(UNSUPPORTED.into());
        }
        Ok(snap.into())
    }

    pub fn apply(t: &Target, bypass: &[String], _warnings: &mut Vec<String>) -> Result<(), String> {
        let mut done = false;
        if has_gnome() {
            let set = |sub: &str, key: &str, v: &str| run("gsettings", &["set", &format!("{GNOME}{sub}"), key, v]).map(drop);
            // GNOME понимает CIDR и `*.domain` в ignore-hosts как есть.
            set("", "ignore-hosts", &gvariant_list(bypass))?;
            for (sub, a) in [(".http", &t.http), (".https", &t.http), (".socks", &t.socks)] {
                let (host, port) = a.as_ref().map(|(h, p)| (h.clone(), *p)).unwrap_or_default();
                set(sub, "host", &format!("'{host}'"))?;
                set(sub, "port", &port.to_string())?;
            }
            set("", "mode", "'manual'")?;
            done = true;
        }
        if let Some((_, write)) = kde_tools() {
            for (key, value) in kde_values(t, bypass) {
                kde_write(write, key, &value)?;
            }
            kde_notify();
            done = true;
        }
        if done { Ok(()) } else { Err(UNSUPPORTED.into()) }
    }

    pub fn restore(snap: &Value) -> Result<(), String> {
        if let Some(g) = snap["gnome"].as_object() {
            // mode последним: сначала вернуть адреса, потом включить прежний режим.
            let mut keys: Vec<(&String, &Value)> = g.iter().collect();
            keys.sort_by_key(|(k, _)| k.as_str() == ":mode");
            for (k, v) in keys {
                let (sub, key) = k.split_once(':').unwrap_or(("", k));
                run("gsettings", &["set", &format!("{GNOME}{sub}"), key, v.as_str().unwrap_or("")])?;
            }
        }
        if let Some(values) = snap["kde"]["values"].as_object() {
            let read = snap["kde"]["tool"].as_str().unwrap_or("kreadconfig5");
            let write = read.replace("kread", "kwrite");
            for (k, v) in values {
                kde_write(&write, k, v.as_str().unwrap_or(""))?;
            }
            kde_notify();
        }
        Ok(())
    }

    pub fn install_close_handler() {
        // Закрытие терминала шлёт SIGHUP — ловит ctrlc с feature `termination` (Cargo.toml).
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod os {
    use super::Target;
    use serde_json::Value;
    pub fn snapshot() -> Result<Value, String> {
        Err("system proxy is supported on Windows, macOS and Linux (GNOME, KDE) only".into())
    }
    pub fn apply(_: &Target, _: &[String], _: &mut Vec<String>) -> Result<(), String> {
        Err("system proxy is supported on Windows, macOS and Linux (GNOME, KDE) only".into())
    }
    pub fn restore(_: &Value) -> Result<(), String> {
        Ok(())
    }
    pub fn install_close_handler() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert_eq!(cidr_to_wildcards("192.168.0.0/16"), Some(vec!["192.168.*".to_string()]));
        assert_eq!(cidr_to_wildcards("10.0.0.0/8"), Some(vec!["10.*".to_string()]));
        let w = cidr_to_wildcards("172.16.0.0/12").unwrap();
        assert_eq!((w.len(), w[0].as_str(), w[15].as_str()), (16, "172.16.*", "172.31.*"));
        let w = cidr_to_wildcards("100.64.0.0/10").unwrap();
        assert_eq!((w.len(), w[63].as_str()), (64, "100.127.*"));
        assert_eq!(cidr_to_wildcards("1.2.3.4/32"), Some(vec!["1.2.3.4".to_string()]));
        assert_eq!(cidr_to_wildcards("192.0.2.0/24"), Some(vec!["192.0.2.*".to_string()]));
        assert_eq!(cidr_to_wildcards("0.0.0.0/0"), Some(vec![]));
        assert_eq!(cidr_to_wildcards("localhost"), None);
        assert_eq!(cidr_to_wildcards("fc00::/7"), None);
    }

    #[test]
    fn target_and_bypass() {
        let t = Target::from_inbounds(&[("mixed".into(), "0.0.0.0".into(), 7890)]).unwrap();
        assert_eq!(t.http, Some(("127.0.0.1".into(), 7890)));
        assert_eq!(describe(&t), "HTTP+SOCKS 127.0.0.1:7890");
        let t = Target::from_inbounds(&[("http".into(), "127.0.0.1".into(), 1), ("socks".into(), "127.0.0.1".into(), 2)]).unwrap();
        assert_eq!(describe(&t), "HTTP 127.0.0.1:1, SOCKS 127.0.0.1:2");
        let b = bypass_list(Some("192.168.0.0/16, localhost, *.local"));
        assert_eq!(b, ["192.168.0.0/16", "localhost", "*.local", "127.0.0.0/8"]);
    }

    #[test]
    fn env_proxies() {
        let t = Target::from_inbounds(&[("mixed".into(), "127.0.0.1".into(), 7890)]).unwrap();
        let v = |n: &str, x: &str| (n.to_string(), x.to_string());
        let vars = [
            v("HTTP_PROXY", "http://127.0.0.1:12334"),
            v("HTTPS_PROXY", "http://localhost:7890/"),
            v("ALL_PROXY", "socks5://u:p@127.0.0.1:7890"),
            v("http_proxy", "[::1]:7890"),
            v("https_proxy", "http://10.0.0.1:7890"),
            v("all_proxy", ""),
        ];
        assert_eq!(foreign_env_proxies(&t, &vars), [vars[0].clone(), vars[4].clone()]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_values() {
        let b = bypass_list(Some("*.local, it's"));
        assert_eq!(os::gvariant_list(&b), r"['*.local', 'it\'s', 'localhost', '127.0.0.0/8']");
        let t = Target::from_inbounds(&[("mixed".into(), "127.0.0.1".into(), 7890)]).unwrap();
        let kv = os::kde_values(&t, &b);
        assert_eq!(kv[0], ("ProxyType", "1".to_string()));
        assert_eq!(kv[1].1, "http://127.0.0.1 7890");
        assert_eq!(kv[3].1, "socks://127.0.0.1 7890");
        assert_eq!(kv[4].1, "*.local,it's,localhost,127.0.0.0/8");
    }
}
