//! Каталог данных и кэш скачанных RULE-SET / GEOIP.
//!
//! `Cache` реализует `singbox_gen::Resources`: текст .list → inline rule-set, путь к .srs →
//! `rule_set[type=local]`, который sing-box читает сам (ARCHITECTURE.md §1, точка соприкосновения 3).
//! `http_get` — общая загрузка (кэш правил и подписка узлов; подписка остаётся в памяти).
//! `find_bin` — поиск sing-box и Xray.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CPROXY_HOME") {
        return d.into();
    }
    let home = || std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| ".".into());
    if cfg!(windows) {
        std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| home()).join("cproxy")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/cproxy")
    } else {
        std::env::var("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|_| home().join(".local/share")).join("cproxy")
    }
}

/// Стабильное имя файла кэша по URL (FNV-1a 64).
fn key(url: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in url.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn open() -> std::io::Result<Self> {
        let dir = data_dir().join("cache");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn file(&self, url: &str) -> PathBuf {
        self.dir.join(key(url))
    }

    pub fn has(&self, url: &str) -> bool {
        self.file(url).exists()
    }

    /// Скачивает URL в кэш; `via` — HTTP-прокси (например, уже запущенный cproxy).
    pub fn download(&self, url: &str, via: Option<&str>) -> Result<u64, String> {
        let body = http_get(url, url, via)?;
        let path = self.file(url);
        let tmp = path.with_extension("part");
        std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        log::debug!(target: "fetch", "{url} → {}", path.display());
        Ok(body.len() as u64)
    }
}

/// GET в память. `shown` — URL для лога (у подписки токен скрыт: settings::redact_source).
pub fn http_get(url: &str, shown: &str, via: Option<&str>) -> Result<Vec<u8>, String> {
    let started = std::time::Instant::now();
    log::debug!(target: "fetch", "GET {shown} via {}", via.unwrap_or("direct"));
    let mut cfg = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(60)));
    if let Some(via) = via {
        cfg = cfg.proxy(Some(ureq::Proxy::new(via).map_err(|e| format!("--via: {e}"))?));
    }
    let agent: ureq::Agent = cfg.build().into();
    let mut resp = agent.get(url).call().map_err(|e| {
        log::debug!(target: "fetch", "GET {shown} failed after {:?}: {e}", started.elapsed());
        e.to_string().replace(url, shown)
    })?;
    let status = resp.status();
    let body = resp.body_mut().with_config().limit(64 << 20).read_to_vec().map_err(|e| e.to_string())?;
    log::debug!(target: "fetch", "GET {shown} → {status}, {} bytes in {:?}", body.len(), started.elapsed());
    Ok(body)
}

impl singbox_gen::Resources for Cache {
    fn text(&self, url: &str) -> Option<String> {
        let r = std::fs::read(self.file(url)).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
        log::trace!(target: "fetch", "cache {} {url}", if r.is_some() { "hit" } else { "MISS" });
        r
    }

    fn path(&self, url: &str) -> Option<String> {
        let p = self.file(url);
        log::trace!(target: "fetch", "cache {} {url} ({})", if p.exists() { "hit" } else { "MISS" }, p.display());
        p.exists().then(|| p.to_string_lossy().into_owned())
    }
}

/// Ищет бинарь (`sing-box`, `xray`): флаг → env → рядом с cproxy → <repo>/bin → ./bin → PATH.
pub fn find_bin(name: &str, flag: Option<&str>, env: &str) -> Option<PathBuf> {
    if let Some(p) = flag.map(PathBuf::from).or_else(|| std::env::var_os(env).map(PathBuf::from)) {
        return Some(p);
    }
    let exe = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().as_deref().and_then(Path::parent) {
        candidates.push(dir.join(&exe));
        // target/{debug,release}/cproxy → <repo>/bin
        candidates.extend(dir.ancestors().nth(2).map(|r| r.join("bin").join(&exe)));
    }
    candidates.push(PathBuf::from("bin").join(&exe));
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|d| d.join(&exe)));
    }
    let found = candidates.iter().find(|p| p.is_file()).cloned();
    log::trace!(target: "cli", "{name}: {} candidates, found {found:?}", candidates.len());
    found
}
