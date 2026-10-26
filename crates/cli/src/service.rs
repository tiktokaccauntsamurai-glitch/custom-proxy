//! Служба systemd для режима сервера (этап 4, docs/SERVER-MODE.md, SERVER-GUIDE.md §9).
//!
//! `cproxy service install|uninstall|status` вызывает `main.rs::service_cmd`. Только Linux с systemd.
//! Установка (под root; без прав — sudo-перезапуск elevate.rs, он передаёт CPROXY_HOME пользователя):
//! - бинари cproxy, sing-box, xray → `LIB` (root, 0755): служебный пользователь не читает домашние каталоги;
//! - данные сервера (server.json, server-keys.json, settings.json и локальные файлы правил/подключения) из
//!   каталога пользователя → `HOME` (владелец `cproxy`, 0700; ключи 0600);
//! - системный пользователь `cproxy` без входа; unit `UNIT`: `run --server`, перезапуск при сбое,
//!   `AmbientCapabilities=CAP_NET_BIND_SERVICE` (порт 443 без root, наследуют дочерние sing-box/Xray),
//!   `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`.
//! Остановка: systemd шлёт SIGTERM cproxy → супервизор гасит ядра (их и так держит PDEATHSIG, §13).
//! Все шаги сначала собираются в план (`plan`), `--dry-run` только печатает его — так проверяется без systemd.

use std::path::{Path, PathBuf};

pub const HOME: &str = "/var/lib/cproxy";
pub const LIB: &str = "/usr/local/lib/cproxy";
pub const UNIT: &str = "/etc/systemd/system/cproxy.service";
pub const USER: &str = "cproxy";

/// Шаг установки: печатается в `--dry-run` и в лог, исполняется по порядку.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Команда (программа, аргументы).
    Run(String, Vec<String>),
    /// Копия файла с правами.
    Copy { from: PathBuf, to: PathBuf, mode: u32 },
    /// Запись текста в файл с правами.
    Write { to: PathBuf, text: String, mode: u32 },
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Step::Run(p, a) => write!(f, "{p} {}", a.join(" ")),
            Step::Copy { from, to, mode } => write!(f, "copy {} → {} ({mode:o})", from.display(), to.display()),
            Step::Write { to, mode, text } => write!(f, "write {} ({mode:o}, {} bytes)", to.display(), text.len()),
        }
    }
}

/// Путь на целевой системе (Linux): всегда через `/`, даже если план строится на Windows (тесты).
fn at(dir: &str, file: &str) -> PathBuf {
    PathBuf::from(format!("{dir}/{file}"))
}

fn run(p: &str, a: &[&str]) -> Step {
    Step::Run(p.into(), a.iter().map(|s| s.to_string()).collect())
}

/// Текст unit-файла. `debug` — полный лог в HOME/logs (решение пользователя: сначала debug).
pub fn unit_text(debug: bool) -> String {
    format!(
        "# Создано `cproxy service install`. Удаление: sudo {LIB}/cproxy service uninstall
[Unit]
Description=cproxy home gateway (VLESS REALITY for Shadowrocket)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
Environment=CPROXY_HOME={HOME}
ExecStart={LIB}/cproxy run --server{}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={HOME}
UMask=0077

[Install]
WantedBy=multi-user.target
",
        if debug { " --debug" } else { " --no-debug" }
    )
}

/// Что взять из каталога пользователя: settings.json переписывается — локальные пути правил/подключения
/// заменяются копиями в HOME (служба не видит /home). URL подписки остаётся URL.
pub struct Sources {
    pub data: PathBuf,
    pub cproxy: PathBuf,
    pub sing_box: PathBuf,
    pub xray: Option<PathBuf>,
}

pub fn plan(src: &Sources, debug: bool, user_exists: bool) -> Result<Vec<Step>, String> {
    for f in ["server.json", "server-keys.json"] {
        if !src.data.join(f).is_file() {
            return Err(format!("{} not found: run `cproxy server init` and `cproxy server user add` first", src.data.join(f).display()));
        }
    }
    let mut steps = Vec::new();
    if !user_exists {
        steps.push(run("useradd", &["--system", "--home-dir", HOME, "--no-create-home", "--shell", "/usr/sbin/nologin", USER]));
    }
    steps.push(run("install", &["-d", "-m", "0755", LIB]));
    steps.push(run("install", &["-d", "-m", "0700", HOME]));
    steps.push(Step::Copy { from: src.cproxy.clone(), to: at(LIB, "cproxy"), mode: 0o755 });
    steps.push(Step::Copy { from: src.sing_box.clone(), to: at(LIB, "sing-box"), mode: 0o755 });
    if let Some(x) = &src.xray {
        steps.push(Step::Copy { from: x.clone(), to: at(LIB, "xray"), mode: 0o755 });
    }
    steps.push(Step::Copy { from: src.data.join("server.json"), to: at(HOME, "server.json"), mode: 0o600 });
    steps.push(Step::Copy { from: src.data.join("server-keys.json"), to: at(HOME, "server-keys.json"), mode: 0o600 });

    // settings.json: только то, что нужно серверу (подключение для выхода vps, правила — если узлы в [Proxy]).
    let settings: serde_json::Value = std::fs::read_to_string(src.data.join("settings.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut out = serde_json::json!({"nodes": settings["nodes"].as_str().unwrap_or("auto"), "system_proxy": false, "tun": false, "debug": debug});
    for (key, name) in [("connection", "connection"), ("rules", "rules")] {
        let Some(v) = settings[key].as_str().filter(|s| !s.is_empty()) else { continue };
        if crate::settings::is_url(v) {
            out[key] = v.into();
        } else {
            let from = PathBuf::from(v);
            let ext = from.extension().and_then(|e| e.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
            let to = at(HOME, &format!("{name}{ext}"));
            steps.push(Step::Copy { from, to: to.clone(), mode: 0o600 });
            out[key] = to.to_string_lossy().into_owned().into();
        }
    }
    steps.push(Step::Write { to: at(HOME, "settings.json"), text: serde_json::to_string_pretty(&out).unwrap(), mode: 0o600 });
    steps.push(run("chown", &["-R", &format!("{USER}:{USER}"), HOME]));
    steps.push(Step::Write { to: PathBuf::from(UNIT), text: unit_text(debug), mode: 0o644 });
    steps.push(run("systemctl", &["daemon-reload"]));
    steps.push(run("systemctl", &["enable", "--now", "cproxy.service"]));
    Ok(steps)
}

pub fn uninstall_plan(purge: bool) -> Vec<Step> {
    let mut s = vec![run("systemctl", &["disable", "--now", "cproxy.service"]), run("rm", &["-f", UNIT]), run("systemctl", &["daemon-reload"])];
    s.push(run("rm", &["-rf", LIB]));
    if purge {
        // Ключи сервера удаляются только по явному --purge: без них телефоны придётся настраивать заново.
        s.push(run("rm", &["-rf", HOME]));
        s.push(run("userdel", &[USER]));
    }
    s
}

#[cfg(unix)]
pub fn execute(steps: &[Step]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    for (i, st) in steps.iter().enumerate() {
        log::info!(target: "service", "[{}/{}] {st}", i + 1, steps.len());
        match st {
            Step::Run(p, a) => {
                let status = std::process::Command::new(p).args(a).status().map_err(|e| format!("{p}: {e}"))?;
                if !status.success() {
                    return Err(format!("`{st}` failed: {status}"));
                }
            }
            Step::Copy { from, to, mode } => {
                // Через временный файл: работающий бинарь (Text file busy) заменяется rename-ом.
                let tmp = to.with_extension("new");
                std::fs::copy(from, &tmp).map_err(|e| format!("copy {} → {}: {e}", from.display(), tmp.display()))?;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(*mode)).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))?;
            }
            Step::Write { to, text, mode } => {
                std::fs::write(to, text).map_err(|e| format!("{}: {e}", to.display()))?;
                std::fs::set_permissions(to, std::fs::Permissions::from_mode(*mode)).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn execute(_: &[Step]) -> Result<(), String> {
    Err("systemd service: Linux only".into())
}

/// Linux с запущенным systemd (`/run/systemd/system` — признак из sd_booted(3)).
pub fn has_systemd() -> bool {
    cfg!(target_os = "linux") && Path::new("/run/systemd/system").is_dir()
}

pub fn user_exists() -> bool {
    std::process::Command::new("id").arg(USER).output().is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_and_plan() {
        let u = unit_text(true);
        assert!(u.contains("ExecStart=/usr/local/lib/cproxy/cproxy run --server --debug"));
        assert!(u.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE") && u.contains("User=cproxy") && u.contains("Environment=CPROXY_HOME=/var/lib/cproxy"));
        assert!(unit_text(false).contains("run --server --no-debug"));

        let dir = std::env::temp_dir().join(format!("cproxy-svc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = Sources { data: dir.clone(), cproxy: "/x/cproxy".into(), sing_box: "/x/sing-box".into(), xray: None };
        assert!(plan(&src, true, true).is_err(), "no server.json yet");
        std::fs::write(dir.join("server.json"), "{}").unwrap();
        std::fs::write(dir.join("server-keys.json"), "{}").unwrap();
        let conn = dir.join("nodes.json");
        std::fs::write(dir.join("settings.json"), serde_json::json!({"connection": conn, "rules": "https://example.com/r.conf", "tun": true}).to_string()).unwrap();
        let steps = plan(&src, true, false).unwrap();
        assert!(matches!(&steps[0], Step::Run(p, a) if p == "useradd" && a.contains(&"cproxy".to_string())));
        let settings = steps.iter().find_map(|s| match s {
            Step::Write { to, text, .. } if to.ends_with("settings.json") => Some(text.clone()),
            _ => None,
        }).unwrap();
        let v: serde_json::Value = serde_json::from_str(&settings).unwrap();
        // Локальный файл подключения → копия в /var/lib/cproxy; URL остаётся; TUN и системный прокси выключены.
        assert_eq!(v["connection"], "/var/lib/cproxy/connection.json");
        assert_eq!(v["rules"], "https://example.com/r.conf");
        assert_eq!((v["tun"].as_bool(), v["system_proxy"].as_bool()), (Some(false), Some(false)));
        assert!(steps.iter().any(|s| matches!(s, Step::Copy { to, mode: 0o600, .. } if to.ends_with("server-keys.json"))));
        assert!(matches!(steps.last().unwrap(), Step::Run(p, a) if p == "systemctl" && a[0] == "enable"));
        assert!(!uninstall_plan(false).iter().any(|s| s.to_string().contains(HOME)), "keys kept without --purge");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
