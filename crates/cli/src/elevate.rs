//! Права администратора для TUN (ARCHITECTURE.md §14).
//!
//! - Windows: wintun-адаптер создаёт только администратор. Без прав `run --tun` перезапускает cproxy
//!   через `ShellExecuteW("runas")` — UAC-запрос, новое окно с теми же аргументами (настройки те же:
//!   тот же пользователь, тот же %APPDATA%; переменные окружения вроде CPROXY_HOME не передаются).
//! - Linux/macOS: нужен root. Без него cproxy перезапускается в том же терминале через
//!   `sudo env CPROXY_HOME=<данные пользователя> CPROXY_OWNER=<uid>:<gid> cproxy <аргументы>` и ждёт.
//!   CPROXY_HOME — чтобы root взял настройки пользователя, а не /root; CPROXY_OWNER — чтобы в конце
//!   вернуть пользователю файлы, созданные root в его папке (`restore_owner`, main.rs::real_main).
//!   `cproxy stop` от пользователя шлёт сигнал через sudo (supervisor os::request_stop).
//! Вызывается из `main.rs::run`.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
        fn ShellExecuteW(hwnd: *mut c_void, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub fn is_admin() -> bool {
        // SAFETY: без аргументов.
        unsafe { IsUserAnAdmin() != 0 }
    }

    /// Аргумент для командной строки Windows (кавычки, если есть пробелы или кавычки).
    fn quote(a: &str) -> String {
        if !a.is_empty() && !a.contains([' ', '\t', '"']) {
            return a.to_string();
        }
        format!("\"{}\"", a.replace('"', "\\\""))
    }

    pub fn relaunch_elevated(args: &[String]) -> Result<std::process::ExitCode, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        let params = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
        log::debug!(target: "elevate", "ShellExecuteW runas {} {params}", exe.display());
        let (op, file, par, dir) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&params), wide(&cwd.to_string_lossy()));
        // SAFETY: все строки с нулём на конце; SW_SHOWNORMAL = 1.
        let rc = unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), file.as_ptr(), par.as_ptr(), dir.as_ptr(), 1) };
        // > 32 — успех; 5 (ERROR_ACCESS_DENIED) / 1223 — пользователь отказал в UAC.
        if rc > 32 { Ok(std::process::ExitCode::SUCCESS) } else { Err(format!("elevation was cancelled or failed (code {rc})")) }
    }

    pub fn restore_owner() {}
}

#[cfg(unix)]
mod imp {
    use std::process::{Command, ExitCode};

    fn id(flag: &str) -> Option<String> {
        let out = Command::new("id").arg(flag).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !s.is_empty()).then_some(s)
    }

    pub fn is_admin() -> bool {
        id("-u").as_deref() == Some("0")
    }

    pub fn relaunch_elevated(args: &[String]) -> Result<ExitCode, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let home = crate::store::data_dir();
        let owner = format!("{}:{}", id("-u").ok_or("id -u failed")?, id("-g").ok_or("id -g failed")?);
        log::debug!(target: "elevate", "sudo env CPROXY_HOME={} CPROXY_OWNER={owner} {} (args redacted)", home.display(), exe.display());
        println!("root is needed ({}): asking for the sudo password...", args.first().map_or("", String::as_str));
        let mut cmd = Command::new("sudo");
        cmd.arg("env").arg(format!("CPROXY_HOME={}", home.display())).arg(format!("CPROXY_OWNER={owner}")).arg(&exe).args(args);
        // Ctrl+C получают оба процесса (одна группа в терминале). Этот только ждёт: игнорирует сигнал,
        // а экземпляр под root штатно останавливается и возвращает системный прокси.
        let _ = ctrlc::set_handler(|| {});
        let status = cmd.status().map_err(|e| format!("sudo: {e}"))?;
        log::debug!(target: "elevate", "elevated cproxy finished: {status}");
        Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
    }

    /// Под root с `CPROXY_OWNER` (наш sudo-перезапуск): вернуть пользователю его папку данных —
    /// логи, run.json, кэш, созданные root. Иначе следующий обычный запуск не сможет в них писать.
    pub fn restore_owner() {
        let Ok(owner) = std::env::var("CPROXY_OWNER") else { return };
        if !is_admin() {
            return;
        }
        let dir = crate::store::data_dir();
        let ok = Command::new("chown").arg("-R").arg(&owner).arg(&dir).status().is_ok_and(|s| s.success());
        log::debug!(target: "elevate", "chown -R {owner} {}: {}", dir.display(), if ok { "ok" } else { "failed" });
    }
}

pub use imp::*;
