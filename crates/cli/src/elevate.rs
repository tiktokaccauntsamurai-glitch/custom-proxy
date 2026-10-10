//! Права администратора для TUN (ARCHITECTURE.md §14).
//!
//! - Windows: wintun-адаптер создаёт только администратор. Без прав `run --tun` перезапускает cproxy
//!   через `ShellExecuteW("runas")` — UAC-запрос, новое окно с теми же аргументами (настройки те же:
//!   тот же пользователь, тот же %APPDATA%; переменные окружения вроде CPROXY_HOME не передаются).
//! - macOS: нужен root (`sudo cproxy run --tun`), сами не повышаем.
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

    pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        let params = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
        log::debug!(target: "elevate", "ShellExecuteW runas {} {params}", exe.display());
        let (op, file, par, dir) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&params), wide(&cwd.to_string_lossy()));
        // SAFETY: все строки с нулём на конце; SW_SHOWNORMAL = 1.
        let rc = unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), file.as_ptr(), par.as_ptr(), dir.as_ptr(), 1) };
        // > 32 — успех; 5 (ERROR_ACCESS_DENIED) / 1223 — пользователь отказал в UAC.
        if rc > 32 { Ok(()) } else { Err(format!("elevation was cancelled or failed (code {rc})")) }
    }
}

#[cfg(unix)]
mod imp {
    pub fn is_admin() -> bool {
        std::process::Command::new("id").arg("-u").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    }

    pub fn relaunch_elevated(_args: &[String]) -> Result<(), String> {
        Err("TUN needs root: run `sudo cproxy run --tun`".into())
    }
}

pub use imp::*;
