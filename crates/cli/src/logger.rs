//! Логгер cproxy (реализация фасада `log`): один файл на запуск + консоль.
//!
//! Пишут в него все крейты через `log::*!` (targets: `cli`, `fetch`, `conf`, `gen::*`) и
//! `main.rs::pump_sing_box_log` — строки sing-box с target `sing-box` (ARCHITECTURE.md §10).
//! Файл: `<data>/logs/cproxy-YYYYMMDD-HHMMSS-<cmd>.log`, хранятся последние `KEEP` файлов. Файл больше
//! `MAX_FILE` — продолжение в новом файле (сервер с trace работает неделями: KEEP × MAX_FILE — потолок на диске).
//! По умолчанию логи выключены (приватность); trace включают `--debug` или `set debug on` (main.rs::file_level).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Log, Metadata, Record};

const KEEP: usize = 20;
const MAX_FILE: u64 = 32 << 20;

struct Sink {
    file: File,
    written: u64,
    dir: PathBuf,
    cmd: String,
}

impl Sink {
    fn write(&mut self, line: &str) {
        if self.written >= MAX_FILE {
            if let Some((f, _)) = create(&self.dir, &self.cmd) {
                let _ = self.file.flush();
                self.file = f;
                self.written = 0;
            }
        }
        if self.file.write_all(line.as_bytes()).is_ok() {
            self.written += line.len() as u64;
        }
    }
}

/// Новый файл лога (старые сверх `KEEP` удаляются).
fn create(dir: &Path, cmd: &str) -> Option<(File, PathBuf)> {
    rotate(dir);
    let stamp: String = utc(SystemTime::now()).chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    let mut p = dir.join(format!("cproxy-{}-{}-{cmd}.log", &stamp[..8], &stamp[8..]));
    // Продолжение в ту же секунду — не затирать только что закрытый файл.
    let mut n = 2;
    while p.exists() {
        p = dir.join(format!("cproxy-{}-{}-{cmd}-{n}.log", &stamp[..8], &stamp[8..]));
        n += 1;
    }
    match File::create(&p) {
        Ok(f) => Some((f, p)),
        Err(e) => {
            eprintln!("warning: cannot create log file {}: {e}", p.display());
            None
        }
    }
}

struct Logger {
    file: Option<Mutex<Sink>>,
    file_level: LevelFilter,
    console_level: LevelFilter,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= self.file_level || m.level() <= self.console_level
    }

    fn log(&self, r: &Record) {
        let (level, target) = (r.level(), r.target());
        if let Some(file) = &self.file {
            if level <= self.file_level {
                let line = format!("{} {:<5} [{target}] {}\n", utc(SystemTime::now()), level, r.args());
                if let Ok(mut f) = file.lock() {
                    f.write(&line);
                }
            }
        }
        // В консоль строки sing-box — только warn+ (иначе на каждое соединение по строке), если не -v.
        let console = if target == "sing-box" && self.console_level < LevelFilter::Debug { Level::Warn } else { level };
        if level <= self.console_level && level <= console {
            match level {
                Level::Error => eprintln!("error: {}", r.args()),
                Level::Warn => eprintln!("warning: {}", r.args()),
                Level::Info => eprintln!("{}", r.args()),
                _ => eprintln!("{level:<5} [{target}] {}", r.args()),
            }
        }
    }

    fn flush(&self) {
        if let Some(Ok(mut f)) = self.file.as_ref().map(Mutex::lock) {
            let _ = f.file.flush();
        }
    }
}

/// Инициализирует логгер. `file_level = Off` — файл не создаётся. Возвращает путь к файлу.
pub fn init(dir: &Path, cmd: &str, file_level: LevelFilter, console_level: LevelFilter) -> Option<PathBuf> {
    let mut path = None;
    let mut file = None;
    if file_level != LevelFilter::Off && std::fs::create_dir_all(dir).is_ok() {
        if let Some((f, p)) = create(dir, cmd) {
            file = Some(Mutex::new(Sink { file: f, written: 0, dir: dir.to_path_buf(), cmd: cmd.to_string() }));
            path = Some(p);
        }
    }
    let max = file_level.max(console_level);
    let _ = log::set_boxed_logger(Box::new(Logger { file, file_level, console_level }));
    log::set_max_level(max);
    // Паника тоже должна оказаться в логе, а не только в консоли.
    std::panic::set_hook(Box::new(|info| {
        log::error!(target: "cli", "panic: {info}");
        log::logger().flush();
    }));
    path
}

/// Оставляет `KEEP - 1` самых новых логов (имена сортируются по времени).
fn rotate(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut logs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("cproxy-") && n.ends_with(".log")))
        .collect();
    logs.sort();
    let excess = logs.len().saturating_sub(KEEP - 1);
    for p in &logs[..excess] {
        let _ = std::fs::remove_file(p);
    }
}

/// `2026-10-10T12:34:56.789Z` без внешних зависимостей (алгоритм days→civil Х. Хиннанта).
pub fn utc(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let sod = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::utc;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn utc_format() {
        assert_eq!(utc(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // 2026-10-10T12:34:56.789Z
        assert_eq!(utc(UNIX_EPOCH + Duration::from_millis(1_791_635_696_789)), "2026-10-10T12:34:56.789Z");
        assert_eq!(utc(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00.000Z");
    }
}
