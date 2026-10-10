//! Супервизор ядер (sing-box, Xray): запуск, наблюдение, перезапуск, остановка, единственный экземпляр.
//!
//! - `os::kill_children_on_exit` — Windows Job Object KILL_ON_JOB_CLOSE: ядра гибнут вместе с cproxy
//!   даже при его убийстве. На Unix — осиротевшие ядра добивает следующий запуск ([`kill_stale`]).
//! - [`Supervisor`] — цикл наблюдения (200 мс): упавшее ядро перезапускается тем же способом
//!   (`Service::spawn`, конфиг снова в stdin), не чаще [`MAX_RESTARTS`] за [`RESTART_WINDOW`] и только если
//!   оно успело проработать [`MIN_UPTIME`] (иначе — плохой конфиг, крутить бессмысленно → ошибка).
//! - [`RunState`] — `<data>/run.json`: PID и адреса запущенного экземпляра (`cproxy status`/`stop`,
//!   запрет второго экземпляра).
//! - Остановка: Ctrl+C (ядра получают его сами, общая консоль), `cproxy stop` (`os::request_stop`).
//! Кто вызывает: `cli/src/main.rs::run` (spawn-замыкания с логированием и stdin-конфигом — там).
//! Схема: docs/ARCHITECTURE.md §13.

pub mod os;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub const MIN_UPTIME: Duration = Duration::from_secs(5);
pub const MAX_RESTARTS: usize = 5;
pub const RESTART_WINDOW: Duration = Duration::from_secs(600);
const TICK: Duration = Duration::from_millis(200);

pub type Spawned = (Child, Vec<JoinHandle<()>>);
pub type SpawnFn = Box<dyn FnMut() -> Result<Spawned, String>>;

/// Одно ядро под наблюдением.
pub struct Service {
    pub name: &'static str,
    spawn: SpawnFn,
    proc: Option<Spawned>,
    started: Instant,
    restarts: VecDeque<Instant>,
    min_uptime: Duration,
}

impl Service {
    pub fn new(name: &'static str, spawn: SpawnFn) -> Self {
        Service { name, spawn, proc: None, started: Instant::now(), restarts: VecDeque::new(), min_uptime: MIN_UPTIME }
    }

    /// Сколько ядро должно проработать, чтобы его падение считалось сбоем, а не ошибкой конфига.
    pub fn min_uptime(mut self, d: Duration) -> Self {
        self.min_uptime = d;
        self
    }

    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|(c, _)| c.id())
    }

    fn start(&mut self) -> Result<(), String> {
        let (mut child, pumps) = (self.spawn)()?;
        log::debug!(target: "supervisor", "{} started, pid {}", self.name, child.id());
        // Ранний выход = ошибка конфига/порта: проверяем коротко после старта.
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(Some(status)) = child.try_wait() {
            join(pumps);
            return Err(format!("{} exited at startup: {status} (see log above)", self.name));
        }
        self.started = Instant::now();
        self.proc = Some((child, pumps));
        Ok(())
    }

    fn stop(&mut self) {
        if let Some((mut child, pumps)) = self.proc.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let status = child.wait();
            join(pumps);
            log::debug!(target: "supervisor", "{} stopped ({status:?})", self.name);
        }
    }
}

fn join(pumps: Vec<JoinHandle<()>>) {
    for t in pumps {
        let _ = t.join();
    }
}

/// Чем закончилась работа.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// Остановка по запросу (Ctrl+C, `cproxy stop`).
    Stopped,
    /// Ядро не удалось удержать (падает сразу или слишком часто).
    Failed(String),
}

pub struct Supervisor {
    services: Vec<Service>,
    stop: Option<os::StopSignal>,
}

impl Supervisor {
    /// Запускает службы по порядку (Xray раньше sing-box: sing-box ходит в его порты).
    /// Ошибка любой — остальные останавливаются.
    pub fn start(mut services: Vec<Service>) -> Result<Self, String> {
        for i in 0..services.len() {
            if let Err(e) = services[i].start() {
                for s in services[..i].iter_mut() {
                    s.stop();
                }
                return Err(e);
            }
        }
        Ok(Supervisor { services, stop: os::StopSignal::listen() })
    }

    pub fn pid(&self, name: &str) -> Option<u32> {
        self.services.iter().find(|s| s.name == name).and_then(Service::pid)
    }

    /// Жив ли сервис сейчас (для ожидания готовности порта).
    pub fn running(&mut self, name: &str) -> bool {
        self.services.iter_mut().find(|s| s.name == name).and_then(|s| s.proc.as_mut()).is_some_and(|(c, _)| matches!(c.try_wait(), Ok(None)))
    }

    /// Запрошена ли остановка через `cproxy stop` (Windows; на Unix он приходит как SIGTERM → ctrlc).
    pub fn stop_requested(&self) -> bool {
        self.stop.as_ref().is_some_and(os::StopSignal::is_set)
    }

    /// Цикл наблюдения до остановки. `stopping` — внешний флаг (Ctrl+C). Перед выходом всё останавливается.
    pub fn wait(&mut self, stopping: impl Fn() -> bool) -> Exit {
        let exit = loop {
            if stopping() || self.stop_requested() {
                log::info!(target: "supervisor", "stop requested");
                break Exit::Stopped;
            }
            if let Some(failure) = self.check(&stopping) {
                break failure;
            }
            std::thread::sleep(TICK);
        };
        self.shutdown();
        exit
    }

    /// Проверяет службы; упавшую перезапускает. `Some` — сдаёмся.
    fn check(&mut self, stopping: &impl Fn() -> bool) -> Option<Exit> {
        for s in self.services.iter_mut() {
            let Some((child, _)) = s.proc.as_mut() else { continue };
            let Ok(Some(status)) = child.try_wait() else { continue };
            let (_, pumps) = s.proc.take().unwrap();
            join(pumps);
            // Ctrl+C ядро получает одновременно с нами — дать флагу выставиться.
            std::thread::sleep(Duration::from_millis(300));
            if stopping() || self.stop.as_ref().is_some_and(os::StopSignal::is_set) {
                return Some(Exit::Stopped);
            }
            let uptime = s.started.elapsed();
            let now = Instant::now();
            while s.restarts.front().is_some_and(|t| now.duration_since(*t) > RESTART_WINDOW) {
                s.restarts.pop_front();
            }
            if uptime < s.min_uptime || s.restarts.len() >= MAX_RESTARTS {
                return Some(Exit::Failed(format!(
                    "{} exited ({status}) after {uptime:?}; {} restart(s) in the last {}s — giving up",
                    s.name,
                    s.restarts.len(),
                    RESTART_WINDOW.as_secs()
                )));
            }
            log::warn!(target: "supervisor", "{} exited unexpectedly ({status}) after {uptime:?}; restarting", s.name);
            s.restarts.push_back(now);
            std::thread::sleep(Duration::from_secs(1));
            if let Err(e) = s.start() {
                return Some(Exit::Failed(e));
            }
        }
        None
    }

    /// Останавливает всё в обратном порядке (sing-box раньше Xray).
    pub fn shutdown(&mut self) {
        for s in self.services.iter_mut().rev() {
            s.stop();
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `<data>/run.json` — запущенный экземпляр.
#[derive(Debug, Clone, PartialEq)]
pub struct RunState {
    pub pid: u32,
    pub started_unix: u64,
    pub listeners: Vec<String>,
    pub cores: Vec<(String, u32)>,
    pub log: Option<String>,
}

impl RunState {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("run.json")
    }

    pub fn now_unix() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let cores: Value = self.cores.iter().map(|(n, p)| json!({"name": n, "pid": p})).collect();
        let v = json!({"pid": self.pid, "started_unix": self.started_unix, "listeners": self.listeners, "cores": cores, "log": self.log});
        std::fs::write(Self::path(dir), serde_json::to_string_pretty(&v).unwrap()).map_err(|e| format!("run.json: {e}"))
    }

    pub fn load(dir: &Path) -> Option<Self> {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(Self::path(dir)).ok()?).ok()?;
        Some(RunState {
            pid: v["pid"].as_u64()? as u32,
            started_unix: v["started_unix"].as_u64().unwrap_or(0),
            listeners: v["listeners"].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect(),
            cores: v["cores"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| Some((c["name"].as_str()?.to_string(), c["pid"].as_u64()? as u32)))
                .collect(),
            log: v["log"].as_str().map(String::from),
        })
    }

    pub fn remove(dir: &Path) {
        let _ = std::fs::remove_file(Self::path(dir));
    }

    /// Жив ли записанный экземпляр cproxy (PID жив и это действительно cproxy).
    pub fn is_running(&self) -> bool {
        self.pid != std::process::id() && os::alive(self.pid) && os::name(self.pid).is_some_and(|n| n.starts_with("cproxy"))
    }
}

/// Прошлый экземпляр убит, а его ядра остались (Unix; на Windows их убирает Job Object) → добить.
/// Убиваем только процессы с ожидаемым именем: PID мог достаться чужой программе.
pub fn kill_stale(state: &RunState) {
    for (name, pid) in &state.cores {
        if os::alive(*pid) && os::name(*pid).is_some_and(|n| n.starts_with(name.as_str())) {
            let ok = os::kill(*pid);
            log::warn!(target: "supervisor", "stale {name} (pid {pid}) from a previous run: killed={ok}");
        }
    }
}

#[cfg(test)]
mod tests;
