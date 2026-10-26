//! Бинарь `cproxy`: разбор аргументов и команды (docs/ARCHITECTURE.md §1, §7, §11).
//! check/gen — только генерация; fetch — сеть (store::Cache); run — ещё и процессы sing-box и Xray.
//! Два конфига (settings.rs): правила (`.conf` Shadowrocket) и подключение (узлы, fmt-nodes).
//! Без аргументов — запуск по сохранённым настройкам; файл, перетащенный на exe, сохраняется в нужное поле.
//! Нет правил/подключения или сохранённый файл не найден — пути спрашиваются в консоли (ask_configs), без команд.
//! `run` включает системный прокси ОС и при выходе возвращает прежний (sysproxy.rs, ARCHITECTURE.md §12).
//! Ядра запускает и перезапускает крейт `supervisor` (Job Object, run.json, `stop`/`status`, §13).
//! TUN (`--tun` / `set tun on`): весь трафик системы; без прав администратора — UAC-перезапуск (elevate.rs, §14).
//! Режим сервера (`server ...`, `run --server`, server.rs): домашний шлюз для Shadowrocket — вход VLESS REALITY,
//! выход по пользователю (домашний IP / VPS / домашняя сеть), docs/SERVER-MODE.md.
//! Логирование (logger.rs, ARCHITECTURE.md §10): всё действие cproxy + журналы sing-box и Xray в одном
//! файле, строки `match[i]` sing-box дополняются исходной строкой .conf.

mod clash;
mod elevate;
mod killswitch;
mod logger;
mod server;
mod service;
mod settings;
mod store;
mod sysproxy;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use core_model::Node;
use log::{Level, LevelFilter};
use settings::{NodesMode, Settings};
use singbox_gen::server::Exit as SrvExit;
use store::Cache;
use supervisor::{Exit, RunState, Service, Supervisor};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
cproxy — приватный прокси с правилами Shadowrocket (движки: sing-box, Xray для xhttp)

Два конфига: ПРАВИЛА (.conf Shadowrocket) и ПОДКЛЮЧЕНИЕ (узлы; файл или URL подписки:
ссылки vless:// vmess:// trojan:// ss:// hy2:// tuic:// socks:// anytls:// wg://, base64,
Clash YAML, sing-box JSON, Xray JSON, [Proxy] из .conf). Пути сохраняются, запуск без
аргументов подключается автоматически. Файл, перетащенный на cproxy.exe, сохраняется сам.

usage:
  cproxy                                  запустить с сохранёнными настройками
  cproxy set rules <file.conf>            сохранить путь к правилам (none — убрать)
  cproxy set connection <file|URL>        сохранить источник узлов (none — убрать)
  cproxy set nodes auto|connection|rules|both
                                          чьи узлы использовать (auto: connection,
                                          если задан, иначе [Proxy] из правил)
  cproxy set system-proxy on|off          включать ли системный прокси при запуске (по умолчанию on)
  cproxy set tun on|off                   режим TUN: ВЕСЬ трафик системы через правила (админ/UAC)
  cproxy set debug on|off                 полный лог (trace) в <data>/logs при каждом запуске
  cproxy set kill-switch on|off           пока cproxy запущен, в интернет ходят только ядра: упало ядро —
                                          трафик не уходит напрямую (админ/root; по умолчанию off)
  cproxy killswitch status|off            состояние / снять защиту, если cproxy убит
  cproxy status                           настройки и запущенный экземпляр
  cproxy stop                             остановить запущенный cproxy (вернёт системный прокси)
  cproxy sysproxy status|off              системный прокси сейчас / вернуть прежний (если завис)
  cproxy groups                           группы запущенного cproxy: тип, текущий узел
  cproxy select GROUP [NODE]              выбрать узел в группе select (запоминается);
                                          без NODE — список узлов группы
  cproxy test [GROUP]                     задержки узлов группы (по умолчанию PROXY)
  cproxy check [rules.conf] [opts]        проверить конфиги
  cproxy fetch [rules.conf] [--via URL] [--force]
                                          скачать RULE-SET / DOMAIN-SET / GEOIP
  cproxy gen   [rules.conf] [-o FILE] [opts]
                                          напечатать конфиг sing-box (содержит секреты!)
  cproxy run   [rules.conf] [opts] [--via URL] [--sing-box PATH] [--xray PATH]
                                          запустить локальный HTTP+SOCKS5 прокси

режим сервера (домашний шлюз для Shadowrocket, docs/SERVER-MODE.md):
  cproxy server init [--host H] [--port N] [--mask SITE]
                                          ключи REALITY и адрес (по умолчанию порт 443,
                                          маска — самый быстрый проверенный сайт)
  cproxy server user add NAME [--exits ru,vps,lan]
                                          устройство: ru — домашний IP, vps — через узлы
                                          подключения, lan — только домашняя сеть
  cproxy server user list | user remove NAME
  cproxy server link NAME                 ссылки vless:// и QR-коды для Shadowrocket
  cproxy server show                      настройки сервера (без секретов)
  cproxy server check                     доступ снаружи: маска, внешний IP, адрес, порт
  cproxy server phone-conf NAME [rules.conf] [-o FILE] [--with-nodes]
                                          .conf для Shadowrocket: ваши правила, AUTO без
                                          Дом-RU/LAN (узлы — по QR; --with-nodes — в [Proxy])
  cproxy server status                    пользователи, соединения, трафик (Clash API)
  cproxy run --server                     запустить сервер (без системного прокси и TUN)
  sudo cproxy service install [--no-debug] [--dry-run]
                                          служба systemd (Linux): автозапуск, порт 443, пользователь cproxy
  sudo cproxy service uninstall [--purge] | cproxy service status

opts (без них берутся сохранённые настройки):
  --nodes FILE|URL   источник узлов на этот запуск
  --nodes-mode M     auto|connection|rules|both на этот запуск
  --system-proxy / --no-system-proxy   системный прокси на этот запуск
  --tun / --no-tun   режим TUN на этот запуск (при TUN системный прокси не включается)
  --kill-switch / --no-kill-switch   kill switch на этот запуск
  --port N       порт для программ (HTTP+SOCKS5). По умолчанию из конфига
                 ([General] http-listen / socks5-listen), иначе 7890
  --lan          слушать 0.0.0.0 (доступ из локальной сети, без пароля)
  --debug / --no-debug   полный лог (trace) в <data>/logs на этот запуск
  --log LEVEL    лог в файл: off|error|warn|info|debug|trace (env CPROXY_LOG).
                 По умолчанию off, или trace при `set debug on`
  -v, --verbose  подробный вывод и в консоль
";

const COMMANDS: [&str; 14] = ["check", "fetch", "gen", "groups", "killswitch", "run", "select", "server", "service", "set", "status", "stop", "sysproxy", "test"];

struct Args {
    cmd: String,
    /// Позиционные аргументы: путь к правилам или `set <key> <value>`.
    pos: Vec<String>,
    out: Option<String>,
    via: Option<String>,
    sing_box: Option<String>,
    xray: Option<String>,
    nodes: Option<String>,
    nodes_mode: Option<NodesMode>,
    sys_proxy: Option<bool>,
    tun: Option<bool>,
    /// `--debug` / `--no-debug`: полный лог на этот запуск.
    debug: Option<bool>,
    /// `run --server`: режим сервера (server.rs).
    server: bool,
    /// `server init --host/--mask`, `server user add --exits`.
    host: Option<String>,
    mask: Option<String>,
    exits: Option<String>,
    /// `server phone-conf --with-nodes`: дописать узлы «Дом-*» в [Proxy].
    with_nodes: bool,
    /// `service install|uninstall --dry-run`: только показать шаги.
    dry_run: bool,
    /// `service uninstall --purge`: удалить и ключи сервера.
    purge: bool,
    /// `--kill-switch` / `--no-kill-switch` на этот запуск.
    kill_switch: Option<bool>,
    /// Исходные аргументы (для UAC-перезапуска с теми же параметрами).
    argv: Vec<String>,
    force: bool,
    log: Option<String>,
    verbose: bool,
    /// Файл лога этого запуска (пишется в run.json для `cproxy status`).
    log_path: Option<String>,
    opts: singbox_gen::Options,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut it = argv.iter().cloned();
    let cmd = it.next().ok_or("")?;
    if !COMMANDS.contains(&cmd.as_str()) {
        return Err(format!("unknown command `{cmd}`"));
    }
    let mut a = Args {
        cmd,
        pos: Vec::new(),
        out: None,
        via: None,
        sing_box: None,
        xray: None,
        nodes: None,
        nodes_mode: None,
        sys_proxy: None,
        tun: None,
        debug: None,
        server: false,
        host: None,
        mask: None,
        exits: None,
        with_nodes: false,
        dry_run: false,
        purge: false,
        kill_switch: None,
        argv: argv.to_vec(),
        force: false,
        log: None,
        verbose: false,
        log_path: None,
        opts: singbox_gen::Options::default(),
    };
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-o" | "--out" => a.out = Some(value("-o")?),
            "--via" => a.via = Some(value("--via")?),
            "--sing-box" => a.sing_box = Some(value("--sing-box")?),
            "--xray" => a.xray = Some(value("--xray")?),
            "--nodes" => a.nodes = Some(value("--nodes")?),
            "--nodes-mode" => {
                let m = value("--nodes-mode")?;
                a.nodes_mode = Some(NodesMode::parse(&m).ok_or(format!("bad --nodes-mode `{m}` ({})", NodesMode::NAMES))?);
            }
            "--port" => a.opts.port = Some(value("--port")?.parse().map_err(|_| "bad --port")?),
            "--log" => a.log = Some(value("--log")?),
            "-v" | "--verbose" => a.verbose = true,
            "--lan" => a.opts.listen = Some("0.0.0.0".into()),
            "--force" => a.force = true,
            "--system-proxy" => a.sys_proxy = Some(true),
            "--no-system-proxy" => a.sys_proxy = Some(false),
            "--tun" => a.tun = Some(true),
            "--no-tun" => a.tun = Some(false),
            "--debug" => a.debug = Some(true),
            "--no-debug" => a.debug = Some(false),
            "--server" => a.server = true,
            "--host" => a.host = Some(value("--host")?),
            "--mask" => a.mask = Some(value("--mask")?),
            "--exits" => a.exits = Some(value("--exits")?),
            "--with-nodes" => a.with_nodes = true,
            "--dry-run" => a.dry_run = true,
            "--purge" => a.purge = true,
            "--kill-switch" => a.kill_switch = Some(true),
            "--no-kill-switch" => a.kill_switch = Some(false),
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => a.pos.push(s.to_string()),
        }
    }
    let max = match a.cmd.as_str() {
        "set" => 2,
        "server" => 3,
        "select" => 2,
        "test" => 1,
        "groups" => 0,
        "service" => 1,
        "killswitch" => 1,
        "status" | "stop" => 0,
        _ => 1,
    };
    if a.pos.len() > max {
        return Err(format!("unexpected argument {}", a.pos[max]));
    }
    if a.cmd == "set" && a.pos.len() != 2 {
        return Err("usage: cproxy set rules|connection|nodes|system-proxy <value>".into());
    }
    if a.cmd == "sysproxy" && !matches!(a.pos.first().map(String::as_str), Some("status") | Some("off")) {
        return Err("usage: cproxy sysproxy status|off".into());
    }
    Ok(a)
}

/// Уровень файла логов: `--log` → `--debug`/`--no-debug` → `CPROXY_LOG` → `set debug` → off.
/// Одна сборка на всё: подробный лог включается при запуске, а не feature-флагом сборки.
fn file_level(a: &Args) -> Result<LevelFilter, String> {
    let parse = |s: String| s.parse().map_err(|_| format!("bad log level `{s}` (off|error|warn|info|debug|trace)"));
    if let Some(s) = a.log.clone() {
        return parse(s);
    }
    if let Some(on) = a.debug {
        return Ok(if on { LevelFilter::Trace } else { LevelFilter::Off });
    }
    if let Ok(s) = std::env::var("CPROXY_LOG") {
        return parse(s);
    }
    Ok(if Settings::load().debug { LevelFilter::Trace } else { LevelFilter::Off })
}

/// Запуск из Проводника (двойной клик / перетаскивание файла на exe): консоль создана для нас
/// одних и закроется вместе с процессом. Тогда в конце ждём Enter, чтобы был виден результат.
/// Windows: `GetConsoleProcessList` (kernel32) — в консоли только наш процесс. Проверять до
/// запуска sing-box: он делит с нами консоль.
#[cfg(windows)]
fn own_console() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    let mut pids = [0u32; 4];
    // SAFETY: буфер на 4 элемента, длина передаётся.
    unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 }
}

#[cfg(not(windows))]
fn own_console() -> bool {
    false
}

fn ask(prompt: &str) -> String {
    print!("{prompt}\n> ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

/// Правила или узлы? По содержимому: секции `[Rule]`/`[General]`/`[Proxy Group]` → правила.
fn classify(path: &str) -> Result<&'static str, String> {
    if settings::is_url(path) {
        return Ok("connection");
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if fmt_nodes::looks_like_rules(&text) {
        return Ok("rules");
    }
    fmt_nodes::parse(&text, path).map(|_| "connection")
}

/// Сохраняет файл/URL в нужное поле настроек и печатает, куда.
fn remember(s: &mut Settings, input: &str) -> Result<(), String> {
    let v = settings::normalize(input)?;
    match classify(&v)? {
        "rules" => {
            println!("правила:     {v}");
            s.rules = Some(v);
        }
        _ => {
            println!("подключение: {}", settings::redact_source(&v));
            s.connection = Some(v);
        }
    }
    s.save()
}

/// Можно спрашивать пользователя: ввод и вывод — консоль (не служба, не конвейер).
fn terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Сохранённый путь к файлу, которого больше нет (перенесли/удалили). URL не проверяется.
fn stale(p: &Option<String>) -> bool {
    p.as_deref().is_some_and(|p| !settings::is_url(p) && !std::path::Path::new(p).is_file())
}

/// Спросить пути к правилам и подключению, которых нет в настройках или которые не найдены на диске,
/// и сохранить (remember). Файл можно перетащить прямо в окно. Enter — пропустить; устаревший путь
/// при этом убирается из настроек, чтобы запуск не падал на нём.
fn ask_configs(s: &mut Settings, rules: bool, connection: bool) {
    let fields: [(bool, &str, &str, fn(&mut Settings) -> &mut Option<String>); 2] = [
        (rules, "Правила", "путь к .conf Shadowrocket (перетащите файл в окно), Enter — без правил:", |s| &mut s.rules),
        (connection, "Подключение", "файл узлов (ссылки, base64, Clash, sing-box/Xray JSON) или URL подписки, Enter — пропустить:", |s| &mut s.connection),
    ];
    for (wanted, name, hint, field) in fields {
        if !wanted {
            continue;
        }
        let old = field(s).clone();
        if stale(&old) {
            println!("{name}: файл не найден: {}", old.as_deref().unwrap_or(""));
            log::warn!(target: "settings", "{name}: saved file not found: {}", old.as_deref().unwrap_or(""));
        }
        while field(s).is_none() || stale(field(s)) {
            let a = ask(&format!("{name}: {hint}"));
            if a.is_empty() {
                if stale(field(s)) {
                    *field(s) = None;
                    match s.save() {
                        Ok(()) => println!("{name}: старый путь убран из настроек"),
                        Err(e) => println!("ошибка: {e}"),
                    }
                }
                break;
            }
            if let Err(e) = remember(s, &a) {
                println!("ошибка: {e}");
            }
        }
    }
}

/// argv для запуска без команды:
/// - `cproxy <файл|URL>` (перетаскивание на exe) → сохранить в нужное поле → `run`;
/// - без аргументов → `run` по настройкам; в своём окне недостающее спрашивается и сохраняется.
fn launch_argv(argv: Vec<String>, interactive: bool) -> Result<Vec<String>, String> {
    match argv.as_slice() {
        [one] if !COMMANDS.contains(&one.as_str()) && !one.starts_with('-') => {
            let mut s = Settings::load();
            remember(&mut s, one)?;
            Ok(vec!["run".into()])
        }
        [] => {
            let mut s = Settings::load();
            if interactive {
                println!("cproxy {VERSION}\n");
            }
            // Своё окно: спросить всё недостающее. Терминал: только если запускать не с чем или путь устарел.
            if interactive || (terminal() && (s.rules.is_none() && s.connection.is_none() || stale(&s.rules) || stale(&s.connection))) {
                ask_configs(&mut s, true, true);
            }
            if s.rules.is_none() && s.connection.is_none() {
                if interactive {
                    println!("\nНечего запускать: нет ни правил, ни подключения. Запустите cproxy снова и укажите путь\n(или перетащите файл на cproxy.exe).\n");
                }
                return Ok(argv);
            }
            if interactive {
                println!("\nНастройки (изменить: перетащите файл на cproxy.exe или `cproxy set ...`):");
                s.print();
                println!();
            }
            Ok(vec!["run".into()])
        }
        _ => Ok(argv),
    }
}

fn pause() {
    print!("\nНажмите Enter, чтобы закрыть окно...");
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(&mut String::new());
}

fn main() -> ExitCode {
    let interactive = own_console();
    let code = match launch_argv(std::env::args().skip(1).collect(), interactive) {
        Ok(argv) => real_main(&argv, interactive),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    };
    if interactive {
        pause();
    }
    code
}

fn real_main(argv: &[String], interactive: bool) -> ExitCode {
    let mut args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprint!("cproxy {VERSION}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let level = match file_level(&args) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // Уровень sing-box = уровень файла (sing-box не знает "off" → log.disabled).
    args.opts.log_level = (level != LevelFilter::Off).then(|| level.to_string().to_lowercase());
    let console = if args.verbose { LevelFilter::Trace } else { LevelFilter::Info };
    let log_path = logger::init(&store::data_dir().join("logs"), &args.cmd, level, console);
    args.log_path = log_path.as_ref().map(|p| p.display().to_string());

    let started = Instant::now();
    log::info!(target: "cli", "cproxy {VERSION} {}/{}", std::env::consts::OS, std::env::consts::ARCH);
    // argv может содержать URL подписки с токеном.
    let shown: Vec<String> = argv.iter().map(|a| settings::redact_source(a)).collect();
    log::debug!(target: "cli", "argv: {shown:?}{}", if interactive { " (own console: launched from Explorer)" } else { "" });
    log::debug!(target: "cli", "data dir: {}", store::data_dir().display());
    if let Some(p) = &log_path {
        log::info!(target: "cli", "log: {} (level {level})", p.display());
    }
    let result = match args.cmd.as_str() {
        "set" => set(&args),
        "status" => status_cmd(),
        "stop" => stop_cmd(),
        "sysproxy" => sysproxy_cmd(&args),
        "server" => server_cmd(&args),
        "groups" => groups_cmd(),
        "select" => select_cmd(&args),
        "test" => test_cmd(&args),
        "service" => service_cmd(&args),
        "killswitch" => killswitch_cmd(&args),
        "check" => check(&args),
        "fetch" => fetch(&args, false),
        "gen" => gen(&args),
        "run" => run(&args),
        other => Err(format!("unknown command `{other}`")),
    };
    let code = match result {
        Ok(code) => {
            log::debug!(target: "cli", "`{}` finished: {code:?} in {:?}", args.cmd, started.elapsed());
            code
        }
        Err(e) => {
            log::error!(target: "cli", "{e}");
            ExitCode::FAILURE
        }
    };
    log::logger().flush();
    elevate::restore_owner();
    code
}

fn set(a: &Args) -> Result<ExitCode, String> {
    let mut s = Settings::load();
    let (key, value) = (a.pos[0].as_str(), a.pos[1].as_str());
    let none = value.eq_ignore_ascii_case("none");
    match key {
        "rules" => s.rules = if none { None } else { Some(settings::normalize(value)?) },
        "connection" => s.connection = if none { None } else { Some(settings::normalize(value)?) },
        "nodes" => s.nodes = NodesMode::parse(value).ok_or(format!("bad nodes mode `{value}` ({})", NodesMode::NAMES))?,
        "system-proxy" => s.system_proxy = on_off(value)?,
        "tun" => s.tun = on_off(value)?,
        "debug" => s.debug = on_off(value)?,
        "kill-switch" | "killswitch" => s.kill_switch = on_off(value)?,
        other => return Err(format!("unknown setting `{other}` (rules|connection|nodes|system-proxy|tun|debug|kill-switch)")),
    }
    s.save()?;
    s.print();
    Ok(ExitCode::SUCCESS)
}

fn on_off(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => Ok(true),
        "off" | "false" | "0" | "no" => Ok(false),
        _ => Err(format!("bad value `{value}` (on|off)")),
    }
}

/// TUN на этот запуск: флаг → настройка.
fn tun_wanted(a: &Args) -> bool {
    a.tun.unwrap_or_else(|| Settings::load().tun)
}

/// Kill switch на этот запуск: флаг → настройка. У сервера нет (его задача — выпускать трафик).
fn kill_switch_wanted(a: &Args) -> bool {
    !a.server && a.kill_switch.unwrap_or_else(|| Settings::load().kill_switch)
}

/// `cproxy killswitch status|off`.
fn killswitch_cmd(a: &Args) -> Result<ExitCode, String> {
    match a.pos.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            let on = killswitch::active();
            println!("kill switch {}", if on { "ВКЛЮЧЁН: в интернет ходят только ядра cproxy" } else { "выключен" });
            println!("настройка   {}", if Settings::load().kill_switch { "on" } else { "off" });
            if on && !running() {
                println!("cproxy не запущен, а защита стоит (процесс был убит): cproxy killswitch off");
            }
            Ok(ExitCode::SUCCESS)
        }
        "off" => {
            if !killswitch::active() {
                println!("kill switch не включён");
                return Ok(ExitCode::SUCCESS);
            }
            if running() {
                return Err("cproxy is running: stop it (cproxy stop) — it removes the kill switch itself".into());
            }
            if !elevate::is_admin() {
                log::info!(target: "killswitch", "removing the kill switch needs administrator rights: relaunching elevated");
                return elevate::relaunch_elevated(&a.argv);
            }
            killswitch::disable();
            println!("kill switch {}", if killswitch::active() { "НЕ снят — см. лог" } else { "снят" });
            Ok(ExitCode::SUCCESS)
        }
        _ => Err("usage: cproxy killswitch status|off".into()),
    }
}

/// `cproxy sysproxy status|off`: показать текущий системный прокси / вернуть сохранённый прежний.
fn sysproxy_cmd(a: &Args) -> Result<ExitCode, String> {
    if a.pos[0] == "off" {
        if !sysproxy::has_backup() {
            println!("cproxy не менял системный прокси (нет резервной копии) — нечего возвращать");
            return Ok(ExitCode::SUCCESS);
        }
        sysproxy::recover_stale();
    }
    println!("{}", serde_json::to_string_pretty(&sysproxy::current()?).unwrap());
    Ok(ExitCode::SUCCESS)
}

/// Путь к правилам: аргумент → настройки. Без правил — пустой документ (весь трафик → PROXY),
/// но только если есть подключение.
fn rules_path(a: &Args, s: &Settings) -> Result<Option<String>, String> {
    match a.pos.first().cloned().or_else(|| s.rules.clone()) {
        Some(p) => Ok(Some(p)),
        None if a.nodes.is_some() || s.connection.is_some() => Ok(None),
        None => Err("no config: pass <rules.conf>, or save one with `cproxy set rules <file>` / `cproxy set connection <file|URL>`".into()),
    }
}

fn load(a: &Args) -> Result<fmt_shadowrocket::Document, String> {
    let s = Settings::load();
    let Some(path) = rules_path(a, &s)? else {
        log::info!(target: "cli", "rules: none (all traffic → PROXY)");
        return Ok(fmt_shadowrocket::Document::default());
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    log::info!(target: "cli", "rules: {path} ({} bytes)", text.len());
    let doc = fmt_shadowrocket::parse(&text);
    let mut seen = vec![path.clone()];
    Ok(with_includes(doc, &path, a.via.as_deref(), &mut seen, 0))
}

/// `[General] include = a.conf, b.conf` (fmt_shadowrocket::merge_included: текущий конфиг важнее). Пути —
/// относительно файла, который включает; URL — в память (как подписка). До 3 уровней, циклы пропускаются.
/// Ошибка чтения — предупреждение, а не отказ: include дополняет конфиг.
fn with_includes(mut doc: fmt_shadowrocket::Document, from: &str, via: Option<&str>, seen: &mut Vec<String>, depth: usize) -> fmt_shadowrocket::Document {
    let Some(list) = doc.general("include") else { return doc };
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let target = if settings::is_url(item) || std::path::Path::new(item).is_absolute() {
            item.to_string()
        } else {
            std::path::Path::new(from).parent().unwrap_or(std::path::Path::new(".")).join(item).to_string_lossy().into_owned()
        };
        let shown = settings::redact_source(&target);
        if seen.contains(&target) || depth >= 3 {
            log::warn!(target: "cli", "include {shown}: {}; skipped", if depth >= 3 { "nested deeper than 3 levels" } else { "already included (cycle)" });
            continue;
        }
        let text = if settings::is_url(&target) {
            store::http_get(&target, &shown, via).map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            std::fs::read_to_string(&target).map_err(|e| e.to_string())
        };
        match text {
            Ok(t) => {
                seen.push(target.clone());
                let inc = with_includes(fmt_shadowrocket::parse(&t), &target, via, seen, depth + 1);
                log::info!(target: "cli", "include: {shown} ({} bytes, {} rules) — the including config has priority", t.len(), inc.data_lines("Rule").count());
                doc = fmt_shadowrocket::merge_included(&doc, &inc, &shown);
            }
            Err(e) => log::warn!(target: "cli", "include {shown}: {e}; skipped"),
        }
    }
    doc
}

/// Узлы по режиму (settings::NodesMode). `None` — генератор берёт `[Proxy]` из правил.
/// Ошибка загрузки подключения — ошибка запуска (fail-closed: без узлов не стартуем молча в DIRECT).
fn load_nodes(a: &Args, doc: &fmt_shadowrocket::Document) -> Result<Option<Vec<Node>>, String> {
    let s = Settings::load();
    let source = a.nodes.clone().or(s.connection.clone());
    let mode = match (a.nodes_mode.unwrap_or(s.nodes), &source) {
        (NodesMode::Auto, Some(_)) => NodesMode::Connection,
        (NodesMode::Auto, None) => NodesMode::Rules,
        (m, _) => m,
    };
    log::debug!(target: "cli", "nodes mode: {} (source {:?})", mode.name(), source.as_deref().map(settings::redact_source));
    if mode == NodesMode::Rules {
        return Ok(None);
    }
    let source = source.ok_or("nodes mode needs a connection: `cproxy set connection <file|URL>` or --nodes")?;
    let shown = settings::redact_source(&source);
    let text = if settings::is_url(&source) {
        // Подписка — только в памяти (решение пользователя: секреты не на диск).
        let body = store::http_get(&source, &shown, a.via.as_deref())?;
        String::from_utf8_lossy(&body).into_owned()
    } else {
        std::fs::read_to_string(&source).map_err(|e| format!("cannot read {source}: {e}"))?
    };
    let parsed = fmt_nodes::parse(&text, &shown)?;
    log::info!(target: "cli", "connection: {shown} — {}, {} node(s)", parsed.format, parsed.nodes.len());
    for w in &parsed.warnings {
        log::warn!(target: "nodes", "{w}");
    }
    let mut nodes = Vec::new();
    if mode == NodesMode::Both {
        // Узлы правил первыми: при совпадении имён генератор оставляет первый.
        nodes = singbox_gen::conf_nodes(doc).map_err(|e| e.to_string())?;
    }
    nodes.extend(parsed.nodes);
    if nodes.is_empty() {
        log::warn!(target: "cli", "no nodes: PROXY and groups are empty → REJECT (fail-closed)");
    }
    Ok(Some(nodes))
}

fn check(a: &Args) -> Result<ExitCode, String> {
    let doc = load(a)?;
    let mut ok = true;
    let mut report = |name: &str, r: Result<usize, core_model::ParseError>| match r {
        Ok(n) => println!("{name:<8} {n}"),
        Err(e) => {
            log::error!(target: "cli", "[{name}] {e}");
            ok = false;
        }
    };
    report("proxies", doc.proxies().map(|v| v.len()));
    report("groups", doc.groups().map(|v| v.len()));
    report("rules", doc.rules().map(|v| v.len()));
    if !ok {
        return Ok(ExitCode::FAILURE);
    }
    let cache = Cache::open().map_err(|e| e.to_string())?;
    let urls = singbox_gen::resource_urls(&doc).map_err(|e| e.to_string())?;
    let missing = urls.iter().filter(|(u, _)| !cache.has(u)).count();
    println!("sets     {} ({missing} not downloaded)", urls.len());
    let mut opts = options(a);
    opts.nodes = load_nodes(a, &doc)?;
    if let Some(n) = &opts.nodes {
        let xray = n.iter().filter(|n| singbox_gen::needs_xray(&n.proxy)).count();
        println!("nodes    {} ({xray} via Xray)", n.len());
    }
    let out = singbox_gen::generate(&doc, &cache, &opts).map_err(|e| e.to_string())?;
    println!("listen   {}", out.listeners.join(", "));
    Ok(ExitCode::SUCCESS)
}

/// TUN: IP серверов Xray-узлов → исключения из TUN. Резолв системным DNS ДО подъёма TUN (адреса настоящие).
/// Не разрешилось — не страшно: остаётся правило `process_name xray → DIRECT` (медленнее, но без петли).
fn xray_server_cidrs(nodes: &[Node]) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut out: Vec<String> = Vec::new();
    for n in nodes.iter().filter(|n| singbox_gen::needs_xray(&n.proxy)) {
        let p = &n.proxy;
        match (p.server.as_str(), p.port).to_socket_addrs() {
            Ok(addrs) => {
                for a in addrs {
                    let c = if a.is_ipv4() { format!("{}/32", a.ip()) } else { format!("{}/128", a.ip()) };
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
            Err(e) => log::warn!(target: "cli", "TUN: cannot resolve Xray server of `{}`: {e}; its traffic goes through TUN (slower)", p.name),
        }
    }
    log::debug!(target: "cli", "TUN: Xray servers excluded from TUN: {out:?}");
    out
}

/// Опции генератора из CLI + выделение портов для Xray.
fn options(a: &Args) -> singbox_gen::Options {
    let s = Settings::load();
    singbox_gen::Options {
        listen: a.opts.listen.clone(),
        port: a.opts.port,
        log_level: a.opts.log_level.clone(),
        nodes: None,
        alloc_port: Some(free_port),
        tun: tun_wanted(a),
        tun_exclude: Vec::new(),
        clash_api: None,
        selections: s.selections,
        // Linux: kill switch пропускает сокеты ядер по метке (killswitch.rs). Windows — по app-id, метка не нужна.
        fwmark: (cfg!(target_os = "linux") && kill_switch_wanted(a)).then_some(killswitch::FWMARK),
    }
}

/// Свободный порт на 127.0.0.1 для узла Xray (ОС выдаёт по bind :0; порт сразу освобождается).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

/// Скачивает недостающие ресурсы; `--force` (кроме `run`) — перекачать все.
fn fetch(a: &Args, from_run: bool) -> Result<ExitCode, String> {
    let doc = load(a)?;
    let cache = Cache::open().map_err(|e| e.to_string())?;
    let urls = singbox_gen::resource_urls(&doc).map_err(|e| e.to_string())?;
    let todo: Vec<_> = urls.iter().filter(|(u, _)| (a.force && !from_run) || !cache.has(u)).collect();
    log::debug!(target: "fetch", "{} resource(s) in config, {} to download", urls.len(), todo.len());
    if todo.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    match &a.via {
        Some(v) => log::info!(target: "fetch", "downloading {} resource(s) via {v}", todo.len()),
        None => log::info!(target: "fetch", "downloading {} resource(s) directly (use --via to go through a proxy)", todo.len()),
    }
    let mut failed = 0;
    for (url, _) in todo {
        match cache.download(url, a.via.as_deref()) {
            Ok(n) => log::info!(target: "fetch", "  ok   {url} ({n} bytes)"),
            Err(e) => {
                failed += 1;
                log::error!(target: "fetch", "  FAIL {url}: {e}");
            }
        }
    }
    Ok(if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn build(a: &Args) -> Result<singbox_gen::Output, String> {
    let started = Instant::now();
    let out = if a.server {
        build_server(a)?
    } else {
        let doc = load(a)?;
        let cache = Cache::open().map_err(|e| e.to_string())?;
        let mut opts = options(a);
        opts.nodes = load_nodes(a, &doc)?;
        if opts.tun {
            let nodes = opts.nodes.clone().unwrap_or_else(|| singbox_gen::conf_nodes(&doc).unwrap_or_default());
            opts.tun_exclude = xray_server_cidrs(&nodes);
        }
        if a.cmd == "run" {
            // Clash API для `cproxy groups|select|test` (clash.rs): случайный порт и secret на каждый запуск.
            opts.clash_api = Some((format!("127.0.0.1:{}", free_port()), server::new_secret(&sing_box_bin(a)?)?));
        }
        singbox_gen::generate(&doc, &cache, &opts).map_err(|e| e.to_string())?
    };
    log::debug!(target: "cli", "generated in {:?}: {} bytes JSON", started.elapsed(), out.config.to_string().len());
    // Карта для чтения лога sing-box: match[i] → строка конфига.
    for (i, origin) in out.rule_origins.iter().enumerate() {
        log::debug!(target: "cli", "route.rules[{i}] ⇐ {origin}");
    }
    log::debug!(target: "cli", "route.final = {} ⇐ {} (no `match` line in sing-box log when final is used)", out.config["route"]["final"], out.final_origin);
    log::trace!(target: "cli", "sing-box config (secrets redacted): {}", singbox_gen::redact(&out.config));
    Ok(out)
}

/// `run --server` / `gen --server`: конфиг домашнего шлюза (server.rs → singbox_gen::server).
fn build_server(a: &Args) -> Result<singbox_gen::Output, String> {
    let cfg = server::Config::load()?;
    let keys = server::Keys::load()?;
    let mut srv = server::build(&cfg, &keys)?;
    if a.cmd == "run" {
        // Clash API для `server status`: случайный порт на 127.0.0.1 и secret на каждый запуск.
        srv.clash_api = Some((format!("127.0.0.1:{}", free_port()), server::new_secret(&sing_box_bin(a)?)?));
    }
    let mut opts = options(a);
    opts.tun = false;
    let nodes = if srv.users.iter().any(|u| u.exit == SrvExit::Proxy) { server_nodes(a)? } else { Vec::new() };
    log::info!(target: "server", "server: {} device(s), {} user(s), {} node(s) for exit vps", cfg.devices.len(), srv.users.len(), nodes.len());
    singbox_gen::server::generate(&srv, nodes, &opts).map_err(|e| e.to_string())
}

/// Узлы выхода vps: подключение (`set connection` / `--nodes`), иначе `[Proxy]` из правил, если они заданы.
fn server_nodes(a: &Args) -> Result<Vec<Node>, String> {
    let s = Settings::load();
    let doc = if a.pos.is_empty() && s.rules.is_none() { fmt_shadowrocket::Document::default() } else { load(a)? };
    match load_nodes(a, &doc)? {
        Some(n) => Ok(n),
        None => singbox_gen::conf_nodes(&doc).map_err(|e| e.to_string()),
    }
}

/// `cproxy server ...`: ключи, устройства, ссылки (server.rs). Сам сервер — `run --server`.
fn server_cmd(a: &Args) -> Result<ExitCode, String> {
    let pos: Vec<&str> = a.pos.iter().map(String::as_str).collect();
    match pos.as_slice() {
        ["init"] => server_init(a),
        ["user", "add", name] => server_user_add(a, name),
        ["user", "remove", name] => server_user_remove(name),
        ["user"] | ["user", "list"] | ["show"] | [] => server_show(),
        ["link", name] => server_link(name),
        ["check"] => server_check(),
        ["status"] => server_status(),
        ["phone-conf", name] => server_phone_conf(a, name, None),
        ["phone-conf", name, rules] => server_phone_conf(a, name, Some(rules)),
        _ => Err("usage: cproxy server init|show|link NAME|user add NAME [--exits ru,vps,lan]|user list|user remove NAME".into()),
    }
}

fn sing_box_bin(a: &Args) -> Result<std::path::PathBuf, String> {
    store::find_bin("sing-box", a.sing_box.as_deref(), "CPROXY_SING_BOX")
        .ok_or_else(|| "sing-box not found: run scripts/fetch-sing-box.ps1 (or .sh), or pass --sing-box PATH".into())
}

/// Ключи создаются один раз: новые сломали бы все телефоны. `--force` — пересоздать (UUID устройств остаются).
fn server_init(a: &Args) -> Result<ExitCode, String> {
    let old = server::Config::load().ok();
    let host = match a.host.clone().or(old.as_ref().map(|c| c.host.clone())) {
        Some(h) => h,
        None => {
            let ip = server::lan_ip().ok_or("cannot detect LAN IP: pass --host <domain or IP>")?;
            println!("--host не задан: беру адрес в локальной сети {ip} (для доступа снаружи: --host <домен DDNS или белый IP>)");
            ip
        }
    };
    let port = a.opts.port.or(old.as_ref().map(|c| c.port)).unwrap_or(server::DEFAULT_PORT);
    let mask = match a.mask.clone() {
        Some(m) => {
            match server::check_mask(&m, 443) {
                Ok(t) => println!("маска {m}: TLS 1.3 + X25519 + HTTP/2, {} мс", t.as_millis()),
                Err(e) if a.force => println!("маска {m}: {e} (--force: всё равно сохраняю)"),
                Err(e) => return Err(format!("mask {m}: {e}; pick another site or pass --force")),
            }
            m
        }
        None => match &old {
            Some(c) => c.mask.clone(),
            None => server::pick_mask()?,
        },
    };
    let keys = match server::Keys::load() {
        Ok(k) if !a.force => {
            println!("ключи уже есть — оставляю (новые: --force, телефоны придётся настроить заново)");
            k
        }
        prev => {
            let mut k = server::new_keys(&sing_box_bin(a)?)?;
            if let Ok(p) = prev {
                k.uuids = p.uuids;
            }
            println!("созданы ключи REALITY");
            k
        }
    };
    let cfg = server::Config { host, listen: "::".into(), port, mask, devices: old.map(|c| c.devices).unwrap_or_default() };
    keys.save()?;
    cfg.save()?;
    println!();
    server_show()?;
    if cfg.devices.is_empty() {
        println!("\nдальше: cproxy server user add iphone   затем   cproxy server link iphone");
    }
    Ok(ExitCode::SUCCESS)
}

fn server_user_add(a: &Args, name: &str) -> Result<ExitCode, String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(format!("bad device name `{name}`: use latin letters, digits, - and _"));
    }
    let mut cfg = server::Config::load()?;
    let mut keys = server::Keys::load()?;
    let mut exits = Vec::new();
    for e in a.exits.as_deref().unwrap_or("ru,vps").split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let x = SrvExit::parse(e).ok_or(format!("bad exit `{e}` ({})", SrvExit::NAMES))?;
        if !exits.contains(&x) {
            exits.push(x);
        }
    }
    let sing_box = sing_box_bin(a)?;
    for x in &exits {
        let user = server::user_name(name, *x);
        if !keys.uuids.contains_key(&user) {
            keys.uuids.insert(user, server::new_uuid(&sing_box)?);
        }
    }
    match cfg.devices.iter_mut().find(|d| d.name == name) {
        Some(d) => {
            for x in exits {
                if !d.exits.contains(&x) {
                    d.exits.push(x);
                }
            }
        }
        None => cfg.devices.push(server::Device { name: name.to_string(), exits }),
    }
    keys.save()?;
    cfg.save()?;
    log::info!(target: "server", "device `{name}` saved");
    server_show()?;
    println!("\nссылки и QR: cproxy server link {name}");
    if running() {
        println!("сервер запущен: перезапустите его (cproxy stop, затем cproxy run --server)");
    }
    Ok(ExitCode::SUCCESS)
}

fn server_user_remove(name: &str) -> Result<ExitCode, String> {
    let mut cfg = server::Config::load()?;
    let mut keys = server::Keys::load()?;
    let Some(d) = cfg.devices.iter().position(|d| d.name == name).map(|i| cfg.devices.remove(i)) else {
        return Err(format!("no device `{name}`"));
    };
    for x in SrvExit::ALL {
        keys.uuids.remove(&server::user_name(&d.name, x));
    }
    keys.save()?;
    cfg.save()?;
    println!("устройство {name} удалено, его ссылки больше не работают{}", if running() { " (после перезапуска сервера)" } else { "" });
    Ok(ExitCode::SUCCESS)
}

fn running() -> bool {
    RunState::load(&store::data_dir()).is_some_and(|s| s.is_running())
}

fn server_show() -> Result<ExitCode, String> {
    let cfg = server::Config::load()?;
    let keys = server::Keys::load()?;
    println!("адрес       {}:{} (слушает [{}]:{})", cfg.host, cfg.port, cfg.listen, cfg.port);
    println!("маска       {}", cfg.mask);
    println!("public key  {}", keys.public_key);
    println!("short id    {}", keys.short_id);
    if cfg.devices.is_empty() {
        println!("устройства  нет");
    }
    for d in &cfg.devices {
        let exits: Vec<String> = d.exits.iter().map(|e| format!("{} ({})", e.name(), e.node_name())).collect();
        println!("устройство  {:<10} {}", d.name, exits.join(", "));
    }
    let dir = store::data_dir();
    println!("файлы       {} | {} (секреты)", dir.join("server.json").display(), dir.join("server-keys.json").display());
    Ok(ExitCode::SUCCESS)
}

/// `cproxy server check` (этап 2, доступ снаружи): маска, внешний IP против `host`, порт, ответ самого сервера
/// глазами сканера — локально и через внешний адрес. FAIL — точно не заработает, `??` — проверить вручную.
fn server_check() -> Result<ExitCode, String> {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    let cfg = server::Config::load()?;
    let mut fails = 0;
    let mut report = |ok: Option<bool>, what: &str, detail: String| {
        let mark = match ok {
            Some(true) => "ok  ",
            Some(false) => {
                fails += 1;
                "FAIL"
            }
            None => "??  ",
        };
        log::debug!(target: "server", "check {what}: {mark} {detail}");
        println!("{mark}  {what:<10} {detail}");
    };

    match server::check_mask(&cfg.mask, 443) {
        Ok(t) => report(Some(true), "маска", format!("{} отвечает TLS 1.3 + X25519 + HTTP/2 за {} мс", cfg.mask, t.as_millis())),
        Err(e) => report(Some(false), "маска", format!("{}: {e} → cproxy server init --mask <другой сайт>", cfg.mask)),
    }

    let public: Option<IpAddr> = match server::public_ip() {
        Ok(ip) => {
            report(Some(true), "внешний IP", format!("{ip} (так эту машину видит интернет)"));
            ip.parse().ok()
        }
        Err(e) => {
            report(None, "внешний IP", format!("не удалось узнать: {e}"));
            None
        }
    };

    let host_ips: Vec<IpAddr> = match (cfg.host.as_str(), cfg.port).to_socket_addrs() {
        Ok(a) => a.map(|a| a.ip()).collect(),
        Err(e) => {
            report(Some(false), "адрес", format!("{} не резолвится: {e} (домен DDNS не создан или не обновлён?)", cfg.host));
            Vec::new()
        }
    };
    let host_public: Vec<IpAddr> = host_ips.iter().copied().filter(|ip| !server::is_private(*ip)).collect();
    if !host_ips.is_empty() && host_public.is_empty() {
        report(None, "адрес", format!("{} — адрес домашней сети: снаружи телефон не подключится. Для мобильной сети: cproxy server init --host <домен DDNS или белый IP>", cfg.host));
    } else if let (Some(p), false) = (public, host_public.is_empty()) {
        if host_public.contains(&p) {
            report(Some(true), "адрес", format!("{} → {p}, совпадает с внешним IP", cfg.host));
        } else {
            let list: Vec<String> = host_public.iter().map(IpAddr::to_string).collect();
            report(Some(false), "адрес", format!(
                "{} → {}, а внешний IP {p}. Причины: DDNS не обновился; на этой машине включён VPN/TUN (тогда внешний IP — его); серый IP провайдера (CGNAT: WAN-адрес роутера не совпадает с внешним)",
                cfg.host, list.join(", ")
            ));
        }
    }

    let local = SocketAddr::from(([127, 0, 0, 1], cfg.port));
    if running() {
        match server::tls_probe(local, &cfg.mask) {
            Ok(t) => report(Some(true), "сервер", format!("порт {} отвечает сканеру как {} ({} мс)", cfg.port, cfg.mask, t.as_millis())),
            Err(e) => report(Some(false), "сервер", format!("127.0.0.1:{} не отвечает как маска: {e} (запущен ли именно сервер: cproxy status)", cfg.port)),
        }
        // Снаружи по внешнему адресу. Изнутри дома это hairpin NAT: многие роутеры его не умеют — тогда не FAIL.
        for ip in &host_public {
            let addr = SocketAddr::new(*ip, cfg.port);
            match server::tls_probe(addr, &cfg.mask) {
                Ok(t) => report(Some(true), "снаружи", format!("{addr} отвечает как {} ({} мс): проброс порта работает", cfg.mask, t.as_millis())),
                Err(e) => report(None, "снаружи", format!("{addr}: {e}. Проброс порта не настроен или роутер не пускает изнутри на свой внешний адрес — проверить с мобильной сети")),
            }
        }
    } else {
        match server::port_check(&cfg.listen, cfg.port) {
            Ok(()) => report(None, "сервер", format!("не запущен; порт {} свободен (cproxy run --server)", cfg.port)),
            Err(e) => report(Some(false), "сервер", format!("не запущен, порт {}: {e}", cfg.port)),
        }
    }
    println!("\nИз дома проверка снаружи неполная: окончательно — телефон в мобильной сети (Wi-Fi выключен), узел «Дом-RU».");
    Ok(if fails == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Перед `run --server`: порт занят → ошибка сразу (иначе sing-box упадёт с невнятным bind). Нет прав → только
/// предупреждение: права проверяются у cproxy, а порт открывает sing-box (ему могли дать `setcap`).
fn server_port_precheck(listen: &str, port: u16) -> Result<(), String> {
    match server::port_check(listen, port) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(format!("port {port} is already in use (another server/web server?): pick another with `cproxy server init --port N`")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            log::warn!(target: "server", "port {port}: {e}. On Linux ports < 1024 need root or `sudo setcap cap_net_bind_service=+ep <sing-box>` (the systemd service will do this itself)");
            Ok(())
        }
        Err(e) => {
            log::warn!(target: "server", "port {port}: {e}");
            Ok(())
        }
    }
}

/// `cproxy server phone-conf NAME [rules.conf]`: правила (аргумент → `set rules`) → `.conf` для телефона (server.rs::phone_conf).
fn server_phone_conf(a: &Args, name: &str, rules: Option<&str>) -> Result<ExitCode, String> {
    let cfg = server::Config::load()?;
    let keys = server::Keys::load()?;
    let d = cfg.devices.iter().find(|d| d.name == name).ok_or(format!("no device `{name}`: cproxy server user add {name}"))?;
    let path = rules.map(String::from).or(Settings::load().rules).ok_or("no rules: pass <rules.conf> or `cproxy set rules <file>`")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let (out, changes) = server::phone_conf(&text, &cfg, &keys, d, a.with_nodes);
    let dest = a.out.clone().unwrap_or_else(|| format!("{name}-shadowrocket.conf"));
    std::fs::write(&dest, &out).map_err(|e| format!("{dest}: {e}"))?;
    log::info!(target: "server", "phone-conf `{name}`: {path} → {dest}, {} change(s)", changes.len());
    println!("правила:  {path}
записано: {dest}");
    for c in &changes {
        println!("  {c}");
    }
    if changes.is_empty() {
        println!("  групп с policy-regex-filter нет — файл совпадает с правилами (плюс строка-заголовок)");
    }
    if a.with_nodes {
        println!("
ВНИМАНИЕ: в файле UUID и ключи — не публикуйте его. Синтаксис узлов VLESS REALITY в .conf Shadowrocket
не подтверждён документацией: если узлы не появятся, добавьте их по QR (cproxy server link {name}).");
    } else {
        println!("
Узлы «Дом-*» добавьте по QR: cproxy server link {name}. Имена должны остаться «Дом-RU», «Дом-VPS», «Дом-LAN».");
    }
    Ok(ExitCode::SUCCESS)
}

/// `cproxy groups`: группы запущенного экземпляра (clash.rs).
fn groups_cmd() -> Result<ExitCode, String> {
    let api = clash::load()?;
    let list = clash::groups(&api.get("/proxies")?);
    if list.is_empty() {
        println!("групп нет");
    }
    for (name, kind, now, all) in &list {
        let kind = match kind.as_str() {
            "Selector" => "select",
            "URLTest" => "url-test",
            k => k,
        };
        println!("{name:<20} {kind:<9} → {now:<28} ({} узл.)", all.len());
    }
    println!("\nвыбрать: cproxy select <группа> <узел>   задержки: cproxy test <группа>");
    Ok(ExitCode::SUCCESS)
}

/// `cproxy select GROUP [NODE]`: переключить selector (PUT /proxies/{group}) и запомнить выбор в settings.json —
/// следующий запуск поднимет группу с ним (Options::selections → `default` selector, как Shadowrocket).
fn select_cmd(a: &Args) -> Result<ExitCode, String> {
    let api = clash::load()?;
    let list = clash::groups(&api.get("/proxies")?);
    let names: Vec<String> = list.iter().map(|g| g.0.clone()).collect();
    let group = a.pos.first().ok_or("usage: cproxy select GROUP [NODE]")?;
    let gname = clash::resolve(&names, group)?.to_string();
    let (_, kind, now, all) = list.iter().find(|g| g.0 == gname).unwrap();
    let Some(node) = a.pos.get(1) else {
        println!("{gname} ({}):", if kind == "Selector" { "select" } else if kind == "URLTest" { "url-test" } else { kind });
        for n in all {
            println!("  {} {n}", if n == now { "→" } else { " " });
        }
        return Ok(ExitCode::SUCCESS);
    };
    if kind != "Selector" {
        return Err(format!("`{gname}` is {kind}: it picks the node itself; only select groups can be switched"));
    }
    let nname = clash::resolve(all, node)?.to_string();
    api.put(&format!("/proxies/{}", clash::seg(&gname)), &serde_json::json!({"name": nname}))?;
    let mut s = Settings::load();
    s.selections.insert(gname.clone(), nname.clone());
    s.save()?;
    log::info!(target: "clash", "select `{gname}` → `{nname}` (saved)");
    println!("{gname} → {nname} (запомнено для следующих запусков)");
    Ok(ExitCode::SUCCESS)
}

/// `cproxy test [GROUP]`: задержка каждого узла группы (GET /group/{name}/delay). У url-test заодно обновляет выбор.
fn test_cmd(a: &Args) -> Result<ExitCode, String> {
    let api = clash::load()?;
    let list = clash::groups(&api.get("/proxies")?);
    let names: Vec<String> = list.iter().map(|g| g.0.clone()).collect();
    let gname = match a.pos.first() {
        Some(g) => clash::resolve(&names, g)?.to_string(),
        None if names.iter().any(|n| n == "PROXY") => "PROXY".into(),
        None => names.first().cloned().ok_or("no groups to test")?,
    };
    let (_, _, _, all) = list.iter().find(|g| g.0 == gname).unwrap();
    println!("{gname}: проверяю {} узл. (https://www.gstatic.com/generate_204, таймаут 5 с)...", all.len());
    let path = format!("/group/{}/delay?url={}&timeout=5000", clash::seg(&gname), clash::seg("https://www.gstatic.com/generate_204"));
    let res = api.get_with(&path, Duration::from_secs(30))?;
    let mut rows: Vec<(String, Option<u64>)> = all.iter().map(|n| (n.clone(), res[n].as_u64().filter(|d| *d > 0))).collect();
    rows.sort_by_key(|(_, d)| d.unwrap_or(u64::MAX));
    for (n, d) in &rows {
        match d {
            Some(ms) => println!("  {ms:>6} мс  {n}"),
            None => println!("  {:>9}  {n}", "нет связи"),
        }
    }
    log::debug!(target: "clash", "test `{gname}`: {rows:?}");
    if let Ok(g) = api.get(&format!("/proxies/{}", clash::seg(&gname))) {
        println!("сейчас: {gname} → {}", g["now"].as_str().unwrap_or("?"));
    }
    Ok(ExitCode::SUCCESS)
}

/// `cproxy server status`: активные соединения по устройствам и трафик с запуска (Clash API sing-box).
fn server_status() -> Result<ExitCode, String> {
    let api = clash::load()?;
    let conns = api.get("/connections")?;
    let total = (conns["uploadTotal"].as_u64().unwrap_or(0), conns["downloadTotal"].as_u64().unwrap_or(0));
    if let Some(st) = RunState::load(&store::data_dir()).filter(RunState::is_running) {
        let up = RunState::now_unix().saturating_sub(st.started_unix);
        println!("сервер      pid {}, работает {}h{:02}m, {}", st.pid, up / 3600, up / 60 % 60, st.listeners.join(", "));
    }
    println!("трафик      ↑ {}  ↓ {}  (всего с запуска)", server::human(total.0), server::human(total.1));
    if let Ok(p) = api.get("/proxies/PROXY") {
        println!("выход vps   {} → {}", p["type"].as_str().unwrap_or("?"), p["now"].as_str().unwrap_or("?"));
    }
    let per = server::per_user(&conns);
    println!("\n{:<16} {:>10} {:>12} {:>12}", "пользователь", "соединений", "↑", "↓");
    if per.is_empty() {
        println!("(активных соединений нет)");
    }
    for (user, (n, up, down)) in &per {
        println!("{user:<16} {n:>10} {:>12} {:>12}", server::human(*up), server::human(*down));
    }
    println!("\n↑/↓ по пользователям — только активные сейчас соединения.");
    log::debug!(target: "server", "status: {} connection(s), {} user(s)", conns["connections"].as_array().map_or(0, Vec::len), per.len());
    Ok(ExitCode::SUCCESS)
}

/// `cproxy service install|uninstall|status` (service.rs, только Linux + systemd).
fn service_cmd(a: &Args) -> Result<ExitCode, String> {
    let what = a.pos.first().map(String::as_str).unwrap_or("status");
    if what == "status" {
        if !service::has_systemd() {
            return Err("systemd service: Linux with systemd only".into());
        }
        let _ = std::process::Command::new("systemctl").args(["status", "--no-pager", "cproxy.service"]).status();
        return Ok(ExitCode::SUCCESS);
    }
    let steps = match what {
        "install" => {
            let src = service::Sources {
                data: store::data_dir(),
                cproxy: std::env::current_exe().map_err(|e| e.to_string())?,
                sing_box: sing_box_bin(a)?,
                xray: store::find_bin("xray", a.xray.as_deref(), "CPROXY_XRAY"),
            };
            // Полный лог по умолчанию (решение пользователя на время отладки), --no-debug — без логов.
            service::plan(&src, a.debug != Some(false), service::user_exists())?
        }
        "uninstall" => service::uninstall_plan(a.purge),
        _ => return Err("usage: cproxy service install [--no-debug] [--dry-run] | uninstall [--purge] [--dry-run] | status".into()),
    };
    if a.dry_run {
        println!("план (--dry-run, ничего не выполняется):");
        for (i, s) in steps.iter().enumerate() {
            println!("  {:>2}. {s}", i + 1);
        }
        let unit = steps.iter().find_map(|s| match s {
            service::Step::Write { to, text, .. } if to.ends_with("cproxy.service") => Some(text.clone()),
            _ => None,
        });
        if let Some(text) = unit {
            println!("\n{}:\n{text}", service::UNIT);
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !service::has_systemd() {
        return Err("systemd service: Linux with systemd only (--dry-run shows the plan anywhere)".into());
    }
    if !elevate::is_admin() {
        log::info!(target: "service", "service {what} needs root: relaunching with sudo");
        return elevate::relaunch_elevated(&a.argv);
    }
    if what == "install" && running() {
        return Err("a cproxy instance is running from your data dir: stop it first (cproxy stop) — the service uses the same port".into());
    }
    service::execute(&steps)?;
    if what == "install" {
        println!("служба установлена и запущена: cproxy service status; логи — {}/logs; sudo {}/cproxy server status", service::HOME, service::LIB);
    } else if a.purge {
        println!("служба удалена вместе с ключами сервера");
    } else {
        println!("служба удалена (ключи остались в {}; --purge — удалить)", service::HOME);
    }
    Ok(ExitCode::SUCCESS)
}

/// Ссылки и QR для Shadowrocket. Ссылка содержит UUID: в лог не пишется.
fn server_link(name: &str) -> Result<ExitCode, String> {
    let cfg = server::Config::load()?;
    let keys = server::Keys::load()?;
    let d = cfg.devices.iter().find(|d| d.name == name).ok_or(format!("no device `{name}`: cproxy server user add {name}"))?;
    println!("Shadowrocket: отсканируйте QR камерой приложения («+» в правом верхнем углу → значок сканера)");
    println!("или скопируйте ссылку и откройте Shadowrocket — он предложит добавить узел.\n");
    for x in &d.exits {
        let Some(l) = server::link(&cfg, &keys, name, *x) else { continue };
        let what = match x {
            SrvExit::Direct => "выход с домашнего IP",
            SrvExit::Proxy => "выход через VPS",
            SrvExit::Lan => "только домашняя сеть",
        };
        println!("{} — {what}\n{l}\n{}", x.node_name(), server::qr(&l)?);
    }
    log::debug!(target: "server", "printed {} link(s) for `{name}`", d.exits.len());
    Ok(ExitCode::SUCCESS)
}

fn gen(a: &Args) -> Result<ExitCode, String> {
    let text = serde_json::to_string_pretty(&build(a)?.config).unwrap();
    match &a.out {
        Some(path) => {
            std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))?;
            log::info!(target: "cli", "written {path}");
        }
        None => println!("{text}"),
    }
    Ok(ExitCode::SUCCESS)
}

type Pumps = Vec<std::thread::JoinHandle<()>>;

/// Запускает ядро с конфигом через stdin (секреты не попадают на диск) и пересылает его вывод в лог.
fn spawn_with_stdin(
    bin: &std::path::Path,
    args: &[&str],
    config: &serde_json::Value,
    target: &'static str,
    origins: Arc<Vec<String>>,
) -> Result<(Child, Pumps), String> {
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    supervisor::os::tie_to_parent(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", bin.display()))?;
    log::debug!(target: "cli", "spawned {target} pid {}", child.id());
    child.stdin.take().unwrap().write_all(config.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let pumps = vec![
        pump(child.stderr.take().unwrap(), target, origins.clone()),
        pump(child.stdout.take().unwrap(), target, origins),
    ];
    Ok((child, pumps))
}

fn run(a: &Args) -> Result<ExitCode, String> {
    // `cproxy run` в консоли: правил/подключения нет или файл перенесли → спросить, а не падать.
    if !a.server && terminal() {
        let s = Settings::load();
        let rules = a.pos.is_empty() && (stale(&s.rules) || s.rules.is_none() && s.connection.is_none() && a.nodes.is_none());
        let connection = a.nodes.is_none() && (stale(&s.connection) || s.rules.is_none() && s.connection.is_none() && a.pos.is_empty());
        if rules || connection {
            log::debug!(target: "cli", "asking for configs: rules={rules} connection={connection}");
            ask_configs(&mut Settings::load(), rules, connection);
        }
    }
    // Сервер не трогает трафик этой машины: без TUN и системного прокси.
    let tun = !a.server && tun_wanted(a);
    let ks = kill_switch_wanted(a);
    if ks {
        killswitch::supported()?;
    }
    if (tun || ks) && !elevate::is_admin() {
        // Windows: UAC → новое окно с теми же аргументами, это окно — всё.
        // Linux/macOS: sudo в этом же терминале, ждём экземпляр под root (elevate.rs).
        log::info!(target: "cli", "{} needs administrator rights: relaunching elevated", if tun { "TUN" } else { "kill switch" });
        let code = elevate::relaunch_elevated(&a.argv)?;
        if cfg!(windows) {
            println!("
TUN: cproxy запущен в новом окне с правами администратора. Это окно можно закрыть.");
        }
        return Ok(code);
    }
    let dir = store::data_dir();
    // Один экземпляр: второй сломал бы порт и системный прокси первого.
    if let Some(prev) = RunState::load(&dir) {
        if prev.is_running() {
            return Err(format!("cproxy is already running (pid {}, {}); stop it: cproxy stop", prev.pid, prev.listeners.join(", ")));
        }
        // Прошлый экземпляр убит: добить его ядра (Unix; на Windows их уже убрал Job Object).
        supervisor::kill_stale(&prev);
        RunState::remove(&dir);
    }
    if a.server {
        let c = server::Config::load()?;
        server_port_precheck(&c.listen, c.port)?;
    }
    // Прошлый запуск убит, не вернув системный прокси / kill switch → вернуть до всего остального.
    sysproxy::recover_stale();
    killswitch::recover_stale();
    // Ядра, запущенные дальше, гибнут вместе с cproxy (Windows Job Object, ARCHITECTURE.md §13).
    match supervisor::os::kill_children_on_exit() {
        Ok(()) => log::debug!(target: "supervisor", "job object: cores are killed when cproxy exits"),
        Err(e) => log::debug!(target: "supervisor", "job object: {e}"),
    }
    let sing_box = store::find_bin("sing-box", a.sing_box.as_deref(), "CPROXY_SING_BOX")
        .ok_or("sing-box not found: run scripts/fetch-sing-box.ps1 (or .sh), or pass --sing-box PATH")?;
    log::info!(target: "cli", "sing-box: {}", sing_box.display());
    if let Ok(out) = std::process::Command::new(&sing_box).arg("version").output() {
        let v = String::from_utf8_lossy(&out.stdout);
        log::debug!(target: "cli", "sing-box {}", v.lines().next().unwrap_or("?").trim_start_matches("sing-box version "));
    }
    if !a.server && fetch(a, true)? != ExitCode::SUCCESS {
        log::warn!(target: "cli", "some resources failed to download; rules using them are skipped");
    }
    let out = build(a)?;
    if a.opts.listen.as_deref() == Some("0.0.0.0") {
        log::warn!(target: "cli", "--lan exposes the proxy to the local network without a password");
    }

    // Ctrl+C получают cproxy, sing-box и Xray (одна консоль / группа процессов). Супервизор видит флаг
    // и останавливает всё, не перезапуская. Второй Ctrl+C — немедленный выход (ядра убьёт Job Object).
    let presses = Arc::new(AtomicUsize::new(0));
    let p = presses.clone();
    let _ = ctrlc::set_handler(move || {
        // Системный прокси возвращаем сразу: дальше трафик пойдёт напрямую, а не в умирающий порт.
        sysproxy::restore();
        if p.fetch_add(1, Ordering::SeqCst) == 0 {
            log::info!(target: "cli", "Ctrl+C / stop: shutting down (press again to force)");
        } else {
            log::warn!(target: "cli", "second Ctrl+C: exiting now");
            log::logger().flush();
            std::process::exit(130);
        }
    });
    // После ctrlc: закрытие окна / выход из системы восстанавливают прокси синхронно (Windows).
    sysproxy::install_close_handler();

    // Порядок важен: Xray (узлы xhttp, ARCHITECTURE.md §11) раньше sing-box — тот ходит в его порты.
    // Нет Xray — ошибка запуска, а не тихий пропуск узлов. Перезапуск ядра = тот же конфиг в stdin.
    let mut services = Vec::new();
    // Полные пути ядер: по ним kill switch узнаёт «свои» соединения (WFP app-id).
    let sing_box_path = std::path::absolute(&sing_box).unwrap_or_else(|_| sing_box.clone());
    let mut xray_path = None;
    if let Some(cfg) = out.xray.clone() {
        let bin = store::find_bin("xray", a.xray.as_deref(), "CPROXY_XRAY")
            .ok_or("xray not found (needed for xhttp nodes): run scripts/fetch-xray.ps1 (or .sh), or pass --xray PATH")?;
        log::info!(target: "cli", "xray: {} ({} node(s))", bin.display(), cfg["outbounds"].as_array().map_or(0, Vec::len));
        xray_path = Some(std::path::absolute(&bin).unwrap_or_else(|_| bin.clone()));
        services.push(Service::new(
            "xray",
            Box::new(move || spawn_with_stdin(&bin, &["run", "-format", "json", "-c", "stdin:"], &cfg, "xray", Arc::default())),
        ));
    }
    {
        let (config, origins) = (out.config.clone(), Arc::new(out.rule_origins.clone()));
        services.push(Service::new(
            "sing-box",
            Box::new(move || spawn_with_stdin(&sing_box, &["run", "-c", "stdin", "--disable-color"], &config, "sing-box", origins.clone())),
        ));
    }
    // Kill switch — до запуска ядер: ни одного соединения мимо них. Ядра разрешаются по пути (Windows: app-id).
    if ks {
        let mut programs = vec![sing_box_path.clone()];
        if let Some(x) = &xray_path {
            programs.push(x.clone());
        }
        killswitch::enable(&killswitch::Allow { programs, tun })?;
    }
    let started = Instant::now();
    let mut sup = match Supervisor::start(services) {
        Ok(s) => s,
        Err(e) => {
            killswitch::disable();
            return Err(e);
        }
    };
    log::info!(target: "cli", "cproxy: listening on {} (Ctrl+C or `cproxy stop` to stop)", out.listeners.join(", "));
    let state = RunState {
        pid: std::process::id(),
        started_unix: RunState::now_unix(),
        listeners: out.listeners.clone(),
        cores: ["xray", "sing-box"].iter().filter_map(|n| sup.pid(n).map(|p| (n.to_string(), p))).collect(),
        log: a.log_path.clone(),
    };
    if let Err(e) = state.save(&dir) {
        log::warn!(target: "supervisor", "{e}");
    }
    let api = out.config.pointer("/experimental/clash_api").map(|v| (v["external_controller"].as_str().unwrap_or("").to_string(), v["secret"].as_str().unwrap_or("").to_string()));
    if let Some((addr, secret)) = &api {
        match clash::save(addr, secret) {
            Ok(()) => log::debug!(target: "clash", "clash api on {addr} (cproxy groups|select|test, server status)"),
            Err(e) => log::warn!(target: "server", "{e}"),
        }
    }

    // При TUN системный прокси не нужен (трафик и так идёт через TUN) — только по явному флагу.
    let want_sys = !a.server && a.sys_proxy.unwrap_or_else(|| Settings::load().system_proxy && !tun);
    if tun {
        log::info!(target: "cli", "TUN mode: all system traffic goes through the rules (adapter `{}`)", singbox_gen::TUN_NAME);
    }
    if let Some(t) = sysproxy::Target::from_inbounds(&out.inbounds) {
        sysproxy::warn_env_proxies(&t);
    }
    if want_sys {
        enable_system_proxy(&out, &load(a)?, || sup.running("sing-box"));
    } else {
        log::debug!(target: "sysproxy", "system proxy disabled by settings/flag");
    }
    let exit = sup.wait(|| presses.load(Ordering::SeqCst) > 0);
    sysproxy::restore();
    RunState::remove(&dir);
    if api.is_some() {
        clash::remove();
    }
    killswitch::disable();
    match exit {
        Exit::Stopped => {
            log::info!(target: "cli", "stopped after {:?}", started.elapsed());
            Ok(ExitCode::SUCCESS)
        }
        Exit::Failed(e) => Err(e),
    }
}

/// `cproxy stop`: штатно остановить запущенный экземпляр (он сам вернёт системный прокси).
fn stop_cmd() -> Result<ExitCode, String> {
    let dir = store::data_dir();
    let Some(st) = RunState::load(&dir).filter(RunState::is_running) else {
        println!("cproxy не запущен");
        return Ok(ExitCode::SUCCESS);
    };
    supervisor::os::request_stop(st.pid)?;
    log::info!(target: "cli", "stop requested for pid {}", st.pid);
    let t = Instant::now();
    while supervisor::os::alive(st.pid) {
        if t.elapsed() > Duration::from_secs(15) {
            return Err(format!("pid {} did not stop in 15s", st.pid));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("остановлен (pid {})", st.pid);
    Ok(ExitCode::SUCCESS)
}

/// `cproxy status`: настройки + запущенный экземпляр + системный прокси.
fn status_cmd() -> Result<ExitCode, String> {
    Settings::load().print();
    let dir = store::data_dir();
    match RunState::load(&dir).filter(RunState::is_running) {
        Some(st) => {
            let up = RunState::now_unix().saturating_sub(st.started_unix);
            println!("\nrunning     pid {}, up {}h{:02}m, {}", st.pid, up / 3600, up / 60 % 60, st.listeners.join(", "));
            for (name, pid) in &st.cores {
                let alive = supervisor::os::alive(*pid);
                println!("  {name:<9} pid {pid}{}", if alive { "" } else { " (restarted — see log)" });
            }
            if let Some(l) = &st.log {
                println!("  log       {l}");
            }
        }
        None => println!("\nrunning     no"),
    }
    println!("sys-proxy   {}", if sysproxy::has_backup() { "set by cproxy (restored on exit)" } else { "not changed by cproxy" });
    Ok(ExitCode::SUCCESS)
}

/// Ждёт, пока sing-box начнёт принимать соединения, и включает системный прокси.
/// Ошибка — не фатальна: прокси работает, просто программы надо настроить вручную.
fn enable_system_proxy(out: &singbox_gen::Output, doc: &fmt_shadowrocket::Document, mut alive: impl FnMut() -> bool) {
    let Some(target) = sysproxy::Target::from_inbounds(&out.inbounds) else { return };
    let (host, port) = target.http.clone().or(target.socks.clone()).unwrap();
    let addr = format!("{host}:{port}");
    let started = Instant::now();
    loop {
        if !alive() {
            return;
        }
        let ok = addr.parse().ok().is_some_and(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_millis(200)).is_ok());
        if ok {
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            log::warn!(target: "sysproxy", "{addr} is not accepting connections after 10s; system proxy not enabled");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let skip = doc.general("skip-proxy");
    let bypass = sysproxy::bypass_list(skip.as_deref());
    let mut warnings = Vec::new();
    match sysproxy::enable(&target, &bypass, &mut warnings) {
        Ok(()) => log::info!(target: "cli", "system proxy → {} (restored on exit; disable: cproxy set system-proxy off)", sysproxy::describe(&target)),
        Err(e) => log::error!(target: "sysproxy", "cannot enable system proxy: {e}"),
    }
    for w in warnings {
        log::warn!(target: "sysproxy", "{w}");
    }
}

/// Поток, пересылающий вывод дочернего ядра в наш логгер (target `sing-box` / `xray`).
fn pump(r: impl Read + Send + 'static, target: &'static str, origins: Arc<Vec<String>>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            let Ok(line) = line else { break };
            if target == "xray" {
                let (level, msg) = parse_xray_line(&line);
                log::log!(target: "xray", level, "{msg}");
            } else {
                let (level, msg) = parse_sing_box_line(&line);
                log::log!(target: "sing-box", level, "{}", annotate(&msg, &origins));
            }
        }
    })
}

/// `2026/10/10 02:13:11.512707 [Info] app/log: ...` → (Info, `app/log: ...`). Формат — Xray `common/log`.
fn parse_xray_line(line: &str) -> (Level, String) {
    let Some(open) = line.find(" [") else { return (Level::Info, line.to_string()) };
    let Some((tag, msg)) = line[open + 2..].split_once("] ") else { return (Level::Info, line.to_string()) };
    let level = match tag {
        "Debug" => Level::Debug,
        "Info" => Level::Info,
        "Warning" => Level::Warn,
        "Error" => Level::Error,
        _ => return (Level::Info, line.to_string()),
    };
    (level, msg.to_string())
}

/// `INFO[0003] [3471 12ms] router: match[5] ...` → (Info, `[3471 12ms] router: match[5] ...`).
/// Формат — sing-box `log/format.go::writePrefix` (без цвета, без полной метки времени).
/// `[id длительность]` — номер соединения: по нему собирается путь одного запроса.
fn parse_sing_box_line(line: &str) -> (Level, String) {
    let line = strip_ansi(line);
    let level = |s: &str| match s {
        "TRACE" => Some(Level::Trace),
        "DEBUG" => Some(Level::Debug),
        "INFO" => Some(Level::Info),
        "WARN" => Some(Level::Warn),
        "ERROR" | "FATAL" | "PANIC" => Some(Level::Error),
        _ => None,
    };
    if let Some(open) = line.find('[') {
        if let (Some(l), Some(close)) = (level(&line[..open]), line[open..].find("] ")) {
            return (l, line[open + close + 2..].to_string());
        }
    }
    let first = line.split_whitespace().next().unwrap_or("");
    match level(first) {
        Some(l) => (l, line[first.len()..].trim_start().to_string()),
        None => (Level::Info, line),
    }
}

/// Дописывает к `match[i]` исходную строку конфига (singbox_gen::Output::rule_origins).
fn annotate(msg: &str, origins: &[String]) -> String {
    let Some(pos) = msg.find("match[") else { return msg.to_string() };
    let digits: String = msg[pos + 6..].chars().take_while(char::is_ascii_digit).collect();
    match digits.parse::<usize>().ok().and_then(|i| origins.get(i)) {
        Some(origin) => format!("{msg}  ⇐ {origin}"),
        None => msg.to_string(),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sing_box_lines() {
        let (l, m) = parse_sing_box_line("DEBUG[0003] [3471 12ms] router: match[3] rule_set=set-0 => route(PROXY)");
        assert_eq!(l, Level::Debug);
        assert_eq!(m, "[3471 12ms] router: match[3] rule_set=set-0 => route(PROXY)");
        let origins = vec!["a".into(), "b".into(), "c".into(), "[Rule] line 9: RULE-SET,x,PROXY".into()];
        assert!(annotate(&m, &origins).ends_with("⇐ [Rule] line 9: RULE-SET,x,PROXY"));
        assert_eq!(parse_sing_box_line("\x1b[31mFATAL\x1b[0m[0000] start service: bind").0, Level::Error);
        assert_eq!(parse_sing_box_line("random text").1, "random text");
    }

    #[test]
    fn args() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&v(&["run", "x.conf", "--port", "1080", "--log", "debug", "--nodes-mode", "both"])).unwrap();
        assert_eq!((a.opts.port, a.log.as_deref(), a.nodes_mode), (Some(1080), Some("debug"), Some(NodesMode::Both)));
        assert!(parse_args(&v(&["run"])).unwrap().pos.is_empty());
        // --log сильнее --debug; --no-debug выключает лог на этот запуск.
        let a = parse_args(&v(&["run", "--debug"])).unwrap();
        assert_eq!(file_level(&a).unwrap(), LevelFilter::Trace);
        let a = parse_args(&v(&["run", "--debug", "--log", "warn"])).unwrap();
        assert_eq!(file_level(&a).unwrap(), LevelFilter::Warn);
        assert_eq!(file_level(&parse_args(&v(&["run", "--no-debug"])).unwrap()).unwrap(), LevelFilter::Off);
        assert!(parse_args(&v(&["set", "rules"])).is_err());
        assert!(parse_args(&v(&["status", "x"])).is_err());
        assert!(parse_args(&v(&["bogus"])).is_err());
    }

    #[test]
    fn xray_lines() {
        let (l, m) = parse_xray_line("2026/10/10 02:13:11.512707 [Warning] core: something");
        assert_eq!((l, m.as_str()), (Level::Warn, "core: something"));
        assert_eq!(parse_xray_line("Xray 26.3.27").1, "Xray 26.3.27");
    }

    #[test]
    fn redact_subscription() {
        assert_eq!(settings::redact_source("https://u:p@sub.example.com/api/v1/client/abc?token=x"), "https://sub.example.com/***");
        assert_eq!(settings::redact_source("C:\\a.json"), "C:\\a.json");
    }
}
