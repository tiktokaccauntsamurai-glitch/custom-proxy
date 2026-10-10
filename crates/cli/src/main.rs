//! Бинарь `cproxy`: разбор аргументов и команды (docs/ARCHITECTURE.md §1, §7, §11).
//! check/gen — только генерация; fetch — сеть (store::Cache); run — ещё и процессы sing-box и Xray.
//! Два конфига (settings.rs): правила (`.conf` Shadowrocket) и подключение (узлы, fmt-nodes).
//! Без аргументов — запуск по сохранённым настройкам; файл, перетащенный на exe, сохраняется в нужное поле.
//! `run` включает системный прокси ОС и при выходе возвращает прежний (sysproxy.rs, ARCHITECTURE.md §12).
//! Ядра запускает и перезапускает крейт `supervisor` (Job Object, run.json, `stop`/`status`, §13).
//! TUN (`--tun` / `set tun on`): весь трафик системы; без прав администратора — UAC-перезапуск (elevate.rs, §14).
//! Логирование (logger.rs, ARCHITECTURE.md §10): всё действие cproxy + журналы sing-box и Xray в одном
//! файле, строки `match[i]` sing-box дополняются исходной строкой .conf.

mod elevate;
mod logger;
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
  cproxy status                           настройки и запущенный экземпляр
  cproxy stop                             остановить запущенный cproxy (вернёт системный прокси)
  cproxy sysproxy status|off              системный прокси сейчас / вернуть прежний (если завис)
  cproxy check [rules.conf] [opts]        проверить конфиги
  cproxy fetch [rules.conf] [--via URL] [--force]
                                          скачать RULE-SET / DOMAIN-SET / GEOIP
  cproxy gen   [rules.conf] [-o FILE] [opts]
                                          напечатать конфиг sing-box (содержит секреты!)
  cproxy run   [rules.conf] [opts] [--via URL] [--sing-box PATH] [--xray PATH]
                                          запустить локальный HTTP+SOCKS5 прокси

opts (без них берутся сохранённые настройки):
  --nodes FILE|URL   источник узлов на этот запуск
  --nodes-mode M     auto|connection|rules|both на этот запуск
  --system-proxy / --no-system-proxy   системный прокси на этот запуск
  --tun / --no-tun   режим TUN на этот запуск (при TUN системный прокси не включается)
  --port N       порт для программ (HTTP+SOCKS5). По умолчанию из конфига
                 ([General] http-listen / socks5-listen), иначе 7890
  --lan          слушать 0.0.0.0 (доступ из локальной сети, без пароля)
  --debug / --no-debug   полный лог (trace) в <data>/logs на этот запуск
  --log LEVEL    лог в файл: off|error|warn|info|debug|trace (env CPROXY_LOG).
                 По умолчанию off, или trace при `set debug on`
  -v, --verbose  подробный вывод и в консоль
";

const COMMANDS: [&str; 8] = ["check", "fetch", "gen", "run", "set", "status", "stop", "sysproxy"];

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
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => a.pos.push(s.to_string()),
        }
    }
    let max = match a.cmd.as_str() {
        "set" => 2,
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
                // Файл можно перетащить прямо в окно. Пустой ввод — пропустить.
                while s.rules.is_none() {
                    let a = ask("Правила: путь к .conf Shadowrocket (перетащите файл в окно), Enter — без правил:");
                    if a.is_empty() {
                        break;
                    }
                    if let Err(e) = remember(&mut s, &a) {
                        println!("ошибка: {e}");
                    }
                }
                while s.connection.is_none() {
                    let a = ask("Подключение: файл узлов (ссылки, base64, Clash, sing-box/Xray JSON) или URL подписки, Enter — пропустить:");
                    if a.is_empty() {
                        break;
                    }
                    if let Err(e) = remember(&mut s, &a) {
                        println!("ошибка: {e}");
                    }
                }
            }
            if s.rules.is_none() && s.connection.is_none() {
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
        other => return Err(format!("unknown setting `{other}` (rules|connection|nodes|system-proxy|tun|debug)")),
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
    Ok(fmt_shadowrocket::parse(&text))
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
    singbox_gen::Options {
        listen: a.opts.listen.clone(),
        port: a.opts.port,
        log_level: a.opts.log_level.clone(),
        nodes: None,
        alloc_port: Some(free_port),
        tun: tun_wanted(a),
        tun_exclude: Vec::new(),
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
    let doc = load(a)?;
    let cache = Cache::open().map_err(|e| e.to_string())?;
    let mut opts = options(a);
    opts.nodes = load_nodes(a, &doc)?;
    if opts.tun {
        let nodes = opts.nodes.clone().unwrap_or_else(|| singbox_gen::conf_nodes(&doc).unwrap_or_default());
        opts.tun_exclude = xray_server_cidrs(&nodes);
    }
    let started = Instant::now();
    let out = singbox_gen::generate(&doc, &cache, &opts).map_err(|e| e.to_string())?;
    log::debug!(target: "cli", "generated in {:?}: {} bytes JSON", started.elapsed(), out.config.to_string().len());
    // Карта для чтения лога sing-box: match[i] → строка конфига.
    for (i, origin) in out.rule_origins.iter().enumerate() {
        log::debug!(target: "cli", "route.rules[{i}] ⇐ {origin}");
    }
    log::debug!(target: "cli", "route.final = {} ⇐ {} (no `match` line in sing-box log when final is used)", out.config["route"]["final"], out.final_origin);
    log::trace!(target: "cli", "sing-box config (secrets redacted): {}", singbox_gen::redact(&out.config));
    Ok(out)
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
    let mut child = std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    let tun = tun_wanted(a);
    if tun && !elevate::is_admin() {
        // wintun создаёт только администратор: UAC → новое окно с теми же аргументами, это окно — всё.
        log::info!(target: "cli", "TUN needs administrator rights: asking via UAC");
        elevate::relaunch_elevated(&a.argv)?;
        println!("
TUN: cproxy запущен в новом окне с правами администратора. Это окно можно закрыть.");
        return Ok(ExitCode::SUCCESS);
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
    // Прошлый запуск убит, не вернув системный прокси → вернуть до всего остального.
    sysproxy::recover_stale();
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
    if fetch(a, true)? != ExitCode::SUCCESS {
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
    if let Some(cfg) = out.xray.clone() {
        let bin = store::find_bin("xray", a.xray.as_deref(), "CPROXY_XRAY")
            .ok_or("xray not found (needed for xhttp nodes): run scripts/fetch-xray.ps1 (or .sh), or pass --xray PATH")?;
        log::info!(target: "cli", "xray: {} ({} node(s))", bin.display(), cfg["outbounds"].as_array().map_or(0, Vec::len));
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
    let started = Instant::now();
    let mut sup = Supervisor::start(services)?;
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

    // При TUN системный прокси не нужен (трафик и так идёт через TUN) — только по явному флагу.
    let want_sys = a.sys_proxy.unwrap_or_else(|| Settings::load().system_proxy && !tun);
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
