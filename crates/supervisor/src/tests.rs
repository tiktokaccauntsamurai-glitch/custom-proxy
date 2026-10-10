use super::*;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Долгий процесс (~30 с) без сети.
fn long() -> Command {
    if cfg!(windows) {
        let mut c = Command::new("ping");
        c.args(["-n", "30", "127.0.0.1"]);
        c
    } else {
        let mut c = Command::new("sleep");
        c.arg("30");
        c
    }
}

/// Процесс, живущий ~`secs` секунд.
fn short(secs: u32) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("ping");
        c.args(["-n", &(secs + 1).to_string(), "127.0.0.1"]);
        c
    } else {
        let mut c = Command::new("sleep");
        c.arg(secs.to_string());
        c
    }
}

fn svc(name: &'static str, mut make: impl FnMut() -> Command + 'static, counter: Arc<AtomicUsize>) -> Service {
    Service::new(
        name,
        Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let child = make().stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| e.to_string())?;
            Ok((child, Vec::new()))
        }),
    )
}

#[test]
fn early_exit_is_startup_error() {
    let n = Arc::new(AtomicUsize::new(0));
    let s = svc("bad", || if cfg!(windows) { let mut c = Command::new("cmd"); c.args(["/c", "exit 3"]); c } else { Command::new("false") }, n.clone());
    let err = Supervisor::start(vec![s]).err().expect("must fail");
    assert!(err.contains("exited at startup"), "{err}");
}

#[test]
fn stop_flag_stops_and_kills() {
    let n = Arc::new(AtomicUsize::new(0));
    let mut sup = Supervisor::start(vec![svc("a", long, n.clone()), svc("b", long, n.clone())]).unwrap();
    let pid = sup.pid("b").unwrap();
    assert!(os::alive(pid));
    let t = Instant::now();
    assert_eq!(sup.wait(|| t.elapsed() > Duration::from_millis(500)), Exit::Stopped);
    assert!(!os::alive(pid), "child must be killed on stop");
}

#[test]
fn crashed_service_is_restarted_then_given_up() {
    let n = Arc::new(AtomicUsize::new(0));
    // Живёт ~1 с, min_uptime 0.5 с → каждое падение «сбой», перезапуск; после MAX_RESTARTS — сдаёмся.
    let s = svc("flaky", || short(1), n.clone()).min_uptime(Duration::from_millis(500));
    let mut sup = Supervisor::start(vec![s]).unwrap();
    let exit = sup.wait(|| false);
    assert!(matches!(&exit, Exit::Failed(m) if m.contains("giving up")), "{exit:?}");
    assert_eq!(n.load(Ordering::SeqCst), 1 + MAX_RESTARTS);
}

#[test]
fn too_short_uptime_is_not_restarted() {
    let n = Arc::new(AtomicUsize::new(0));
    let s = svc("cfg", || short(1), n.clone()); // MIN_UPTIME 5 с > 1 с
    let mut sup = Supervisor::start(vec![s]).unwrap();
    assert!(matches!(sup.wait(|| false), Exit::Failed(_)));
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

#[test]
fn run_state_roundtrip_and_self_checks() {
    let dir = std::env::temp_dir().join(format!("cproxy-sup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let st = RunState { pid: std::process::id(), started_unix: 1, listeners: vec!["mixed 127.0.0.1:7890".into()], cores: vec![("sing-box".into(), 42)], log: None };
    st.save(&dir).unwrap();
    assert_eq!(RunState::load(&dir), Some(st.clone()));
    // Свой PID не считается «другим запущенным экземпляром».
    assert!(!st.is_running());
    assert!(os::alive(std::process::id()));
    assert!(os::name(std::process::id()).is_some());
    RunState::remove(&dir);
    assert!(RunState::load(&dir).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
