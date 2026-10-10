//! Платформенные примитивы супервизора: Job Object (Windows), проверка/имя/убийство процесса по PID,
//! сигнал остановки от `cproxy stop` (Windows — именованное событие, Unix — SIGTERM).

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const STILL_ACTIVE: u32 = 259;
    const WAIT_OBJECT_0: u32 = 0;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimit {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct IoCounters([u64; 6]);
    /// JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, len: u32) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
        fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
        fn TerminateProcess(process: Handle, code: u32) -> i32;
        fn CreateEventW(attrs: *mut c_void, manual: i32, initial: i32, name: *const u16) -> Handle;
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> Handle;
        fn SetEvent(event: Handle) -> i32;
        fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
        fn CloseHandle(h: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: хэндл получен из Open*/Create* и ещё не закрыт.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32, access: u32) -> Option<Owned> {
        // SAFETY: OpenProcess с валидными аргументами; NULL → None.
        let h = unsafe { OpenProcess(access, 0, pid) };
        (!h.is_null()).then_some(Owned(h))
    }

    /// Помещает текущий процесс в Job Object с KILL_ON_JOB_CLOSE: дочерние процессы, запущенные после
    /// этого, попадают в job автоматически и гибнут вместе с нами, даже при аварийном завершении.
    /// Хэндл job намеренно не закрывается (его закроет ОС при выходе — это и есть сигнал).
    pub fn kill_children_on_exit() -> Result<(), String> {
        // SAFETY: создаём безымянный job, структура лимитов — точная раскладка из winnt.h (x64/arm64).
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job.is_null() {
                return Err(format!("CreateJobObjectW failed: {}", GetLastError()));
            }
            let mut info = ExtendedLimit::default();
            info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let len = std::mem::size_of::<ExtendedLimit>() as u32;
            if SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS, &mut info as *mut _ as *mut c_void, len) == 0 {
                return Err(format!("SetInformationJobObject failed: {}", GetLastError()));
            }
            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                return Err(format!("AssignProcessToJobObject failed: {}", GetLastError()));
            }
        }
        Ok(())
    }

    pub fn alive(pid: u32) -> bool {
        let Some(h) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else { return false };
        let mut code = 0u32;
        // SAFETY: валидный хэндл процесса.
        unsafe { GetExitCodeProcess(h.0, &mut code) != 0 && code == STILL_ACTIVE }
    }

    /// Имя исполняемого файла (`sing-box.exe`) — защита от убийства чужого процесса с переиспользованным PID.
    pub fn name(pid: u32) -> Option<String> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: буфер на len символов.
        if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        path.rsplit(['\\', '/']).next().map(str::to_ascii_lowercase)
    }

    pub fn kill(pid: u32) -> bool {
        let Some(h) = open(pid, PROCESS_TERMINATE | SYNCHRONIZE) else { return false };
        // SAFETY: валидный хэндл с правом TERMINATE.
        unsafe { TerminateProcess(h.0, 1) != 0 }
    }

    fn event_name(pid: u32) -> String {
        format!("Local\\cproxy-stop-{pid}")
    }

    /// Событие «остановись», которое выставляет `cproxy stop` (manual-reset, изначально сброшено).
    pub struct StopSignal(Owned);
    unsafe impl Send for StopSignal {}

    impl StopSignal {
        pub fn listen() -> Option<Self> {
            let name = wide(&event_name(std::process::id()));
            // SAFETY: имя с нулём, атрибуты по умолчанию.
            let h = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, name.as_ptr()) };
            (!h.is_null()).then(|| StopSignal(Owned(h)))
        }
        pub fn is_set(&self) -> bool {
            // SAFETY: валидный хэндл события, таймаут 0.
            unsafe { WaitForSingleObject(self.0 .0, 0) == WAIT_OBJECT_0 }
        }
    }

    pub fn request_stop(pid: u32) -> Result<(), String> {
        let name = wide(&event_name(pid));
        // SAFETY: имя с нулём.
        let h = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        if h.is_null() {
            return Err(format!("cannot signal pid {pid} (no stop event; error {})", unsafe { GetLastError() }));
        }
        let h = Owned(h);
        // SAFETY: валидный хэндл с правом MODIFY_STATE.
        if unsafe { SetEvent(h.0) } == 0 {
            return Err("SetEvent failed".into());
        }
        Ok(())
    }
}

#[cfg(unix)]
mod imp {
    //! Без libc: `kill`/`ps` из системы. Job Object нет — осиротевшие ядра добивает следующий запуск
    //! (supervisor::kill_stale по run.json).
    use std::process::{Command, Stdio};

    pub fn kill_children_on_exit() -> Result<(), String> {
        Err("not available on this OS (stale cores are cleaned up on next start)".into())
    }

    fn quiet(cmd: &mut Command) -> bool {
        cmd.stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    pub fn alive(pid: u32) -> bool {
        quiet(Command::new("kill").args(["-0", &pid.to_string()]))
    }

    pub fn name(pid: u32) -> Option<String> {
        let out = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then(|| s.rsplit('/').next().unwrap_or(&s).to_ascii_lowercase())
    }

    pub fn kill(pid: u32) -> bool {
        quiet(Command::new("kill").args(["-9", &pid.to_string()]))
    }

    /// Unix: `cproxy stop` шлёт SIGTERM, его ловит ctrlc (feature `termination`) → обычный путь Ctrl+C.
    pub struct StopSignal;
    impl StopSignal {
        pub fn listen() -> Option<Self> {
            Some(StopSignal)
        }
        pub fn is_set(&self) -> bool {
            false
        }
    }

    pub fn request_stop(pid: u32) -> Result<(), String> {
        if quiet(Command::new("kill").args(["-TERM", &pid.to_string()])) { Ok(()) } else { Err(format!("kill -TERM {pid} failed")) }
    }
}

pub use imp::*;
