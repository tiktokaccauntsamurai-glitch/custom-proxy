//! Kill switch: пока cproxy запущен, исходящий трафик разрешён только ядрам (sing-box, Xray), loopback, домашней
//! сети, DHCP и (в TUN) адресам TUN. Упало ядро — трафик не уходит напрямую (решение пользователя, сессия 6:
//! брандмауэр ОС, в TUN и с системным прокси, по умолчанию выключен; `set kill-switch on|off`).
//!
//! Вызывает `main.rs::run`: `recover_stale` до всего, `enable` после генерации и до запуска ядер, `disable` при
//! выходе (а также при закрытии окна — sysproxy.rs::on_close). Убили cproxy — защита остаётся (fail-closed) до
//! `cproxy killswitch off`, следующего `cproxy run` или перезагрузки. Состояние — `<data>/killswitch.json`.
//!
//! Windows — WFP (fwpuclnt.dll, FFI без зависимостей): свой подслой с весом 0xFFFF, жёсткий block всего на
//! `ALE_AUTH_CONNECT_V4/V6` (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT — разрешающие правила Windows Firewall его не
//! перекрывают) и permit с большим весом для app-id ядер и адресов. Обычные правила Windows Firewall не подходят:
//! встроенные разрешающие правила (Core Networking, приложения Store) пропускали бы трафик мимо. Фильтры не
//! persistent: живут до удаления или перезагрузки. Структуры и GUID — Windows SDK 10.0.26100 (fwptypes.h,
//! fwpmtypes.h, fwpmu.h). ARCHITECTURE.md §17.
//! Linux — nftables: таблица `inet cproxy_killswitch`, `policy drop` на output; ядра узнаются по метке сокета
//! (`route.default_mark` sing-box, `sockopt.mark` Xray — `singbox_gen::Options::fwmark`). Нужен root.

use std::path::PathBuf;

/// Метка сокетов ядер (Linux, SO_MARK). Совпадает с `Options::fwmark` в main.rs.
pub const FWMARK: u32 = 0x2c70;
/// Сети, которые остаются доступны: loopback, частные, link-local, multicast, broadcast.
pub const LAN_V4: &[(&str, u8)] = &[("127.0.0.0", 8), ("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16), ("169.254.0.0", 16), ("224.0.0.0", 4), ("255.255.255.255", 32)];
pub const LAN_V6: &[(&str, u8)] = &[("::1", 128), ("fe80::", 10), ("fc00::", 7), ("ff00::", 8)];
/// Адреса TUN (`singbox_gen::tun_inbound`): исходящие соединения программ в TUN идут с них.
pub const TUN_V4: (&str, u8) = ("172.19.0.0", 30);
pub const TUN_V6: (&str, u8) = ("fdfe:dcba:9876::", 126);

pub struct Allow {
    /// Ядра (полные пути): sing-box, Xray.
    pub programs: Vec<PathBuf>,
    pub tun: bool,
}

fn state_path() -> PathBuf {
    crate::store::data_dir().join("killswitch.json")
}

pub fn active() -> bool {
    state_path().exists()
}

/// Включить. Файл состояния пишется до изменения: упадём посередине — `disable` всё равно уберёт.
pub fn enable(allow: &Allow) -> Result<(), String> {
    let p = state_path();
    let state = serde_json::json!({"pid": std::process::id(), "tun": allow.tun, "programs": allow.programs});
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&p, state.to_string()).map_err(|e| format!("{}: {e}", p.display()))?;
    match os::enable(allow) {
        Ok(()) => {
            log::info!(target: "killswitch", "kill switch on: only {} may reach the internet{}", allow.programs.iter().map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()).collect::<Vec<_>>().join(", "), if allow.tun { " (+ TUN)" } else { "" });
            Ok(())
        }
        Err(e) => {
            let _ = os::disable();
            let _ = std::fs::remove_file(&p);
            Err(format!("kill switch: {e}"))
        }
    }
}

pub fn disable() {
    if !active() {
        return;
    }
    match os::disable() {
        Ok(()) => {
            let _ = std::fs::remove_file(state_path());
            log::info!(target: "killswitch", "kill switch off");
        }
        Err(e) => log::error!(target: "killswitch", "cannot remove kill switch: {e} (run `cproxy killswitch off` as administrator/root, or reboot)"),
    }
}

/// Прошлый запуск не снял защиту (убит) — снять до всего остального, иначе даже скачивание правил не пройдёт.
pub fn recover_stale() {
    if active() {
        log::warn!(target: "killswitch", "previous run left the kill switch on ({}); removing it", state_path().display());
        disable();
    }
}

/// Права на изменение брандмауэра есть только у администратора/root.
pub fn supported() -> Result<(), String> {
    if cfg!(any(windows, target_os = "linux")) {
        Ok(())
    } else {
        Err("kill switch is supported on Windows and Linux only (macOS: not yet)".into())
    }
}

#[allow(dead_code)]
fn v4(ip: &str) -> u32 {
    ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0)
}

#[allow(dead_code)]
fn v6(ip: &str) -> [u8; 16] {
    ip.parse::<std::net::Ipv6Addr>().map(|a| a.octets()).unwrap_or([0; 16])
}

/// Текст для `nft -f -` (Linux). Пересоздаёт таблицу атомарно (`table` + `delete table` + `table {…}`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn nft_script(tun: bool) -> String {
    let lan4: Vec<String> = LAN_V4.iter().map(|(a, b)| if *b == 32 { a.to_string() } else { format!("{a}/{b}") }).collect();
    let lan6: Vec<String> = LAN_V6.iter().map(|(a, b)| format!("{a}/{b}")).collect();
    format!(
        "table inet cproxy_killswitch\ndelete table inet cproxy_killswitch\ntable inet cproxy_killswitch {{\n  chain output {{\n    type filter hook output priority filter; policy drop;\n    oifname \"lo\" accept\n    meta mark {FWMARK:#x} accept\n{}    ip daddr {{ {} }} accept\n    ip6 daddr {{ {} }} accept\n    udp dport {{ 67, 547 }} accept\n  }}\n}}\n",
        if tun { format!("    oifname \"{}\" accept\n", singbox_gen::TUN_NAME) } else { String::new() },
        lan4.join(", "),
        lan6.join(", ")
    )
}

#[cfg(target_os = "linux")]
mod os {
    use super::Allow;
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn nft(script: &str) -> Result<(), String> {
        let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("nft: {e} (install nftables)"))?;
        child.stdin.take().unwrap().write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() { Ok(()) } else { Err(format!("nft: {}", String::from_utf8_lossy(&out.stderr).trim())) }
    }

    pub fn enable(allow: &Allow) -> Result<(), String> {
        let s = super::nft_script(allow.tun);
        log::debug!(target: "killswitch", "nft -f -:\n{s}");
        nft(&s)
    }

    pub fn disable() -> Result<(), String> {
        // `table` + `delete` — без ошибки, если таблицы уже нет.
        nft("table inet cproxy_killswitch\ndelete table inet cproxy_killswitch\n")
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod os {
    use super::Allow;
    pub fn enable(_: &Allow) -> Result<(), String> {
        super::supported()
    }
    pub fn disable() -> Result<(), String> {
        Ok(())
    }
}

#[cfg(windows)]
mod os {
    //! WFP через fwpuclnt.dll. Раскладка структур — repr(C) по fwptypes.h / fwpmtypes.h (x64 и x86 совпадают
    //! по смыслу: объединения — на указатель/u64).
    use super::{Allow, LAN_V4, LAN_V6, TUN_V4, TUN_V6};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }

    const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
        Guid { d1, d2, d3, d4 }
    }

    // fwpmu.h
    const LAYER_CONNECT_V4: Guid = guid(0xc38d57d1, 0x05a7, 0x4c33, [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82]);
    const LAYER_CONNECT_V6: Guid = guid(0x4a72393b, 0x319f, 0x44bc, [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4]);
    const COND_APP_ID: Guid = guid(0xd78e1e87, 0x8644, 0x4ea5, [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71]);
    const COND_REMOTE_ADDR: Guid = guid(0xb235ae9a, 0x1d64, 0x49b8, [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45]);
    const COND_LOCAL_ADDR: Guid = guid(0xd9ee00de, 0xc1ef, 0x4617, [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57]);
    const COND_PROTOCOL: Guid = guid(0x3971ef2b, 0x623e, 0x4f9a, [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7]);
    const COND_REMOTE_PORT: Guid = guid(0xc35a604d, 0xd22b, 0x4e1a, [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b]);

    /// Свои ключи: «cprx» + «ks» + номер. Подслой — номер 0xffff, фильтры — 0..MAX_FILTERS.
    const fn our_key(n: u16) -> Guid {
        guid(0x63707278, 0x6b73, n, [0x8a, 0x1e, 0x5c, 0x3d, 0x77, 0x02, 0x4f, 0x91])
    }
    const SUBLAYER: Guid = our_key(0xffff);
    const MAX_FILTERS: u16 = 64;

    // fwptypes.h: FWP_DATA_TYPE
    const FWP_EMPTY: u32 = 0;
    const FWP_UINT8: u32 = 1;
    const FWP_UINT16: u32 = 2;
    const FWP_BYTE_BLOB_TYPE: u32 = 12;
    const FWP_V4_ADDR_MASK: u32 = 0x100;
    const FWP_V6_ADDR_MASK: u32 = 0x101;
    const FWP_MATCH_EQUAL: u32 = 0;
    const FWP_ACTION_BLOCK: u32 = 0x1001;
    const FWP_ACTION_PERMIT: u32 = 0x1002;
    const FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: u32 = 0x8;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
    const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320007;

    #[repr(C)]
    struct DisplayData {
        name: *const u16,
        description: *const u16,
    }

    #[repr(C)]
    struct ByteBlob {
        size: u32,
        data: *mut u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union ValueU {
        u8_: u8,
        u16_: u16,
        u64_: u64,
        ptr: *const c_void,
    }

    /// FWP_VALUE0 и FWP_CONDITION_VALUE0 одинаковы по раскладке: тип + объединение размера указателя.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Value {
        kind: u32,
        u: ValueU,
    }

    #[repr(C)]
    struct V4Mask {
        addr: u32,
        mask: u32,
    }

    #[repr(C)]
    struct V6Mask {
        addr: [u8; 16],
        prefix: u8,
    }

    #[repr(C)]
    struct Condition {
        field: Guid,
        match_type: u32,
        value: Value,
    }

    #[repr(C)]
    struct Action {
        kind: u32,
        filter_type: Guid,
    }

    #[repr(C)]
    union FilterCtx {
        raw: u64,
        key: Guid,
    }

    #[repr(C)]
    struct Filter {
        filter_key: Guid,
        display: DisplayData,
        flags: u32,
        provider_key: *const Guid,
        provider_data: ByteBlob,
        layer_key: Guid,
        sublayer_key: Guid,
        weight: Value,
        num_conditions: u32,
        conditions: *const Condition,
        action: Action,
        ctx: FilterCtx,
        reserved: *const Guid,
        filter_id: u64,
        effective_weight: Value,
    }

    #[repr(C)]
    struct SubLayer {
        key: Guid,
        display: DisplayData,
        flags: u32,
        provider_key: *const Guid,
        provider_data: ByteBlob,
        weight: u16,
    }

    #[link(name = "fwpuclnt")]
    extern "system" {
        fn FwpmEngineOpen0(server: *const u16, authn: u32, ident: *const c_void, session: *const c_void, engine: *mut *mut c_void) -> u32;
        fn FwpmEngineClose0(engine: *mut c_void) -> u32;
        fn FwpmTransactionBegin0(engine: *mut c_void, flags: u32) -> u32;
        fn FwpmTransactionCommit0(engine: *mut c_void) -> u32;
        fn FwpmTransactionAbort0(engine: *mut c_void) -> u32;
        fn FwpmSubLayerAdd0(engine: *mut c_void, sublayer: *const SubLayer, sd: *const c_void) -> u32;
        fn FwpmSubLayerDeleteByKey0(engine: *mut c_void, key: *const Guid) -> u32;
        fn FwpmFilterAdd0(engine: *mut c_void, filter: *const Filter, sd: *const c_void, id: *mut u64) -> u32;
        fn FwpmFilterDeleteByKey0(engine: *mut c_void, key: *const Guid) -> u32;
        fn FwpmGetAppIdFromFileName0(file: *const u16, app_id: *mut *mut ByteBlob) -> u32;
        fn FwpmFreeMemory0(p: *mut *mut c_void);
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn check(what: &str, rc: u32) -> Result<(), String> {
        match rc {
            0 => Ok(()),
            5 => Err(format!("{what}: access denied (administrator rights needed)")),
            _ => Err(format!("{what}: error 0x{rc:08x}")),
        }
    }

    struct Engine(*mut c_void);

    impl Engine {
        fn open() -> Result<Self, String> {
            let mut h = std::ptr::null_mut();
            // SAFETY: локальный движок, без сессии (не dynamic: фильтры переживают закрытие дескриптора).
            check("FwpmEngineOpen0", unsafe { FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), std::ptr::null(), &mut h) })?;
            Ok(Engine(h))
        }

        /// Всё внутри одной транзакции: либо все фильтры, либо ни одного.
        fn transaction(&self, f: impl FnOnce(&Engine) -> Result<(), String>) -> Result<(), String> {
            // SAFETY: дескриптор открыт.
            check("FwpmTransactionBegin0", unsafe { FwpmTransactionBegin0(self.0, 0) })?;
            match f(self) {
                Ok(()) => check("FwpmTransactionCommit0", unsafe { FwpmTransactionCommit0(self.0) }),
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.0) };
                    Err(e)
                }
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: дескриптор из FwpmEngineOpen0.
            unsafe { FwpmEngineClose0(self.0) };
        }
    }

    /// App-id программы (FWP_BYTE_BLOB от WFP; освобождается FwpmFreeMemory0).
    struct AppId(*mut ByteBlob);

    impl AppId {
        fn of(path: &std::path::Path) -> Result<Self, String> {
            let w = wide(&path.to_string_lossy());
            let mut blob = std::ptr::null_mut();
            // SAFETY: строка с нулём на конце; blob выделяет WFP.
            check(&format!("FwpmGetAppIdFromFileName0({})", path.display()), unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) })?;
            Ok(AppId(blob))
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            let mut p = self.0 as *mut c_void;
            // SAFETY: память выделена WFP.
            unsafe { FwpmFreeMemory0(&mut p) };
        }
    }

    fn value(kind: u32, u: ValueU) -> Value {
        Value { kind, u }
    }

    fn cond(field: Guid, v: Value) -> Condition {
        Condition { field, match_type: FWP_MATCH_EQUAL, value: v }
    }

    struct Builder<'a> {
        engine: &'a Engine,
        next: u16,
        name: Vec<u16>,
    }

    impl Builder<'_> {
        fn add(&mut self, layer: Guid, weight: u8, action: u32, conds: &[Condition]) -> Result<(), String> {
            if self.next >= MAX_FILTERS {
                return Err("too many kill switch filters".into());
            }
            let f = Filter {
                filter_key: our_key(self.next),
                display: DisplayData { name: self.name.as_ptr(), description: std::ptr::null() },
                flags: if action == FWP_ACTION_BLOCK { FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT } else { 0 },
                provider_key: std::ptr::null(),
                provider_data: ByteBlob { size: 0, data: std::ptr::null_mut() },
                layer_key: layer,
                sublayer_key: SUBLAYER,
                weight: value(FWP_UINT8, ValueU { u8_: weight }),
                num_conditions: conds.len() as u32,
                conditions: if conds.is_empty() { std::ptr::null() } else { conds.as_ptr() },
                action: Action { kind: action, filter_type: guid(0, 0, 0, [0; 8]) },
                ctx: FilterCtx { raw: 0 },
                reserved: std::ptr::null(),
                filter_id: 0,
                effective_weight: value(FWP_EMPTY, ValueU { u64_: 0 }),
            };
            let mut id = 0u64;
            // SAFETY: все указатели в `f` и `conds` живут до возврата.
            check("FwpmFilterAdd0", unsafe { FwpmFilterAdd0(self.engine.0, &f, std::ptr::null(), &mut id) })?;
            log::debug!(target: "killswitch", "wfp filter #{} id {id}: weight {weight} {} with {} condition(s)", self.next, if action == FWP_ACTION_BLOCK { "BLOCK" } else { "permit" }, conds.len());
            self.next += 1;
            Ok(())
        }
    }

    pub fn enable(allow: &Allow) -> Result<(), String> {
        // Старые фильтры (прошлый запуск) — убрать: ключи те же.
        let _ = disable();
        let apps: Vec<AppId> = allow.programs.iter().map(|p| AppId::of(p)).collect::<Result<_, _>>()?;
        let engine = Engine::open()?;
        let name = wide("cproxy kill switch");
        engine.transaction(|e| {
            let sub = SubLayer {
                key: SUBLAYER,
                display: DisplayData { name: name.as_ptr(), description: std::ptr::null() },
                flags: 0,
                provider_key: std::ptr::null(),
                provider_data: ByteBlob { size: 0, data: std::ptr::null_mut() },
                weight: 0xffff,
            };
            // SAFETY: структура и имя живут до возврата.
            check("FwpmSubLayerAdd0", unsafe { FwpmSubLayerAdd0(e.0, &sub, std::ptr::null()) })?;
            let mut b = Builder { engine: e, next: 0, name: name.clone() };
            let v4m: Vec<V4Mask> = LAN_V4.iter().map(|(a, p)| V4Mask { addr: super::v4(a), mask: if *p == 0 { 0 } else { u32::MAX << (32 - *p as u32) } }).collect();
            let v6m: Vec<V6Mask> = LAN_V6.iter().map(|(a, p)| V6Mask { addr: super::v6(a), prefix: *p }).collect();
            let tun4 = V4Mask { addr: super::v4(TUN_V4.0), mask: u32::MAX << (32 - TUN_V4.1 as u32) };
            let tun6 = V6Mask { addr: super::v6(TUN_V6.0), prefix: TUN_V6.1 };
            for (layer, v6) in [(LAYER_CONNECT_V4, false), (LAYER_CONNECT_V6, true)] {
                // 1. Ядра — куда угодно.
                for app in &apps {
                    b.add(layer, 15, FWP_ACTION_PERMIT, &[cond(COND_APP_ID, value(FWP_BYTE_BLOB_TYPE, ValueU { ptr: app.0 as *const c_void }))])?;
                }
                // 2. Домашняя сеть и loopback (условия одного поля — ИЛИ).
                let lan: Vec<Condition> = if v6 {
                    v6m.iter().map(|m| cond(COND_REMOTE_ADDR, value(FWP_V6_ADDR_MASK, ValueU { ptr: m as *const V6Mask as *const c_void }))).collect()
                } else {
                    v4m.iter().map(|m| cond(COND_REMOTE_ADDR, value(FWP_V4_ADDR_MASK, ValueU { ptr: m as *const V4Mask as *const c_void }))).collect()
                };
                b.add(layer, 14, FWP_ACTION_PERMIT, &lan)?;
                // 3. TUN: соединения программ в TUN идут с его адреса — их принимает sing-box.
                if allow.tun {
                    let c = if v6 {
                        cond(COND_LOCAL_ADDR, value(FWP_V6_ADDR_MASK, ValueU { ptr: &tun6 as *const V6Mask as *const c_void }))
                    } else {
                        cond(COND_LOCAL_ADDR, value(FWP_V4_ADDR_MASK, ValueU { ptr: &tun4 as *const V4Mask as *const c_void }))
                    };
                    b.add(layer, 14, FWP_ACTION_PERMIT, &[c])?;
                }
                // 4. DHCP (UDP 67 / DHCPv6 547): без него сеть отвалится при продлении аренды.
                let port = if v6 { 547 } else { 67 };
                b.add(layer, 14, FWP_ACTION_PERMIT, &[cond(COND_PROTOCOL, value(FWP_UINT8, ValueU { u8_: 17 })), cond(COND_REMOTE_PORT, value(FWP_UINT16, ValueU { u16_: port }))])?;
                // 5. Всё остальное — жёсткий block.
                b.add(layer, 0, FWP_ACTION_BLOCK, &[])?;
            }
            log::debug!(target: "killswitch", "wfp: sublayer + {} filters", b.next);
            Ok(())
        })
    }

    pub fn disable() -> Result<(), String> {
        let engine = Engine::open()?;
        engine.transaction(|e| {
            for n in 0..MAX_FILTERS {
                let k = our_key(n);
                // SAFETY: ключ живёт до возврата.
                let rc = unsafe { FwpmFilterDeleteByKey0(e.0, &k) };
                if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND {
                    check("FwpmFilterDeleteByKey0", rc)?;
                }
            }
            let rc = unsafe { FwpmSubLayerDeleteByKey0(e.0, &SUBLAYER) };
            if rc != 0 && rc != FWP_E_SUBLAYER_NOT_FOUND {
                check("FwpmSubLayerDeleteByKey0", rc)?;
            }
            Ok(())
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Раскладка как в C (x64): размеры и смещения проверены по fwptypes.h / fwpmtypes.h.
        #[test]
        #[cfg(target_pointer_width = "64")]
        fn layout() {
            assert_eq!(std::mem::size_of::<Guid>(), 16);
            assert_eq!(std::mem::size_of::<Value>(), 16);
            assert_eq!(std::mem::size_of::<Condition>(), 40);
            assert_eq!(std::mem::size_of::<Action>(), 20);
            // FWPM_SUBLAYER0 x64: 16+16+4(+4)+8+16+2(+6) = 72.
            assert_eq!(std::mem::size_of::<SubLayer>(), 72);
            // FWPM_FILTER0 x64: 16+16+4(+4)+8+16+16+16+16+4(+4)+8+20(+4)+16+8+8+16 = 200.
            assert_eq!(std::mem::size_of::<Filter>(), 200);
            assert_eq!(std::mem::size_of::<V6Mask>(), 17);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nft() {
        let s = super::nft_script(true);
        assert!(s.contains("policy drop;") && s.contains("meta mark 0x2c70 accept") && s.contains("oifname \"cproxy\" accept"));
        assert!(s.contains("ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept"));
        assert!(!super::nft_script(false).contains("oifname \"cproxy\""));
        assert!(s.starts_with("table inet cproxy_killswitch\ndelete table inet cproxy_killswitch\n"));
    }
}
