//! Windows platform layer: hand-written FFI (no windows-sys), clocks, registry, power calls, adapters.
//! Everything that can be decoded without Windows lives in the pure modules; this file only moves bytes.
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

pub mod monitor;
pub mod service;

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::beacon::Adapter;
use crate::evlog::json_str;
use crate::power::{PowerReq, WakeMethod};
use crate::pstruct;
use crate::stamp::Stamp;
use crate::state::Shared;

pub type HANDLE = *mut c_void;
pub type BOOL = i32;

#[repr(C)]
pub struct SystemPowerStatus {
    pub bytes: [u8; 12],
}

#[repr(C)]
struct Luid {
    low: u32,
    high: i32,
}

#[repr(C)]
struct TokenPrivileges {
    count: u32,
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
struct SystemTime {
    w: [u16; 8],
}

#[repr(C)]
struct Tzi {
    bias: i32,
    standard_name: [u16; 32],
    standard_date: SystemTime,
    standard_bias: i32,
    daylight_name: [u16; 32],
    daylight_date: SystemTime,
    daylight_bias: i32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn QueryPerformanceCounter(v: *mut i64) -> BOOL;
    pub fn QueryPerformanceFrequency(v: *mut i64) -> BOOL;
    pub fn GetSystemTimePreciseAsFileTime(ft: *mut u64);
    pub fn GetTickCount64() -> u64;
    pub fn QueryUnbiasedInterruptTime(v: *mut u64) -> BOOL;
    pub fn GetModuleHandleW(name: *const u16) -> HANDLE;
    pub fn LoadLibraryW(name: *const u16) -> HANDLE;
    pub fn GetProcAddress(h: HANDLE, name: *const u8) -> *mut c_void;
    pub fn CreateWaitableTimerW(attr: *mut c_void, manual: BOOL, name: *const u16) -> HANDLE;
    pub fn SetWaitableTimer(h: HANDLE, due: *const i64, period: i32, cb: *mut c_void, arg: *mut c_void, resume: BOOL) -> BOOL;
    pub fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    pub fn CloseHandle(h: HANDLE) -> BOOL;
    pub fn GetSystemPowerStatus(s: *mut SystemPowerStatus) -> BOOL;
    pub fn GetLastError() -> u32;
    pub fn ProcessIdToSessionId(pid: u32, sid: *mut u32) -> BOOL;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentProcess() -> HANDLE;
    fn GetTimeZoneInformation(t: *mut Tzi) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(hkey: isize, sub: *const u16, opts: u32, sam: u32, out: *mut isize) -> i32;
    fn RegQueryValueExW(hkey: isize, name: *const u16, reserved: *mut u32, ty: *mut u32, data: *mut u8, len: *mut u32) -> i32;
    fn RegCloseKey(hkey: isize) -> i32;
    fn OpenProcessToken(p: HANDLE, access: u32, tok: *mut HANDLE) -> BOOL;
    fn LookupPrivilegeValueW(sys: *const u16, name: *const u16, luid: *mut Luid) -> BOOL;
    fn AdjustTokenPrivileges(tok: HANDLE, disable_all: BOOL, new: *const TokenPrivileges, buflen: u32, prev: *mut c_void, retlen: *mut u32) -> BOOL;
    fn InitiateSystemShutdownExW(machine: *const u16, msg: *const u16, timeout: u32, force: BOOL, reboot: BOOL, reason: u32) -> BOOL;
}

#[link(name = "user32")]
extern "system" {
    fn PostMessageW(h: HANDLE, msg: u32, wp: usize, lp: isize) -> BOOL;
}

#[repr(C)]
struct IpAddrString {
    next: *mut IpAddrString,
    ip: [u8; 16],
    mask: [u8; 16],
    context: u32,
}

/// Prefix of IP_ADAPTER_INFO up to IpAddressList (all we read; the OS owns the buffer).
#[repr(C)]
struct IpAdapterInfo {
    next: *mut IpAdapterInfo,
    combo_index: u32,
    adapter_name: [u8; 260],
    description: [u8; 132],
    address_length: u32,
    address: [u8; 8],
    index: u32,
    ty: u32,
    dhcp_enabled: u32,
    current_ip: *mut IpAddrString,
    ip_list: IpAddrString,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersInfo(info: *mut IpAdapterInfo, len: *mut u32) -> u32;
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Look up an export at run time (older import libraries lack some of these).
pub fn proc(dll: &str, name: &str) -> Option<*mut c_void> {
    let w = wide(dll);
    // SAFETY: valid NUL-terminated wide string; handles are only used for the lookup.
    unsafe {
        let mut m = GetModuleHandleW(w.as_ptr());
        if m.is_null() {
            m = LoadLibraryW(w.as_ptr());
        }
        if m.is_null() {
            return None;
        }
        let c = format!("{}\0", name);
        let p = GetProcAddress(m, c.as_ptr());
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

// ------------------------------------------------------------------------------------------------ clocks

pub fn stamp_now() -> Stamp {
    static QI: OnceLock<usize> = OnceLock::new();
    static HZ: OnceLock<u64> = OnceLock::new();
    let qi = *QI.get_or_init(|| proc("kernelbase.dll", "QueryInterruptTime").map(|p| p as usize).unwrap_or(0));
    let hz = *HZ.get_or_init(|| {
        let mut f = 0i64;
        unsafe { QueryPerformanceFrequency(&mut f) };
        f.max(1) as u64
    });
    let (mut q, mut ft, mut unb, mut int) = (0i64, 0u64, 0u64, 0u64);
    // SAFETY: out-pointers to locals; QueryInterruptTime has the signature void(PULONGLONG).
    unsafe {
        QueryPerformanceCounter(&mut q);
        GetSystemTimePreciseAsFileTime(&mut ft);
        QueryUnbiasedInterruptTime(&mut unb);
        if qi != 0 {
            let f: unsafe extern "system" fn(*mut u64) = std::mem::transmute(qi);
            f(&mut int);
        }
        Stamp { qpc: q as u64, qpc_hz: hz, wall_100ns: ft, tick_ms: GetTickCount64(), unbiased_100ns: unb, interrupt_100ns: int }
    }
}

// ------------------------------------------------------------------------------------------------ registry

const HKLM: isize = 0x8000_0002u32 as i32 as isize;

pub enum RegVal {
    Str(String),
    Dword(u32),
}

pub fn reg_get(sub: &str, name: &str) -> Option<RegVal> {
    let (s, n) = (wide(sub), wide(name));
    // KEY_READ | KEY_WOW64_64KEY
    // SAFETY: standard registry read with a bounded buffer.
    unsafe {
        let mut k = 0isize;
        if RegOpenKeyExW(HKLM, s.as_ptr(), 0, 0x2_0019 | 0x100, &mut k) != 0 {
            return None;
        }
        let mut ty = 0u32;
        let mut buf = vec![0u8; 4096];
        let mut len = buf.len() as u32;
        let rc = RegQueryValueExW(k, n.as_ptr(), null_mut(), &mut ty, buf.as_mut_ptr(), &mut len);
        RegCloseKey(k);
        if rc != 0 {
            return None;
        }
        buf.truncate(len as usize);
        match ty {
            4 if buf.len() >= 4 => Some(RegVal::Dword(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))),
            1 | 2 => {
                let u: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|c| *c != 0).collect();
                Some(RegVal::Str(String::from_utf16_lossy(&u)))
            }
            _ => None,
        }
    }
}

fn reg_json(sub: &str, name: &str) -> String {
    match reg_get(sub, name) {
        Some(RegVal::Str(s)) => json_str(&s),
        Some(RegVal::Dword(d)) => d.to_string(),
        None => "null".into(),
    }
}

// ------------------------------------------------------------------------------------------------ power queries

fn nt_power(level: i32, out: &mut [u8]) -> Result<(), i32> {
    let p = proc("powrprof.dll", "CallNtPowerInformation").ok_or(-1)?;
    // SAFETY: documented signature NTSTATUS(POWER_INFORMATION_LEVEL, PVOID, ULONG, PVOID, ULONG).
    let f: unsafe extern "system" fn(i32, *mut c_void, u32, *mut c_void, u32) -> i32 = unsafe { std::mem::transmute(p) };
    let st = unsafe { f(level, null_mut(), 0, out.as_mut_ptr() as *mut c_void, out.len() as u32) };
    if st == 0 {
        Ok(())
    } else {
        Err(st)
    }
}

pub fn power_status_bytes() -> [u8; 12] {
    let mut s = SystemPowerStatus { bytes: [255; 12] };
    // SAFETY: SYSTEM_POWER_STATUS is 12 bytes: BYTE x4, DWORD x2.
    if unsafe { GetSystemPowerStatus(&mut s) } == 0 {
        return [255; 12];
    }
    s.bytes
}

/// One sample: (data JSON, change key). The key leaves out fields that tick every second.
pub fn sample() -> (String, String) {
    let st = power_status_bytes();
    let mut bat = [0u8; 32];
    let bat_ok = nt_power(5, &mut bat).is_ok();
    let mut pi = [0u8; 16];
    let pi_ok = nt_power(12, &mut pi).is_ok();
    let a = pstruct::power_status(&st);
    let b = if bat_ok { pstruct::battery_state(&bat) } else { "null".into() };
    let c = if pi_ok { pstruct::power_information(&pi) } else { "null".into() };
    (format!("{{\"status\":{},\"battery\":{},\"power_info\":{}}}", a, b, c), format!("{}|{}", a, b))
}

pub fn sample_json() -> String {
    sample().0
}

pub fn capabilities_json() -> String {
    let mut b = [0u8; 128];
    match nt_power(4, &mut b[..76]) {
        Ok(()) => pstruct::capabilities(&b[..76]),
        Err(e) => format!("{{\"error\":\"CallNtPowerInformation(4) failed: {:#x}\"}}", e),
    }
}

/// Last wake/sleep interrupt times and the thread-execution-state summary the kernel keeps (levels 14, 15, 16).
pub fn transition_json() -> String {
    let mut o = String::from("{");
    for (lvl, name, sz) in [(14, "last_wake_time_100ns", 8usize), (15, "last_sleep_time_100ns", 8), (16, "execution_state", 4)] {
        let mut b = [0u8; 8];
        let v = match nt_power(lvl, &mut b[..sz]) {
            Ok(()) => {
                if sz == 8 {
                    u64::from_le_bytes(b).to_string()
                } else {
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string()
                }
            }
            Err(_) => "null".into(),
        };
        o.push_str(&format!("\"{}\":{},", name, v));
    }
    o.push_str(&format!("\"tick_ms\":{}}}", unsafe { GetTickCount64() }));
    o
}

// ------------------------------------------------------------------------------------------------ identity

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

pub fn os_short() -> String {
    const CV: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let g = |n: &str| match reg_get(CV, n) {
        Some(RegVal::Str(s)) => s,
        Some(RegVal::Dword(d)) => d.to_string(),
        None => "?".into(),
    };
    format!("{} {} build {}.{}", g("ProductName"), g("DisplayVersion"), g("CurrentBuildNumber"), g("UBR"))
}

pub fn info_json() -> String {
    const BIOS: &str = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    const CV: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    const PWR: &str = "SYSTEM\\CurrentControlSet\\Control\\Power";
    let mut o = String::from("{");
    o.push_str("\"dmi\":{");
    let dmi = ["SystemManufacturer", "SystemProductName", "SystemVersion", "SystemFamily", "SystemSKU", "BIOSVendor", "BIOSVersion", "BIOSReleaseDate", "BaseBoardManufacturer", "BaseBoardProduct", "BaseBoardVersion"];
    o.push_str(&dmi.iter().map(|k| format!("\"{}\":{}", k, reg_json(BIOS, k))).collect::<Vec<_>>().join(","));
    o.push_str("},\"os\":{");
    let os = ["ProductName", "DisplayVersion", "ReleaseId", "EditionID", "CurrentBuild", "CurrentBuildNumber", "UBR", "InstallDate"];
    o.push_str(&os.iter().map(|k| format!("\"{}\":{}", k, reg_json(CV, k))).collect::<Vec<_>>().join(","));
    o.push_str("},\"power_config\":{");
    o.push_str(&format!(
        "\"HibernateEnabled\":{},\"CsEnabled\":{},\"PlatformAoAcOverride\":{},\"HiberbootEnabled\":{},\"hiberfil_sys_present\":{}",
        reg_json(PWR, "HibernateEnabled"),
        reg_json(PWR, "CsEnabled"),
        reg_json(PWR, "PlatformAoAcOverride"),
        reg_json("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", "HiberbootEnabled"),
        std::fs::metadata("C:\\hiberfil.sys").is_ok()
    ));
    let st = power_status_bytes();
    let mut sid = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid) };
    o.push_str(&format!(
        "}},\"host\":{},\"user\":{},\"pid\":{},\"session_id\":{},\"tick_ms\":{},\"battery_present\":{},\"power_status\":{},\"capabilities\":{}}}",
        json_str(&hostname()),
        json_str(&std::env::var("USERNAME").unwrap_or_default()),
        unsafe { GetCurrentProcessId() },
        sid,
        unsafe { GetTickCount64() },
        pstruct::battery_present(&st),
        pstruct::power_status(&st),
        capabilities_json()
    ));
    o
}

pub fn adapters() -> Vec<Adapter> {
    let mut len = 0u32;
    // SAFETY: the two-call pattern of GetAdaptersInfo; the buffer is 8-byte aligned and OS-filled.
    unsafe {
        if GetAdaptersInfo(null_mut(), &mut len) != 111 || len == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u64; (len as usize + 7) / 8];
        if GetAdaptersInfo(buf.as_mut_ptr() as *mut IpAdapterInfo, &mut len) != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut a = buf.as_ptr() as *const IpAdapterInfo;
        let mut guard = 0;
        while !a.is_null() && guard < 64 {
            guard += 1;
            let ad = &*a;
            if ad.address_length == 6 && ad.ty != 24 {
                let name = cstr(&ad.description);
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&ad.address[..6]);
                let mut ip = &ad.ip_list as *const IpAddrString;
                let mut g2 = 0;
                while !ip.is_null() && g2 < 16 {
                    g2 += 1;
                    let e = &*ip;
                    if let (Ok(i), Ok(m)) = (cstr(&e.ip).parse::<std::net::Ipv4Addr>(), cstr(&e.mask).parse::<std::net::Ipv4Addr>()) {
                        if !i.is_unspecified() && !i.is_loopback() && !(i.octets()[0] == 169 && i.octets()[1] == 254) {
                            out.push(Adapter { name: name.clone(), mac, ip: i, mask: m });
                        }
                    }
                    ip = e.next;
                }
            }
            a = ad.next;
        }
        out
    }
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

// ------------------------------------------------------------------------------------------------ actions

pub fn power_supported() -> bool {
    true
}

fn enable_privilege(name: &str) -> Result<(), String> {
    // SAFETY: standard token privilege adjustment on our own process token.
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), 0x28, &mut tok) == 0 {
            return Err(format!("OpenProcessToken: {}", last_error()));
        }
        let mut luid = Luid { low: 0, high: 0 };
        let n = wide(name);
        if LookupPrivilegeValueW(null(), n.as_ptr(), &mut luid) == 0 {
            CloseHandle(tok);
            return Err(format!("LookupPrivilegeValue: {}", last_error()));
        }
        let tp = TokenPrivileges { count: 1, luid, attributes: 2 };
        AdjustTokenPrivileges(tok, 0, &tp, 0, null_mut(), null_mut());
        let e = GetLastError();
        CloseHandle(tok);
        if e != 0 {
            return Err(format!("AdjustTokenPrivileges: {} (privilege not held)", e));
        }
        Ok(())
    }
}

fn arm_timer(sh: &Arc<Shared>, secs: u64) -> Result<(), String> {
    // SAFETY: waitable timer with resume flag; a thread waits on it so the handle outlives the call.
    unsafe {
        let h = CreateWaitableTimerW(null_mut(), 1, null());
        if h.is_null() {
            return Err(format!("CreateWaitableTimer: {}", last_error()));
        }
        let due: i64 = -((secs as i64) * 10_000_000);
        if SetWaitableTimer(h, &due, 0, null_mut(), null_mut(), 1) == 0 {
            let e = last_error();
            CloseHandle(h);
            return Err(format!("SetWaitableTimer: {}", e));
        }
        let hv = h as usize;
        let sh2 = sh.clone();
        std::thread::spawn(move || {
            let h = hv as HANDLE;
            let r = WaitForSingleObject(h, 0xFFFF_FFFF);
            sh2.emit("api", "wake_timer_fired", &format!("{{\"wait_result\":{}}}", r));
            CloseHandle(h);
        });
    }
    Ok(())
}

fn local_iso_after(secs: u64) -> String {
    let mut t: Tzi = unsafe { std::mem::zeroed() };
    let state = unsafe { GetTimeZoneInformation(&mut t) };
    let bias_min = t.bias + if state == 2 { t.daylight_bias } else { t.standard_bias };
    let ft = Stamp::now().wall_100ns as i64 + (secs as i64) * 10_000_000 - (bias_min as i64) * 600_000_000;
    crate::stamp::filetime_to_iso_local(ft as u64)
}

fn arm_task(sh: &Arc<Shared>, secs: u64) -> Result<(), String> {
    let xml = crate::power::wake_task_xml(&local_iso_after(secs));
    let path = sh.cfg.oracle_dir.join("wake-task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let args: Vec<String> = ["/create", "/tn", "i7oracled-wake", "/xml", &path.to_string_lossy(), "/f"].iter().map(|s| s.to_string()).collect();
    let r = crate::exec::exec_capture("schtasks.exe", &args, None, Duration::from_secs(30), 1 << 16);
    if r.exit == Some(0) {
        Ok(())
    } else {
        Err(format!("schtasks /create failed: exit {:?} {}{}", r.exit, crate::exec::lossy(&r.stdout), crate::exec::lossy(&r.stderr)))
    }
}

pub fn power_action(sh: &Arc<Shared>, req: &PowerReq) -> Result<String, String> {
    use crate::power::Action;
    enable_privilege("SeShutdownPrivilege")?;
    let mut armed = Vec::new();
    if let Some(n) = req.wake_after_s {
        if matches!(req.wake_method, WakeMethod::Timer | WakeMethod::Both) {
            arm_timer(sh, n)?;
            armed.push("timer");
        }
        if matches!(req.wake_method, WakeMethod::Task | WakeMethod::Both) {
            arm_task(sh, n)?;
            armed.push("task");
        }
    }
    sh.emit("api", "power_call", &format!("{{\"action\":{},\"armed\":{:?},\"tick_ms\":{}}}", json_str(req.action.name()), armed, unsafe { GetTickCount64() }));
    match req.action {
        Action::Sleep | Action::Hibernate => {
            let p = proc("powrprof.dll", "SetSuspendState").ok_or("SetSuspendState not found")?;
            // SAFETY: BOOLEAN SetSuspendState(BOOLEAN Hibernate, BOOLEAN ForceCritical, BOOLEAN DisableWakeEvent).
            let f: unsafe extern "system" fn(u8, u8, u8) -> u8 = unsafe { std::mem::transmute(p) };
            let ok = unsafe { f((req.action == Action::Hibernate) as u8, 1, 0) };
            if ok == 0 {
                return Err(format!("SetSuspendState failed: {}", last_error()));
            }
            Ok("SetSuspendState returned (the machine has resumed)".into())
        }
        Action::Shutdown | Action::Reboot => {
            let msg = wide("i7oracled remote request");
            // SHTDN_REASON_FLAG_PLANNED | MAJOR_OTHER | MINOR_OTHER
            let ok = unsafe { InitiateSystemShutdownExW(null(), msg.as_ptr(), 3, 1, (req.action == Action::Reboot) as BOOL, 0x8000_0000) };
            if ok == 0 {
                return Err(format!("InitiateSystemShutdownEx failed: {}", last_error()));
            }
            Ok("shutdown initiated".into())
        }
        Action::ModernStandbyHint => {
            // HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2 = off. Only a hint: whether the platform then enters
            // Modern Standby is up to the idle timers; see docs/ORACLED.md.
            let ok = unsafe { PostMessageW(0xFFFF as HANDLE, 0x0112, 0xF170, 2) };
            if ok == 0 {
                return Err(format!("PostMessage failed: {}", last_error()));
            }
            Ok("monitor-off broadcast posted; idle timers decide the rest".into())
        }
    }
}

pub fn start_recorders(sh: &Arc<Shared>) {
    monitor::start(sh);
}

pub fn run_service() -> Result<(), String> {
    service::run()
}
