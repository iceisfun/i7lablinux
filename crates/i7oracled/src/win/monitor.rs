//! Power-event recording: hidden top-level window (WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_ENDSESSION,
//! WM_DISPLAYCHANGE, power-setting notifications), PowerRegisterSuspendResumeNotification callback, a 1 s sampler
//! with clock-jump detection, and the post-resume diagnostics thread.
//!
//! The window is a hidden TOP-LEVEL window, not message-only: message-only windows are not sent the broadcast
//! messages (PBT_APM*, WM_ENDSESSION, WM_DISPLAYCHANGE).
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{proc, wide, HANDLE};
use crate::evlog::json_str;
use crate::power::{self, Guid};
use crate::stamp::{jump, Stamp};
use crate::state::{lock, Mode, Shared, GLOBAL};

#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    wnd_proc: Option<unsafe extern "system" fn(HANDLE, u32, usize, isize) -> isize>,
    cls_extra: i32,
    wnd_extra: i32,
    instance: HANDLE,
    icon: HANDLE,
    cursor: HANDLE,
    background: HANDLE,
    menu_name: *const u16,
    class_name: *const u16,
    icon_sm: HANDLE,
}

#[repr(C)]
struct Msg {
    hwnd: HANDLE,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt: [i32; 2],
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WndClassExW) -> u16;
    fn CreateWindowExW(ex: u32, class: *const u16, title: *const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: HANDLE, menu: HANDLE, inst: HANDLE, param: *mut c_void) -> HANDLE;
    fn DefWindowProcW(h: HANDLE, m: u32, wp: usize, lp: isize) -> isize;
    fn GetMessageW(m: *mut Msg, h: HANDLE, min: u32, max: u32) -> i32;
    fn TranslateMessage(m: *const Msg) -> i32;
    fn DispatchMessageW(m: *const Msg) -> isize;
    fn PostQuitMessage(code: i32);
    fn PostMessageW(h: HANDLE, m: u32, wp: usize, lp: isize) -> i32;
    fn DestroyWindow(h: HANDLE) -> i32;
    fn RegisterPowerSettingNotification(recipient: HANDLE, guid: *const [u8; 16], flags: u32) -> HANDLE;
}

#[repr(C)]
struct SubscribeParams {
    callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> u32,
    context: *mut c_void,
}

static HWND: AtomicIsize = AtomicIsize::new(0);

fn sh() -> Option<&'static Arc<Shared>> {
    GLOBAL.get()
}

fn src(kind: &str) -> String {
    let mode = sh().map(|s| s.mode.name()).unwrap_or("unknown");
    format!("{}-{}", mode, kind)
}

/// Decode and record one power broadcast, whichever channel it arrived on.
/// `lparam` is the POWERBROADCAST_SETTING pointer for PBT_POWERSETTINGCHANGE.
pub fn pbt_event(source: &str, channel: &str, ty: u32, lparam: *const u8) {
    let Some(s) = sh() else { return };
    let stamp = Stamp::now();
    let prev = lock(&s.last_stamp).replace(stamp);
    let since = prev.map(|p| jump(&p, &stamp).json()).unwrap_or_else(|| "null".into());
    if ty == power::PBT_POWERSETTINGCHANGE && !lparam.is_null() {
        // POWERBROADCAST_SETTING { GUID PowerSetting; DWORD DataLength; UCHAR Data[1]; }
        // SAFETY: the OS guarantees the header and DataLength bytes of data for this message type.
        let (g, data) = unsafe {
            let g = std::slice::from_raw_parts(lparam, 16).to_vec();
            let len = u32::from_le_bytes([*lparam.add(16), *lparam.add(17), *lparam.add(18), *lparam.add(19)]) as usize;
            (g, std::slice::from_raw_parts(lparam.add(20), len.min(256)).to_vec())
        };
        if let Some(guid) = Guid::from_bytes(&g) {
            let d = power::decode_setting(&guid, &data);
            s.emit_at(source, "power_setting", &stamp, &format!("{{\"channel\":{},\"since_last_sample\":{},\"setting\":{}}}", json_str(channel), since, d));
        }
    } else {
        s.emit_at(source, "pbt", &stamp, &format!("{{\"channel\":{},\"pbt\":{},\"code\":{},\"since_last_sample\":{}}}", json_str(channel), json_str(power::pbt_name(ty)), ty, since));
        match ty {
            power::PBT_APMSUSPEND => {
                s.counters.suspends.fetch_add(1, Ordering::Relaxed);
            }
            power::PBT_APMRESUMEAUTOMATIC | power::PBT_APMRESUMESUSPEND => {
                s.counters.resumes.fetch_add(1, Ordering::Relaxed);
                if s.mode != Mode::Agent {
                    spawn_after_resume(s.clone());
                }
            }
            _ => {}
        }
    }
    let (d, _) = super::sample();
    s.emit(source, "sample", &format!("{{\"reason\":{},\"sample\":{}}}", json_str(channel), d));
}

/// Debounced: one diagnostics pass per resume burst (RESUMEAUTOMATIC and RESUMESUSPEND both arrive, through up to three channels, and a resumed guest delivers them seconds apart).
fn spawn_after_resume(s: Arc<Shared>) {
    static LAST: AtomicIsize = AtomicIsize::new(0);
    let now = (Stamp::now().tick_ms / 1000) as isize;
    if now - LAST.swap(now, Ordering::SeqCst) < 30 {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        s.emit("diag", "after_resume", &format!("{{\"transition\":{},\"capabilities\":{}}}", super::transition_json(), super::capabilities_json()));
        powercfg_snapshot(&s, "after-resume");
    });
}

/// `powercfg /requests` and `/lastwake` output as an event (thread-execution-state requests, last wake source).
pub fn powercfg_snapshot(s: &Arc<Shared>, why: &str) {
    for (name, args) in [("requests", vec!["/requests".to_string()]), ("lastwake", vec!["/lastwake".to_string()])] {
        let r = crate::exec::exec_capture("powercfg.exe", &args, None, Duration::from_secs(30), 64 << 10);
        let text: String = crate::exec::lossy(&r.stdout).chars().take(12_000).collect();
        s.emit("diag", "powercfg", &format!("{{\"why\":{},\"what\":{},\"exit\":{},\"output\":{}}}", json_str(why), json_str(name), r.exit.map(|c| c.to_string()).unwrap_or_else(|| "null".into()), json_str(&text)));
    }
}

// ------------------------------------------------------------------------------------------------ window

unsafe extern "system" fn wndproc(hwnd: HANDLE, msg: u32, wp: usize, lp: isize) -> isize {
    match msg {
        power::WM_POWERBROADCAST => {
            pbt_event(&src("win"), "WM_POWERBROADCAST", wp as u32, lp as *const u8);
            1 // TRUE: grant (queries are not on Win10) / acknowledged
        }
        0x0011 => {
            if let Some(s) = sh() {
                s.emit(&src("win"), "wm_queryendsession", &format!("{{\"lparam\":{},\"logoff\":{},\"closeapp\":{},\"critical\":{}}}", lp as u32, (lp as u32) & 0x8000_0000 != 0, (lp as u32) & 1 != 0, (lp as u32) & 0x4000_0000 != 0));
            }
            1
        }
        0x0016 => {
            if let Some(s) = sh() {
                s.emit(&src("win"), "wm_endsession", &format!("{{\"ending\":{},\"lparam\":{}}}", wp != 0, lp as u32));
            }
            0
        }
        0x007E => {
            if let Some(s) = sh() {
                s.emit(&src("win"), "wm_displaychange", &format!("{{\"bpp\":{},\"width\":{},\"height\":{}}}", wp, (lp as u32) & 0xFFFF, ((lp as u32) >> 16) & 0xFFFF));
            }
            0
        }
        0x0010 => {
            DestroyWindow(hwnd);
            0
        }
        0x0002 => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

pub fn register_settings(recipient: HANDLE, flags: u32) -> Vec<(&'static str, u32)> {
    let mut res = Vec::new();
    for (name, g) in power::SETTINGS {
        let guid = Guid::parse(g).expect("static guid");
        // SAFETY: valid GUID pointer for the call; the returned handle lives until process exit.
        let h = unsafe { RegisterPowerSettingNotification(recipient, &guid.0, flags) };
        res.push((*name, if h.is_null() { super::last_error() } else { 0 }));
    }
    res
}

fn window_thread(s: Arc<Shared>) {
    let class = wide("I7OracledPowerWindow");
    let title = wide("i7oracled");
    // SAFETY: plain Win32 window creation on this thread; the class and title buffers outlive the calls.
    unsafe {
        let inst = super::GetModuleHandleW(std::ptr::null());
        let wc = WndClassExW { cb_size: std::mem::size_of::<WndClassExW>() as u32, style: 0, wnd_proc: Some(wndproc), cls_extra: 0, wnd_extra: 0, instance: inst, icon: null_mut(), cursor: null_mut(), background: null_mut(), menu_name: std::ptr::null(), class_name: class.as_ptr(), icon_sm: null_mut() };
        if RegisterClassExW(&wc) == 0 {
            s.emit(&src("win"), "error", &format!("{{\"what\":\"RegisterClassEx\",\"code\":{}}}", super::last_error()));
            return;
        }
        // WS_POPUP, WS_EX_TOOLWINDOW; never shown.
        let hwnd = CreateWindowExW(0x80, class.as_ptr(), title.as_ptr(), 0x8000_0000, 0, 0, 0, 0, null_mut(), null_mut(), inst, null_mut());
        if hwnd.is_null() {
            s.emit(&src("win"), "error", &format!("{{\"what\":\"CreateWindowEx\",\"code\":{}}}", super::last_error()));
            return;
        }
        HWND.store(hwnd as isize, Ordering::SeqCst);
        let regs = register_settings(hwnd, 0); // DEVICE_NOTIFY_WINDOW_HANDLE
        let list: Vec<String> = regs.iter().map(|(n, c)| format!("{{\"setting\":{},\"error\":{}}}", json_str(n), c)).collect();
        let sr = register_suspend_resume_callback();
        s.emit(&src("win"), "monitor_ready", &format!("{{\"hwnd\":{},\"settings\":[{}],\"suspend_resume_callback_error\":{}}}", hwnd as usize, list.join(","), sr));
        let mut m: Msg = std::mem::zeroed();
        while GetMessageW(&mut m, null_mut(), 0, 0) > 0 {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

// ------------------------------------------------------------------------------------------------ suspend/resume callback

unsafe extern "system" fn resume_cb(_ctx: *mut c_void, ty: u32, _setting: *mut c_void) -> u32 {
    pbt_event(&src("cb"), "PowerRegisterSuspendResumeNotification", ty, std::ptr::null());
    0
}

/// Returns 0 on success or the Win32 error / 0xFFFFFFFF when the export is missing.
pub fn register_suspend_resume_callback() -> u32 {
    static DONE: AtomicIsize = AtomicIsize::new(0);
    if DONE.swap(1, Ordering::SeqCst) == 1 {
        return 0;
    }
    let Some(p) = proc("powrprof.dll", "PowerRegisterSuspendResumeNotification") else { return 0xFFFF_FFFF };
    // SAFETY: ULONG PowerRegisterSuspendResumeNotification(ULONG Flags, HANDLE Recipient, PHPOWERNOTIFY Handle);
    // with DEVICE_NOTIFY_CALLBACK (2) the recipient is a DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS that must stay alive.
    let f: unsafe extern "system" fn(u32, *mut c_void, *mut HANDLE) -> u32 = unsafe { std::mem::transmute(p) };
    let params = Box::leak(Box::new(SubscribeParams { callback: resume_cb, context: null_mut() }));
    let mut h: HANDLE = null_mut();
    unsafe { f(2, params as *mut SubscribeParams as *mut c_void, &mut h) }
}

// ------------------------------------------------------------------------------------------------ sampler

fn sampler(s: Arc<Shared>) {
    let mut prev: Option<Stamp> = None;
    let mut last_key = String::new();
    let mut last_written = Instant::now() - Duration::from_secs(3600);
    while !s.stop.load(Ordering::SeqCst) {
        let now = Stamp::now();
        if let Some(p) = prev {
            let j = jump(&p, &now);
            if j.is_gap(1000.0, 1500.0) {
                s.emit_at("sampler", "clock_jump", &now, &format!("{{\"expected_ms\":1000,\"delta\":{}}}", j.json()));
            }
        }
        *lock(&s.last_stamp) = Some(now);
        prev = Some(now);
        let (data, key) = super::sample();
        if key != last_key || last_written.elapsed() >= Duration::from_secs(s.cfg.heartbeat_s) {
            s.emit_at("sampler", "sample", &now, &format!("{{\"reason\":{},\"sample\":{}}}", json_str(if key != last_key { "changed" } else { "heartbeat" }), data));
            last_key = key;
            last_written = Instant::now();
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub fn start(s: &Arc<Shared>) {
    let (a, b) = (s.clone(), s.clone());
    std::thread::Builder::new().name("window".into()).spawn(move || window_thread(a)).ok();
    if s.mode != Mode::Agent {
        // the service (or console) process owns sampling and diagnostics; the agent only forwards window events
        std::thread::Builder::new().name("sampler".into()).spawn(move || sampler(b)).ok();
        let c = s.clone();
        std::thread::spawn(move || powercfg_snapshot(&c, "start"));
    }
}

pub fn stop_window() {
    let h = HWND.load(Ordering::SeqCst);
    if h != 0 {
        // SAFETY: posting WM_CLOSE to our own window.
        unsafe { PostMessageW(h as HANDLE, 0x0010, 0, 0) };
    }
}
