//! Windows service plumbing: StartServiceCtrlDispatcher, ServiceMain, the control handler that receives
//! SERVICE_CONTROL_POWEREVENT (with the same PBT_* codes and power-setting payloads as a window would)
//! and SERVICE_CONTROL_SESSIONCHANGE.
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use super::monitor;
use super::wide;
use crate::state::{Mode, GLOBAL};

pub const SERVICE_NAME: &str = "i7oracled";

#[repr(C)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit: u32,
    svc_exit: u32,
    check_point: u32,
    wait_hint: u32,
}

#[repr(C)]
struct ServiceTableEntryW {
    name: *const u16,
    proc_: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
}

#[link(name = "advapi32")]
extern "system" {
    fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> i32;
    fn RegisterServiceCtrlHandlerExW(name: *const u16, handler: unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32, ctx: *mut c_void) -> isize;
    fn SetServiceStatus(h: isize, st: *const ServiceStatus) -> i32;
}

static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static STATE: AtomicIsize = AtomicIsize::new(0);

const RUNNING: u32 = 4;
const STOP_PENDING: u32 = 3;
const START_PENDING: u32 = 2;
const STOPPED: u32 = 1;
// STOP | SHUTDOWN | PAUSE_CONTINUE(no) | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN
const ACCEPT: u32 = 0x1 | 0x4 | 0x40 | 0x80 | 0x100;

fn report(state: u32, accepted: u32, wait_hint: u32) {
    let h = STATUS_HANDLE.load(Ordering::SeqCst);
    if h == 0 {
        return;
    }
    STATE.store(state as isize, Ordering::SeqCst);
    let st = ServiceStatus { service_type: 0x10, current_state: state, controls_accepted: if state == START_PENDING { 0 } else { accepted }, win32_exit: 0, svc_exit: 0, check_point: 0, wait_hint };
    // SAFETY: status handle from RegisterServiceCtrlHandlerEx, struct is fully initialised.
    unsafe { SetServiceStatus(h, &st) };
}

unsafe extern "system" fn handler(ctrl: u32, evtype: u32, evdata: *mut c_void, _ctx: *mut c_void) -> u32 {
    let sh = GLOBAL.get();
    match ctrl {
        // STOP, SHUTDOWN, PRESHUTDOWN
        0x1 | 0x5 | 0xF => {
            if let Some(s) = sh {
                s.emit("service-ctl", "service_control", &format!("{{\"control\":{},\"name\":\"{}\"}}", ctrl, match ctrl { 1 => "STOP", 5 => "SHUTDOWN", _ => "PRESHUTDOWN" }));
                s.stop.store(true, Ordering::SeqCst);
            }
            report(STOP_PENDING, 0, 10_000);
            0
        }
        // INTERROGATE
        0x4 => {
            report(STATE.load(Ordering::SeqCst) as u32, ACCEPT, 0);
            0
        }
        // POWEREVENT
        0xD => {
            monitor::pbt_event("service-ctl", "SERVICE_CONTROL_POWEREVENT", evtype, evdata as *const u8);
            0
        }
        // SESSIONCHANGE: WTSSESSION_NOTIFICATION { DWORD cbSize; DWORD dwSessionId; }
        0xE => {
            if let Some(s) = sh {
                let sid = if evdata.is_null() { 0 } else { *(evdata as *const u32).add(1) };
                let name = match evtype {
                    1 => "WTS_CONSOLE_CONNECT",
                    2 => "WTS_CONSOLE_DISCONNECT",
                    3 => "WTS_REMOTE_CONNECT",
                    4 => "WTS_REMOTE_DISCONNECT",
                    5 => "WTS_SESSION_LOGON",
                    6 => "WTS_SESSION_LOGOFF",
                    7 => "WTS_SESSION_LOCK",
                    8 => "WTS_SESSION_UNLOCK",
                    _ => "WTS_OTHER",
                };
                s.emit("service-ctl", "session_change", &format!("{{\"event\":\"{}\",\"code\":{},\"session\":{}}}", name, evtype, sid));
            }
            0
        }
        _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE_NAME);
    let h = RegisterServiceCtrlHandlerExW(name.as_ptr(), handler, null_mut());
    if h == 0 {
        return;
    }
    STATUS_HANDLE.store(h, Ordering::SeqCst);
    report(START_PENDING, 0, 15_000);
    match crate::daemon::build(Mode::Service, &crate::daemon::Overrides::default_for_service()) {
        Ok(sh) => {
            crate::daemon::start(&sh);
            // power-setting notifications by service handle (the window path is registered by monitor::start)
            let regs = monitor::register_settings(h as *mut c_void, 1); // DEVICE_NOTIFY_SERVICE_HANDLE
            let list: Vec<String> = regs.iter().map(|(n, c)| format!("{{\"setting\":\"{}\",\"error\":{}}}", n, c)).collect();
            let cb = monitor::register_suspend_resume_callback();
            sh.emit("service-ctl", "monitor_ready", &format!("{{\"settings\":[{}],\"suspend_resume_callback_error\":{}}}", list.join(","), cb));
            report(RUNNING, ACCEPT, 0);
            while !sh.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(250));
            }
            monitor::stop_window();
            sh.emit("service-ctl", "service_stopped", "{}");
            std::thread::sleep(Duration::from_millis(300));
        }
        Err(e) => {
            eprintln!("i7oracled: start failed: {}", e);
        }
    }
    report(STOPPED, 0, 0);
}

pub fn run() -> Result<(), String> {
    let name = wide(SERVICE_NAME);
    let table = [ServiceTableEntryW { name: name.as_ptr(), proc_: Some(service_main) }, ServiceTableEntryW { name: std::ptr::null(), proc_: None }];
    // SAFETY: table is NUL-terminated and outlives the (blocking) call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(format!("StartServiceCtrlDispatcher failed: {} (not started by the service control manager? use `console`)", super::last_error()));
    }
    Ok(())
}
