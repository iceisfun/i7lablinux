//! Shared live state for the front ends (review feasibility F8). Owner: P6a. Consumers: console TUI (P5),
//! SSE `/api/v1/events` (P7), beacon `state`/`attention` (P6b), `tui.dump` (P5 via `console_frame`).
//!
//! `Snapshots` holds an `Arc<Snapshot>` replaced every 2 s by one P6a thread (readers clone the Arc, never
//! block the writer). `EventBus` fans out discrete events to every subscriber; a slow subscriber loses events
//! (bounded queue, `try_send`) instead of stalling the daemon.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// One consistent view of the host, refreshed every 2 s.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// milliseconds since boot when taken
    pub taken_ms: u64,
    /// labprobe summaries as JSON (system, cpu, mem, thermal, net, block verdicts): same object as
    /// `GET /api/v1/overview`
    pub overview_json: String,
    /// human strings, most severe first ("NO CONTROL PATH: unbound 10ec:8126 at 03:00.0", "NO ADMIN KEY: ...", ...)
    pub attention: Vec<String>,
    /// "booting" | "ready" | "busy" | "degraded" | "shutdown"
    pub state: String,
    /// iface name, MAC, IPv4 list
    pub links: Vec<(String, String, Vec<String>)>,
    /// open ether sessions (client MAC, role, idle s) and HTTP clients seen in the last minute
    pub sessions: Vec<String>,
    /// protocol counters (`stats` command), JSON
    pub stats_json: String,
}

#[derive(Default)]
pub struct Snapshots {
    current: RwLock<Arc<Snapshot>>,
    /// last rendered console frame as text (`labtui::Buffer::to_text()`), written by the console TUI after each
    /// present, read by `tui.dump` (review feasibility F24)
    pub console_frame: Mutex<String>,
}

impl Snapshots {
    pub fn get(&self) -> Arc<Snapshot> {
        self.current.read().unwrap().clone()
    }
    pub fn set(&self, s: Snapshot) {
        *self.current.write().unwrap() = Arc::new(s);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// one audit line (as `Audit::record` wrote it)
    Audit(String),
    /// job id, state, progress JSON
    Job { id: u32, json: String },
    /// `msg TEXT`: show on the console
    Msg(String),
    /// `tui tab NAME` / `tui reset` (None)
    TuiTab(Option<String>),
    /// `identify --seconds N` (Duration::ZERO = stop)
    Identify(Duration),
    /// link up/down, address change: iface name
    Link(String),
}

pub const SUBSCRIBER_QUEUE: usize = 256;

#[derive(Default)]
pub struct EventBus {
    subs: Mutex<Vec<SyncSender<Event>>>,
}

impl EventBus {
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE);
        self.subs.lock().unwrap().push(tx);
        rx
    }

    /// Never blocks. Disconnected subscribers are removed; full queues drop this event.
    pub fn publish(&self, ev: Event) {
        self.subs.lock().unwrap().retain(|tx| match tx.try_send(ev.clone()) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fanout_and_cleanup() {
        let bus = EventBus::default();
        let a = bus.subscribe();
        let b = bus.subscribe();
        drop(b);
        bus.publish(Event::Msg("hi".into()));
        assert_eq!(a.try_recv().unwrap(), Event::Msg("hi".into()));
        assert_eq!(bus.subs.lock().unwrap().len(), 1);
        let s = Snapshots::default();
        s.set(Snapshot { state: "ready".into(), ..Default::default() });
        assert_eq!(s.get().state, "ready");
    }
}
