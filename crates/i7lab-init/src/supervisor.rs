//! Service supervision policy, pure (no processes, no clock): the caller feeds `now` in milliseconds and performs
//! the returned actions. Host-tested.
//!
//! * `i7labd` is respawned with exponential backoff 1 s -> 30 s; a run of 60 s resets the backoff.
//! * If `i7labd` exits 5 times within 60 s and the console is open, the fallback activates: console shells
//!   (`/bin/i7labsh -l`) are enabled on the console ttys and every later `i7labd` starts with `I7LAB_TUI=off`, so the
//!   two never fight over tty1. An `i7labd` that was started WITH the TUI and runs cleanly while the fallback is
//!   active is restarted once with the TUI off.
//! * Console shells are respawned (typing `exit` gives a fresh prompt) with a short backoff.

pub const INITIAL_BACKOFF_MS: u64 = 1_000;
pub const MAX_BACKOFF_MS: u64 = 30_000;
pub const DAEMON_STABLE_MS: u64 = 60_000;
pub const SHELL_STABLE_MS: u64 = 3_000;
pub const CRASH_LIMIT: usize = 5;
pub const CRASH_WINDOW_MS: u64 = 60_000;
pub const CLEAN_START_MS: u64 = 10_000;
pub const RESTART_DELAY_MS: u64 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Daemon,
    /// console shell on this tty (name below /dev, e.g. "tty1", "ttyS0")
    Shell(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Disabled,
    Down { not_before: u64 },
    Starting,
    Running { pid: i32, since: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// spawn service `idx`; for the daemon `tui_off` says whether to pass I7LAB_TUI=off
    Start { idx: usize, tui_off: bool },
    /// ask a running service to stop (SIGTERM); it is restarted by the normal path
    Stop { pid: i32 },
}

#[derive(Clone, Debug)]
pub struct Svc {
    pub name: String,
    pub kind: Kind,
    pub state: State,
    pub backoff_ms: u64,
    /// failure times inside the crash window
    exits: Vec<u64>,
    pub starts: u32,
    tui_off_at_start: bool,
    restart_requested: bool,
}

impl Svc {
    fn new(name: String, kind: Kind, state: State) -> Svc {
        Svc { name, kind, state, backoff_ms: INITIAL_BACKOFF_MS, exits: Vec::new(), starts: 0, tui_off_at_start: false, restart_requested: false }
    }
    fn stable_ms(&self) -> u64 {
        match self.kind {
            Kind::Daemon => DAEMON_STABLE_MS,
            Kind::Shell(_) => SHELL_STABLE_MS,
        }
    }
    pub fn pid(&self) -> Option<i32> {
        match self.state {
            State::Running { pid, .. } => Some(pid),
            _ => None,
        }
    }
}

pub struct Supervisor {
    svcs: Vec<Svc>,
    shells_allowed: bool,
    tui_off_boot: bool,
    fallback: bool,
}

impl Supervisor {
    /// `shells_allowed` = console is `open`. `tui_off_boot` = `i7lab.tui=off`: nothing else owns the console, so the
    /// shells run from the start. Index 0 is always the daemon.
    pub fn new(shell_ttys: &[String], shells_allowed: bool, tui_off_boot: bool) -> Supervisor {
        let mut svcs = vec![Svc::new("i7labd".into(), Kind::Daemon, State::Down { not_before: 0 })];
        for t in shell_ttys {
            svcs.push(Svc::new(format!("sh-{}", t), Kind::Shell(t.clone()), State::Disabled));
        }
        let mut s = Supervisor { svcs, shells_allowed, tui_off_boot, fallback: false };
        if tui_off_boot {
            s.enable_shells(0);
        }
        s
    }

    pub fn services(&self) -> &[Svc] {
        &self.svcs
    }

    pub fn fallback_active(&self) -> bool {
        self.fallback
    }

    /// Does a daemon started now run without the TUI?
    pub fn tui_off(&self) -> bool {
        self.tui_off_boot || self.fallback
    }

    fn enable_shells(&mut self, now: u64) {
        if !self.shells_allowed {
            return;
        }
        for s in &mut self.svcs {
            if matches!(s.kind, Kind::Shell(_)) && s.state == State::Disabled {
                s.state = State::Down { not_before: now };
            }
        }
    }

    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();

        if !self.fallback && self.shells_allowed && self.svcs[0].exits.len() >= CRASH_LIMIT {
            self.fallback = true;
            self.enable_shells(now);
        }

        if self.fallback {
            let d = &mut self.svcs[0];
            if let State::Running { pid, since } = d.state {
                if !d.tui_off_at_start && now.saturating_sub(since) >= CLEAN_START_MS && !d.restart_requested {
                    d.restart_requested = true;
                    out.push(Action::Stop { pid });
                }
            }
        }

        let tui_off = self.tui_off();
        for (idx, s) in self.svcs.iter_mut().enumerate() {
            if let State::Down { not_before } = s.state {
                if now >= not_before {
                    s.state = State::Starting;
                    out.push(Action::Start { idx, tui_off: matches!(s.kind, Kind::Daemon) && tui_off });
                }
            }
        }
        out
    }

    /// The driver spawned service `idx` successfully.
    pub fn spawned(&mut self, idx: usize, pid: i32, now: u64) {
        let tui_off = self.tui_off();
        let s = &mut self.svcs[idx];
        s.state = State::Running { pid, since: now };
        s.starts += 1;
        s.tui_off_at_start = tui_off;
        s.restart_requested = false;
    }

    /// The driver could not spawn service `idx` (missing binary, fork failure): counts as an immediate failure.
    pub fn spawn_failed(&mut self, idx: usize, now: u64) {
        self.failed(idx, now, 0);
    }

    /// A child exited. Returns the service index when it was one of ours.
    pub fn on_exit(&mut self, now: u64, pid: i32) -> Option<usize> {
        let idx = self.svcs.iter().position(|s| s.pid() == Some(pid))?;
        let since = match self.svcs[idx].state {
            State::Running { since, .. } => since,
            _ => now,
        };
        self.failed(idx, now, now.saturating_sub(since));
        Some(idx)
    }

    fn failed(&mut self, idx: usize, now: u64, ran_ms: u64) {
        let s = &mut self.svcs[idx];
        if s.restart_requested {
            // our own restart: no penalty
            s.restart_requested = false;
            s.state = State::Down { not_before: now + RESTART_DELAY_MS };
            return;
        }
        if ran_ms >= s.stable_ms() {
            s.backoff_ms = INITIAL_BACKOFF_MS;
            s.exits.clear();
        }
        s.exits.retain(|t| now.saturating_sub(*t) < CRASH_WINDOW_MS);
        s.exits.push(now);
        s.state = State::Down { not_before: now + s.backoff_ms };
        s.backoff_ms = (s.backoff_ms * 2).min(MAX_BACKOFF_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sup(shells: bool) -> Supervisor {
        Supervisor::new(&["tty1".to_string(), "ttyS0".to_string()], shells, false)
    }
    fn start_daemon(s: &mut Supervisor, now: u64, pid: i32) {
        let a = s.tick(now);
        assert!(a.contains(&Action::Start { idx: 0, tui_off: s.tui_off() }), "{a:?}");
        s.spawned(0, pid, now);
    }

    #[test]
    fn daemon_starts_at_once_and_only_once() {
        let mut s = sup(true);
        assert_eq!(s.tick(0), vec![Action::Start { idx: 0, tui_off: false }]);
        assert!(s.tick(1).is_empty()); // Starting: not offered again
        s.spawned(0, 100, 5);
        assert!(s.tick(10).is_empty());
        assert_eq!(s.services()[0].pid(), Some(100));
    }

    #[test]
    fn backoff_doubles_and_caps_at_30s() {
        let mut s = sup(false);
        let mut now = 0;
        let mut delays = Vec::new();
        for pid in 1..=8 {
            start_daemon(&mut s, now, pid);
            s.on_exit(now, pid); // dies immediately
            let State::Down { not_before } = s.services()[0].state else { panic!() };
            delays.push(not_before - now);
            now = not_before;
        }
        assert_eq!(delays, vec![1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
    }

    #[test]
    fn stable_run_resets_backoff() {
        let mut s = sup(false);
        start_daemon(&mut s, 0, 1);
        s.on_exit(0, 1);
        start_daemon(&mut s, 1000, 2);
        s.on_exit(1000, 2); // backoff is now 4 s
        start_daemon(&mut s, 3000, 3);
        s.on_exit(3000 + DAEMON_STABLE_MS, 3);
        let State::Down { not_before } = s.services()[0].state else { panic!() };
        assert_eq!(not_before, 3000 + DAEMON_STABLE_MS + INITIAL_BACKOFF_MS);
    }

    #[test]
    fn unknown_pid_is_not_ours() {
        let mut s = sup(true);
        start_daemon(&mut s, 0, 7);
        assert_eq!(s.on_exit(1, 999), None);
    }

    #[test]
    fn crash_loop_activates_fallback_and_enables_shells() {
        let mut s = sup(true);
        let mut now = 0;
        for pid in 1..=5 {
            // a shell must not start before the loop is detected
            let acts = s.tick(now);
            assert!(!acts.iter().any(|a| matches!(a, Action::Start { idx, .. } if *idx > 0)), "{acts:?}");
            s.spawned(0, pid, now);
            s.on_exit(now, pid);
            let State::Down { not_before } = s.services()[0].state else { panic!() };
            now = not_before;
        }
        assert!(!s.fallback_active());
        let acts = s.tick(now);
        assert!(s.fallback_active());
        assert!(s.tui_off());
        assert!(acts.contains(&Action::Start { idx: 1, tui_off: false }));
        assert!(acts.contains(&Action::Start { idx: 2, tui_off: false }));
        assert!(acts.contains(&Action::Start { idx: 0, tui_off: true }), "daemon restarts without the TUI: {acts:?}");
    }

    #[test]
    fn locked_console_never_gets_a_shell() {
        let mut s = sup(false);
        let mut now = 0;
        for pid in 1..=7 {
            let _ = s.tick(now);
            s.spawned(0, pid, now);
            s.on_exit(now, pid);
            let State::Down { not_before } = s.services()[0].state else { panic!() };
            now = not_before;
        }
        let acts = s.tick(now);
        assert!(!s.fallback_active());
        assert!(acts.iter().all(|a| !matches!(a, Action::Start { idx, .. } if *idx > 0)));
        assert!(s.services()[1..].iter().all(|x| x.state == State::Disabled));
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let mut s = sup(true);
        let mut now = 0;
        for pid in 1..=10 {
            let _ = s.tick(now);
            s.spawned(0, pid, now);
            s.on_exit(now, pid);
            now += CRASH_WINDOW_MS + 1000; // far apart
        }
        let _ = s.tick(now);
        assert!(!s.fallback_active());
    }

    #[test]
    fn tui_off_boot_runs_shells_from_the_start_without_fallback() {
        let mut s = Supervisor::new(&["tty1".to_string()], true, true);
        let acts = s.tick(0);
        assert!(acts.contains(&Action::Start { idx: 0, tui_off: true }));
        assert!(acts.contains(&Action::Start { idx: 1, tui_off: false }));
        assert!(!s.fallback_active());
    }

    #[test]
    fn shell_respawns_after_exit_with_small_backoff() {
        let mut s = Supervisor::new(&["tty1".to_string()], true, true);
        let _ = s.tick(0);
        s.spawned(0, 10, 0);
        s.spawned(1, 11, 0);
        s.on_exit(10_000, 11); // user typed exit after 10 s: stable
        let State::Down { not_before } = s.services()[1].state else { panic!() };
        assert_eq!(not_before, 10_000 + INITIAL_BACKOFF_MS);
        let acts = s.tick(11_000);
        assert_eq!(acts, vec![Action::Start { idx: 1, tui_off: false }]);
    }

    #[test]
    fn spawn_failure_backs_off_like_a_crash() {
        let mut s = sup(false);
        let a = s.tick(0);
        assert_eq!(a.len(), 1);
        s.spawn_failed(0, 0);
        assert!(s.tick(500).is_empty());
        assert_eq!(s.tick(1000).len(), 1);
    }

    #[test]
    fn daemon_started_with_tui_is_restarted_once_when_fallback_is_active() {
        let mut s = sup(true);
        // daemon starts with the TUI (no fallback yet) and runs
        start_daemon(&mut s, 0, 50);
        // force the fallback as the crash loop of an earlier incarnation would have
        s.svcs[0].exits = vec![0; CRASH_LIMIT];
        let acts = s.tick(CLEAN_START_MS + 1);
        assert!(s.fallback_active());
        assert!(acts.contains(&Action::Stop { pid: 50 }), "{acts:?}");
        // the request is not repeated while it is pending
        assert!(!s.tick(CLEAN_START_MS + 2).contains(&Action::Stop { pid: 50 }));
        // its exit is not a crash and the restart carries I7LAB_TUI=off
        s.on_exit(CLEAN_START_MS + 3, 50);
        let acts = s.tick(CLEAN_START_MS + 3 + RESTART_DELAY_MS);
        assert!(acts.contains(&Action::Start { idx: 0, tui_off: true }), "{acts:?}");
        s.spawned(0, 51, CLEAN_START_MS + 600);
        assert!(s.tick(100_000).iter().all(|a| !matches!(a, Action::Stop { .. })), "restarted at most once");
    }
}
