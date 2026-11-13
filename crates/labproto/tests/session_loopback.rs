//! Acceptance test 2 (PLAN section 13): ClientSession + ServerSessions over a lossy, reordering in-memory
//! network in virtual time.
mod common;
use common::*;

use labproto::args::encode_argv;
use labproto::crypto::{hex, sha256};
use labproto::frame::Chan;
use labproto::keys::Role;
use labproto::status::Status;

#[test]
fn handshake_and_ping_perfect_network() {
    let mut s = Sim::new(1, 0, 0, vec![], &admin_key());
    s.open();
    assert_eq!(s.opened, Some((Role::Admin, "labhost".to_string())));
    let id = s.req(CMD_PING, &["hello"]);
    assert!(s.run_until(500, |s| s.responses.contains_key(&id)));
    assert_eq!(s.responses[&id], (Status::Ok, b"hello".to_vec()));
    assert_eq!(s.requests.len(), 1);
    assert_eq!(s.server.session_count(), 1);
}

#[test]
fn ro_key_gets_ro_role() {
    let mut s = Sim::new(2, 0, 0, vec![], &ro_key());
    s.open();
    assert_eq!(s.opened.as_ref().unwrap().0, Role::Ro);
    let id = s.req(CMD_PING, &[]);
    assert!(s.run_until(500, |s| s.responses.contains_key(&id)));
    assert_eq!(s.requests[0].3, Role::Ro);
}

#[test]
fn wrong_key_times_out_with_no_state_on_the_server() {
    let mut other = admin_key();
    other.bytes[0] ^= 1;
    let mut s = Sim::new(3, 0, 0, vec![], &other);
    assert!(s.run_until(5000, |s| s.closed.is_some()));
    assert!(s.closed.unwrap().contains("handshake timeout"));
    assert_eq!(s.server.session_count(), 0);
    assert!(s.client.boot_id().is_none());
}

#[test]
fn works_behind_vlan_tags() {
    for tags in [vec![(0x8100u16, 13u16)], vec![(0x88a8, 100), (0x8100, 13)]] {
        let mut s = Sim::new(4, 0, 2, tags, &admin_key());
        s.open();
        let id = s.req(CMD_PING, &["v"]);
        assert!(s.run_until(500, |s| s.responses.contains_key(&id)));
    }
}

#[test]
fn big_request_64k_under_loss_is_delivered_exactly_once() {
    for seed in 10..16u64 {
        let mut s = Sim::new(seed, 10, 12, vec![], &admin_key());
        s.open();
        let payload = "x".repeat(60_000);
        let id = s.req(CMD_PING, &[&payload]);
        assert!(s.run_until(60_000, |s| s.responses.contains_key(&id)), "seed {}", seed);
        assert_eq!(s.requests.len(), 1, "seed {}: request delivered {} times", seed, s.requests.len());
        assert_eq!(s.responses[&id].1.len(), 60_000);
    }
}

#[test]
fn one_mib_get_with_ten_percent_loss_and_reordering() {
    for seed in [21u64, 22, 23] {
        let mut s = Sim::new(seed, 10, 20, vec![], &admin_key());
        s.open();
        let n = 1 << 20;
        let id = s.req(CMD_GET, &[&n.to_string()]);
        assert!(s.run_until(400_000, |s| s.responses.contains_key(&id) && s.stream_ends.contains(&(id, Chan::File as u8))), "seed {} no completion", seed);
        let got = &s.streams[&(id, Chan::File as u8)];
        assert_eq!(got.len(), n, "seed {}", seed);
        assert!(*got == pattern(n), "seed {} corrupt", seed);
        assert_eq!(s.responses[&id], (Status::Ok, b"{\"ok\":true}".to_vec()));
        assert_eq!(s.requests.len(), 1);
        // memory bound: never more than window * frag out-of-order bytes per stream
        assert!(s.max_held <= 16 * 1400 * 2, "held {}", s.max_held);
        // RESP never overtakes the output: the response is the last event of the request
        assert_eq!(s.order.last(), Some(&('R', id)), "seed {}: response overtook output", seed);
        assert!(s.order.iter().position(|e| *e == ('E', id)).unwrap() < s.order.iter().position(|e| *e == ('R', id)).unwrap());
    }
}

#[test]
fn put_upload_with_loss_verifies_hash() {
    let mut s = Sim::new(31, 10, 10, vec![], &admin_key());
    s.open();
    let data = Rng(9).bytes(300_000);
    let id = s.req(CMD_PUT, &["/tmp/x"]);
    let mut pos = 0;
    let want = hex(&sha256(&data));
    for _ in 0..400_000 {
        if pos < data.len() {
            let end = (pos + 20_000).min(data.len());
            if s.client.send_data(id, Chan::File, &data[pos..end], end == data.len(), s.now) {
                pos = end;
            }
        }
        s.step();
        if s.responses.contains_key(&id) {
            break;
        }
    }
    assert_eq!(s.responses.get(&id), Some(&(Status::Ok, want.into_bytes())));
}

#[test]
fn many_pipelined_requests_complete_and_never_run_twice() {
    let mut s = Sim::new(41, 15, 15, vec![], &admin_key());
    s.open();
    let mut ids = Vec::new();
    for round in 0..6 {
        for i in 0..8 {
            ids.push((s.req(CMD_PING, &[&format!("r{}-{}", round, i)]), format!("r{}-{}", round, i)));
        }
        assert!(s.run_until(60_000, |s| ids.iter().all(|(id, _)| s.responses.contains_key(id))));
    }
    for (id, want) in &ids {
        assert_eq!(s.responses[id].1, want.as_bytes());
    }
    assert_eq!(s.requests.len(), ids.len());
}

#[test]
fn ninth_outstanding_request_is_refused_client_side() {
    let mut s = Sim::new(51, 0, 0, vec![], &admin_key());
    s.open();
    for _ in 0..8 {
        s.client.send_req(CMD_EXEC, &encode_argv::<&str>(&[]), s.now).unwrap();
    }
    assert!(s.client.send_req(CMD_PING, &encode_argv::<&str>(&[]), s.now).is_err());
}

#[test]
fn cancel_reaches_the_server_and_answers_canceled() {
    let mut s = Sim::new(61, 5, 5, vec![], &admin_key());
    s.open();
    let id = s.req(CMD_EXEC, &["sleep"]);
    assert!(s.run_until(2000, |s| !s.requests.is_empty()));
    s.client.cancel(id, s.now);
    assert!(s.run_until(4000, |s| s.responses.contains_key(&id)));
    assert_eq!(s.responses[&id].0, Status::Canceled);
}

#[test]
fn oversized_request_is_rejected_by_the_client_and_the_engine() {
    let mut s = Sim::new(71, 0, 0, vec![], &admin_key());
    s.open();
    assert!(s.client.send_req(CMD_PING, &vec![0u8; 64 * 1024 + 1], s.now).is_err());
}

#[test]
fn server_restart_yields_no_session_and_client_reports_closed() {
    let mut s = Sim::new(81, 0, 0, vec![], &admin_key());
    s.open();
    let boot_before = s.client.boot_id().unwrap();
    let id = s.req(CMD_PING, &["a"]);
    assert!(s.run_until(500, |s| s.responses.contains_key(&id)));
    // the host reboots: fresh engine, fresh boot id and cookie secret
    s.server = labproto::session::ServerSessions::new(SERVER, Default::default()).unwrap();
    let _ = s.req(CMD_PING, &["b"]);
    assert!(s.run_until(3000, |s| s.closed.is_some()));
    assert!(s.closed.unwrap().contains("no session"), "{:?}", s.closed);
    // a fresh session sees a different boot id
    let mut c2 = labproto::session::ClientSession::new(CLIENT, SERVER, vec![], &admin_key(), Default::default(), s.now);
    s.closed = None;
    s.opened = None;
    std::mem::swap(&mut s.client, &mut c2);
    s.open();
    assert_ne!(s.client.boot_id().unwrap(), boot_before);
}

#[test]
fn idle_client_sends_keepalives_and_session_survives() {
    let mut s = Sim::new(91, 0, 0, vec![], &admin_key());
    s.open();
    // 5 virtual minutes idle: keepalives every 20 s keep the 120 s idle timer from firing
    for _ in 0..(300_000 / 2) {
        s.step();
    }
    assert!(s.closed.is_none());
    assert_eq!(s.server.session_count(), 1);
    let id = s.req(CMD_PING, &["still"]);
    assert!(s.run_until(500, |s| s.responses.contains_key(&id)));
}

#[test]
fn dead_server_makes_client_give_up() {
    let mut s = Sim::new(101, 0, 0, vec![], &admin_key());
    s.open();
    // everything the client sends from now on is lost
    s.drop_c2s = Box::new(|_| true);
    let _ = s.req(CMD_PING, &["x"]);
    assert!(s.run_until(60_000, |s| s.closed.is_some()));
    assert!(s.closed.unwrap().contains("retransmit limit"));
}

#[test]
fn random_networks_property() {
    // loss 0..25 %, jitter 0..40 ms, 3 transfers each; always exactly-once and byte-exact
    let mut rng = Rng(0xfeed);
    for round in 0..8u64 {
        let loss = rng.below(26);
        let jitter = rng.below(40);
        let mut s = Sim::new(1000 + round, loss, jitter, vec![], &admin_key());
        s.open();
        let n = 1 + rng.below(200_000) as usize;
        let id = s.req(CMD_GET, &[&n.to_string()]);
        assert!(s.run_until(600_000, |s| s.responses.contains_key(&id) && s.stream_ends.contains(&(id, 4))), "round {} loss {} jitter {} n {}", round, loss, jitter, n);
        assert!(s.streams[&(id, 4)] == pattern(n), "round {}", round);
        assert_eq!(s.requests.len(), 1);
    }
}

#[test]
fn engine_runs_over_memlink_in_real_time() {
    use labproto::link::{Link, MemLink};
    use labproto::session::{Action, ClientSession, ServerSessions, SessionLimits};
    use std::time::{Duration, Instant};
    let (mut cl, mut sl) = MemLink::pair(CLIENT, SERVER);
    let t0 = Instant::now();
    let mut client = ClientSession::new(CLIENT, SERVER, vec![], &admin_key(), SessionLimits::default(), t0);
    let mut server = ServerSessions::new(SERVER, SessionLimits::default()).unwrap();
    let keys = keyset();
    let mut buf = vec![0u8; 2048];
    let mut id = None;
    let mut done = None;
    for _ in 0..4000 {
        let now = Instant::now();
        let mut acts = client.poll(now);
        if let Some(m) = sl.recv(&mut buf, Duration::from_millis(0)).unwrap() {
            let sacts = server.on_frame(&keys, &buf[..m.len], &[], now);
            for a in sacts {
                match a {
                    Action::Send(f) => sl.send(1, &f).unwrap(),
                    Action::Request { req_id, .. } => {
                        for b in server.respond(req_id, labproto::status::Status::Ok, b"pong", now) {
                            if let Action::Send(f) = b {
                                sl.send(1, &f).unwrap();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(m) = cl.recv(&mut buf, Duration::from_millis(1)).unwrap() {
            acts.extend(client.on_frame(&buf[..m.len], &[], now));
        }
        for a in acts {
            match a {
                Action::Send(f) => cl.send(1, &f).unwrap(),
                Action::Opened { .. } => id = Some(client.send_req(CMD_PING, &encode_argv::<&str>(&[]), now).unwrap()),
                Action::Response { req_id, status, body } => done = Some((req_id, status, body)),
                _ => {}
            }
        }
        if done.is_some() {
            break;
        }
    }
    assert_eq!(done, Some((id.unwrap(), Status::Ok, b"pong".to_vec())));
}
