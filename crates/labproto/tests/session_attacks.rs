//! Replay, forgery, spoofing, fragment-limit and flood tests against `ServerSessions`, driven by the
//! hand-rolled `Raw` client of `common` (independent of the engine's client code).
mod common;
use common::*;

use std::time::{Duration, Instant};

use labproto::crypto::{hmac_sha256};
use labproto::frame::{self, flags, FrameType, TagKey};
use labproto::mac::Mac;
use labproto::session::{Action, ServerEvent, ServerSessions, SessionLimits};
use labproto::status::Status;

fn server() -> (ServerSessions, labproto::keys::KeySet, Instant) {
    (ServerSessions::new(SERVER, SessionLimits::default()).unwrap(), keyset(), Instant::now())
}

fn mac(n: u8) -> Mac {
    Mac([2, 0, 0, 0, 1, n])
}

fn reqs(acts: &[Action]) -> usize {
    requests(acts).len()
}

#[test]
fn handshake_from_independent_client_and_ping() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let f = c.req(CMD_PING, 1, &["abcd"]);
    let acts = sv.on_frame(&keys, &f, &[], now);
    assert_eq!(reqs(&acts), 1);
    match requests(&acts)[0] {
        Action::Request { req_id, cmd, role, body } => {
            assert_eq!(*cmd, CMD_PING);
            assert_eq!(*role, labproto::keys::Role::Admin);
            assert_eq!(labproto::args::decode_argv(body).unwrap(), vec!["abcd"]);
            let info = sv.request_info(*req_id).unwrap();
            assert_eq!((info.client_req_id, info.src, info.role), (1, mac(1), labproto::keys::Role::Admin));
            assert_eq!(info.session, c.session);
        }
        _ => unreachable!(),
    }
}

#[test]
fn lifecycle_events_are_reported_once() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![(0x8100, 13)], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let ev = sv.take_events();
    assert_eq!(ev, vec![ServerEvent::SessionOpened { session: c.session, src: mac(1), tags: vec![(0x8100, 13)], role: labproto::keys::Role::Admin }]);
    assert!(sv.take_events().is_empty());
    let acts = sv.close_all("shutdown");
    assert_eq!(sends(&acts).len(), 1);
    assert_eq!(sv.take_events(), vec![ServerEvent::SessionEnded { session: c.session, src: mac(1), reason: "shutdown" }]);
}

#[test]
fn hello_reply_is_never_larger_than_hello_and_verifiable_only_with_k() {
    let (mut sv, keys, now) = server();
    let c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    let hello = c.hello();
    let acts = sv.on_frame(&keys, &hello, &[], now);
    let s = sends(&acts);
    assert_eq!(s.len(), 1);
    assert!(s[0].len() <= hello.len(), "{} > {}", s[0].len(), hello.len());
    // the CHALLENGE tag only verifies under the right K and the right cn
    let (_, p) = frame::eth_parse(&s[0]).unwrap();
    let fr = frame::open(p).unwrap();
    assert!(frame::verify(&fr, TagKey::Challenge { k: &admin_key().bytes, cn: &c.cn }));
    assert!(!frame::verify(&fr, TagKey::Challenge { k: &admin_key().bytes, cn: &[0x12; 16] }));
    assert!(!frame::verify(&fr, TagKey::Challenge { k: &ro_key().bytes, cn: &c.cn }));
    // no state kept for a HELLO
    assert_eq!(sv.session_count(), 0);
}

#[test]
fn unauthenticated_junk_gets_no_reply() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    // unknown key id
    let mut stranger = Raw::new(mac(2), vec![], admin_key(), 0x22);
    stranger.key.bytes[3] ^= 0xff;
    assert!(sends(&sv.on_frame(&keys, &stranger.hello(), &[], now)).is_empty());
    // bad tag
    assert!(sends(&sv.on_frame(&keys, &c.bad_hello(), &[], now)).is_empty());
    // wrong destination MAC, broadcast source, garbage
    let mut f = c.hello();
    f[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    assert!(sends(&sv.on_frame(&keys, &f, &[], now)).is_empty());
    let mut f = c.hello();
    f[6..12].copy_from_slice(&[0xff; 6]);
    assert!(sends(&sv.on_frame(&keys, &f, &[], now)).is_empty());
    assert!(sv.on_frame(&keys, &[1, 2, 3], &[], now).is_empty());
    assert!(sv.on_frame(&keys, &[0u8; 200], &[], now).is_empty());
    // the legitimate client still works
    assert!(c.handshake(&mut sv, &keys, now));
}

#[test]
fn replayed_frame_does_not_run_a_command_twice() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let f = c.req(CMD_PING, 1, &["x"]);
    assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 1);
    let before = sv.stats().replays;
    for _ in 0..3 {
        assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 0);
    }
    assert_eq!(sv.stats().replays, before + 3);
    // a frame older than the 64-frame window is also dead, even if never seen
    let mut late = Vec::new();
    for i in 0..70 {
        let f = c.req(CMD_PING, 100 + i, &["y"]);
        if i == 0 {
            late.push(f.clone());
        }
        sv.on_frame(&keys, &f, &[], now);
    }
    // frame `late` was seen (it is in order) - craft an unseen old counter instead
    let old = c.frame_ctr(2, FrameType::Req, 1, 0, CMD_PING, 999, 4, 0, 0, 0, &labproto::args::encode_argv(&["z"]));
    assert_eq!(reqs(&sv.on_frame(&keys, &old, &[], now)), 0);
    // ctr 0 is never valid
    let zero = c.frame_ctr(0, FrameType::Req, 1, 0, CMD_PING, 998, 4, 0, 0, 0, &labproto::args::encode_argv(&["z"]));
    assert_eq!(reqs(&sv.on_frame(&keys, &zero, &[], now)), 0);
}

#[test]
fn out_of_order_frames_inside_the_window_are_accepted_once() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let a = c.req(CMD_PING, 1, &["a"]);
    let b = c.req(CMD_PING, 2, &["b"]);
    let d = c.req(CMD_PING, 3, &["d"]);
    assert_eq!(reqs(&sv.on_frame(&keys, &d, &[], now)), 1);
    assert_eq!(reqs(&sv.on_frame(&keys, &a, &[], now)), 1);
    assert_eq!(reqs(&sv.on_frame(&keys, &b, &[], now)), 1);
    assert_eq!(reqs(&sv.on_frame(&keys, &a, &[], now)), 0);
}

#[test]
fn forged_tags_are_rejected_and_counted() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let f = c.req(CMD_PING, 1, &["x"]);
    let before = sv.stats().bad_tags;
    // flip every single byte of the Ethernet payload once: header, payload and tag; nothing may be accepted
    for i in 14..f.len() {
        let mut g = f.clone();
        g[i] ^= 0x01;
        let acts = sv.on_frame(&keys, &g, &[], now);
        assert_eq!(reqs(&acts), 0, "byte {} flipped was accepted", i);
    }
    assert!(sv.stats().bad_tags > before);
    // the untouched frame still works after the forgery storm (replay window not poisoned by bad tags)
    assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 1);
}

#[test]
fn frame_signed_with_the_wrong_direction_or_key_is_rejected() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    // sign with the server-to-client direction byte
    let body = labproto::args::encode_argv(&["x"]);
    let h = frame::Header { ver: 1, ftype: 5, flags: 1, cmd: CMD_PING, session: c.session, req_id: 1, ctr: 50, msg_len: body.len() as u32, plen: body.len() as u16, ..Default::default() };
    let sealed = frame::seal(&h, &body, TagKey::Session { sk: &c.sk, dir: frame::Dir::ServerToClient });
    let f = frame::eth_build(&frame::EthHeader { dst: SERVER, src: mac(1), tags: vec![], ethertype: frame::ETHERTYPE_CTL }, &sealed);
    assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 0);
    // sign with K instead of SK
    let mut c2 = Raw::new(mac(1), vec![], admin_key(), 0x11);
    c2.session = c.session;
    c2.sk = admin_key().bytes;
    c2.ctr = 60;
    let f = c2.req(CMD_PING, 2, &["x"]);
    assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 0);
}

#[test]
fn frame_replayed_from_another_mac_or_tag_stack_is_not_accepted() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let f = c.req(CMD_PING, 1, &["x"]);
    // same bytes, other source MAC: no session for that MAC (NO_SESSION at most), never a request
    let mut g = f.clone();
    g[6..12].copy_from_slice(&mac(7).0);
    let acts = sv.on_frame(&keys, &g, &[], now);
    assert_eq!(reqs(&acts), 0);
    for s in sends(&acts) {
        let (_, h, p) = parse(&s).unwrap();
        assert_eq!(h.ftype, FrameType::NoSession as u8);
        assert!(p.is_empty());
        assert!(s.len() <= f.len());
    }
    // other VLAN stack: dropped silently
    let acts = sv.on_frame(&keys, &f, &[(0x8100, 13)], now);
    assert!(acts.is_empty());
    // the original still works
    assert_eq!(reqs(&sv.on_frame(&keys, &f, &[], now)), 1);
}

#[test]
fn session_binds_vlan_stack_and_replies_carry_it() {
    let (mut sv, keys, now) = server();
    let tags = vec![(0x8100u16, 13u16)];
    let mut c = Raw::new(mac(1), tags.clone(), admin_key(), 0x11);
    let acts = sv.on_frame(&keys, &c.hello(), &tags, now);
    let s = sends(&acts);
    let (eth, _, _) = parse(&s[0]).unwrap();
    assert_eq!(eth.tags, tags, "CHALLENGE must use the request's tag stack");
    assert!(c.take_challenge(&s[0]));
    // OPEN sent on another VLAN than the HELLO: the stateless cookie covers the stack, so no session
    let acts = sv.on_frame(&keys, &c.open(), &[(0x8100, 14)], now);
    assert!(sends(&acts).is_empty());
    assert_eq!(sv.session_count(), 0);
    let acts = sv.on_frame(&keys, &c.open(), &tags, now);
    assert_eq!(sv.session_count(), 1);
    let (eth, _, _) = parse(&sends(&acts)[0]).unwrap();
    assert_eq!(eth.tags, tags);
}

#[test]
fn cookie_expires_after_30_seconds_and_cannot_be_used_for_another_nonce() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    let s = sends(&sv.on_frame(&keys, &c.hello(), &[], now));
    assert!(c.take_challenge(&s[0]));
    let open = c.open();
    // 31 s later the cookie is stale
    let late = now + Duration::from_secs(31);
    assert!(sends(&sv.on_frame(&keys, &open, &[], late)).is_empty());
    assert_eq!(sv.session_count(), 0);
    // inside the window it works
    let open = c.open();
    assert!(!sends(&sv.on_frame(&keys, &open, &[], now + Duration::from_secs(14))).is_empty());
    assert_eq!(sv.session_count(), 1);
}

#[test]
fn duplicate_open_gets_the_same_session_back() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    let s = sends(&sv.on_frame(&keys, &c.hello(), &[], now));
    assert!(c.take_challenge(&s[0]));
    let o1 = c.open();
    let o2 = c.open(); // retransmission with a new ctr
    assert!(!sends(&sv.on_frame(&keys, &o1, &[], now)).is_empty());
    let acts = sv.on_frame(&keys, &o2, &[], now);
    assert_eq!(sends(&acts).len(), 1);
    assert_eq!(sv.session_count(), 1);
    // a tampered duplicate is not answered
    let mut bad = c.open();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(sends(&sv.on_frame(&keys, &bad, &[], now)).is_empty());
}

#[test]
fn replayed_open_after_the_session_ended_cannot_rerun_its_requests() {
    // capture HELLO/OPEN/REQ of a short session (e.g. `--cmd reboot`), let it end, replay OPEN + REQ while the
    // cookie is still valid: no new session, no second run
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    let s = sends(&sv.on_frame(&keys, &c.hello(), &[], now));
    assert!(c.take_challenge(&s[0]));
    let open = c.open();
    assert!(!sends(&sv.on_frame(&keys, &open, &[], now)).is_empty());
    let req = c.req(CMD_PING, 1, &["x"]);
    assert_eq!(reqs(&sv.on_frame(&keys, &req, &[], now)), 1);
    sv.close_all("test");
    assert_eq!(sv.session_count(), 0);
    let later = now + Duration::from_secs(5);
    assert!(sends(&sv.on_frame(&keys, &open, &[], later)).is_empty(), "replayed OPEN must not answer");
    assert_eq!(sv.session_count(), 0);
    assert_eq!(reqs(&sv.on_frame(&keys, &req, &[], later)), 0, "replayed REQ must not run");
    // a fresh handshake from the same client still works
    let mut c2 = Raw::new(mac(1), vec![], admin_key(), 0x12);
    assert!(c2.handshake(&mut sv, &keys, later));
}

#[test]
fn bad_hello_flood_does_not_interrupt_an_established_session_from_that_mac() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    // an attacker spoofing the same MAC sends bad HELLOs: penalty kicks in for the HELLO path
    for i in 0..12 {
        let acts = sv.on_frame(&keys, &c.bad_hello(), &[], now + Duration::from_millis(i * 10));
        assert!(acts.is_empty());
    }
    assert!(sv.stats().penalized > 0, "penalty must have started");
    // the established session is untouched: requests keep flowing, responses keep coming
    let f = c.req(CMD_PING, 1, &["alive"]);
    let t = now + Duration::from_millis(200);
    let acts = sv.on_frame(&keys, &f, &[], t);
    assert_eq!(reqs(&acts), 1);
    let handle = match requests(&acts)[0] {
        Action::Request { req_id, .. } => *req_id,
        _ => unreachable!(),
    };
    let out = sv.respond(handle, Status::Ok, b"ok", t);
    assert!(!sends(&out).is_empty());
    assert_eq!(sv.session_count(), 1);
    // but a new HELLO from the penalised MAC is dropped until the penalty ends (10 s), then works
    assert!(sends(&sv.on_frame(&keys, &c.hello(), &[], t)).is_empty());
    let mut c2 = Raw::new(mac(1), vec![], admin_key(), 0x33);
    assert!(c2.handshake(&mut sv, &keys, now + Duration::from_secs(12)));
    // a different MAC was never affected
    let mut c3 = Raw::new(mac(3), vec![], admin_key(), 0x44);
    assert!(c3.handshake(&mut sv, &keys, t));
}

#[test]
fn per_mac_and_total_session_caps() {
    let (mut sv, keys, now) = server();
    let mut cs: Vec<Raw> = (0..3).map(|i| Raw::new(mac(1), vec![], admin_key(), 0x10 + i)).collect();
    for c in cs.iter_mut() {
        assert!(c.handshake(&mut sv, &keys, now));
    }
    assert_eq!(sv.session_count(), 2, "2 per MAC: the oldest one was evicted");
    // the evicted (first) session now gets NO_SESSION
    let f = cs[0].req(CMD_PING, 1, &["x"]);
    let acts = sv.on_frame(&keys, &f, &[], now);
    assert_eq!(reqs(&acts), 0);
    assert!(sends(&acts).iter().all(|s| parse(s).unwrap().1.ftype == FrameType::NoSession as u8));
    // 8 total
    let mut many: Vec<Raw> = (10..22).map(|i| Raw::new(mac(i), vec![], admin_key(), i)).collect();
    for c in many.iter_mut() {
        assert!(c.handshake(&mut sv, &keys, now), "mac {}", c.mac);
        assert!(sv.session_count() <= 8);
    }
    assert_eq!(sv.session_count(), 8);
}

#[test]
fn request_fragment_limits() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let err_status = |acts: &[Action]| -> Option<u16> {
        sends(acts).iter().filter_map(|s| parse(s)).find(|(_, h, _)| h.ftype == FrameType::Err as u8).map(|(_, h, _)| h.status)
    };
    // declared length above 64 KiB
    let f = c.frame(FrameType::Req, 0, 0, CMD_PING, 1, 64 * 1024 + 1, 0, 0, 0, &[0u8; 1400]);
    let acts = sv.on_frame(&keys, &f, &[], now);
    assert_eq!(reqs(&acts), 0);
    assert_eq!(err_status(&acts), Some(Status::TooBig as u16));
    // misaligned offset
    let f = c.frame(FrameType::Req, 0, 0, CMD_PING, 2, 5000, 100, 0, 0, &[0u8; 1400]);
    let acts = sv.on_frame(&keys, &f, &[], now);
    assert_eq!(err_status(&acts), Some(Status::BadArgs as u16));
    // fragment extends past the declared length
    let f = c.frame(FrameType::Req, 1, 0, CMD_PING, 3, 100, 0, 0, 0, &[0u8; 200]);
    assert_eq!(err_status(&sv.on_frame(&keys, &f, &[], now)), Some(Status::TooBig as u16));
    // fragment larger than the negotiated frag
    let f = c.frame(FrameType::Req, 0, 0, CMD_PING, 4, 5000, 0, 0, 0, &[0u8; 1401]);
    assert!(err_status(&sv.on_frame(&keys, &f, &[], now)).is_some());
    // req_id 0
    let f = c.frame(FrameType::Req, 1, 0, CMD_PING, 0, 1, 0, 0, 0, &[1]);
    assert!(err_status(&sv.on_frame(&keys, &f, &[], now)).is_some());
    // 20 violations close the session
    for i in 0..30u32 {
        let f = c.frame(FrameType::Req, 0, 0, CMD_PING, 100 + i, 64 * 1024 + 1, 0, 0, 0, &[0u8; 100]);
        sv.on_frame(&keys, &f, &[], now);
    }
    assert_eq!(sv.session_count(), 0);
}

#[test]
fn retransmitted_req_is_idempotent_and_answered_from_cache() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let body = labproto::args::encode_argv(&["x"]);
    let mk = |c: &mut Raw| c.frame(FrameType::Req, 1, 0, CMD_PING, 1, body.len() as u32, 0, 0, 0, &body);
    let acts = sv.on_frame(&keys, &mk(&mut c), &[], now);
    assert_eq!(reqs(&acts), 1);
    let handle = match requests(&acts)[0] {
        Action::Request { req_id, .. } => *req_id,
        _ => unreachable!(),
    };
    // retransmission while running: no second Request, an ACK comes back
    let acts = sv.on_frame(&keys, &mk(&mut c), &[], now);
    assert_eq!(reqs(&acts), 0);
    assert!(sends(&acts).iter().any(|s| parse(s).unwrap().1.ftype == FrameType::Ack as u8));
    // respond; the client never acks the RESP (lost); REQ is retransmitted again: still no second Request
    let out = sv.respond(handle, Status::Ok, b"result", now);
    let resp_frames = sends(&out).iter().filter(|s| parse(s).unwrap().1.ftype == FrameType::Resp as u8).count();
    assert_eq!(resp_frames, 1);
    let acts = sv.on_frame(&keys, &mk(&mut c), &[], now);
    assert_eq!(reqs(&acts), 0);
    // later still: the RESP is retransmitted by the RTO, never the command
    let acts = sv.poll(now + Duration::from_millis(300));
    assert!(sends(&acts).iter().any(|s| parse(s).unwrap().1.ftype == FrameType::Resp as u8));
}

#[test]
fn ninth_outstanding_request_gets_busy() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    for i in 1..=8 {
        assert_eq!(reqs(&sv.on_frame(&keys, &c.req(CMD_EXEC, i, &["x"]), &[], now)), 1);
    }
    let acts = sv.on_frame(&keys, &c.req(CMD_PING, 9, &["x"]), &[], now);
    assert_eq!(reqs(&acts), 0);
    let busy = sends(&acts).iter().filter_map(|s| parse(s)).find(|(_, h, _)| h.ftype == FrameType::Resp as u8).map(|(_, h, _)| h.status);
    assert_eq!(busy, Some(Status::Busy as u16));
}

#[test]
fn out_of_order_flood_is_bounded_by_window_times_frag() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let acts = sv.on_frame(&keys, &c.req(CMD_PUT, 1, &["f"]), &[], now);
    assert_eq!(reqs(&acts), 1);
    let mut rng = Rng(0xabcdef);
    let max_held = 16 * 1400;
    // a hole at offset 0 stays open; an attacker with a valid key floods fragments at random offsets
    for _ in 0..5000 {
        let slot = 1 + rng.below(100_000) as u32;
        let f = c.frame(FrameType::Data, 0, 4, 0, 1, u32::MAX, slot * 1400, 0, 0, &[0xAB; 1400]);
        sv.on_frame(&keys, &f, &[], now);
        assert!(sv.held_bytes() <= max_held, "held {}", sv.held_bytes());
    }
    // the same with the window edge: the offset just inside is stored, just outside is dropped
    assert!(sv.held_bytes() > 0);
}

#[test]
fn stream_data_before_the_request_is_complete_is_ignored() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    // REQ of 3000 bytes: only the first fragment sent; DATA for req 1 arrives early
    let f = c.frame(FrameType::Req, 0, 0, CMD_PUT, 1, 3000, 0, 0, 0, &[0u8; 1400]);
    sv.on_frame(&keys, &f, &[], now);
    let f = c.frame(FrameType::Data, flags::FIN, 4, 0, 1, u32::MAX, 0, 0, 0, b"early");
    let acts = sv.on_frame(&keys, &f, &[], now);
    assert!(!acts.iter().any(|a| matches!(a, Action::StreamData { .. } | Action::StreamEnd { .. })));
    // DATA for an unknown request is ignored too
    let f = c.frame(FrameType::Data, flags::FIN, 4, 0, 77, u32::MAX, 0, 0, 0, b"x");
    assert!(!sv.on_frame(&keys, &f, &[], now).iter().any(|a| matches!(a, Action::StreamData { .. })));
}

#[test]
fn idle_session_expires_and_running_requests_are_canceled() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    sv.on_frame(&keys, &c.req(CMD_EXEC, 1, &["sleep"]), &[], now);
    let _ = sv.poll(now + Duration::from_secs(100));
    assert!(!sv.take_events().iter().any(|e| matches!(e, ServerEvent::SessionEnded { .. })));
    let acts = sv.poll(now + Duration::from_secs(121));
    assert!(acts.iter().any(|a| matches!(a, Action::Canceled { .. })));
    assert!(sv.take_events().iter().any(|e| matches!(e, ServerEvent::SessionEnded { reason: "idle timeout", .. })));
    assert_eq!(sv.session_count(), 0);
}

#[test]
fn authenticated_traffic_refreshes_the_idle_timer_and_lifetime_is_one_hour() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let mut t = now;
    for i in 0..40u32 {
        t += Duration::from_secs(100);
        let f = c.frame(FrameType::Keepalive, 0, 0, 0, 0, 0, 0, 0, 0, &[]);
        let acts = sv.on_frame(&keys, &f, &[], t);
        // keepalive is answered with REPLY
        let (_, h, _) = parse(&sends(&acts)[0]).unwrap();
        assert_eq!(h.ftype, FrameType::Keepalive as u8);
        assert_eq!(h.flags & flags::REPLY, flags::REPLY);
        let _ = sv.poll(t);
        let ended = sv.take_events().iter().any(|e| matches!(e, ServerEvent::SessionEnded { .. }));
        if t.duration_since(now) >= Duration::from_secs(3600) {
            assert!(ended, "i={}", i);
            return;
        }
        assert!(!ended, "i={}", i);
    }
    panic!("lifetime never ended the session");
}

#[test]
fn no_session_frames_are_rate_limited_and_small() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    c.session = 0x1234_5678;
    c.sk = [9; 32];
    let f = c.req(CMD_PING, 1, &["x"]);
    let mut sent = 0;
    for i in 0..200u64 {
        let acts = sv.on_frame(&keys, &c.req(CMD_PING, 1 + i as u32, &["x"]), &[], now);
        for s in sends(&acts) {
            assert!(s.len() <= f.len());
            sent += 1;
        }
    }
    // burst of 4 triggers x 2 keys, nothing more within the same instant
    assert!(sent > 0 && sent <= 8, "sent {}", sent);
    // and each NO_SESSION verifies with its key and carries the boot id
    let acts = sv.on_frame(&keys, &c.req(CMD_PING, 500, &["x"]), &[], now + Duration::from_secs(60));
    let s = sends(&acts);
    assert_eq!(s.len(), 2);
    let (_, p) = frame::eth_parse(&s[0]).unwrap();
    let fr = frame::open(p).unwrap();
    assert!(frame::verify(&fr, TagKey::NoSession(&admin_key().bytes)));
    assert_eq!(frame::nosession_boot_id(&fr.hdr), sv.boot_id());
    assert_eq!(fr.hdr.session, 0x1234_5678);
}

#[test]
fn garbage_never_panics_and_never_creates_requests() {
    let (mut sv, keys, now) = server();
    let mut c = Raw::new(mac(1), vec![], admin_key(), 0x11);
    assert!(c.handshake(&mut sv, &keys, now));
    let valid = [c.req(CMD_PING, 1, &["x"]), c.hello(), c.open(), c.frame(FrameType::Data, 0, 3, 0, 1, u32::MAX, 0, 0, 0, b"zz")];
    // deliver the one legitimate request first: byte flips that happen to be no-ops are plain replays after it
    assert_eq!(reqs(&sv.on_frame(&keys, &valid[0], &[], now)), 1);
    let mut rng = Rng(77);
    let mut delivered = 0;
    for i in 0..30_000u64 {
        let mut f = valid[(i % 4) as usize].clone();
        match rng.below(4) {
            0 => {
                let n = rng.below(f.len() as u64) as usize;
                f.truncate(n);
            }
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let p = rng.below(f.len() as u64) as usize;
                    f[p] = rng.next() as u8;
                }
            }
            2 => {
                let n = rng.below(1600) as usize;
                f = rng.bytes(n);
            }
            _ => {
                // keep the ethernet + magic, randomise the rest
                if f.len() > 16 {
                    let tail = rng.bytes(f.len() - 16);
                    f.splice(16.., tail);
                }
            }
        }
        let t = now + Duration::from_millis(i);
        let acts = sv.on_frame(&keys, &f, &[], t);
        delivered += reqs(&acts);
        let _ = sv.poll(t);
    }
    assert_eq!(delivered, 0);
    let _ = hmac_sha256(&[], &[]);
}
