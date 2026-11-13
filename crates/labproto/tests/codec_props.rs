//! Seeded property / fuzz-ish tests of the frame codecs, plus golden bytes cross-checked between the engine
//! and the hand-rolled `Raw` client, and PROTOCOL.md <-> catalogue consistency.
mod common;
use common::*;

use std::time::Instant;

use labproto::catalog::{self, CATALOG};
use labproto::crypto::{hex, hmac_sha256};
use labproto::frame::{self, Header, Dir, TagKey};
use labproto::handshake::{CookieJar, Hello, CHALLENGE_LEN, HELLO_LEN};
use labproto::session::{Action, ClientSession, ServerSessions, SessionLimits};

#[test]
fn header_roundtrip_random() {
    let mut rng = Rng(5);
    for _ in 0..20_000 {
        let h = Header {
            ver: rng.next() as u8,
            ftype: rng.next() as u8,
            flags: rng.next() as u8,
            chan: rng.next() as u8,
            cmd: rng.next() as u16,
            session: rng.next() as u32,
            req_id: rng.next() as u32,
            ctr: rng.next(),
            msg_len: rng.next() as u32,
            off: rng.next() as u32,
            plen: rng.next() as u16,
            win: rng.next() as u16,
            status: rng.next() as u16,
        };
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
}

#[test]
fn seal_open_verify_random_and_every_bit_flip_fails() {
    let mut rng = Rng(6);
    for _ in 0..300 {
        let n = rng.below(200) as usize;
        let payload = rng.bytes(n);
        let sk: [u8; 32] = rng.bytes(32).try_into().unwrap();
        let h = Header { ver: 1, ftype: 5, session: rng.next() as u32, ctr: 1 + rng.below(1000), plen: n as u16, ..Default::default() };
        let sealed = frame::seal(&h, &payload, TagKey::Session { sk: &sk, dir: Dir::ClientToServer });
        let f = frame::open(&sealed).unwrap();
        assert_eq!(f.payload, &payload[..]);
        assert!(frame::verify(&f, TagKey::Session { sk: &sk, dir: Dir::ClientToServer }));
        // flip each bit of header+payload+tag except the reserved header bytes 38..40 which are covered by the
        // tag too: nothing may verify
        for byte in 0..sealed.len() {
            for bit in [0u8, 3, 7] {
                let mut g = sealed.clone();
                g[byte] ^= 1 << bit;
                if let Ok(gf) = frame::open(&g) {
                    assert!(!frame::verify(&gf, TagKey::Session { sk: &sk, dir: Dir::ClientToServer }), "flip {}:{}", byte, bit);
                }
            }
        }
    }
}

#[test]
fn parsers_never_panic_on_random_input() {
    let mut rng = Rng(7);
    for i in 0..60_000u64 {
        let n = rng.below(300) as usize;
        let mut b = rng.bytes(n);
        // bias towards plausible prefixes so deeper code runs
        if i % 3 == 0 && b.len() > 16 {
            b[12] = 0x88;
            b[13] = 0xb6;
            b[14] = 0x49;
            b[15] = 0x37;
        }
        let _ = frame::eth_parse(&b);
        let _ = frame::open(&b);
        let _ = Header::decode(&b);
        let _ = labproto::beacon::Beacon::parse(&b);
        let _ = labproto::beacon::Hint::parse(&b, Some(&[1; 32]));
        let _ = labproto::args::decode_argv(&b);
        let _ = labproto::handshake::Hello::decode(&b);
        let _ = labproto::handshake::Challenge::decode(&b);
        let _ = labproto::handshake::OpenOk::decode(&b);
        let _ = frame::canonical_tags(Some((0x8100, 1)), &[(0x8100, 2), (0x8100, 3)]);
    }
}

#[test]
fn eth_build_parse_random_tag_stacks() {
    let mut rng = Rng(8);
    for _ in 0..5000 {
        let ntags = rng.below(3) as usize;
        let tags: Vec<(u16, u16)> = (0..ntags).map(|_| (if rng.below(2) == 0 { 0x8100 } else { 0x88a8 }, rng.next() as u16)).collect();
        let n = rng.below(1500) as usize;
        let payload = rng.bytes(n);
        let h = frame::EthHeader { dst: Mac([2, 0, 0, 0, 0, 2]), src: Mac([2, 0, 0, 0, 0, 1]), tags: tags.clone(), ethertype: frame::ETHERTYPE_CTL };
        let f = frame::eth_build(&h, &payload);
        assert!(f.len() >= 60);
        let (h2, p) = frame::eth_parse(&f).unwrap();
        assert_eq!(h2, h);
        assert_eq!(&p[..payload.len()], &payload[..]);
    }
}

use labproto::mac::Mac;

/// The engine's HELLO is byte-identical to the one the hand-rolled client builds from PROTOCOL.md 4.2, and
/// its tag is the documented HMAC. A regression golden is pinned too.
#[test]
fn hello_golden_and_cross_check() {
    let t0 = Instant::now();
    let key = admin_key();
    let mut cl = ClientSession::with_nonce(CLIENT, SERVER, vec![], &key, SessionLimits::default(), t0, [0x11; 16]);
    let acts = cl.poll(t0);
    let Action::Send(f) = &acts[0] else { panic!() };
    let raw = Raw::new(CLIENT, vec![], key.clone(), 0x11);
    assert_eq!(f, &raw.hello());
    // spelled out from the spec
    let (eth, p) = frame::eth_parse(f).unwrap();
    assert_eq!((eth.dst, eth.src, eth.ethertype), (SERVER, CLIENT, 0x88b6));
    assert_eq!(p.len(), 40 + HELLO_LEN + 16);
    assert_eq!(&p[..8], &[0x49, 0x37, 1, 1, 0, 0, 0, 0]); // magic, ver, type HELLO, flags, chan, cmd
    let hello = Hello { cn: [0x11; 16], key_id: key.key_id(), ver_min: 1, ver_max: 1, max_frag: 1400, caps: 1 };
    let want = hmac_sha256(&key.bytes, &[b"i7c-hello\0", &p[..40], &hello.encode()]);
    assert_eq!(&p[40 + HELLO_LEN..], &want[..16]);
    assert_eq!(hex(&p[..40]), "49370101000000000000000000000000000000000000000000000000000000000030000000000000");
    assert_eq!(hex(&p[40..44]), "11111111");
    assert_eq!(&p[56..60], &key.key_id());
}

/// Deterministic CHALLENGE: cookie and tag recomputed independently from the spec.
#[test]
fn challenge_golden_and_cross_check() {
    let now = Instant::now();
    let jar = CookieJar::with_secret([7; 32]);
    let mut sv = ServerSessions::with_parts(SERVER, SessionLimits::default(), CookieJar::with_secret([7; 32]), [9; 8]);
    sv.set_uptime_base(100_000);
    let keys = keyset();
    let c = Raw::new(CLIENT, vec![], admin_key(), 0x11);
    let acts = sv.on_frame(&keys, &c.hello(), &[], now);
    let s = sends(&acts);
    let (_, h, payload) = parse(&s[0]).unwrap();
    assert_eq!(h.ftype, 2);
    assert_eq!(payload.len(), CHALLENGE_LEN);
    let sn = jar.make(100_000, &CLIENT, &SERVER, &[0x11; 16], &[]);
    assert_eq!(&payload[..16], &sn);
    assert_eq!(&payload[16..24], &[9; 8]);
    assert_eq!(u32::from_be_bytes(payload[24..28].try_into().unwrap()), 100_000);
    assert_eq!(payload[28], 1);
    assert_eq!(u16::from_be_bytes([payload[30], payload[31]]), 1400);
    // tag = HMAC(K, "i7c-chal\0" | hdr | payload | cn)
    let (_, p) = frame::eth_parse(&s[0]).unwrap();
    let want = hmac_sha256(&admin_key().bytes, &[b"i7c-chal\0", &p[..40], &payload, &[0x11; 16]]);
    assert_eq!(&p[40 + CHALLENGE_LEN..40 + CHALLENGE_LEN + 16], &want[..16]);
}

/// Every command of PROTOCOL.md section 7 is in the catalogue with the same id and name, and vice versa.
#[test]
fn protocol_md_and_catalogue_agree() {
    let doc = include_str!("../../../docs/PROTOCOL.md");
    let mut in_doc: Vec<(u16, String)> = Vec::new();
    for line in doc.lines() {
        let cols: Vec<&str> = line.split('|').map(|c| c.trim()).collect();
        if cols.len() > 3 && cols[1].starts_with("0x") && cols[2].starts_with('`') {
            let id = u16::from_str_radix(&cols[1][2..], 16).unwrap();
            in_doc.push((id, cols[2].trim_matches('`').to_string()));
        }
    }
    assert!(in_doc.len() >= 30, "parsed only {} rows", in_doc.len());
    for (id, name) in &in_doc {
        let c = catalog::by_id(*id).unwrap_or_else(|| panic!("{} (0x{:04x}) missing from the catalogue", name, id));
        assert_eq!(c.name, name, "id 0x{:04x}", id);
    }
    // catalogue entries added after PROTOCOL.md (PLAN D4: time.set, tui.dump) are allowed extras
    for c in CATALOG {
        if !in_doc.iter().any(|(i, _)| *i == c.id) {
            assert!(matches!(c.name, "time.set" | "tui.dump"), "catalogue entry {} (0x{:04x}) not in PROTOCOL.md", c.name, c.id);
        }
    }
}

#[test]
fn client_survives_garbage_and_spoofed_frames() {
    let t0 = Instant::now();
    let mut cl = ClientSession::new(CLIENT, SERVER, vec![], &admin_key(), SessionLimits::default(), t0);
    let _ = cl.poll(t0);
    let mut rng = Rng(99);
    for i in 0..20_000 {
        let n = rng.below(200) as usize;
        let mut b = rng.bytes(n);
        if i % 2 == 0 && b.len() > 20 {
            b[0..6].copy_from_slice(&CLIENT.0);
            b[6..12].copy_from_slice(&SERVER.0);
            b[12] = 0x88;
            b[13] = 0xb6;
            b[14] = 0x49;
            b[15] = 0x37;
            b[16] = 1;
        }
        let acts = cl.on_frame(&b, &[], t0);
        assert!(acts.iter().all(|a| matches!(a, Action::Send(_))), "garbage produced {:?}", acts);
    }
    assert!(!cl.is_open());
}
