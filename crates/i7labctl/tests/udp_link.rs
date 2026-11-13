//! The real connector's `--link udp:` path (UdpLink on loopback): discover over actual sockets.
mod common;

use std::net::UdpSocket;

use common::*;
use labproto::beacon::Beacon;
use labproto::frame;
use labproto::Mac;

#[test]
fn discover_over_a_udp_link() {
    need_json!();
    let t = T::new("udp");
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local_port = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let src = Mac([0x52, 0x54, 0, 0x17, 0, 1]);
    let mut b = Beacon { version: 2, fields: vec![] };
    b.set("mac", &src.to_string());
    b.set("host", "udp-host");
    b.set("state", "ready");
    let eth = frame::EthHeader { dst: Mac::BROADCAST, src, tags: vec![], ethertype: frame::ETHERTYPE_BEACON };
    let f = frame::eth_build(&eth, &b.encode_v2(None, &src));
    let sender = std::thread::spawn(move || {
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_millis(60));
            let _ = peer.send_to(&f, ("127.0.0.1", local_port));
        }
    });
    let mut env = t.env();
    env.connector = Box::new(i7labctl::cmds::RealConnect);
    let link = format!("udp:{}:{}", local_port, 9); // remote port is irrelevant for listening
    let code = i7labctl::cli::run_with(vec!["discover".into(), "--link".into(), link, "--listen".into(), "1.5".into(), "--no-registry".into()], &mut env);
    sender.join().unwrap();
    assert_eq!(code, 0, "{}", t.err.text());
    assert!(t.out.text().contains("udp-host"), "{}", t.out.text());
}

#[test]
fn bad_link_specs_are_usage_errors() {
    let t = T::new("udpbad");
    let mut env = t.env();
    env.connector = Box::new(i7labctl::cmds::RealConnect);
    assert_eq!(i7labctl::cli::run_with(vec!["discover".into(), "--link".into(), "tap:0".into(), "--listen".into(), "0.1".into()], &mut env), 2);
}

#[test]
fn raw_ethernet_without_privileges_explains_the_fix() {
    // AF_PACKET needs CAP_NET_RAW; this runs as a normal user in CI. P2's PacketLink is still a stub, which
    // also lands here: either way the message names the way out and the exit is 4.
    let t = T::new("noraw");
    let mut env = t.env();
    env.connector = Box::new(i7labctl::cmds::RealConnect);
    let code = i7labctl::cli::run_with(vec!["discover".into(), "--listen".into(), "0.1".into(), "--no-registry".into()], &mut env);
    if code == 0 {
        return; // running as root with a working PacketLink
    }
    assert_eq!(code, 4, "{}", t.err.text());
    assert!(t.err.text().contains("Ethernet"), "{}", t.err.text());
}
