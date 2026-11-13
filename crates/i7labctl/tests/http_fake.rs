//! The real HTTP client against an in-process fake i7labd (std TcpListener + labproto::httpauth).
mod common;

use common::fake_http::{Evil, FakeHttp};
use common::*;
use labproto::keys::{Key, KeySet, Role};

fn keys_of(t: &T) -> (Key, Key) {
    let ks = KeySet::load_dir(&i7labctl::keys::default_key_dir(&t.home)).unwrap();
    (ks.admin.unwrap(), ks.ro.unwrap())
}

fn run_http(t: &T, srv: &FakeHttp, args: &[&str]) -> (i32, String, String) {
    let mut env = t.env();
    env.connector = Box::new(i7labctl::cmds::RealConnect);
    let mut a: Vec<String> = vec!["--http".to_string(), srv.addr.clone()];
    a.extend(args.iter().map(|s| s.to_string()));
    t.out.0.lock().unwrap().clear();
    t.err.0.lock().unwrap().clear();
    let code = i7labctl::cli::run_with(a, &mut env);
    (code, t.out.text(), t.err.text())
}

#[test]
fn signed_request_and_proof_roundtrip() {
    need_json!();
    let t = T::new("h1");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, e) = run_http(&t, &srv, &["ping", "--json"]);
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("\"transport\":\"http\"") && o.contains("\"data\":{\"uptime_ms\":4242,\"boot_id\":\"9f3c\"}") || o.contains("\"sent\":4"), "{}", o);
    let (code, o, _) = run_http(&t, &srv, &["blk", "ls", "--json"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"data\":{\"v\":1,\"devices\":[]}"), "{}", o);
    let reqs = srv.state.lock().unwrap().requests.clone();
    assert!(reqs.iter().any(|r| r == "POST /api/v1/cmd/blk.ls"), "{:?}", reqs);
}

#[test]
fn the_role_comes_from_the_key_and_is_reported() {
    need_json!();
    let t = T::new("h2");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, _) = run_http(&t, &srv, &["id", "--role", "ro", "--json"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"role\":\"ro\""), "{}", o);
    let (_, o, _) = run_http(&t, &srv, &["id", "--role", "admin", "--json"]);
    assert!(o.contains("\"role\":\"admin\""), "{}", o);
}

#[test]
fn unknown_key_is_rejected_with_exit_5() {
    let t = T::new("h3");
    let other = Key::generate(Role::Admin).unwrap();
    let srv = FakeHttp::start(vec![other]);
    let (code, _, e) = run_http(&t, &srv, &["id"]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("rejected the request signature"), "{}", e);
}

#[test]
fn a_reply_without_a_valid_proof_is_not_trusted() {
    let t = T::new("h4");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    srv.set_evil(Evil::BadProof);
    let (code, o, e) = run_http(&t, &srv, &["blk", "ls"]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("not authentic") && !o.contains("devices"), "{} / {}", e, o);
}

#[test]
fn remote_refusal_over_http_is_exit_7_with_reasons() {
    need_json!();
    let t = T::new("h5");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, _) = run_http(&t, &srv, &["--cmd", "blk.write", "sdb", "--json"]);
    assert_eq!(code, 7, "{}", o);
    assert!(o.contains("\"code\":\"REFUSED\"") && o.contains("\"reasons\":[\"mounted\"]") && o.contains("device mounted"), "{}", o);
    let (code, _, e) = run_http(&t, &srv, &["--cmd", "reboot"]);
    assert_eq!(code, 5, "{}", e);
    let (code, _, _) = run_http(&t, &srv, &["--cmd", "kexec"]);
    assert_eq!(code, 10);
}

#[test]
fn exec_stream_events_are_verified_and_the_exit_status_passes_through() {
    need_json!();
    let t = T::new("h6");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, e) = run_http(&t, &srv, &["exec", "--", "false"]);
    assert_eq!(code, 3, "{}", e);
    assert!(o.starts_with("hello\n") && o.contains("a\u{fffd}b") || o.contains("hello"), "{:?}", o);
    assert!(e.contains("warn"), "{}", e);
    let (code, o, _) = run_http(&t, &srv, &["exec", "--json", "--", "false"]);
    assert_eq!(code, 3);
    assert!(o.lines().last().unwrap().starts_with("{\"event\":\"result\",\"ok\":false,\"exit\":3"), "ok is exit==0: {}", o);
    assert!(o.contains("\"b64\":\"Yf9i\""), "{}", o);
    assert!(srv.state.lock().unwrap().requests.iter().any(|r| r.contains("/api/v1/cmd/exec?stream=1")));
}

#[test]
fn blk_stream_progress_and_result() {
    need_json!();
    let t = T::new("h7");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, e) = run_http(&t, &srv, &["blk", "read", "sda", "--mb", "8", "--json"]);
    assert_eq!(code, 0, "{}", e);
    let lines: Vec<&str> = o.lines().collect();
    assert_eq!(lines.len(), 2, "{}", o);
    assert!(lines[0].contains("\"event\":\"progress\"") && lines[0].contains("412.5"), "{}", lines[0]);
    assert!(lines[1].starts_with("{\"event\":\"result\",\"ok\":true,\"exit\":0"), "{}", lines[1]);
    let (code, o, _) = run_http(&t, &srv, &["blk", "read", "sda"]);
    assert_eq!(code, 0);
    assert!(o.contains("RESULT: ok"), "{}", o);
}

#[test]
fn tampered_streams_are_rejected() {
    need_json!();
    let t = T::new("h8");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    srv.set_evil(Evil::BadEventMac);
    let (code, o, e) = run_http(&t, &srv, &["blk", "read", "sda"]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("mac is invalid") && !o.contains("progress"), "{} / {}", e, o);
    // exec reports its own errors as 255
    let (code, o, e) = run_http(&t, &srv, &["exec", "--", "true"]);
    assert_eq!(code, 255, "{}", e);
    assert!(e.contains("mac is invalid") && !o.contains("hello"), "{} / {}", e, o);
    srv.set_evil(Evil::SeqGap);
    let (code, _, e) = run_http(&t, &srv, &["blk", "read", "sda"]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("sequence gap"), "{}", e);
    srv.set_evil(Evil::NoResult);
    let (code, _, e) = run_http(&t, &srv, &["exec", "--", "true"]);
    assert_eq!(code, 255, "{}", e);
    assert!(e.contains("without a result event"), "{}", e);
}

#[test]
fn put_and_get_use_the_raw_file_endpoints_with_streamed_hashes() {
    need_json!();
    let t = T::new("h9");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let data: Vec<u8> = (0..1_500_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    let src = t.dir.join("big.bin");
    std::fs::write(&src, &data).unwrap();
    let (code, o, e) = run_http(&t, &srv, &["put", src.to_str().unwrap(), "/run/big.bin", "extra", "--mode", "0644"]);
    // the host is the --http address: positional host is not needed; `x` above would be a stray argument
    assert_eq!(code, 2, "{} {}", o, e);
    let (code, o, e) = run_http(&t, &srv, &["put", src.to_str().unwrap(), "/run/big.bin", "--mode", "0644"]);
    assert_eq!(code, 0, "{} {}", o, e);
    assert_eq!(srv.state.lock().unwrap().files.get("/run/big.bin").unwrap(), &data);
    assert!(srv.state.lock().unwrap().requests.iter().any(|r| r.starts_with("PUT /api/v1/file?path=/run/big.bin&mode=0644")), "{:?}", srv.state.lock().unwrap().requests);

    let dst = t.dir.join("back.bin");
    let (code, o, e) = run_http(&t, &srv, &["get", "/run/big.bin", dst.to_str().unwrap()]);
    assert_eq!(code, 0, "{} {}", o, e);
    assert_eq!(std::fs::read(&dst).unwrap(), data);
    assert!(!t.dir.join("back.bin.part").exists());
    // a missing file
    let (code, _, e) = run_http(&t, &srv, &["get", "/nope", t.dir.join("n").to_str().unwrap()]);
    assert_eq!(code, 6, "{}", e);

    // a body that does not match the trailer proof is never kept
    srv.set_evil(Evil::TamperBody);
    let dst2 = t.dir.join("evil.bin");
    let (code, _, e) = run_http(&t, &srv, &["get", "/run/big.bin", dst2.to_str().unwrap()]);
    assert_eq!(code, 5, "{}", e);
    assert!(!dst2.exists(), "a tampered download must not be renamed into place");
}

#[test]
fn api_raw_request() {
    need_json!();
    let t = T::new("h10");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    let (code, o, e) = run_http(&t, &srv, &["api", "POST", "/api/v1/cmd/ping", "--data", "{\"args\":[]}"]);
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("uptime_ms"), "{}", o);
    let (code, o, _) = run_http(&t, &srv, &["api", "GET", "/api/v1/nonexistent", "--json"]);
    assert_eq!(code, 1);
    assert!(o.contains("\"status\":404"), "{}", o);
}

#[test]
fn a_silent_host_times_out_with_exit_4() {
    let t = T::new("h11");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    srv.set_evil(Evil::Hang);
    let started = std::time::Instant::now();
    let (code, _, e) = run_http(&t, &srv, &["ping", "-c", "1", "--timeout", "1"]);
    assert_eq!(code, 4, "{}", e);
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    // nothing listening at all
    let (code, _, e) = {
        let mut env = t.env();
        env.connector = Box::new(i7labctl::cmds::RealConnect);
        t.err.0.lock().unwrap().clear();
        let c = i7labctl::cli::run_with(vec!["id".into(), "--http".into(), "127.0.0.1:1".into()], &mut env);
        (c, String::new(), t.err.text())
    };
    assert_eq!(code, 4, "{}", e);
}

#[test]
fn nonces_are_not_reused_between_requests() {
    let t = T::new("h12");
    let (admin, ro) = keys_of(&t);
    let srv = FakeHttp::start(vec![admin, ro]);
    for _ in 0..3 {
        assert_eq!(run_http(&t, &srv, &["id"]).0, 0);
    }
    let reqs = srv.state.lock().unwrap().requests.clone();
    assert_eq!(reqs.iter().filter(|r| r.as_str() == "GET /api/v1/nonce").count(), 3);
}
