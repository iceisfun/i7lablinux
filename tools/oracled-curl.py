#!/usr/bin/env python3
"""Signed HTTP client for i7oracled (and any i7labd-style HTTP API). Python 3 standard library only.

  oracled-curl.py [--host HOST] [--port 8765] [--key-file FILE | --key i7k1:...] METHOD PATH [BODY | @FILE | -]

Scheme (identical to i7labd, docs/PROTOCOL.md, crates/labproto/src/httpauth.rs):
  GET /nonce                          -> {"nonce": "...", "ttl_s": 30}
  X-Lab-Key:   first 4 bytes of SHA256("i7c-keyid" + K), hex
  X-Lab-Nonce: the nonce
  X-Lab-Auth:  hex(HMAC-SHA256(K, "lp-req\\n" nonce "\\n" METHOD "\\n" TARGET "\\n" hex(sha256(body))))
  reply header X-Lab-Proof must equal hex(HMAC-SHA256(K, "lp-resp\\n" nonce "\\n" status "\\n" hex(sha256(reply body))))
TARGET is the path with its query string exactly as sent.

Key lookup: --key, --key-file, $I7ORACLED_KEY (a key line), $I7ORACLED_KEYFILE, then
$I7LABCTL_KEYDIR/<role>.key, ~/.config/i7labctl/keys/<role>.key, ./keys/<role>.key. --role picks admin (default) or ro.

Examples:
  oracled-curl.py --host 192.0.2.40 GET /info
  oracled-curl.py --host 192.0.2.40 POST /run '{"name":"win10_foo_probe.exe","timeout_s":60}'
  oracled-curl.py --host 192.0.2.40 POST /power '{"action":"sleep","wake_after_s":30}'
  oracled-curl.py --host 192.0.2.40 GET '/events?since=120'
  oracled-curl.py --host 192.0.2.40 --follow --since 0        # poll /events and print new records until Ctrl-C
Exit status: 0 on 2xx with a valid proof, 1 on HTTP errors, 2 on usage/key errors, 3 on a bad or missing proof.
"""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import sys
import time


def sha(b):
    return hashlib.sha256(b).hexdigest()


def key_id(k):
    return hashlib.sha256(b"i7c-keyid" + k).hexdigest()[:8]


def parse_key(line):
    p = line.strip().split(":")
    if len(p) != 3 or p[0] != "i7k1" or p[1] not in ("admin", "ro") or len(p[2]) != 64:
        raise ValueError("not an i7k1:<role>:<64 hex> key line")
    return p[1], bytes.fromhex(p[2])


def find_key(a):
    if a.key:
        return parse_key(a.key)
    path = a.key_file or os.environ.get("I7ORACLED_KEYFILE")
    if os.environ.get("I7ORACLED_KEY") and not path:
        return parse_key(os.environ["I7ORACLED_KEY"])
    cands = [path] if path else [
        os.path.join(os.environ.get("I7LABCTL_KEYDIR", ""), a.role + ".key") if os.environ.get("I7LABCTL_KEYDIR") else None,
        os.path.expanduser("~/.config/i7labctl/keys/%s.key" % a.role),
        os.path.join("keys", a.role + ".key"),
    ]
    for c in cands:
        if c and os.path.exists(c):
            with open(c) as f:
                return parse_key(f.read())
    raise FileNotFoundError("no %s key found (use --key-file)" % a.role)


class Client:
    def __init__(self, host, port, key, timeout):
        self.host, self.port, self.key, self.timeout = host, port, key, timeout

    def request(self, method, target, body=b""):
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request("GET", "/nonce")
            nonce = json.loads(c.getresponse().read())["nonce"]
        finally:
            c.close()
        mac = hmac.new(self.key, ("lp-req\n%s\n%s\n%s\n%s" % (nonce, method, target, sha(body))).encode(), hashlib.sha256).hexdigest()
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request(method, target, body=body if body else None, headers={
                "X-Lab-Key": key_id(self.key), "X-Lab-Nonce": nonce, "X-Lab-Auth": mac,
                "Content-Type": "application/json", "Content-Length": str(len(body))})
            r = c.getresponse()
            data = r.read()
            proof = r.getheader("X-Lab-Proof")
        finally:
            c.close()
        want = hmac.new(self.key, ("lp-resp\n%s\n%d\n%s" % (nonce, r.status, sha(data))).encode(), hashlib.sha256).hexdigest()
        proof_ok = proof is not None and hmac.compare_digest(proof, want)
        return r.status, data, proof_ok


def main():
    ap = argparse.ArgumentParser(description="signed requests for i7oracled", add_help=True)
    ap.add_argument("--host", default=os.environ.get("I7ORACLED_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("I7ORACLED_PORT", "8765")))
    ap.add_argument("--key")
    ap.add_argument("--key-file")
    ap.add_argument("--role", choices=["admin", "ro"], default="admin")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--raw", action="store_true", help="print the body only, no status line")
    ap.add_argument("--follow", action="store_true", help="poll GET /events and print each new record (JSON lines)")
    ap.add_argument("--since", type=int, default=0, help="with --follow: start after this seq")
    ap.add_argument("method", nargs="?")
    ap.add_argument("path", nargs="?")
    ap.add_argument("body", nargs="?", default="")
    a = ap.parse_args()
    try:
        role, k = find_key(a)
    except Exception as e:
        print("oracled-curl: %s" % e, file=sys.stderr)
        return 2
    cl = Client(a.host, a.port, k, a.timeout)
    if a.follow:
        since = a.since
        try:
            while True:
                try:
                    st, data, ok = cl.request("GET", "/events?since=%d&limit=1000" % since)
                    if st == 200 and ok:
                        d = json.loads(data)
                        for ev in d["events"]:
                            print(json.dumps(ev, separators=(",", ":")), flush=True)
                        since = max(since, d["next"])
                    elif st != 200:
                        print("# http %d" % st, file=sys.stderr)
                except (OSError, http.client.HTTPException, ValueError) as e:
                    print("# %s (machine asleep or rebooting? retrying)" % e, file=sys.stderr)
                time.sleep(1.0)
        except KeyboardInterrupt:
            return 0
    if not a.method or not a.path:
        ap.print_usage(sys.stderr)
        return 2
    if a.body == "-":
        body = sys.stdin.buffer.read()
    elif a.body.startswith("@"):
        with open(a.body[1:], "rb") as f:
            body = f.read()
    else:
        body = a.body.encode()
    try:
        st, data, ok = cl.request(a.method.upper(), a.path, body)
    except (OSError, http.client.HTTPException) as e:
        print("oracled-curl: %s" % e, file=sys.stderr)
        return 1
    if not a.raw:
        print("# HTTP %d  proof %s  (%s key)" % (st, "ok" if ok else "BAD/MISSING", role), file=sys.stderr)
    sys.stdout.buffer.write(data if data.endswith(b"\n") else data + b"\n")
    if not ok:
        # authentication failures (401, 429) are answered without a proof by design
        return 1 if st in (401, 429) else 3
    return 0 if st < 400 else 1


if __name__ == "__main__":
    sys.exit(main())
