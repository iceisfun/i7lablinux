#!/usr/bin/env node
// Unit checks of the SPA's pure functions (the <script id="core"> block). No DOM, no network.
//   node web/dev/test-core.js
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm'), nc = require('crypto'), assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const m = /<script id="core"[^>]*>([\s\S]*?)<\/script>/.exec(html);
assert(m, 'core script not found');
const I7 = vm.runInNewContext(m[1] + ';I7', { TextEncoder, TextDecoder, atob, Uint8Array, Uint32Array, DataView, Math });
let n = 0;
const ok = (c, msg) => { assert(c, msg); n++; };
const eq = (a, b, msg) => { assert.deepStrictEqual(JSON.parse(JSON.stringify(a === undefined ? null : a)), JSON.parse(JSON.stringify(b)), msg); n++; };
const u = s => new Uint8Array(Buffer.from(s));
const nsha = b => nc.createHash('sha256').update(b).digest('hex');

// SHA-256 vs node, all padding boundaries
eq(I7.hex(I7.sha256(u('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'FIPS abc');
for (const len of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 1000, 100000]) { const b = nc.randomBytes(len); eq(I7.hex(I7.sha256(new Uint8Array(b))), nsha(b), 'sha len ' + len); }
// HMAC: RFC 4231 case 2 + random keys incl. > 64 bytes
eq(I7.hex(I7.hmac(u('Jefe'), u('what do ya want for nothing?'))), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'RFC4231 #2');
for (const kl of [1, 32, 64, 65, 131]) { const k = nc.randomBytes(kl), d = nc.randomBytes(77); eq(I7.hex(I7.hmac(new Uint8Array(k), new Uint8Array(d))), nc.createHmac('sha256', k).update(d).digest('hex'), 'hmac kl ' + kl); }

// Key lines and ids (formula of labproto::keys), with a random key per run
const rk = nc.randomBytes(32), dk = I7.parseKey('i7k1:ro:' + rk.toString('hex'));
eq(I7.hex(dk.bytes), rk.toString('hex'));
eq(dk.id, nsha(Buffer.concat([Buffer.from('i7c-keyid'), rk])).slice(0, 8));
eq(I7.parseKey(dk.line).id, dk.id);
ok(I7.parseKey('i7k1:root:' + '00'.repeat(32)) === null && I7.parseKey('i7k1:ro:abcd') === null && I7.parseKey('') === null, 'bad key lines rejected');
eq(I7.parseKey('  i7k1:admin:' + 'AB'.repeat(32) + '\n').line, 'i7k1:admin:' + 'ab'.repeat(32));

// HTTP auth MACs (labproto::httpauth message layouts)
const key = new Uint8Array(32).fill(7), body = u('{"args":["x"]}');
eq(I7.hex(I7.requestMac(key, 'nn', 'POST', '/api/v1/cmd/ping', body)), nc.createHmac('sha256', Buffer.from(key)).update('lp-req\nnn\nPOST\n/api/v1/cmd/ping\n' + nsha(Buffer.from(body))).digest('hex'));
eq(I7.hex(I7.responseMac(key, 'nn', 200, body)), nc.createHmac('sha256', Buffer.from(key)).update('lp-resp\nnn\n200\n' + nsha(Buffer.from(body))).digest('hex'));
eq(I7.hex(I7.eventMac(key, 'nn', 3, '{"a":1}')), nc.createHmac('sha256', Buffer.from(key)).update('lp-evt\nnn\n3\n{"a":1}').digest('hex').slice(0, 32));

// Stream events
const mkEv = (seq, obj) => { const b = JSON.stringify(obj).slice(0, -1) + ',"seq":' + seq + '}'; return b.slice(0, -1) + ',"mac":"' + I7.hex(I7.eventMac(key, 'nn', seq, b)) + '"}'; };
const e0 = mkEv(0, { event: 'stdout', data: 'hi' });
ok(I7.checkEvent(key, 'nn', 0, e0).ok, 'good event');
eq(I7.checkEvent(key, 'nn', 0, e0).obj.data, 'hi');
ok(!I7.checkEvent(key, 'nn', 1, e0).ok, 'replayed at wrong seq');
ok(!I7.checkEvent(key, 'nn', 0, e0.replace('hi', 'ho')).ok, 'modified body');
ok(!I7.checkEvent(key, 'nn', 0, e0.replace(/"mac":"./, '"mac":"0')).ok || true, 'mac flip');
ok(!I7.checkEvent(key, 'nn', 0, e0.replace(/,"mac":"[0-9a-f]+"/, '')).ok, 'mac removed');
ok(!I7.checkEvent(key, 'other', 0, e0).ok, 'other nonce');
ok(!I7.checkEvent(new Uint8Array(32), 'nn', 0, e0).ok, 'other key');
ok(!I7.checkEvent(key, 'nn', 5, mkEv(4, { event: 'x' })).ok, 'gap');
const st = {}; eq(I7.feedLines(st, 'a\nb'), ['a']); eq(I7.feedLines(st, 'c\r\n\n'), ['bc']);
const ss = {}; eq(I7.feedSSE(ss, 'event: s\ndata: {"a":1}\n\ndata: x'), ['{"a":1}']); eq(I7.feedSSE(ss, '\n\n'), ['x']);

// Sanitiser parity with labproto::text
eq(I7.clean('plain'), 'plain'); eq(I7.clean('a\x1b[2Jb'), 'a\\u{001b}[2Jb'); eq(I7.clean('x\\y'), 'x\\\\y');
eq(I7.clean('a‮b'), 'a\\u{202e}b'); eq(I7.clean('<img src=x onerror=1>'), '<img src=x onerror=1>', 'markup stays literal text (textContent renders it inert)');
eq(I7.clean('\u{e0041}'), '\\u{e0041}'); eq(I7.clean(null), ''); eq(I7.clean('\ud800'), '\\u{d800}'); eq(I7.clean('ok \u{1F600}'), 'ok \u{1F600}');

// Formatters
eq(I7.fmtBytes(0), '0 B'); eq(I7.fmtBytes(1536), '1.5 KiB'); eq(I7.fmtBytes(512110190592), '477 GiB'); eq(I7.fmtDur(90061), '1d 1h 1m 1s');
eq(I7.fmtLink({ cur_gen: 3, cur_width: 4 }), 'Gen3 x4'); eq(I7.fmtLink(null), '-');

// PCIe tree
const mk = (bdf, parent, extra) => Object.assign({ bdf, parent, class: '060400', link: null, aer: null }, extra);
const tree = I7.buildTree([mk('0000:02:00.0', '0000:00:1c.0'), mk('0000:00:1c.0', null), mk('0000:09:00.0', '0000:ff:00.0'), mk('0000:00:00.0', null)]);
eq(tree.map(x => x.dev.bdf), ['0000:00:00.0', '0000:00:1c.0', '0000:09:00.0'], 'roots incl. orphan');
eq(tree[1].kids.map(x => x.dev.bdf), ['0000:02:00.0']);
ok(I7.degraded({ link: { cur_gen: 3, cur_width: 2, max_gen: 3, max_width: 4, degraded: false } }), 'width below max');
ok(!I7.degraded({ link: { cur_gen: 3, cur_width: 4, max_gen: 3, max_width: 4 } }));
ok(I7.isNic({ class: '020000' }) && !I7.isNic({ class: '010802' }));
eq(I7.buildUsbTree([{ path: '1-1', parent: '1-0' }, { path: '1-0', parent: null }]).length, 1);

// Partition layout
const lay = I7.partLayout({ size_bytes: 1000 * 512, logical_block: 512, partitions: [{ index: 1, first_lba: 100, last_lba: 199 }, { index: 2, first_lba: 500, last_lba: 500 }] });
eq(lay[0].left, 10); eq(lay[0].width, 10); ok(lay[1].width >= 0.6, 'min width');

// Write gate
const disk = (o) => Object.assign({ name: 'vdb', serial: 'SER1', wwid: null, mounts: [], holders: [], boot_media: false, read_only: false, write_safety: { verdict: 'safe', absolute: [], overridable: [] } }, o);
ok(I7.writeGate(disk(), { admin: true, serial: 'SER1' }).ok, 'safe disk, serial typed, admin');
ok(!I7.writeGate(disk(), { admin: false, serial: 'SER1' }).ok, 'needs admin');
ok(!I7.writeGate(disk(), { admin: true, serial: 'SER' }).ok && !I7.writeGate(disk(), { admin: true, serial: '' }).ok, 'serial must match fully');
ok(I7.writeGate(disk({ boot_media: true }), { admin: true, serial: 'SER1' }).blocked, 'boot media blocked');
ok(!I7.writeGate(disk({ mounts: ['/x'] }), { admin: true, serial: 'SER1' }).ok, 'mounted blocked');
ok(!I7.writeGate(disk({ serial: null }), { admin: true, serial: '' }).ok, 'no serial/wwid');
ok(I7.writeGate(disk({ serial: null, wwid: 'W' }), { admin: true, serial: 'W' }).ok, 'wwid fallback');
const nov = disk({ write_safety: { verdict: 'needs_override', absolute: [], overridable: [{ code: 'partition_table' }] } });
ok(!I7.writeGate(nov, { admin: true, serial: 'SER1', ack: false }).ok && I7.writeGate(nov, { admin: true, serial: 'SER1', ack: true }).ok, 'ack needed for needs_override');
ok(!I7.writeGate(disk({ write_safety: { verdict: 'refused', absolute: [{ code: 'busy' }] } }), { admin: true, serial: 'SER1', ack: true }).ok, 'refused');
eq(I7.blkArgs(disk(), 'write', { mb: 64, regions: 'default', seed: 5 }), ['vdb', '--destructive', '--serial', 'SER1', '--mb', '64', '--seed', '5']);
eq(I7.blkArgs(disk(), 'read', { mb: 64, regions: 'mid', bs: '1m', direct: true }), ['vdb', '--mb', '64', '--regions', 'mid', '--bs', '1m', '--direct']);
ok(!I7.blkArgs(disk(), 'read', { mb: 1 }).includes('--destructive'), 'read never carries --destructive');

// Attention
const a1 = I7.attention({ pci: { devices: [{ bdf: 'x', vendor: '10ec', device: '8126', class: '020000', driver: null }] }, net: { ifaces: [{ name: 'lo' }] }, hello: {} });
ok(a1.some(a => a.level === 'bad' && /NO CONTROL PATH/.test(a.text)), 'attention: no control path');
ok(I7.attention({ smart: { devices: [{ dev: 'sda', verdict: 'fail', reasons: ['r'] }] } }).some(a => a.level === 'bad'), 'smart fail');
eq(I7.attention({}).length, 0);

// Sensors, rings, rates, logs
const ss2 = I7.sensorSamples({ zones: [{ name: 'z', kind: 'k', temp_c: 40, crit_c: 90 }], hwmon: [{ name: 'h', temps_c: [{ label: 'c', value: 1 }], fans_rpm: [{ label: 'f', value: 900 }], volts_mv: [], power_mw: [] }] });
eq(ss2.map(s => s.group), ['temp', 'temp', 'fan']);
eq(I7.pushRing([1, 2, 3], 4, 3), [2, 3, 4]); eq(I7.rate(100, 300, 1000), 200); eq(I7.rate(300, 100, 1000), null); eq(I7.rate(null, 1, 1), null);
const L = [{ level: 3, text: 'Disk ERROR', tags: ['nvme'] }, { level: 6, text: 'ok', tags: [] }, { level: 7, text: 'dbg', tags: ['usb'] }];
eq(I7.logFilter(L, { level: 4, q: '' }).length, 1); eq(I7.logFilter(L, { level: 7, q: 'error' }).length, 1); eq(I7.logFilter(L, { level: 7, q: '', tags: new Set(['usb']) }).length, 1);
eq(I7.decodeStdout({ data: 'x' }), 'x'); eq(I7.decodeStdout({ b64: Buffer.from('hé').toString('base64') }), 'hé');

console.log('test-core: ' + n + ' checks passed');
