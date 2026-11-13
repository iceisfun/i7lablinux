#!/usr/bin/env python3
"""Mock i7labd HTTP API for developing web/index.html (std-only Python 3).

    python3 web/dev/mock-server.py [--port 8080] [--bind 127.0.0.1]

Implements the contract of docs/PLAN.md C3/C4/C17 for real: single-use nonces, HMAC request check
with the documented DEMO keys (K = SHA256("i7lablinux-demo-<role>")), X-Lab-Proof on responses, per-event
`seq`+`mac` on NDJSON and SSE, role checks, a nonce CSP on `/`. The probe data is a fixture that includes
hostile strings (HTML/script in model, serial, DMI) to exercise the SPA's escaping.

Demo keys to paste in the SPA (or use its "demo read-only key" button):
    i7k1:ro:<hex sha256("i7lablinux-demo-ro")>      printed at start-up
"""
import argparse, hashlib, hmac, json, math, os, random, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, '..', 'index.html')


def demo(role):
    return hashlib.sha256(('i7lablinux-demo-' + role).encode()).digest()


KEYS = {}
for _r in ('ro', 'admin'):
    _k = demo(_r)
    KEYS[hashlib.sha256(b'i7c-keyid' + _k).digest()[:4].hex()] = (_r, _k)

NONCES = {}
NLOCK = threading.Lock()
T0 = time.time()
SERVER_NONCE = secrets.token_hex(12)  # per-boot CSP nonce
STATE = {'writes': [], 'time': None, 'msg': None, 'reboot': None}

HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'

BLOCK = [
    {'name': 'nvme0n1', 'devno': '259:0', 'size_bytes': 512110190592, 'logical_block': 512, 'physical_block': 512, 'kind': 'nvme',
     'model': 'Samsung SSD 970 EVO Plus 500GB', 'vendor': None, 'serial': 'S4EVNX0M123456A', 'serial_source': 'nvme', 'wwid': 'nvme.144d-53345956', 'firmware_rev': '2B2QEXM7',
     'rotational': False, 'removable': False, 'read_only': False,
     'partition_table': {'kind': 'gpt', 'disk_guid': 'aaaa', 'header_crc_ok': True, 'backup_ok': True},
     'partitions': [{'index': 1, 'first_lba': 2048, 'last_lba': 1050623, 'type_guid': None, 'mbr_type': None, 'name': 'EFI', 'part_uuid': '1111'},
                    {'index': 2, 'first_lba': 1050624, 'last_lba': 900000000, 'type_guid': None, 'mbr_type': None, 'name': 'root', 'part_uuid': '2222'}],
     'signatures': [{'kind': 'ext4', 'offset': 1080, 'label': 'rootfs', 'uuid': 'u'}], 'mounts': [], 'holders': [], 'boot_media': False,
     'write_safety': {'verdict': 'needs_override', 'absolute': [], 'overridable': [{'code': 'partition_table', 'detail': 'gpt', 'overridable': True}, {'code': 'signature', 'detail': 'ext4', 'overridable': True}]}},
    {'name': 'sda', 'devno': '8:0', 'size_bytes': 31914983424, 'logical_block': 512, 'physical_block': 512, 'kind': 'usb',
     'model': HOSTILE, 'vendor': 'Gener‮ic', 'serial': '<b>0123</b>\x1b[2J', 'serial_source': 'usb', 'wwid': None, 'firmware_rev': '1.00',
     'rotational': False, 'removable': True, 'read_only': False, 'partition_table': {'kind': 'gpt', 'disk_guid': 'bbbb', 'header_crc_ok': True, 'backup_ok': True},
     'partitions': [{'index': 1, 'first_lba': 2048, 'last_lba': 131071, 'type_guid': None, 'mbr_type': None, 'name': 'i7lab.boot', 'part_uuid': '3333'}],
     'signatures': [{'kind': 'vfat', 'offset': 0, 'label': 'ESP', 'uuid': None}], 'mounts': ['/boot'], 'holders': [], 'boot_media': True,
     'write_safety': {'verdict': 'refused', 'absolute': [{'code': 'boot_media', 'detail': None, 'overridable': False}, {'code': 'mounted', 'detail': '/boot', 'overridable': False}], 'overridable': []}},
    {'name': 'vdb', 'devno': '254:16', 'size_bytes': 8589934592, 'logical_block': 512, 'physical_block': 4096, 'kind': 'virtio',
     'model': None, 'vendor': '0x1af4', 'serial': 'TESTDISK01', 'serial_source': 'virtio', 'wwid': None, 'firmware_rev': None,
     'rotational': False, 'removable': False, 'read_only': False, 'partition_table': None, 'partitions': [], 'signatures': [], 'mounts': [], 'holders': [], 'boot_media': False,
     'write_safety': {'verdict': 'safe', 'absolute': [], 'overridable': []}},
]
SMART = {'v': 1, 'devices': [
    {'dev': 'nvme0n1', 'kind': 'nvme', 'verdict': 'pass', 'reasons': [], 'temperature_c': 38.0, 'power_on_hours': 4120, 'attrs': [],
     'nvme': {'critical_warning': 0, 'temperature_c': 38.0, 'available_spare': 100, 'percentage_used': 3, 'data_units_read': 123456, 'data_units_written': 98765, 'power_cycles': 210, 'power_on_hours': 4120, 'unsafe_shutdowns': 5, 'media_errors': 0, 'error_log_entries': 0}},
    {'dev': 'sda', 'kind': 'unsupported', 'verdict': 'unknown', 'reasons': ['USB bridge without SAT'], 'temperature_c': None, 'power_on_hours': None, 'attrs': [], 'nvme': None}]}


def pci(bdf, parent, v, d, cls, cname, vn, dn, drv, link=None, aer=None, bars=None):
    return {'bdf': bdf, 'parent': parent, 'vendor': v, 'device': d, 'subsys_vendor': v, 'subsys_device': '0001', 'class': cls, 'revision': 1, 'class_name': cname,
            'vendor_name': vn, 'device_name': dn, 'driver': drv, 'link': link, 'iommu_group': 3, 'numa_node': 0, 'aer': aer, 'bars': bars or [], 'caps': ['pm', 'msi', 'pcie'], 'config_hex': None}


PCI = {'v': 1, 'iommu_enabled': True, 'devices': [
    pci('0000:00:00.0', None, '8086', '3e30', '060000', 'Host bridge', 'Intel', '8th Gen Host Bridge', None),
    pci('0000:00:1c.0', None, '8086', 'a338', '060400', 'PCI bridge', 'Intel', 'Root Port #1', 'pcieport', {'cur_gen': 3, 'cur_width': 4, 'max_gen': 3, 'max_width': 4, 'degraded': False}),
    pci('0000:01:00.0', '0000:00:1c.0', '144d', 'a808', '010802', 'NVM controller', 'Samsung', 'NVMe SSD Controller', 'nvme', {'cur_gen': 3, 'cur_width': 2, 'max_gen': 3, 'max_width': 4, 'degraded': True},
        {'correctable': 4, 'nonfatal': 0, 'fatal': 0}, [{'index': 0, 'base': 0xf7000000, 'size': 16384, 'kind': 'mem64', 'prefetch': False}]),
    pci('0000:00:1c.2', None, '8086', 'a33a', '060400', 'PCI bridge', 'Intel', 'Root Port #3', 'pcieport', {'cur_gen': 1, 'cur_width': 1, 'max_gen': 1, 'max_width': 1, 'degraded': False}),
    pci('0000:02:00.0', '0000:00:1c.2', '8086', '15b8', '020000', 'Ethernet controller', 'Intel', 'I219-V', 'e1000e'),
    pci('0000:03:00.0', '0000:00:1c.2', '10ec', '8126', '020000', 'Ethernet controller', 'Realtek', 'RTL8126 5GbE', None),
]}
NET = {'v': 1, 'ifaces': [
    {'name': 'lo', 'mac': None, 'perm_mac': None, 'driver': None, 'bus_info': None, 'operstate': 'unknown', 'carrier': True, 'speed_mbps': None, 'duplex': None, 'mtu': 65536, 'ipv4': ['127.0.0.1/8'], 'ipv6': [], 'vlan_of': None, 'vlan_id': None, 'rx_bytes': 1, 'tx_bytes': 1, 'rx_errors': 0, 'tx_errors': 0, 'carrier_changes': 0},
    {'name': 'eth0', 'mac': '52:54:00:17:00:02', 'perm_mac': '52:54:00:17:00:02', 'driver': 'e1000e', 'bus_info': '0000:02:00.0', 'operstate': 'up', 'carrier': True, 'speed_mbps': 1000, 'duplex': 'full', 'mtu': 1500,
     'ipv4': ['10.0.2.15/24'], 'ipv6': ['fe80::5054:ff:fe17:2/64'], 'vlan_of': None, 'vlan_id': None, 'rx_bytes': 0, 'tx_bytes': 0, 'rx_errors': 0, 'tx_errors': 0, 'carrier_changes': 1},
    {'name': 'eth0.13', 'mac': '52:54:00:17:00:02', 'perm_mac': None, 'driver': None, 'bus_info': None, 'operstate': 'up', 'carrier': True, 'speed_mbps': None, 'duplex': None, 'mtu': 1500,
     'ipv4': [], 'ipv6': [], 'vlan_of': 'eth0', 'vlan_id': 13, 'rx_bytes': 0, 'tx_bytes': 0, 'rx_errors': 0, 'tx_errors': 0, 'carrier_changes': 0}]}
USB = {'v': 1, 'devices': [
    {'path': '1-0', 'parent': None, 'busnum': 1, 'devnum': 1, 'vid': '1d6b', 'pid': '0002', 'class': 9, 'speed_mbps': 480, 'manufacturer': 'Linux', 'product': 'xHCI Host Controller', 'serial': None, 'drivers': ['hub']},
    {'path': '1-1', 'parent': '1-0', 'busnum': 1, 'devnum': 2, 'vid': '0951', 'pid': '1666', 'class': 0, 'speed_mbps': 480, 'manufacturer': 'Kingston', 'product': HOSTILE, 'serial': '\x1b]0;pwn\x07', 'drivers': ['usb-storage']},
    {'path': '1-1.4', 'parent': '1-1', 'busnum': 1, 'devnum': 3, 'vid': '046d', 'pid': 'c52b', 'class': 0, 'speed_mbps': 12, 'manufacturer': 'Logitech', 'product': 'USB Receiver', 'serial': None, 'drivers': ['usbhid']}]}


def sysinfo():
    return {'v': 1, 'hostname': 'lab-' + HOSTILE[:4], 'kernel': '6.12.6-i7lab', 'cmdline': 'i7lab.console=open', 'uptime_s': time.time() - T0 + 4000, 'load': [0.1, 0.2, 0.3],
            'boot_id': 'abcd', 'boot_mode': 'uefi', 'image_build': 'mock-1'}


def thermal():
    t = time.time()
    return {'v': 1, 'zones': [{'name': 'thermal_zone0', 'kind': 'x86_pkg_temp', 'temp_c': 55 + 6 * math.sin(t / 7), 'crit_c': 100.0}],
            'hwmon': [{'name': 'coretemp', 'temps_c': [{'label': 'Core 0', 'value': 52 + 5 * math.sin(t / 5), 'max': 90.0, 'crit': 100.0}, {'label': 'Core 1', 'value': 50 + 4 * math.cos(t / 6), 'max': 90.0, 'crit': 100.0}],
                       'fans_rpm': [{'label': 'fan1', 'value': 1800 + random.randint(-40, 40), 'max': None, 'crit': None}], 'volts_mv': [{'label': 'in0', 'value': 12010 + random.randint(-15, 15), 'max': None, 'crit': None}], 'power_mw': []},
                      {'name': 'nvme', 'temps_c': [{'label': 'Composite', 'value': 38 + 2 * math.sin(t / 9), 'max': 84.0, 'crit': 90.0}], 'fans_rpm': [], 'volts_mv': [], 'power_mw': []}],
            'alarms': []}


def kmsg():
    base = [(6, 'Linux version 6.12.6-i7lab', ['boot']), (6, 'e1000e 0000:02:00.0 eth0: link up', ['net', 'e1000e']), (4, 'nvme nvme0: pcie link degraded x2 of x4', ['nvme', 'pci']),
            (3, 'usb 1-1: device descriptor read error', ['usb']), (6, HOSTILE, ['hostile']), (7, 'debug: \x1b[31mred\x1b[0m text', [])]
    return {'v': 1, 'lines': [{'seq': i, 'level': l, 'ts_us': 1000000 * i + 1234, 'text': x, 'tags': g} for i, (l, x, g) in enumerate(base)]
            + [{'seq': 99, 'level': 6, 'ts_us': int((time.time() - T0) * 1e6), 'text': 'tick %d' % int(time.time() - T0), 'tags': ['tick']}]}


def probes(names):
    out = {'v': 1}
    for n in names:
        if n == 'system': out[n] = sysinfo()
        elif n == 'cpu': out[n] = {'v': 1, 'vendor': 'GenuineIntel', 'model_name': 'Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz', 'family': 6, 'model': 158, 'stepping': 10, 'microcode': '0xf6', 'codename': None, 'sockets': 1, 'cores': 6, 'threads': 12, 'flags_summary': ['avx2'], 'freq_mhz': 3200.0, 'caches': [], 'vulnerabilities': {}}
        elif n == 'mem': out[n] = {'v': 1, 'total_kib': 16 * 1024 * 1024, 'available_kib': 12 * 1024 * 1024, 'swap_kib': 0, 'dimms': [], 'ecc': None, 'edac': []}
        elif n == 'dmi': out[n] = {'v': 1, 'sys_vendor': 'LENOVO', 'product_name': 'ThinkCentre M720q', 'product_serial': HOSTILE, 'product_uuid': None, 'board_vendor': 'LENOVO', 'board_name': '3110', 'board_serial': None, 'bios_vendor': 'LENOVO', 'bios_version': 'M1UKT', 'bios_date': '01/01/2020'}
        elif n == 'pci': out[n] = PCI
        elif n == 'usb': out[n] = USB
        elif n == 'block': out[n] = {'v': 1, 'devices': BLOCK}
        elif n == 'net':
            tt = time.time() - T0
            for i in NET['ifaces']:
                if i['name'] == 'eth0': i['rx_bytes'] = int(tt * 1.2e6); i['tx_bytes'] = int(tt * 3e5)
            out[n] = NET
        elif n == 'thermal': out[n] = thermal()
        elif n == 'smart': out[n] = SMART
        elif n == 'kmsg': out[n] = kmsg()
        elif n == 'firmware': out[n] = {'v': 1, 'boot_mode': 'uefi', 'secure_boot': False}
        else: out[n] = {'error': 'unsupported', 'message': 'unknown section ' + n}
    return out


COMMANDS = [(1, 'ping', 'ro', False, '[ECHO]', 'round trip'), (2, 'id', 'ro', False, '', 'identity'), (3, 'cmds', 'ro', False, '', 'list commands'),
            (0x15, 'blk.read', 'ro', True, 'DEV [--mb N]', 'read test'), (0x16, 'blk.write', 'admin', True, 'DEV --destructive --serial S', 'destructive write test'),
            (0x17, 'blk.verify', 'ro', True, 'DEV --seed N', 'verify'), (0x70, 'logs', 'ro', True, '[--audit]', 'logs'), (0x80, 'identify', 'admin', False, '[--seconds N]', 'blink'),
            (0x81, 'msg', 'admin', False, 'TEXT..', 'console message'), (5, 'time.set', 'admin', False, 'SECS', 'set clock'), (0x82, 'tui', 'admin', False, 'tab NAME', 'tui'),
            (0x40, 'reboot', 'admin', False, '[--force]', 'reboot'), (0x41, 'poweroff', 'admin', False, '[--delay S]', 'power off'), (0x42, 'kexec', 'admin', False, '--kernel PATH', 'kexec (planned)')]


def emac(key, nonce, seq, body):
    return hmac.new(key, ('lp-evt\n%s\n%d\n%s' % (nonce, seq, body)).encode(), hashlib.sha256).digest()[:16].hex()


def event_line(key, nonce, seq, obj):
    body = json.dumps(obj, separators=(',', ':'))[:-1] + ',"seq":%d}' % seq
    return body[:-1] + ',"mac":"%s"}' % emac(key, nonce, seq, body)


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'i7labd-mock'

    def log_message(self, fmt, *a):
        if os.environ.get('MOCK_QUIET') != '1':
            super().log_message(fmt, *a)

    # --- plumbing
    def send(self, status, body=b'', ctype='application/json', extra=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache')
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def err(self, status, code, msg, key=None, nonce=None, reasons=None):
        e = {'error': {'code': code, 'message': msg}}
        if reasons: e['error']['reasons'] = reasons
        self.reply(status, e, key, nonce)

    def reply(self, status, obj, key=None, nonce=None):
        body = json.dumps(obj).encode()
        extra = {}
        if key is not None:
            extra['X-Lab-Proof'] = hmac.new(key, ('lp-resp\n%s\n%d\n%s' % (nonce, status, hashlib.sha256(body).hexdigest())).encode(), hashlib.sha256).hexdigest()
        if os.environ.get('MOCK_BAD_PROOF') == '1' and 'X-Lab-Proof' in extra:  # test hook: a host that does not hold the key
            extra['X-Lab-Proof'] = ('0' if extra['X-Lab-Proof'][0] != '0' else '1') + extra['X-Lab-Proof'][1:]
        self.send(status, body, extra=extra)

    def auth(self, body):
        kid, nonce, mac = self.headers.get('X-Lab-Key'), self.headers.get('X-Lab-Nonce'), self.headers.get('X-Lab-Auth')
        if not (kid and nonce and mac) or kid not in KEYS:
            time.sleep(0.2); self.err(401, 'AUTH', 'missing or unknown key'); return None
        with NLOCK:
            ok = NONCES.pop(nonce, 0) > time.time()
        role, key = KEYS[kid]
        target = self.path
        want = hmac.new(key, ('lp-req\n%s\n%s\n%s\n%s' % (nonce, self.command, target, hashlib.sha256(body).hexdigest())).encode(), hashlib.sha256).hexdigest()
        if not ok or not hmac.compare_digest(want, mac.strip()):
            time.sleep(0.2); self.err(401, 'AUTH', 'bad signature or nonce'); return None
        return role, key, nonce

    # --- routing
    def do_GET(self): self.route(b'')

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        self.route(self.rfile.read(n))

    def route(self, body):
        u = urlsplit(self.path); p = u.path
        if p == '/' or p == '/index.html':
            html = open(INDEX, encoding='utf-8').read().replace('__I7LAB_NONCE__', SERVER_NONCE).encode()
            return self.send(200, html, 'text/html; charset=utf-8', {'Content-Security-Policy': "default-src 'self'; script-src 'nonce-%s'; style-src 'self' 'unsafe-inline'" % SERVER_NONCE})
        if p == '/api/v1/hello':
            return self.reply(200, {'v': 1, 'hostname': sysinfo()['hostname'], 'version': '0.1.0-mock', 'build': 'mock-1', 'boot_id': 'abcd', 'state': 'ready', 'demo': True, 'proto': 1})
        if p == '/api/v1/nonce':
            n = secrets.token_hex(16)
            with NLOCK: NONCES[n] = time.time() + 30
            return self.reply(200, {'nonce': n})
        a = self.auth(body)
        if a is None: return
        role, key, nonce = a
        q = parse_qs(u.query)
        if p.startswith('/api/v1/probe/'):
            return self.reply(200, probes(p[len('/api/v1/probe/'):].split(',')), key, nonce)
        if p == '/api/v1/events':
            return self.sse(key, nonce)
        if p == '/api/v1/openapi.json':
            return self.reply(200, {'openapi': '3.0.0', 'paths': {}}, key, nonce)
        if p.startswith('/api/v1/cmd/') and self.command == 'POST':
            name = p[len('/api/v1/cmd/'):]
            try: args = json.loads(body or b'{}').get('args', [])
            except Exception: return self.err(400, 'BAD_ARGS', 'body must be {"args":[..]}', key, nonce)
            return self.cmd(name, args, role, key, nonce, q.get('stream') == ['1'])
        self.err(404, 'NOT_FOUND', 'no such route', key, nonce)

    def sse(self, key, nonce):
        self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.send_header('Cache-Control', 'no-cache')
        self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
        seq = 0
        try:
            while True:
                ev = {'event': 'snapshot', 'state': 'ready', 'attention': ['DEMO KEYS: mock host'], 'taken_ms': int(time.time() * 1000)}
                self.chunk(('event: snapshot\ndata: %s\n\n' % event_line(key, nonce, seq, ev)).encode()); seq += 1
                time.sleep(1.0 if os.environ.get('MOCK_FAST') else 2.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def chunk(self, data):
        self.wfile.write(b'%x\r\n' % len(data) + data + b'\r\n'); self.wfile.flush()

    def stream_events(self, key, nonce, events):
        self.send_response(200); self.send_header('Content-Type', 'application/x-ndjson'); self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
        try:
            for seq, (delay, ev) in enumerate(events):
                time.sleep(delay)
                self.chunk((event_line(key, nonce, seq, ev) + '\n').encode())
            self.wfile.write(b'0\r\n\r\n'); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def cmd(self, name, args, role, key, nonce, stream):
        spec = next((c for c in COMMANDS if c[1] == name), None)
        if spec is None: return self.err(404, 'UNKNOWN_CMD', 'unknown command ' + name, key, nonce)
        if spec[1] == 'kexec': return self.err(501, 'UNSUPPORTED', 'planned v0.4', key, nonce)
        if spec[2] == 'admin' and role != 'admin': return self.err(403, 'DENIED', 'admin key required for ' + name, key, nonce)
        if name == 'ping': return self.reply(200, {'echo': ' '.join(args), 'uptime_ms': int((time.time() - T0) * 1000), 'boot_id': 'abcd'}, key, nonce)
        if name == 'id': return self.reply(200, {'v': 1, 'version': '0.1.0-mock', 'build': 'mock-1', 'hostname': sysinfo()['hostname'], 'boot_id': 'abcd', 'role': role, 'kid': 'ro=%s admin=%s' % tuple(k for k in KEYS), 'state': 'ready', 'proto': 1, 'caps': 1023}, key, nonce)
        if name == 'cmds':
            cs = [{'id': c[0], 'name': c[1], 'group': 0, 'access': c[2], 'streams': c[3], 'usage': c[4], 'summary': c[5], 'planned': c[1] == 'kexec', 'since': 'v0.4' if c[1] == 'kexec' else 'v0.1'} for c in COMMANDS]
            return self.reply(200, {'v': 1, 'commands': cs}, key, nonce)
        if name in ('identify', 'msg', 'tui', 'time.set'):
            STATE[name] = args; return self.reply(200, {'ok': True, 'args': args}, key, nonce)
        if name in ('reboot', 'poweroff'):
            STATE['reboot'] = (name, args); return self.reply(200, {'ok': True, 'scheduled': name}, key, nonce)
        if name == 'logs':
            lines = ['audit line %d from %s\n' % (i, args) for i in range(5)] + ['<img src=x onerror=1>\n']
            return self.stream_events(key, nonce, [(0, {'event': 'stdout', 'data': ''.join(lines)}), (0, {'event': 'result', 'ok': True, 'exit': 0})])
        if name in ('blk.read', 'blk.verify', 'blk.write'):
            dev = next((b for b in BLOCK if args and b['name'] == args[0]), None)
            if dev is None: return self.err(404, 'NOT_FOUND', 'no such device', key, nonce)
            if name == 'blk.write':
                why = []
                if '--destructive' not in args: why.append({'code': 'not_destructive', 'detail': None, 'overridable': False})
                try: ser = args[args.index('--serial') + 1]
                except Exception: ser = None
                if ser != dev['serial']: why.append({'code': 'serial_mismatch', 'detail': None, 'overridable': False})
                why += dev['write_safety']['absolute']
                if why: return self.err(409, 'REFUSED', 'write refused by the safety gate', key, nonce, why)
                STATE['writes'].append(args)
            regs = ['start', 'mid', 'end']
            evs = [(0.15, {'event': 'progress', 'region': regs[i // 4], 'done_bytes': (i + 1) * 1000, 'total_bytes': 12000, 'mib_s': 400 + 20 * math.sin(i)}) for i in range(12)]
            rep = {'v': 1, 'dev': dev['name'], 'mode': name.split('.')[1], 'ok': True, 'regions': [{'name': r, 'offset': 0, 'len': 268435456, 'mib_s': 410.5, 'lat_max_us': 900, 'io_errors': 0, 'mismatches': 0, 'first_mismatch': None} for r in regs]}
            evs.append((0, {'event': 'result', 'ok': True, 'exit': 0, 'report': rep}))
            if stream: return self.stream_events(key, nonce, evs)
            return self.reply(200, rep, key, nonce)
        self.err(501, 'UNSUPPORTED', name, key, nonce)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--port', type=int, default=8080); ap.add_argument('--bind', default='127.0.0.1')
    a = ap.parse_args()
    for r in ('ro', 'admin'): print('i7k1:%s:%s' % (r, demo(r).hex()))
    srv = ThreadingHTTPServer((a.bind, a.port), H); srv.daemon_threads = True
    print('mock i7labd on http://%s:%d/' % (a.bind, a.port), flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main()
