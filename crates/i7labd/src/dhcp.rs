//! DHCP client, pure part, copied from the earlier lab-init prototype (same author; no crate
//! dependency). Packet encode/decode (all input untrusted, bounds-checked), IPv4/UDP framing for an AF_PACKET
//! socket, and the lease state machine. No I/O and no clock here. The per-NIC driver is in `netcfg.rs`. Owner: P6b.

use std::net::Ipv4Addr;

pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
const FIXED: usize = 236;
const OPT_START: usize = FIXED + 4;
pub const BCAST_MAC: [u8; 6] = [0xff; 6];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsgType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MsgType {
    fn from_u8(v: u8) -> Option<MsgType> {
        Some(match v {
            1 => MsgType::Discover,
            2 => MsgType::Offer,
            3 => MsgType::Request,
            4 => MsgType::Decline,
            5 => MsgType::Ack,
            6 => MsgType::Nak,
            7 => MsgType::Release,
            8 => MsgType::Inform,
            _ => return None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    NotBootReply,
    BadHardware,
    BadMagic,
    TruncatedOption,
    BadOption(u8),
    NoMsgType,
    BadMsgType(u8),
    NotIpv4,
    NotUdp,
    Fragment,
    BadIpHeader,
    BadIpChecksum,
    BadUdp,
    WrongPorts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    pub xid: u32,
    pub chaddr: [u8; 6],
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub mtype: MsgType,
    pub server_id: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub lease_secs: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
}

fn ip4(d: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(d[0], d[1], d[2], d[3])
}

/// Number of leading one bits if `m` is a contiguous netmask.
pub fn prefix_len(m: Ipv4Addr) -> Option<u8> {
    let v = u32::from(m);
    let p = v.leading_ones();
    if p == 32 || v.checked_shl(p).unwrap_or(0) == 0 {
        Some(p as u8)
    } else {
        None
    }
}

fn be32(d: &[u8]) -> u32 {
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// Decodes a BOOTP/DHCP reply payload (no Ethernet/IP/UDP headers). Never panics, never indexes unchecked.
/// Only the options we use are validated; unknown options are skipped by their length. Option overload (52) is
/// not supported (the sname/file fields are ignored).
pub fn decode(p: &[u8]) -> Result<Msg, DecodeError> {
    if p.len() < OPT_START {
        return Err(DecodeError::TooShort);
    }
    if p[0] != 2 {
        return Err(DecodeError::NotBootReply);
    }
    if p[1] != 1 || p[2] != 6 {
        return Err(DecodeError::BadHardware);
    }
    if p[FIXED..OPT_START] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let mut m = Msg {
        xid: be32(&p[4..8]),
        chaddr: p[28..34].try_into().unwrap(),
        ciaddr: ip4(&p[12..16]),
        yiaddr: ip4(&p[16..20]),
        mtype: MsgType::Discover,
        server_id: None,
        mask: None,
        routers: Vec::new(),
        lease_secs: None,
        t1: None,
        t2: None,
    };
    let o = &p[OPT_START..];
    let mut mt: Option<u8> = None;
    let mut i = 0;
    while i < o.len() {
        let c = o[i];
        i += 1;
        if c == 0 {
            continue;
        }
        if c == 255 {
            break;
        }
        if i >= o.len() {
            return Err(DecodeError::TruncatedOption);
        }
        let l = o[i] as usize;
        i += 1;
        if i + l > o.len() {
            return Err(DecodeError::TruncatedOption);
        }
        let d = &o[i..i + l];
        i += l;
        match c {
            53 => {
                if l != 1 {
                    return Err(DecodeError::BadOption(c));
                }
                mt.get_or_insert(d[0]);
            }
            54 => {
                if l != 4 {
                    return Err(DecodeError::BadOption(c));
                }
                m.server_id.get_or_insert(ip4(d));
            }
            1 => {
                // tolerant like udhcpc: a bad mask is ignored (the classful default applies), the reply survives
                if l == 4 && prefix_len(ip4(d)).is_some() {
                    m.mask.get_or_insert(ip4(d));
                }
            }
            3 => {
                // tolerant: a trailing partial address is dropped; fewer than 4 bytes means no router
                if l >= 4 && m.routers.is_empty() {
                    m.routers = d.chunks_exact(4).take(8).map(ip4).collect();
                }
            }
            51 | 58 | 59 => {
                // tolerant: a wrong-length time option is ignored
                if l == 4 {
                    let slot = match c {
                        51 => &mut m.lease_secs,
                        58 => &mut m.t1,
                        _ => &mut m.t2,
                    };
                    slot.get_or_insert(be32(d));
                }
            }
            _ => {}
        }
    }
    let t = mt.ok_or(DecodeError::NoMsgType)?;
    m.mtype = MsgType::from_u8(t).ok_or(DecodeError::BadMsgType(t))?;
    Ok(m)
}

pub fn csum(data: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut it = data.chunks_exact(2);
    for c in &mut it {
        s += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = it.remainder() {
        s += (*b as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rx {
    pub src_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub msg: Msg,
}

/// Decodes a whole Ethernet frame from an AF_PACKET SOCK_RAW socket: IPv4, no fragments, UDP 67 -> 68, valid IP
/// header checksum. The UDP checksum is NOT verified: receive offload and virtual NICs deliver packets with
/// partial/zero checksums, and xid + chaddr + cookie matching (done by the caller) is the real filter.
pub fn decode_frame(f: &[u8]) -> Result<Rx, DecodeError> {
    if f.len() < 14 + 20 + 8 {
        return Err(DecodeError::TooShort);
    }
    if f[12] != 0x08 || f[13] != 0x00 {
        return Err(DecodeError::NotIpv4);
    }
    let ip = &f[14..];
    if ip[0] >> 4 != 4 {
        return Err(DecodeError::NotIpv4);
    }
    let ihl = (ip[0] & 15) as usize * 4;
    let tot = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ihl < 20 || tot < ihl + 8 || tot > ip.len() {
        return Err(DecodeError::BadIpHeader);
    }
    if csum(&ip[..ihl]) != 0 {
        return Err(DecodeError::BadIpChecksum);
    }
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        return Err(DecodeError::Fragment);
    }
    if ip[9] != 17 {
        return Err(DecodeError::NotUdp);
    }
    let udp = &ip[ihl..tot];
    let (sp, dp) = (u16::from_be_bytes([udp[0], udp[1]]), u16::from_be_bytes([udp[2], udp[3]]));
    if sp != 67 || dp != 68 {
        return Err(DecodeError::WrongPorts);
    }
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if ulen < 8 || ulen > udp.len() {
        return Err(DecodeError::BadUdp);
    }
    let msg = decode(&udp[8..ulen])?;
    Ok(Rx { src_mac: f[6..12].try_into().unwrap(), src_ip: ip4(&ip[12..16]), msg })
}

/// What the state machine wants sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub kind: MsgType,
    pub ciaddr: Ipv4Addr,
    pub requested: Option<Ipv4Addr>,
    pub server: Option<Ipv4Addr>,
    /// Some(server) = unicast renew; None = broadcast.
    pub unicast_to: Option<Ipv4Addr>,
}

pub fn encode(o: &Out, xid: u32, mac: [u8; 6], hostname: &str) -> Vec<u8> {
    let mut p = vec![0u8; OPT_START];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    if o.ciaddr.is_unspecified() {
        p[10] = 0x80; // broadcast flag: we have no address yet
    }
    p[12..16].copy_from_slice(&o.ciaddr.octets());
    p[28..34].copy_from_slice(&mac);
    p[FIXED..OPT_START].copy_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, o.kind as u8]);
    p.extend_from_slice(&[61, 7, 1]);
    p.extend_from_slice(&mac);
    if let Some(r) = o.requested {
        p.extend_from_slice(&[50, 4]);
        p.extend_from_slice(&r.octets());
    }
    if let Some(s) = o.server {
        p.extend_from_slice(&[54, 4]);
        p.extend_from_slice(&s.octets());
    }
    let h = hostname.as_bytes();
    if !h.is_empty() && h.len() <= 63 {
        p.push(12);
        p.push(h.len() as u8);
        p.extend_from_slice(h);
    }
    p.extend_from_slice(&[55, 7, 1, 3, 6, 28, 51, 58, 59]);
    p.push(255);
    while p.len() < 300 {
        p.push(0);
    }
    p
}

/// Ethernet + IPv4 + UDP (68 -> 67) around `payload`, with IP and UDP checksums.
pub fn build_frame(src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let tot = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + tot);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0x45, 0x10, (tot >> 8) as u8, tot as u8, 0, 0, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut udp = vec![0, 68, 0, 67, (udp_len >> 8) as u8, udp_len as u8, 0, 0];
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.extend_from_slice(&[0, 17, (udp_len >> 8) as u8, udp_len as u8]);
    pseudo.extend_from_slice(&udp);
    let mut uc = csum(&pseudo);
    if uc == 0 {
        uc = 0xffff;
    }
    udp[6..8].copy_from_slice(&uc.to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp);
    f
}

// ---------------------------------------------------------------- state machine

pub const GAP_MS: u64 = 2_000;
pub const TRIES: u32 = 3;
pub const PAUSE_MS: u64 = 10_000;
pub const NAK_PAUSE_MS: u64 = 1_000;
pub const MIN_RETRY_MS: u64 = 4_000;
pub const INFINITE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub server: Ipv4Addr,
    pub lease_secs: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Send(Out),
    /// Apply (or refresh) this lease on the interface.
    Configure(Lease),
    /// The lease is gone (NAK or expiry): remove the address WE configured.
    Deconfigure,
}

fn classful_mask(ip: Ipv4Addr) -> Ipv4Addr {
    match ip.octets()[0] {
        0..=127 => Ipv4Addr::new(255, 0, 0, 0),
        128..=191 => Ipv4Addr::new(255, 255, 0, 0),
        _ => Ipv4Addr::new(255, 255, 255, 0),
    }
}

/// `(t1, t2)` in seconds from the lease, using the server's options only when sane (t1 < t2 < lease).
pub fn timers(lease: u32, t1: Option<u32>, t2: Option<u32>) -> (u64, u64) {
    let l = lease as u64;
    let d1 = l / 2;
    let d2 = l * 7 / 8;
    let (a, b) = (t1.map(u64::from).unwrap_or(d1), t2.map(u64::from).unwrap_or(d2));
    if a < b && b < l {
        (a, b)
    } else {
        (d1, d2)
    }
}

fn add_secs(now: u64, s: u64) -> u64 {
    now.saturating_add(s.saturating_mul(1000))
}

pub struct Fsm {
    pub state: State,
    xid: u32,
    tries: u32,
    deadline: u64,
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    lease: Option<Lease>,
    t1_at: u64,
    t2_at: u64,
    exp_at: u64,
    server_mac: Option<[u8; 6]>,
    mac: [u8; 6],
}

fn retry(now: u64, target: u64) -> u64 {
    let rem = target.saturating_sub(now);
    (now + (rem / 2).max(MIN_RETRY_MS)).min(target)
}

impl Fsm {
    pub fn new(mac: [u8; 6], xid: u32) -> Fsm {
        Fsm { state: State::Init, xid, tries: 0, deadline: 0, offer: None, lease: None, t1_at: 0, t2_at: 0, exp_at: 0, server_mac: None, mac }
    }
    pub fn xid(&self) -> u32 {
        self.xid
    }
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    /// Next time `tick` has anything to do.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
    pub fn server_mac(&self) -> Option<[u8; 6]> {
        self.server_mac
    }
    #[allow(dead_code)]
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    fn discover(&self) -> Out {
        Out { kind: MsgType::Discover, ciaddr: Ipv4Addr::UNSPECIFIED, requested: None, server: None, unicast_to: None }
    }
    fn select_request(&self) -> Option<Out> {
        let (ip, srv) = self.offer?;
        Some(Out { kind: MsgType::Request, ciaddr: Ipv4Addr::UNSPECIFIED, requested: Some(ip), server: Some(srv), unicast_to: None })
    }
    fn renew_request(&self, unicast: bool) -> Option<Out> {
        let l = self.lease.as_ref()?;
        Some(Out { kind: MsgType::Request, ciaddr: l.ip, requested: None, server: None, unicast_to: if unicast { Some(l.server) } else { None } })
    }
    fn to_init(&mut self, now: u64, pause: u64) {
        self.state = State::Init;
        self.deadline = now.saturating_add(pause);
        self.offer = None;
        self.tries = 0;
    }
    fn drop_lease(&mut self, now: u64, pause: u64) -> Vec<Action> {
        let had = self.lease.take().is_some();
        self.server_mac = None;
        self.to_init(now, pause);
        if had {
            vec![Action::Deconfigure]
        } else {
            vec![]
        }
    }

    /// Advance on the clock.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        if now < self.deadline {
            return vec![];
        }
        match self.state {
            State::Init => {
                self.xid = self.xid.wrapping_add(1);
                self.tries = 1;
                self.state = State::Selecting;
                self.deadline = now + GAP_MS;
                self.offer = None;
                vec![Action::Send(self.discover())]
            }
            State::Selecting => {
                if self.tries < TRIES {
                    self.tries += 1;
                    self.deadline = now + GAP_MS;
                    vec![Action::Send(self.discover())]
                } else {
                    self.to_init(now, PAUSE_MS);
                    vec![]
                }
            }
            State::Requesting => {
                if self.tries < TRIES {
                    if let Some(o) = self.select_request() {
                        self.tries += 1;
                        self.deadline = now + GAP_MS;
                        return vec![Action::Send(o)];
                    }
                }
                self.to_init(now, PAUSE_MS);
                vec![]
            }
            State::Bound | State::Renewing | State::Rebinding => self.tick_bound(now),
        }
    }

    fn tick_bound(&mut self, now: u64) -> Vec<Action> {
        if now >= self.exp_at {
            return self.drop_lease(now, 0);
        }
        if now >= self.t2_at {
            if self.state != State::Rebinding {
                self.xid = self.xid.wrapping_add(1);
                self.state = State::Rebinding;
            }
            self.deadline = retry(now, self.exp_at);
            return self.renew_request(false).map(Action::Send).into_iter().collect();
        }
        if now >= self.t1_at {
            if self.state == State::Bound {
                self.xid = self.xid.wrapping_add(1);
                self.state = State::Renewing;
            }
            self.deadline = retry(now, self.t2_at);
            return self.renew_request(true).map(Action::Send).into_iter().collect();
        }
        self.deadline = self.t1_at;
        vec![]
    }

    /// A decoded reply from the wire. Wrong xid / chaddr is ignored here too (defence in depth).
    pub fn on_rx(&mut self, now: u64, rx: &Rx) -> Vec<Action> {
        let m = &rx.msg;
        if m.xid != self.xid || m.chaddr != self.mac {
            return vec![];
        }
        match (self.state, m.mtype) {
            (State::Selecting, MsgType::Offer) => {
                let (Some(srv), false) = (m.server_id, m.yiaddr.is_unspecified()) else { return vec![] };
                self.offer = Some((m.yiaddr, srv));
                self.state = State::Requesting;
                self.tries = 1;
                self.deadline = now + GAP_MS;
                self.select_request().map(Action::Send).into_iter().collect()
            }
            (State::Requesting | State::Renewing | State::Rebinding, MsgType::Ack) => {
                if m.yiaddr.is_unspecified() {
                    return vec![];
                }
                let server = m.server_id.or(Some(rx.src_ip)).unwrap();
                let ls = match m.lease_secs {
                    None => 3600,
                    Some(0) => return vec![],
                    Some(v) => v, // the server's lease is honoured as given; MIN_RETRY_MS only spaces renew retries
                };
                let lease = Lease { ip: m.yiaddr, mask: m.mask.unwrap_or_else(|| classful_mask(m.yiaddr)), router: m.routers.first().copied(), server, lease_secs: ls };
                if ls == INFINITE {
                    self.t1_at = u64::MAX;
                    self.t2_at = u64::MAX;
                    self.exp_at = u64::MAX;
                } else {
                    let (t1, t2) = timers(ls, m.t1, m.t2);
                    self.t1_at = add_secs(now, t1);
                    self.t2_at = add_secs(now, t2);
                    self.exp_at = add_secs(now, ls as u64);
                }
                self.deadline = self.t1_at;
                self.state = State::Bound;
                self.offer = None;
                self.server_mac = Some(rx.src_mac);
                self.lease = Some(lease.clone());
                vec![Action::Configure(lease)]
            }
            (State::Requesting | State::Renewing | State::Rebinding, MsgType::Nak) => self.drop_lease(now, NAK_PAUSE_MS),
            _ => vec![],
        }
    }
}

/// Ownership rule: the client only removes an address it configured itself. A beacon hint (or anything else) that
/// put a different address on the interface is never touched.
pub fn should_deconfigure(ours: Option<Ipv4Addr>, current: Option<Ipv4Addr>) -> bool {
    matches!((ours, current), (Some(a), Some(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const SRV: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const YI: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 77);

    fn reply(kind: u8, xid: u32, opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; OPT_START];
        p[0] = 2;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[16..20].copy_from_slice(&YI.octets());
        p[28..34].copy_from_slice(&MAC);
        p[FIXED..].copy_from_slice(&MAGIC);
        p.extend_from_slice(&[53, 1, kind]);
        p.extend_from_slice(opts);
        p.push(255);
        p
    }
    fn std_opts() -> Vec<u8> {
        let mut o = vec![54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 0, 3, 8, 10, 0, 0, 1, 10, 0, 0, 2, 51, 4, 0, 0, 0x0e, 0x10];
        o.extend_from_slice(&[6, 4, 8, 8, 8, 8]);
        o
    }
    fn rx(kind: u8, xid: u32, opts: &[u8]) -> Rx {
        Rx { src_mac: [2; 6], src_ip: SRV, msg: decode(&reply(kind, xid, opts)).unwrap() }
    }

    #[test]
    fn decode_offer_options() {
        let m = decode(&reply(2, 7, &std_opts())).unwrap();
        assert_eq!(m.mtype, MsgType::Offer);
        assert_eq!((m.xid, m.chaddr, m.yiaddr), (7, MAC, YI));
        assert_eq!(m.server_id, Some(SRV));
        assert_eq!(m.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(m.routers, vec![SRV, Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(m.lease_secs, Some(3600));
    }
    #[test]
    fn decode_malformed() {
        assert_eq!(decode(&[]), Err(DecodeError::TooShort));
        assert_eq!(decode(&[0; 239]), Err(DecodeError::TooShort));
        let good = reply(2, 1, &std_opts());
        let mut b = good.clone();
        b[0] = 1;
        assert_eq!(decode(&b), Err(DecodeError::NotBootReply));
        let mut b = good.clone();
        b[2] = 8;
        assert_eq!(decode(&b), Err(DecodeError::BadHardware));
        let mut b = good.clone();
        b[FIXED] = 0;
        assert_eq!(decode(&b), Err(DecodeError::BadMagic));
        // option runs off the end
        let mut b = good[..OPT_START].to_vec();
        b.extend_from_slice(&[53, 1, 2, 54, 4, 10, 0]);
        assert_eq!(decode(&b), Err(DecodeError::TruncatedOption));
        let mut b = good[..OPT_START].to_vec();
        b.extend_from_slice(&[53, 1, 2, 54]);
        assert_eq!(decode(&b), Err(DecodeError::TruncatedOption), "code with no length byte");
        let mut b = good[..OPT_START].to_vec();
        b.extend_from_slice(&[53, 1, 2, 99, 255, 1, 2]);
        assert_eq!(decode(&b), Err(DecodeError::TruncatedOption), "length 255 past the end");
        // bad fixed-size option lengths
        for opt in [[54u8, 3, 1, 2, 3].as_slice(), &[53, 2, 1, 1]] {
            let mut b = good[..OPT_START].to_vec();
            b.extend_from_slice(&[53, 1, 2]);
            b.extend_from_slice(opt);
            b.push(255);
            assert!(matches!(decode(&b), Err(DecodeError::BadOption(_))), "{opt:?}");
        }
        // no message type / bad message type
        let mut b = good[..OPT_START].to_vec();
        b.extend_from_slice(&[255]);
        assert_eq!(decode(&b), Err(DecodeError::NoMsgType));
        assert_eq!(decode(&reply(0, 1, &[])), Err(DecodeError::BadMsgType(0)));
        assert_eq!(decode(&reply(99, 1, &[])), Err(DecodeError::BadMsgType(99)));
    }
    #[test]
    fn decode_tolerates_nonconforming_server_options() {
        let with = |opt: &[u8]| {
            let mut o = vec![54, 4, 10, 0, 0, 1];
            o.extend_from_slice(opt);
            decode(&reply(2, 1, &o)).expect("reply must survive")
        };
        assert_eq!(with(&[1, 4, 255, 0, 255, 0]).mask, None, "non-contiguous mask ignored");
        assert_eq!(with(&[1, 3, 255, 0, 0]).mask, None);
        assert_eq!(with(&[3, 6, 10, 0, 0, 1, 10, 0]).routers, vec![SRV], "partial trailing router dropped");
        assert!(with(&[3, 3, 1, 2, 3]).routers.is_empty());
        assert!(with(&[3, 0]).routers.is_empty());
        let m = with(&[51, 2, 0, 1, 58, 3, 1, 2, 3, 59, 5, 1, 2, 3, 4, 5]);
        assert_eq!((m.lease_secs, m.t1, m.t2), (None, None, None));
        assert_eq!(with(&[51, 4, 0, 0, 1, 0]).lease_secs, Some(256), "good option still parsed");
        // the lenient parse still yields a usable lease through the FSM
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        let mut o = std_opts();
        o.extend_from_slice(&[1, 4, 255, 0, 255, 0]);
        assert!(!f.on_rx(1, &rx(2, x, &o)).is_empty());
    }
    #[test]
    fn decode_tolerates_pad_unknown_and_missing_end() {
        let mut b = reply(5, 1, &[0, 0, 0, 200, 3, 1, 2, 3, 54, 4, 1, 2, 3, 4]);
        b.pop(); // drop the 255 end marker
        let m = decode(&b).unwrap();
        assert_eq!(m.server_id, Some(Ipv4Addr::new(1, 2, 3, 4)));
        let m = decode(&reply(5, 1, &[54, 4, 1, 1, 1, 1, 54, 4, 2, 2, 2, 2])).unwrap();
        assert_eq!(m.server_id, Some(Ipv4Addr::new(1, 1, 1, 1)), "first duplicate wins");
    }
    #[test]
    fn decode_every_truncation_never_panics() {
        let good = reply(2, 1, &std_opts());
        for n in 0..good.len() {
            let _ = decode(&good[..n]);
        }
        let mut x = 0x1234_5678u32;
        for _ in 0..2000 {
            let mut b = good.clone();
            for _ in 0..4 {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                let i = (x >> 8) as usize % b.len();
                b[i] = (x >> 24) as u8;
            }
            let _ = decode(&b);
        }
    }
    #[test]
    fn prefix_lens() {
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_len(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
        assert_eq!(prefix_len(Ipv4Addr::new(255, 0, 255, 0)), None);
    }
    #[test]
    fn encode_discover_and_request() {
        let d = encode(&Out { kind: MsgType::Discover, ciaddr: Ipv4Addr::UNSPECIFIED, requested: None, server: None, unicast_to: None }, 0xdeadbeef, MAC, "lab-proxy");
        assert!(d.len() >= 300);
        assert_eq!(&d[4..8], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(d[10], 0x80);
        assert_eq!(&d[28..34], &MAC);
        assert_eq!(&d[FIXED..OPT_START], &MAGIC);
        assert_eq!(&d[OPT_START..OPT_START + 3], &[53, 1, 1]);
        let r = encode(&Out { kind: MsgType::Request, ciaddr: Ipv4Addr::UNSPECIFIED, requested: Some(YI), server: Some(SRV), unicast_to: None }, 1, MAC, "");
        let opts = &r[OPT_START..];
        assert!(opts.windows(6).any(|w| w == [50, 4, 10, 0, 0, 77]));
        assert!(opts.windows(6).any(|w| w == [54, 4, 10, 0, 0, 1]));
        let ren = encode(&Out { kind: MsgType::Request, ciaddr: YI, requested: None, server: None, unicast_to: Some(SRV) }, 1, MAC, "");
        assert_eq!(ren[10], 0, "no broadcast flag once we hold an address");
        assert_eq!(&ren[12..16], &YI.octets());
    }
    #[test]
    fn encode_wire_format_is_exact() {
        let o = Out { kind: MsgType::Request, ciaddr: Ipv4Addr::UNSPECIFIED, requested: Some(YI), server: Some(SRV), unicast_to: None };
        let p = encode(&o, 0x01020304, MAC, "lab-proxy");
        assert_eq!(&p[0..4], &[1, 1, 6, 0], "BOOTREQUEST, ethernet, hlen 6, hops 0");
        assert_eq!(&p[4..8], &[1, 2, 3, 4]);
        assert_eq!(&p[FIXED..OPT_START], &[0x63, 0x82, 0x53, 0x63], "literal magic cookie");
        let mut want = vec![53, 1, 3, 61, 7, 1];
        want.extend_from_slice(&MAC);
        want.extend_from_slice(&[50, 4, 10, 0, 0, 77, 54, 4, 10, 0, 0, 1, 12, 9]);
        want.extend_from_slice(b"lab-proxy");
        want.extend_from_slice(&[55, 7, 1, 3, 6, 28, 51, 58, 59, 255]);
        assert_eq!(&p[OPT_START..OPT_START + want.len()], &want[..]);
        assert!(p[OPT_START + want.len()..].iter().all(|b| *b == 0));
        assert_eq!(p.len(), 300, "padded to exactly 300");
    }
    #[test]
    fn frame_wire_format_is_exact() {
        let dst = [0xff; 6];
        let f = build_frame(MAC, dst, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, &[1, 2, 3, 4]);
        assert_eq!(&f[0..6], &dst);
        assert_eq!(&f[6..12], &MAC);
        assert_eq!(&f[12..14], &[8, 0]);
        let ip = &f[14..34];
        assert_eq!(ip[0], 0x45);
        assert_eq!(&ip[2..4], &[0, 32]);
        assert_eq!(ip[8], 64, "ttl");
        assert_eq!(ip[9], 17);
        assert_eq!(&ip[16..20], &[255; 4]);
        assert_eq!(csum(ip), 0, "ip header checksum verifies");
        let udp = &f[34..];
        assert_eq!(&udp[0..4], &[0, 68, 0, 67], "68 -> 67");
        assert_eq!(&udp[4..6], &[0, 12]);
        let mut pseudo = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, 17, 0, 12];
        pseudo.extend_from_slice(udp);
        assert_eq!(csum(&pseudo), 0, "udp checksum verifies");
    }
    #[test]
    fn csum_carry_folding() {
        assert_eq!(csum(&[]), 0xffff);
        assert_eq!(csum(&[0xff, 0xff, 0x00, 0x01]), 0xfffe, "end-around carry");
        assert_eq!(csum(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), 0x0000);
        assert_eq!(csum(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x02]), 0xfffd, "carry then another add");
        assert_eq!(csum(&[0x01]), 0xfeff, "odd trailing byte is the high half");
        // many carries: 0x8000 * 40 = 0x140000 folds in two rounds
        let v: Vec<u8> = (0..40).flat_map(|_| [0x80u8, 0x00]).collect();
        assert_eq!(csum(&v), !0x0014u16);
    }
    #[test]
    fn frame_port_check_needs_both_ports() {
        let pl = encode(&Out { kind: MsgType::Offer, ciaddr: Ipv4Addr::UNSPECIFIED, requested: None, server: None, unicast_to: None }, 1, MAC, "");
        let mut payload = pl.clone();
        payload[0] = 2;
        let mk = |sp: u16, dp: u16| {
            let mut f = build_frame(MAC, MAC, SRV, YI, &payload);
            f[34..36].copy_from_slice(&sp.to_be_bytes());
            f[36..38].copy_from_slice(&dp.to_be_bytes());
            f
        };
        assert!(decode_frame(&mk(67, 68)).is_ok());
        assert_eq!(decode_frame(&mk(67, 69)), Err(DecodeError::WrongPorts));
        assert_eq!(decode_frame(&mk(66, 68)), Err(DecodeError::WrongPorts));
        assert_eq!(decode_frame(&mk(68, 67)), Err(DecodeError::WrongPorts));
    }
    #[test]
    fn requesting_retries_are_spaced_by_gap() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1000, &rx(2, x, &std_opts()));
        assert!(f.tick(1000 + GAP_MS - 1).is_empty(), "no early Request");
        assert_eq!(sends(&f.tick(1000 + GAP_MS)), vec![MsgType::Request]);
        assert!(f.tick(1000 + GAP_MS + 1).is_empty(), "deadline moves forward, no flood");
        assert!(f.deadline() > 1000 + GAP_MS);
    }
    #[test]
    fn frame_roundtrip_and_rejects() {
        // build a server->client frame by hand around a reply payload
        let payload = reply(5, 9, &std_opts());
        let mut f = build_frame([2; 6], BCAST_MAC, SRV, Ipv4Addr::BROADCAST, &payload);
        // our builder emits 68->67; flip to 67->68 for a reply and fix the IP header (ports are not in it)
        f[34..38].copy_from_slice(&[0, 67, 0, 68]);
        let r = decode_frame(&f).unwrap();
        assert_eq!(r.src_mac, [2; 6]);
        assert_eq!(r.src_ip, SRV);
        assert_eq!(r.msg.mtype, MsgType::Ack);
        // wrong ports (our own request direction)
        let own = build_frame(MAC, BCAST_MAC, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, &payload);
        assert_eq!(decode_frame(&own), Err(DecodeError::WrongPorts));
        // corrupt IP header
        let mut b = f.clone();
        b[22] ^= 0xff;
        assert_eq!(decode_frame(&b), Err(DecodeError::BadIpChecksum));
        // not IP / not UDP / fragment / short / bad lengths
        let mut b = f.clone();
        b[12] = 0x86;
        assert_eq!(decode_frame(&b), Err(DecodeError::NotIpv4));
        let mut b = f.clone();
        b[23] = 6;
        b[24] = 0;
        b[25] = 0;
        let c = csum(&b[14..34]);
        b[24..26].copy_from_slice(&c.to_be_bytes());
        assert_eq!(decode_frame(&b), Err(DecodeError::NotUdp));
        let mut b = f.clone();
        b[20] = 0x20; // more-fragments
        b[24] = 0;
        b[25] = 0;
        let c = csum(&b[14..34]);
        b[24..26].copy_from_slice(&c.to_be_bytes());
        assert_eq!(decode_frame(&b), Err(DecodeError::Fragment));
        assert_eq!(decode_frame(&f[..30]), Err(DecodeError::TooShort));
        let mut b = f.clone();
        b[16] = 0xff; // total length bigger than the frame
        assert_eq!(decode_frame(&b), Err(DecodeError::BadIpHeader));
        let mut b = f.clone();
        b[38] = 0xff; // udp length bigger than the datagram
        assert_eq!(decode_frame(&b), Err(DecodeError::BadUdp));
        for n in 0..f.len() {
            let _ = decode_frame(&f[..n]);
        }
    }
    #[test]
    fn frame_checksums_verify() {
        let f = build_frame(MAC, BCAST_MAC, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, &[1, 2, 3]);
        assert_eq!(csum(&f[14..34]), 0, "ip header checksum folds to zero");
        assert_eq!(f.len(), 14 + 20 + 8 + 3);
        let mut pseudo = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, 17, 0, 11];
        pseudo.extend_from_slice(&f[34..]);
        assert_eq!(csum(&pseudo), 0, "udp checksum verifies with the pseudo header");
    }
    #[test]
    fn timers_sanity() {
        assert_eq!(timers(3600, None, None), (1800, 3150));
        assert_eq!(timers(3600, Some(100), Some(200)), (100, 200));
        assert_eq!(timers(3600, Some(5000), Some(200)), (1800, 3150), "insane server timers ignored");
        assert_eq!(timers(3600, Some(100), Some(4000)), (1800, 3150));
    }

    fn sends(a: &[Action]) -> Vec<MsgType> {
        a.iter().filter_map(|x| if let Action::Send(o) = x { Some(o.kind) } else { None }).collect()
    }

    #[test]
    fn discover_schedule_matches_udhcpc() {
        // udhcpc -t 3 -T 2 -A 10: sends at 0, 2, 4 s, gives up at 6 s, pauses 10 s, starts again at 16 s
        let mut f = Fsm::new(MAC, 100);
        let mut times = Vec::new();
        let mut now = 0;
        while now <= 17_000 {
            if !sends(&f.tick(now)).is_empty() {
                times.push(now);
            }
            now += 500;
        }
        assert_eq!(times, vec![0, 2000, 4000, 16_000]);
    }
    #[test]
    fn full_lease_flow_and_renew() {
        let mut f = Fsm::new(MAC, 100);
        let a = f.tick(0);
        assert_eq!(sends(&a), vec![MsgType::Discover]);
        let xid = f.xid();
        // wrong xid and wrong mac are ignored
        assert!(f.on_rx(10, &rx(2, xid + 1, &std_opts())).is_empty());
        let mut bad = rx(2, xid, &std_opts());
        bad.msg.chaddr = [9; 6];
        assert!(f.on_rx(10, &bad).is_empty());
        // offer without a server id is ignored
        assert!(f.on_rx(10, &rx(2, xid, &[1, 4, 255, 255, 255, 0])).is_empty());
        let a = f.on_rx(20, &rx(2, xid, &std_opts()));
        match &a[..] {
            [Action::Send(o)] => {
                assert_eq!((o.kind, o.requested, o.server, o.ciaddr), (MsgType::Request, Some(YI), Some(SRV), Ipv4Addr::UNSPECIFIED));
            }
            x => panic!("{x:?}"),
        }
        assert_eq!(f.state, State::Requesting);
        let a = f.on_rx(30, &rx(5, xid, &std_opts()));
        let Action::Configure(l) = &a[0] else { panic!() };
        assert_eq!((l.ip, l.router, l.lease_secs), (YI, Some(SRV), 3600));
        assert_eq!(f.state, State::Bound);
        assert_eq!(f.server_mac(), Some([2; 6]));
        assert!(f.tick(1_000_000).is_empty(), "nothing to do before t1");
    }
    fn bound(f: &mut Fsm, at: u64) {
        f.tick(at);
        let x = f.xid();
        f.on_rx(at, &rx(2, x, &std_opts()));
        let a = f.on_rx(at, &rx(5, x, &std_opts()));
        assert!(matches!(a[0], Action::Configure(_)));
    }
    #[test]
    fn renew_rebind_expire() {
        let mut f = Fsm::new(MAC, 5);
        bound(&mut f, 0); // lease 3600 s: t1 1800 s, t2 3150 s
        assert!(f.tick(1_799_000).is_empty());
        let a = f.tick(1_800_000);
        let [Action::Send(o)] = &a[..] else { panic!("{a:?}") };
        assert_eq!((f.state, o.unicast_to, o.ciaddr), (State::Renewing, Some(SRV), YI));
        // renewal ACK -> bound again, new timers
        let x = f.xid();
        let a = f.on_rx(1_801_000, &rx(5, x, &std_opts()));
        assert!(matches!(a[0], Action::Configure(_)));
        assert_eq!(f.state, State::Bound);
        // let it go unanswered: renewing retries, then rebinding at t2 (broadcast), then expiry
        let mut f = Fsm::new(MAC, 5);
        bound(&mut f, 0);
        f.tick(1_800_000);
        let mut saw_rebind = false;
        let mut now = 1_800_000;
        let mut deconf_at = None;
        while now < 4_000_000 && deconf_at.is_none() {
            now += 1000;
            for a in f.tick(now) {
                match a {
                    Action::Send(o) if f.state == State::Rebinding => {
                        assert_eq!(o.unicast_to, None);
                        saw_rebind = true;
                    }
                    Action::Send(o) => assert_eq!(o.unicast_to, Some(SRV)),
                    Action::Deconfigure => deconf_at = Some(now),
                    _ => {}
                }
            }
        }
        assert!(saw_rebind);
        assert_eq!(deconf_at, Some(3_600_000));
        assert_eq!(f.state, State::Init);
        assert!(f.lease().is_none());
        // and it restarts discovery right away
        assert_eq!(sends(&f.tick(3_600_000)), vec![MsgType::Discover]);
    }
    #[test]
    fn nak_drops_lease_and_restarts() {
        let mut f = Fsm::new(MAC, 5);
        bound(&mut f, 0);
        f.tick(1_800_000);
        let x = f.xid();
        let a = f.on_rx(1_800_100, &rx(6, x, &[54, 4, 10, 0, 0, 1]));
        assert_eq!(a, vec![Action::Deconfigure]);
        assert_eq!(f.state, State::Init);
        assert!(f.tick(1_800_500).is_empty(), "NAK pause");
        assert_eq!(sends(&f.tick(1_801_200)), vec![MsgType::Discover]);
        // NAK while requesting: nothing to deconfigure
        let mut g = Fsm::new(MAC, 1);
        g.tick(0);
        let x = g.xid();
        g.on_rx(1, &rx(2, x, &std_opts()));
        assert!(g.on_rx(2, &rx(6, x, &[])).is_empty());
        assert_eq!(g.state, State::Init);
    }
    #[test]
    fn requesting_timeout_returns_to_init() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &std_opts()));
        assert_eq!(sends(&f.tick(2001)), vec![MsgType::Request]);
        assert_eq!(sends(&f.tick(4002)), vec![MsgType::Request]);
        assert!(f.tick(6003).is_empty());
        assert_eq!(f.state, State::Init);
    }
    #[test]
    fn bad_acks_ignored() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &std_opts()));
        // yiaddr 0
        let mut z = rx(5, x, &std_opts());
        z.msg.yiaddr = Ipv4Addr::UNSPECIFIED;
        assert!(f.on_rx(2, &z).is_empty());
        // lease time 0
        assert!(f.on_rx(2, &rx(5, x, &[51, 4, 0, 0, 0, 0])).is_empty());
        assert_eq!(f.state, State::Requesting);
        // ACK in Selecting is ignored
        let mut g = Fsm::new(MAC, 1);
        g.tick(0);
        let gx = g.xid();
        assert!(g.on_rx(1, &rx(5, gx, &std_opts())).is_empty());
    }
    #[test]
    fn defaults_for_sparse_ack() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &[54, 4, 10, 0, 0, 1]));
        let a = f.on_rx(2, &rx(5, x, &[]));
        let Action::Configure(l) = &a[0] else { panic!() };
        assert_eq!(l.mask, Ipv4Addr::new(255, 0, 0, 0), "classful /8 for 10.x");
        assert_eq!(l.router, None);
        assert_eq!(l.lease_secs, 3600);
        assert_eq!(l.server, SRV, "falls back to the source address");
    }
    #[test]
    fn infinite_lease_never_renews() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &std_opts()));
        f.on_rx(2, &rx(5, x, &[54, 4, 10, 0, 0, 1, 51, 4, 255, 255, 255, 255]));
        assert_eq!(f.state, State::Bound);
        assert!(f.tick(u64::MAX - 1).is_empty());
        assert_eq!(f.state, State::Bound);
    }
    #[test]
    fn magic_cookie_is_rfc2131() {
        assert_eq!(MAGIC, [0x63, 0x82, 0x53, 0x63]);
        assert_eq!(u32::from_be_bytes(MAGIC), 0x6382_5363);
    }
    /// Bind with a short server lease and return the time of the Deconfigure action found by ticking each second.
    fn short_lease_run(lease: u32) -> (Lease, Option<u64>, Vec<u64>) {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &std_opts()));
        let o = [54, 4, 10, 0, 0, 1, 51, 4].iter().copied().chain(lease.to_be_bytes()).collect::<Vec<u8>>();
        let a = f.on_rx(2, &rx(5, x, &o));
        let l = match &a[0] {
            Action::Configure(l) => l.clone(),
            other => panic!("{other:?}"),
        };
        let (mut deconf, mut renews) = (None, vec![]);
        let mut t = 2u64;
        while t < 200_000 && deconf.is_none() {
            t += 250;
            for act in f.tick(t) {
                match act {
                    Action::Deconfigure => deconf = Some(t),
                    Action::Send(_) => renews.push(t),
                    _ => {}
                }
            }
        }
        (l, deconf, renews)
    }
    #[test]
    fn short_lease_is_honoured_not_stretched() {
        let (l, deconf, renews) = short_lease_run(20);
        assert_eq!(l.lease_secs, 20);
        let d = deconf.expect("20 s lease must expire");
        assert_eq!(d, 20_002, "expires exactly lease_secs after the ACK (at t=2 ms), not at 60 s");
        assert!(!renews.is_empty(), "renewals were tried before expiry");
        assert!(renews.iter().all(|r| *r < d));
        assert!(renews[0] >= 10_000, "t1 = lease/2 after ack at 2 ms");
        let (l, deconf, _) = short_lease_run(59);
        assert_eq!(l.lease_secs, 59);
        assert_eq!(deconf, Some(59_002));
        let (l, deconf, _) = short_lease_run(1);
        assert_eq!(l.lease_secs, 1);
        assert_eq!(deconf, Some(1_002), "a 1 s lease expires after 1 s");
    }
    #[test]
    fn short_lease_retries_keep_the_minimum_spacing() {
        let (_, _, renews) = short_lease_run(30);
        for w in renews.windows(2) {
            assert!(w[1] - w[0] >= 250 && w[1] > w[0]);
        }
        // renewal retries after the first are spaced by at least MIN_RETRY_MS unless the target is nearer
        assert_eq!(retry(0, 1_000), 1_000);
        assert_eq!(retry(0, 100_000), 50_000);
        assert_eq!(retry(0, 6_000), 4_000, "rem/2 = 3000 is raised to MIN_RETRY_MS");
    }
    #[test]
    fn xid_changes_per_transaction() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let a = f.xid();
        f.tick(10_000_000);
        // third retry window passed, back to Init pause, then new discover has a new xid
        let mut now = 10_000_000;
        for _ in 0..40 {
            now += 3000;
            f.tick(now);
        }
        assert_ne!(f.xid(), a);
    }
    #[test]
    fn hint_address_is_never_removed() {
        let ours = Some(YI);
        assert!(should_deconfigure(ours, Some(YI)));
        assert!(!should_deconfigure(ours, Some(Ipv4Addr::new(192, 168, 77, 5))), "a hint on the interface stays");
        assert!(!should_deconfigure(None, Some(YI)), "never configured by us");
        assert!(!should_deconfigure(ours, None));
    }

    // ---- pins found by mutation testing (each names the behaviour it protects)

    fn server_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = build_frame([2; 6], BCAST_MAC, SRV, Ipv4Addr::BROADCAST, payload);
        f[34..38].copy_from_slice(&[0, 67, 0, 68]);
        f
    }
    /// Rewrites the IPv4 header with `edit` and recomputes its checksum.
    fn with_ip(f: &[u8], edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let mut b = f.to_vec();
        edit(&mut b[14..34]);
        b[24] = 0;
        b[25] = 0;
        let c = csum(&b[14..34]);
        b[24..26].copy_from_slice(&c.to_be_bytes());
        b
    }

    #[test]
    fn message_types_map_exactly() {
        for (n, t) in [(1, MsgType::Discover), (2, MsgType::Offer), (3, MsgType::Request), (4, MsgType::Decline), (5, MsgType::Ack), (6, MsgType::Nak), (7, MsgType::Release), (8, MsgType::Inform)] {
            assert_eq!(decode(&reply(n, 1, &[])).unwrap().mtype, t, "{n}");
            assert_eq!(t as u8, n);
        }
        assert_eq!(decode(&reply(0, 1, &[])), Err(DecodeError::BadMsgType(0)));
        assert_eq!(decode(&reply(9, 1, &[])), Err(DecodeError::BadMsgType(9)));
    }
    #[test]
    fn magic_cookie_bytes_and_position() {
        assert_eq!(MAGIC, [0x63, 0x82, 0x53, 0x63]);
        assert_eq!((FIXED, OPT_START), (236, 240));
        let mut b = reply(2, 1, &[]);
        for i in 0..4 {
            let mut c = b.clone();
            c[FIXED + i] ^= 1;
            assert_eq!(decode(&c), Err(DecodeError::BadMagic), "byte {i}");
        }
        b[FIXED - 1] = 0xAA; // the byte before the cookie is not part of it
        assert!(decode(&b).is_ok());
    }
    #[test]
    fn decode_fixed_header_fields_use_distinct_bytes() {
        let mut p = reply(2, 0x0102_0304, &[51, 4, 1, 2, 3, 4, 58, 4, 5, 6, 7, 8, 59, 4, 9, 10, 11, 12, 54, 4, 192, 168, 7, 9, 1, 4, 255, 255, 240, 0]);
        p[12..16].copy_from_slice(&[1, 2, 3, 4]);
        p[16..20].copy_from_slice(&[11, 12, 13, 14]);
        p[28..34].copy_from_slice(&[21, 22, 23, 24, 25, 26]);
        let m = decode(&p).unwrap();
        assert_eq!(m.xid, 0x0102_0304);
        assert_eq!(m.ciaddr, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(m.yiaddr, Ipv4Addr::new(11, 12, 13, 14));
        assert_eq!(m.chaddr, [21, 22, 23, 24, 25, 26]);
        assert_eq!(m.lease_secs, Some(0x0102_0304));
        assert_eq!(m.t1, Some(0x0506_0708));
        assert_eq!(m.t2, Some(0x090A_0B0C));
        assert_eq!(m.server_id, Some(Ipv4Addr::new(192, 168, 7, 9)));
        assert_eq!(m.mask, Some(Ipv4Addr::new(255, 255, 240, 0)));
    }
    #[test]
    fn decode_length_boundaries() {
        let full = reply(2, 1, &[]);
        let bare = &full[..OPT_START];
        assert_eq!(decode(bare), Err(DecodeError::NoMsgType), "exactly the fixed part: parsed, no type");
        assert_eq!(decode(&bare[..OPT_START - 1]), Err(DecodeError::TooShort));
    }
    #[test]
    fn decode_router_rules() {
        let r = |opts: &[u8]| decode(&reply(2, 1, opts)).unwrap().routers;
        assert_eq!(r(&[3, 4, 1, 2, 3, 4]), vec![Ipv4Addr::new(1, 2, 3, 4)], "exactly one address");
        assert!(r(&[3, 3, 1, 2, 3]).is_empty());
        assert!(r(&[3, 0]).is_empty());
        assert_eq!(r(&[3, 6, 1, 2, 3, 4, 5, 6]).len(), 1, "partial trailing address dropped");
        assert_eq!(r(&[3, 4, 1, 1, 1, 1, 3, 4, 2, 2, 2, 2]), vec![Ipv4Addr::new(1, 1, 1, 1)], "first option 3 wins");
        let mut o = vec![3, 40];
        for i in 0..10u8 {
            o.extend_from_slice(&[10, 0, 0, i]);
        }
        let got = r(&o);
        assert_eq!(got.len(), 8, "at most 8 routers");
        assert_eq!(got[7], Ipv4Addr::new(10, 0, 0, 7));
        assert!(r(&[3, 2, 9, 9, 3, 4, 7, 7, 7, 7]).len() == 1, "a too-short option 3 does not block a later good one");
    }
    #[test]
    fn decode_time_option_codes() {
        let m = decode(&reply(2, 1, &[51, 4, 0, 0, 0, 1, 58, 4, 0, 0, 0, 2, 59, 4, 0, 0, 0, 3])).unwrap();
        assert_eq!((m.lease_secs, m.t1, m.t2), (Some(1), Some(2), Some(3)));
        for other in [50u8, 52, 56, 57, 60, 61] {
            let m = decode(&reply(2, 1, &[other, 4, 0, 0, 0, 9])).unwrap();
            assert_eq!((m.lease_secs, m.t1, m.t2), (None, None, None), "option {other} is not a time option");
        }
        let m = decode(&reply(2, 1, &[51, 4, 0, 0, 0, 1, 51, 4, 0, 0, 0, 9])).unwrap();
        assert_eq!(m.lease_secs, Some(1), "first wins");
        let m = decode(&reply(2, 1, &[58, 3, 0, 0, 1, 59, 5, 0, 0, 0, 0, 1])).unwrap();
        assert_eq!((m.t1, m.t2), (None, None), "wrong-length time options ignored");
    }
    #[test]
    fn prefix_lengths_exact() {
        for n in 0..=32u8 {
            let v = if n == 0 { 0 } else { u32::MAX << (32 - n as u32) };
            assert_eq!(prefix_len(Ipv4Addr::from(v)), Some(n));
        }
        assert_eq!(prefix_len(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(prefix_len(Ipv4Addr::new(0, 255, 255, 255)), None);
    }
    #[test]
    fn classful_default_masks() {
        for (ip, m) in [
            ([0, 5, 5, 5], [255, 0, 0, 0]),
            ([10, 200, 7, 7], [255, 0, 0, 0]),
            ([127, 255, 255, 255], [255, 0, 0, 0]),
            ([128, 0, 0, 0], [255, 255, 0, 0]),
            ([172, 16, 5, 5], [255, 255, 0, 0]),
            ([191, 255, 255, 255], [255, 255, 0, 0]),
            ([192, 0, 0, 1], [255, 255, 255, 0]),
            ([223, 1, 2, 3], [255, 255, 255, 0]),
            ([200, 5, 5, 5], [255, 255, 255, 0]),
        ] {
            assert_eq!(classful_mask(Ipv4Addr::from(ip)), Ipv4Addr::from(m), "{ip:?}");
        }
    }
    #[test]
    fn timers_boundaries() {
        assert_eq!(timers(3600, Some(200), Some(200)), (1800, 3150), "t1 == t2 is insane");
        assert_eq!(timers(3600, Some(200), Some(3600)), (1800, 3150), "t2 == lease is insane");
        assert_eq!(timers(3600, Some(1799), Some(3599)), (1799, 3599), "just inside is accepted");
        assert_eq!(timers(3600, Some(3599), None), (1800, 3150), "t1 above the default t2");
        assert_eq!(timers(3600, Some(0), Some(1)), (0, 1));
    }
    #[test]
    fn decode_frame_header_checks() {
        let f = server_frame(&reply(5, 9, &std_opts()));
        assert!(decode_frame(&f).is_ok());
        // truncated at and around the minimum frame length (14 + 20 + 8 = 42)
        assert_eq!(decode_frame(&f[..41]), Err(DecodeError::TooShort));
        assert_eq!(decode_frame(&f[..42]), Err(DecodeError::BadIpHeader), "total length claims more than present");
        // IHL
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[0] = 0x44)), Err(DecodeError::BadIpHeader), "ihl 16 bytes");
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[0] = 0x46)), Err(DecodeError::BadIpChecksum), "ihl 24 over a 20 byte checksum");
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[0] = 0x65)), Err(DecodeError::NotIpv4), "version 6");
        // total length: ihl + 7 is too small, ihl + 8 reaches the udp parser (empty datagram), more than the frame is bad
        let tot = |n: u16| move |ip: &mut [u8]| ip[2..4].copy_from_slice(&n.to_be_bytes());
        assert_eq!(decode_frame(&with_ip(&f, tot(27))), Err(DecodeError::BadIpHeader));
        assert_eq!(decode_frame(&with_ip(&f, tot(28))), Err(DecodeError::BadUdp), "udp length field exceeds the 8 bytes present");
        let n = (f.len() - 14) as u16;
        assert!(decode_frame(&with_ip(&f, tot(n))).is_ok());
        assert_eq!(decode_frame(&with_ip(&f, tot(n + 1))), Err(DecodeError::BadIpHeader));
        // fragmentation bits: MF (byte 6) and offset (byte 7) reject, DF (0x40) does not
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[6] = 0x20)), Err(DecodeError::Fragment));
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[7] = 0x01)), Err(DecodeError::Fragment));
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[6] = 0x1f)), Err(DecodeError::Fragment), "offset high bits");
        assert!(decode_frame(&with_ip(&f, |ip| ip[6] = 0x40)).is_ok(), "DF is fine");
        assert_eq!(decode_frame(&with_ip(&f, |ip| ip[9] = 6)), Err(DecodeError::NotUdp));
    }
    #[test]
    fn decode_frame_udp_length_checks() {
        let f = server_frame(&reply(5, 9, &std_opts()));
        let ulen = |n: u16| {
            let mut b = f.clone();
            b[38..40].copy_from_slice(&n.to_be_bytes());
            b
        };
        assert_eq!(decode_frame(&ulen(7)), Err(DecodeError::BadUdp));
        assert_eq!(decode_frame(&ulen(8)), Err(DecodeError::TooShort), "an empty dhcp payload reaches decode()");
        assert_eq!(decode_frame(&ulen(9)), Err(DecodeError::TooShort));
        let full = (f.len() - 34) as u16;
        assert!(decode_frame(&ulen(full)).is_ok());
        assert_eq!(decode_frame(&ulen(full + 1)), Err(DecodeError::BadUdp));
        let mut b = f.clone();
        b[34..36].copy_from_slice(&[0, 68]);
        assert_eq!(decode_frame(&b), Err(DecodeError::WrongPorts));
        let mut b = f.clone();
        b[36..38].copy_from_slice(&[0, 67]);
        assert_eq!(decode_frame(&b), Err(DecodeError::WrongPorts));
    }
    #[test]
    fn encode_hostname_limits() {
        let o = Out { kind: MsgType::Discover, ciaddr: Ipv4Addr::UNSPECIFIED, requested: None, server: None, unicast_to: None };
        let has12 = |p: &[u8], len: usize| p.windows(2).any(|w| w == [12, len as u8]);
        assert!(!has12(&encode(&o, 1, MAC, ""), 0), "empty hostname: no option 12");
        let p = encode(&o, 1, MAC, &"h".repeat(63));
        assert!(has12(&p, 63));
        assert!(!has12(&encode(&o, 1, MAC, &"h".repeat(64)), 64));
        assert!(has12(&encode(&o, 1, MAC, "a"), 1));
        assert!(encode(&o, 1, MAC, &"h".repeat(63)).len() >= 300);
    }
    #[test]
    fn frame_ip_and_udp_headers_exact() {
        let payload = vec![0xA5u8; 300];
        let f = build_frame(MAC, BCAST_MAC, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, &payload);
        let tot = 20 + 8 + 300;
        assert_eq!(f.len(), 14 + tot);
        assert_eq!(&f[14..24], &[0x45, 0x10, (tot >> 8) as u8, tot as u8, 0, 0, 0, 0, 64, 17], "ver/tos/len/id/frag/ttl/proto");
        assert_eq!(&f[34..40], &[0, 68, 0, 67, ((8 + 300) >> 8) as u8, (8 + 300) as u8]);
        // independent UDP checksum over pseudo header (length 308 has a non-zero high byte)
        let mut pseudo = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, 17, 1, 52];
        pseudo.extend_from_slice(&f[34..]);
        assert_eq!(csum(&pseudo), 0);
    }
    #[test]
    fn udp_checksum_zero_is_sent_as_ffff() {
        let sip = Ipv4Addr::new(10, 1, 2, 3);
        let dip = Ipv4Addr::new(10, 1, 2, 4);
        let mut found = false;
        for x in 0..=u16::MAX {
            let pl = x.to_be_bytes();
            let f = build_frame(MAC, BCAST_MAC, sip, dip, &pl);
            let mut ps = Vec::new();
            ps.extend_from_slice(&sip.octets());
            ps.extend_from_slice(&dip.octets());
            ps.extend_from_slice(&[0, 17, 0, 10]);
            ps.extend_from_slice(&[0, 68, 0, 67, 0, 10, 0, 0]);
            ps.extend_from_slice(&pl);
            let c = csum(&ps);
            let field = u16::from_be_bytes([f[40], f[41]]);
            assert_ne!(field, 0, "x={x}");
            if c == 0 {
                assert_eq!(field, 0xffff);
                found = true;
            } else {
                assert_eq!(field, c);
            }
        }
        assert!(found, "a payload with a zero checksum exists in the search space");
    }
    #[test]
    fn fsm_xid_advances_by_one_per_transaction() {
        let mut f = Fsm::new(MAC, 50);
        f.tick(0);
        assert_eq!(f.xid(), 51, "discover");
        let x = f.xid();
        f.on_rx(1, &rx(2, x, &std_opts()));
        f.on_rx(2, &rx(5, x, &[54, 4, 10, 0, 0, 1, 51, 4, 0, 0, 0x0e, 0x10]));
        assert_eq!(f.state, State::Bound);
        assert_eq!(f.xid(), 51, "no change binding");
        f.tick(1_802_000); // t1
        assert_eq!(f.state, State::Renewing);
        assert_eq!(f.xid(), 52);
        f.tick(1_810_000); // still renewing: same transaction
        assert_eq!(f.xid(), 52);
        f.tick(3_152_002); // t2
        assert_eq!(f.state, State::Rebinding);
        assert_eq!(f.xid(), 53);
        f.tick(3_160_000);
        assert_eq!(f.xid(), 53);
    }
    #[test]
    fn fsm_t1_t2_fire_exactly_at_their_time() {
        let mut f = Fsm::new(MAC, 1);
        f.tick(0);
        let x = f.xid();
        f.on_rx(0, &rx(2, x, &std_opts()));
        f.on_rx(0, &rx(5, x, &[54, 4, 10, 0, 0, 1, 51, 4, 0, 0, 0, 100]));
        // lease 100 s: t1 = 50 s, t2 = 87 s, expiry 100 s, all measured from the ack at 0
        assert!(f.tick(49_999).is_empty());
        assert_eq!(sends(&f.tick(50_000)), vec![MsgType::Request]);
        assert_eq!(f.state, State::Renewing);
        let a = f.tick(87_000);
        assert_eq!(f.state, State::Rebinding, "t2 exactly");
        assert_eq!(a.len(), 1);
        assert_eq!(f.tick(100_000), vec![Action::Deconfigure], "expiry exactly");
    }
}
