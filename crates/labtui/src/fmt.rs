//! Small formatting helpers shared by the pages. Owner: P5.

use labprobe::pci::PcieLink;

/// Decimal bytes as disk vendors count: `512.1 GB`, `2.0 TB`.
pub fn bytes_dec(b: u64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", b)
    } else {
        format!("{:.1} {}", v, U[i])
    }
}

/// Binary sizes for memory: input KiB, output `15.6 GiB`.
pub fn kib_bin(kib: u64) -> String {
    let v = kib as f64;
    if kib >= 1024 * 1024 {
        format!("{:.1} GiB", v / (1024.0 * 1024.0))
    } else if kib >= 1024 {
        format!("{:.0} MiB", v / 1024.0)
    } else {
        format!("{} KiB", kib)
    }
}

pub fn bytes_bin(b: u64) -> String {
    kib_bin(b / 1024)
}

/// `1d 02:03:04` / `02:03:04`.
pub fn uptime(s: f64) -> String {
    let t = if s.is_finite() && s > 0.0 { s as u64 } else { 0 };
    let (d, h, m, sec) = (t / 86400, (t / 3600) % 24, (t / 60) % 60, t % 60);
    if d > 0 {
        format!("{}d {:02}:{:02}:{:02}", d, h, m, sec)
    } else {
        format!("{:02}:{:02}:{:02}", h, m, sec)
    }
}

/// `x4 Gen3`, with the maximum appended when the link runs below it.
pub fn pcie_link(l: &PcieLink) -> String {
    let cur = match (l.cur_width, l.cur_gen) {
        (Some(w), Some(g)) => format!("x{} Gen{}", w, g),
        (Some(w), None) => format!("x{}", w),
        _ => return "-".into(),
    };
    if l.degraded {
        if let (Some(w), Some(g)) = (l.max_width, l.max_gen) {
            return format!("{} (max x{} Gen{})", cur, w, g);
        }
    }
    cur
}

/// Bits per second as `940 Mb/s`, `1.2 Gb/s`.
pub fn bps(bytes_per_s: f64) -> String {
    let b = bytes_per_s * 8.0;
    if b >= 1e9 {
        format!("{:.1} Gb/s", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} Mb/s", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} kb/s", b / 1e3)
    } else {
        format!("{:.0} b/s", b)
    }
}

pub fn hex16(v: u16) -> String {
    format!("{:04x}", v)
}

/// kernel log timestamp `[  12.345678]`
pub fn kmsg_time(ts_us: u64) -> String {
    format!("[{:>5}.{:06}]", ts_us / 1_000_000, ts_us % 1_000_000)
}

pub fn opt(s: &Option<String>) -> String {
    s.clone().unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        assert_eq!(bytes_dec(512_110_190_592), "512.1 GB");
        assert_eq!(bytes_dec(999), "999 B");
        assert_eq!(bytes_dec(2_000_000_000_000), "2.0 TB");
        assert_eq!(kib_bin(16 * 1024 * 1024), "16.0 GiB");
        assert_eq!(kib_bin(2048), "2 MiB");
        assert_eq!(uptime(3725.4), "01:02:05");
        assert_eq!(uptime(90061.0), "1d 01:01:01");
        assert_eq!(uptime(f64::NAN), "00:00:00");
        let l = PcieLink { cur_gen: Some(1), cur_width: Some(1), max_gen: Some(3), max_width: Some(4), degraded: true };
        assert_eq!(pcie_link(&l), "x1 Gen1 (max x4 Gen3)");
        assert_eq!(pcie_link(&PcieLink { degraded: false, ..l }), "x1 Gen1");
        assert_eq!(bps(125_000_000.0), "1.0 Gb/s");
        assert_eq!(kmsg_time(12_345_678), "[   12.345678]");
    }
}
