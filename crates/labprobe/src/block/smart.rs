//! SMART health without external tools. NVMe: admin commands Identify Controller and Get Log Page 0x02 through
//! NVME_IOCTL_ADMIN_CMD. SATA (and USB bridges that implement SAT): ATA PASS-THROUGH(16) through SG_IO with
//! SMART READ DATA, SMART READ THRESHOLDS and SMART RETURN STATUS. Only read commands are ever sent. The raw
//! buffers are parsed by pure functions covered by unit tests over buffers in tests/fixtures/smart/. Owner: P4.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct SmartAttr {
    pub id: u8,
    pub name: String,
    pub value: u8,
    pub worst: u8,
    pub thresh: u8,
    pub raw: u64,
    pub failing_now: bool,
}

#[derive(Clone, Debug, Default)]
pub struct NvmeHealth {
    pub critical_warning: u8,
    pub temperature_c: f64,
    pub available_spare: u8,
    pub percentage_used: u8,
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub power_cycles: u64,
    pub power_on_hours: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
    /// available-spare threshold (percent) from the log page
    pub spare_threshold: u8,
    /// WCTEMP / CCTEMP of Identify Controller in degrees C (None when 0 = not reported)
    pub warning_temp_c: Option<f64>,
    pub critical_temp_c: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct SmartReport {
    pub dev: String,
    /// "ata" | "nvme" | "usb-bridge" (USB disk whose bridge does not pass SMART) | "unsupported"
    pub kind: String,
    /// "pass" | "warn" | "fail" | "unknown"
    pub verdict: String,
    pub reasons: Vec<String>,
    pub temperature_c: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub attrs: Vec<SmartAttr>,
    pub nvme: Option<NvmeHealth>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SmartAll {
    pub devices: Vec<SmartReport>,
}


// ---------------------------------------------------------------------------------------------------------------
// NVMe

fn le_u128(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    u128::from_le_bytes(a)
}

fn sat(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

fn ascii_field(b: &[u8]) -> Option<String> {
    let s: String = b.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { ' ' }).collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Identify Controller (4096 bytes): serial 4..24, model 24..64, firmware 64..72, WCTEMP 266, CCTEMP 268 (Kelvin).
pub fn parse_nvme_identify(b: &[u8]) -> Option<(Option<String>, Option<String>, Option<String>, Option<f64>, Option<f64>)> {
    if b.len() < 272 {
        return None;
    }
    let kelvin = |o: usize| {
        let k = u16::from_le_bytes([b[o], b[o + 1]]);
        (k > 273).then(|| k as f64 - 273.0)
    };
    Some((ascii_field(&b[24..64]), ascii_field(&b[4..24]), ascii_field(&b[64..72]), kelvin(266), kelvin(268)))
}

/// SMART / Health Information log page (512 bytes).
pub fn parse_nvme_log(b: &[u8]) -> Option<NvmeHealth> {
    if b.len() < 192 {
        return None;
    }
    let kelvin = u16::from_le_bytes([b[1], b[2]]);
    Some(NvmeHealth {
        critical_warning: b[0],
        temperature_c: kelvin as f64 - 273.0,
        available_spare: b[3],
        spare_threshold: b[4],
        percentage_used: b[5],
        data_units_read: sat(le_u128(&b[32..48])),
        data_units_written: sat(le_u128(&b[48..64])),
        power_cycles: sat(le_u128(&b[112..128])),
        power_on_hours: sat(le_u128(&b[128..144])),
        unsafe_shutdowns: sat(le_u128(&b[144..160])),
        media_errors: sat(le_u128(&b[160..176])),
        error_log_entries: sat(le_u128(&b[176..192])),
        warning_temp_c: None,
        critical_temp_c: None,
    })
}

/// Verdict and reasons from the health log: critical-warning bits and exhausted spare fail the disk; a hot
/// controller, media errors and a worn-out drive warn.
pub fn nvme_verdict(h: &NvmeHealth) -> (&'static str, Vec<String>) {
    let mut fail = Vec::new();
    let mut warn = Vec::new();
    let w = h.critical_warning;
    if w & 0x01 != 0 {
        fail.push("available spare below threshold".to_string());
    }
    if w & 0x04 != 0 {
        fail.push("reliability degraded (NVM subsystem)".to_string());
    }
    if w & 0x08 != 0 {
        fail.push("media placed in read-only mode".to_string());
    }
    if w & 0x10 != 0 {
        fail.push("volatile memory backup failed".to_string());
    }
    if w & 0x02 != 0 {
        warn.push("temperature outside the operating range".to_string());
    }
    if w & 0x20 != 0 {
        warn.push("persistent memory region read-only".to_string());
    }
    if h.spare_threshold > 0 && h.available_spare < h.spare_threshold && w & 0x01 == 0 {
        fail.push(format!("available spare {}% below threshold {}%", h.available_spare, h.spare_threshold));
    }
    if let Some(c) = h.critical_temp_c {
        if h.temperature_c >= c {
            fail.push(format!("temperature {:.0} C at or above the critical {:.0} C", h.temperature_c, c));
        }
    }
    if let Some(c) = h.warning_temp_c {
        if h.temperature_c >= c && h.critical_temp_c.map(|k| h.temperature_c < k).unwrap_or(true) {
            warn.push(format!("temperature {:.0} C at or above the warning {:.0} C", h.temperature_c, c));
        }
    }
    if h.media_errors > 0 {
        warn.push(format!("{} media and data integrity errors", h.media_errors));
    }
    if h.percentage_used >= 100 {
        warn.push(format!("endurance used {}% (rated life reached)", h.percentage_used));
    } else if h.percentage_used >= 90 {
        warn.push(format!("endurance used {}%", h.percentage_used));
    }
    if !fail.is_empty() {
        fail.extend(warn);
        ("fail", fail)
    } else if !warn.is_empty() {
        ("warn", warn)
    } else {
        ("pass", Vec::new())
    }
}

/// The whole NVMe report from the two raw buffers.
pub fn nvme_report(dev: &str, identify: Option<&[u8]>, log: &[u8]) -> Option<SmartReport> {
    let mut h = parse_nvme_log(log)?;
    let (model, serial, firmware) = match identify.and_then(parse_nvme_identify) {
        Some((m, s, f, wc, cc)) => {
            h.warning_temp_c = wc;
            h.critical_temp_c = cc;
            (m, s, f)
        }
        None => (None, None, None),
    };
    let (verdict, reasons) = nvme_verdict(&h);
    Some(SmartReport {
        dev: dev.into(),
        kind: "nvme".into(),
        verdict: verdict.into(),
        reasons,
        temperature_c: Some(h.temperature_c),
        power_on_hours: Some(h.power_on_hours),
        nvme: Some(h),
        model,
        serial,
        firmware,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------------------------------------------
// ATA

/// Attribute names (smartmontools naming) for the ids that matter for health.
pub fn ata_attr_name(id: u8) -> &'static str {
    match id {
        1 => "Raw_Read_Error_Rate",
        3 => "Spin_Up_Time",
        4 => "Start_Stop_Count",
        5 => "Reallocated_Sector_Ct",
        7 => "Seek_Error_Rate",
        9 => "Power_On_Hours",
        10 => "Spin_Retry_Count",
        12 => "Power_Cycle_Count",
        170 => "Available_Reservd_Space",
        173 => "Wear_Leveling_Count",
        174 => "Unexpected_Power_Loss_Ct",
        175 => "Program_Fail_Count_Chip",
        176 => "Erase_Fail_Count_Chip",
        177 => "Wear_Leveling_Count",
        178 => "Used_Rsvd_Blk_Cnt_Chip",
        179 => "Used_Rsvd_Blk_Cnt_Tot",
        180 => "Unused_Rsvd_Blk_Cnt_Tot",
        181 => "Program_Fail_Cnt_Total",
        182 => "Erase_Fail_Count_Total",
        183 => "Runtime_Bad_Block",
        184 => "End-to-End_Error",
        187 => "Reported_Uncorrect",
        188 => "Command_Timeout",
        189 => "High_Fly_Writes",
        190 => "Airflow_Temperature_Cel",
        191 => "G-Sense_Error_Rate",
        192 => "Power-Off_Retract_Count",
        193 => "Load_Cycle_Count",
        194 => "Temperature_Celsius",
        195 => "Hardware_ECC_Recovered",
        196 => "Reallocated_Event_Count",
        197 => "Current_Pending_Sector",
        198 => "Offline_Uncorrectable",
        199 => "UDMA_CRC_Error_Count",
        202 => "Percent_Lifetime_Remain",
        206 => "Flying_Height",
        231 => "SSD_Life_Left",
        232 => "Available_Reservd_Space",
        233 => "Media_Wearout_Indicator",
        234 => "Thermal_Throttle_Status",
        241 => "Total_LBAs_Written",
        242 => "Total_LBAs_Read",
        245 => "Flash_Writes_GiB",
        _ => "Unknown_Attribute",
    }
}

/// SMART READ DATA (512 bytes): 30 entries of 12 bytes from offset 2: id, flags(2), value, worst, raw(6), reserved.
/// `thresholds` is the SMART READ THRESHOLDS page (entries of id + threshold byte at the same offsets).
pub fn parse_ata_attrs(data: &[u8], thresholds: Option<&[u8]>) -> Vec<SmartAttr> {
    let mut v = Vec::new();
    if data.len() < 362 {
        return v;
    }
    for i in 0..30 {
        let o = 2 + i * 12;
        let id = data[o];
        if id == 0 {
            continue;
        }
        let (value, worst) = (data[o + 3], data[o + 4]);
        let mut raw = 0u64;
        for k in 0..6 {
            raw |= (data[o + 5 + k] as u64) << (8 * k);
        }
        let thresh = thresholds.filter(|t| t.len() >= o + 2).and_then(|t| (t[o] == id).then_some(t[o + 1])).unwrap_or(0);
        // "failing now": normalised value at or below a non-zero threshold (0xfe/0xff thresholds are never met)
        let failing_now = thresh > 0 && thresh < 0xfe && value <= thresh;
        v.push(SmartAttr { id, name: ata_attr_name(id).to_string(), value, worst, thresh, raw, failing_now });
    }
    v
}

/// The two LBA bytes the drive answered SMART RETURN STATUS with, from the ATA Status Return descriptor (0x09) in
/// descriptor-format sense data: (0x4f, 0xc2) = threshold not exceeded, (0xf4, 0x2c) = exceeded.
pub fn ata_return_status(sense: &[u8]) -> Option<bool> {
    if sense.len() < 8 || !matches!(sense[0] & 0x7f, 0x72 | 0x73) {
        return None;
    }
    let mut o = 8;
    while o + 2 <= sense.len() {
        let (code, len) = (sense[o], sense[o + 1] as usize);
        if code == 0x09 && len >= 0x0c && o + 14 <= sense.len() {
            return match (sense[o + 9], sense[o + 11]) {
                (0x4f, 0xc2) => Some(true),
                (0xf4, 0x2c) => Some(false),
                _ => None,
            };
        }
        o += 2 + len;
    }
    None
}

/// ATA PASS-THROUGH(16) CDB for a SMART subcommand. `data_in`: one 512-byte PIO data-in sector (sector count 1)
/// or no data. `ck_cond` asks for the register values back in the sense data (needed for RETURN STATUS).
pub fn ata_cdb(feature: u8, data_in: bool, ck_cond: bool) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = 0x85;
    c[1] = if data_in { 4 << 1 } else { 3 << 1 }; // PIO data-in / non-data
    c[2] = (u8::from(ck_cond) << 5) | if data_in { (1 << 3) | (1 << 2) | 2 } else { 0 }; // T_DIR in, BYTE_BLOCK, T_LENGTH = sector count
    c[4] = feature;
    c[6] = u8::from(data_in); // sector count
    c[10] = 0x4f; // LBA mid: SMART signature
    c[12] = 0xc2; // LBA high
    c[14] = 0xb0; // SMART
    c
}

pub const SMART_READ_DATA: u8 = 0xd0;
pub const SMART_READ_THRESHOLDS: u8 = 0xd1;
pub const SMART_RETURN_STATUS: u8 = 0xda;

/// Verdict and reasons for a SATA/USB-SAT disk. `status` is the RETURN STATUS answer (`Some(false)` = the drive
/// itself says a threshold is exceeded).
pub fn ata_verdict(attrs: &[SmartAttr], status: Option<bool>) -> (&'static str, Vec<String>) {
    let mut fail = Vec::new();
    let mut warn = Vec::new();
    if status == Some(false) {
        fail.push("drive reports SMART threshold exceeded (RETURN STATUS)".to_string());
    }
    for a in attrs {
        if a.failing_now {
            fail.push(format!("{} (id {}) value {} at or below threshold {}", a.name, a.id, a.value, a.thresh));
        }
        let raw16 = a.raw & 0xffff_ffff;
        match a.id {
            5 | 196 if raw16 > 0 => warn.push(format!("{} {}", a.name, raw16)),
            187 | 197 | 198 if raw16 > 0 => warn.push(format!("{} {}", a.name, raw16)),
            // normalised remaining-life counters count down from 100
            177 | 202 | 231 | 233 if a.value <= 10 && a.value > 0 && !a.failing_now => warn.push(format!("{} {}% left", a.name, a.value)),
            _ => {}
        }
    }
    if let Some(t) = ata_temperature(attrs) {
        if t >= 70.0 {
            warn.push(format!("temperature {:.0} C", t));
        }
    }
    if !fail.is_empty() {
        fail.extend(warn);
        ("fail", fail)
    } else if !warn.is_empty() {
        ("warn", warn)
    } else if status.is_none() && attrs.is_empty() {
        ("unknown", vec!["no SMART data".to_string()])
    } else {
        ("pass", Vec::new())
    }
}

fn ata_temperature(attrs: &[SmartAttr]) -> Option<f64> {
    attrs.iter().find(|a| a.id == 194).or_else(|| attrs.iter().find(|a| a.id == 190)).map(|a| (a.raw & 0xff) as f64)
}

pub fn ata_report(dev: &str, attrs: Vec<SmartAttr>, status: Option<bool>) -> SmartReport {
    let (verdict, reasons) = ata_verdict(&attrs, status);
    SmartReport {
        dev: dev.into(),
        kind: "ata".into(),
        verdict: verdict.into(),
        reasons,
        temperature_c: ata_temperature(&attrs),
        power_on_hours: attrs.iter().find(|a| a.id == 9).map(|a| a.raw & 0xffff_ffff),
        attrs,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// live probing

fn unsupported(dev: &str, why: &str) -> SmartReport {
    SmartReport { dev: dev.into(), kind: "unsupported".into(), verdict: "unknown".into(), reasons: vec![why.to_string()], ..Default::default() }
}

fn nvme_live(dev: &str) -> Result<SmartReport, ProbeError> {
    use super::ioctl::{self, AlignedBuf};
    let f = ioctl::open(std::path::Path::new(&format!("/dev/{}", dev)), false, false, false)?;
    let mut id = AlignedBuf::new(4096);
    let identify = ioctl::nvme_admin_read(&f, 0x06, 0, 1, &mut id, 4096).map(|st| st == 0).unwrap_or(false);
    let mut log = AlignedBuf::new(4096);
    // Get Log Page 0x02, NSID 0xffffffff (controller-wide), NUMD = 512/4 - 1
    let st = ioctl::nvme_admin_read(&f, 0x02, 0xffff_ffff, (127 << 16) | 0x02, &mut log, 512)?;
    if st != 0 {
        return Ok(SmartReport { dev: dev.into(), kind: "nvme".into(), verdict: "unknown".into(), reasons: vec![format!("Get Log Page failed, NVMe status 0x{:x}", st)], ..Default::default() });
    }
    nvme_report(dev, identify.then(|| &id.as_slice()[..4096]), &log.as_slice()[..512]).ok_or_else(|| ProbeError::Parse("short SMART log".into()))
}

/// One SMART subcommand through SAT. `Ok(None)` = the device or bridge did not answer.
fn ata_cmd(f: &std::fs::File, feature: u8, data_in: bool) -> Option<(Vec<u8>, super::ioctl::SgResult)> {
    let cdb = ata_cdb(feature, data_in, !data_in);
    let mut buf = vec![0u8; if data_in { 512 } else { 0 }];
    let r = super::ioctl::sg_io(f, &cdb, if data_in { Some(&mut buf[..]) } else { None }, 5000).ok()?;
    if r.host_status != 0 {
        return None;
    }
    if data_in && r.status != 0 {
        return None;
    }
    Some((buf, r))
}

fn ata_live(dev: &str, usb: bool) -> Result<SmartReport, ProbeError> {
    let f = super::ioctl::open(std::path::Path::new(&format!("/dev/{}", dev)), false, false, false)?;
    let data = ata_cmd(&f, SMART_READ_DATA, true);
    let Some((data, _)) = data else {
        let kind = if usb { "usb-bridge" } else { "ata" };
        let why = if usb { "not available (bridge)" } else { "SMART READ DATA failed (SMART disabled or not supported)" };
        return Ok(SmartReport { dev: dev.into(), kind: kind.into(), verdict: "unknown".into(), reasons: vec![why.to_string()], ..Default::default() });
    };
    let thr = ata_cmd(&f, SMART_READ_THRESHOLDS, true).map(|x| x.0);
    let status = ata_cmd(&f, SMART_RETURN_STATUS, false).and_then(|(_, r)| ata_return_status(&r.sense));
    Ok(ata_report(dev, parse_ata_attrs(&data, thr.as_deref()), status))
}

pub fn probe(ctx: &ProbeCtx, dev: &str) -> Result<SmartReport, ProbeError> {
    if !super::valid_dev_name(dev) {
        return Err(ProbeError::NotFound(dev.to_string()));
    }
    // fixtures and unprivileged runs have no device nodes to ask
    if ctx.root != std::path::Path::new("/") || !ctx.privileged {
        return Ok(unsupported(dev, "SMART needs the live system and root"));
    }
    let real = super::enumerate::real_sys_path(ctx, &format!("/sys/block/{}", dev));
    let kind = real.as_deref().and_then(super::enumerate::kind_from_path).unwrap_or_else(|| super::enumerate::kind_of(dev));
    use super::DiskKind::*;
    let r = match kind {
        Nvme => nvme_live(dev),
        Sata | Scsi => ata_live(dev, false),
        Usb => ata_live(dev, true),
        Virtio | Mmc | Other => return Ok(unsupported(dev, "no SMART on this kind of device")),
    };
    match r {
        Ok(rep) => Ok(rep),
        Err(ProbeError::Io(e)) => Ok(SmartReport { dev: dev.into(), kind: kind.name().into(), verdict: "unknown".into(), reasons: vec![format!("cannot ask the device: {}", e)], ..Default::default() }),
        Err(e) => Err(e),
    }
}

pub fn probe_all(ctx: &ProbeCtx) -> Result<SmartAll, ProbeError> {
    let disks = super::enumerate::enumerate(ctx, false)?;
    let devices = disks.devices.iter().filter_map(|d| probe(ctx, &d.name).ok()).collect();
    Ok(SmartAll { devices })
}

/// SMART verdicts for the `smart` field of `blk ls`: only the live root, only NVMe and SATA (a USB bridge can
/// stall for seconds, so USB disks are asked by `blk smart` only), cached for a minute so a refreshing console
/// does not hammer the drives.
pub fn verdicts(ctx: &ProbeCtx, devices: &[super::BlockDevice]) -> Vec<(String, String)> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static CACHE: Mutex<Vec<(String, Instant, String)>> = Mutex::new(Vec::new());
    if ctx.root != std::path::Path::new("/") || !ctx.privileged {
        return Vec::new();
    }
    let mut out = Vec::new();
    for d in devices.iter().filter(|d| matches!(d.kind, super::DiskKind::Nvme | super::DiskKind::Sata)) {
        let cached = CACHE.lock().ok().and_then(|c| c.iter().find(|(n, t, _)| *n == d.name && t.elapsed() < Duration::from_secs(60)).map(|(_, _, v)| v.clone()));
        let v = match cached {
            Some(v) => v,
            None => {
                let v = probe(ctx, &d.name).map(|r| r.verdict).unwrap_or_else(|_| "unknown".into());
                if let Ok(mut c) = CACHE.lock() {
                    c.retain(|(n, _, _)| *n != d.name);
                    c.push((d.name.clone(), Instant::now(), v.clone()));
                }
                v
            }
        };
        out.push((d.name.clone(), v));
    }
    out
}

impl ToJson for SmartReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str("dev", &self.dev);
        w.field_str("kind", &self.kind);
        w.field_str("verdict", &self.verdict);
        w.key("reasons");
        w.value(&self.reasons);
        w.field_opt_f64("temperature_c", self.temperature_c);
        w.field_opt_u64("power_on_hours", self.power_on_hours);
        w.field_opt_str("model", self.model.as_deref());
        w.field_opt_str("serial", self.serial.as_deref());
        w.field_opt_str("firmware", self.firmware.as_deref());
        w.key("attrs");
        w.begin_array();
        for a in &self.attrs {
            w.begin_object();
            w.field_u64("id", a.id as u64);
            w.field_str("name", &a.name);
            w.field_u64("value", a.value as u64);
            w.field_u64("worst", a.worst as u64);
            w.field_u64("thresh", a.thresh as u64);
            w.field_u64("raw", a.raw);
            w.field_bool("failing_now", a.failing_now);
            w.end_object();
        }
        w.end_array();
        w.key("nvme");
        match &self.nvme {
            None => w.null(),
            Some(n) => {
                w.begin_object();
                w.field_u64("critical_warning", n.critical_warning as u64);
                w.field_f64("temperature_c", n.temperature_c);
                w.field_u64("available_spare", n.available_spare as u64);
                w.field_u64("percentage_used", n.percentage_used as u64);
                w.field_u64("data_units_read", n.data_units_read);
                w.field_u64("data_units_written", n.data_units_written);
                w.field_u64("power_cycles", n.power_cycles);
                w.field_u64("power_on_hours", n.power_on_hours);
                w.field_u64("unsafe_shutdowns", n.unsafe_shutdowns);
                w.field_u64("media_errors", n.media_errors);
                w.field_u64("error_log_entries", n.error_log_entries);
                w.field_u64("spare_threshold", n.spare_threshold as u64);
                w.field_opt_f64("warning_temp_c", n.warning_temp_c);
                w.field_opt_f64("critical_temp_c", n.critical_temp_c);
                w.field_u64("data_read_bytes", n.data_units_read.saturating_mul(512_000));
                w.field_u64("data_written_bytes", n.data_units_written.saturating_mul(512_000));
                w.end_object();
            }
        }
        w.end_object();
    }
}

impl ToJson for SmartAll {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("devices");
        w.value(&self.devices);
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded-format buffer from tests/fixtures/smart/<name> (hex bytes, `#` comment lines).
    fn buf(name: &str) -> Vec<u8> {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smart").join(name);
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .flat_map(|l| l.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect::<Vec<_>>())
            .collect()
    }

    #[test]
    fn nvme_identify_fields() {
        let (model, serial, fw, wc, cc) = parse_nvme_identify(&buf("nvme-identify.hex")).unwrap();
        assert_eq!(model.as_deref(), Some("WD Green SN3000 500GB"));
        assert_eq!(serial.as_deref(), Some("TESTSER00001"));
        assert_eq!(fw.as_deref(), Some("FIXT0001"));
        assert_eq!((wc, cc), (Some(85.0), Some(90.0)));
        assert!(parse_nvme_identify(&[0; 100]).is_none());
    }

    #[test]
    fn nvme_healthy_log() {
        let r = nvme_report("nvme0n1", Some(&buf("nvme-identify.hex")), &buf("nvme-log02-healthy.hex")).unwrap();
        assert_eq!((r.kind.as_str(), r.verdict.as_str()), ("nvme", "pass"));
        assert!(r.reasons.is_empty(), "{:?}", r.reasons);
        let h = r.nvme.unwrap();
        assert_eq!(h.critical_warning, 0);
        assert_eq!(h.temperature_c, 38.0);
        assert_eq!((h.available_spare, h.spare_threshold, h.percentage_used), (100, 10, 1));
        assert_eq!((h.data_units_read, h.data_units_written), (1_234_567, 2_345_678));
        assert_eq!((h.power_cycles, h.power_on_hours, h.unsafe_shutdowns, h.media_errors, h.error_log_entries), (312, 1034, 21, 0, 0));
        assert_eq!(r.power_on_hours, Some(1034));
        assert_eq!(r.model.as_deref(), Some("WD Green SN3000 500GB"));
    }

    #[test]
    fn nvme_failing_log_fails() {
        let r = nvme_report("nvme1n1", None, &buf("nvme-log02-failing.hex")).unwrap();
        assert_eq!(r.verdict, "fail");
        let all = r.reasons.join("|");
        assert!(all.contains("available spare below threshold") && all.contains("reliability degraded") && all.contains("17 media") && all.contains("endurance used 103%"), "{}", all);
    }

    #[test]
    fn nvme_temperature_and_media_errors_warn_or_fail() {
        let mut h = parse_nvme_log(&buf("nvme-log02-healthy.hex")).unwrap();
        h.warning_temp_c = Some(85.0);
        h.critical_temp_c = Some(90.0);
        h.temperature_c = 86.0;
        assert_eq!(nvme_verdict(&h).0, "warn");
        h.temperature_c = 91.0;
        assert_eq!(nvme_verdict(&h).0, "fail");
        h.temperature_c = 40.0;
        h.media_errors = 1;
        assert_eq!(nvme_verdict(&h).0, "warn");
        assert!(parse_nvme_log(&[0; 10]).is_none());
    }

    #[test]
    fn ata_healthy_attributes() {
        let a = parse_ata_attrs(&buf("ata-smart-data-healthy.hex"), Some(&buf("ata-smart-thresholds.hex")));
        assert_eq!(a.len(), 9);
        let by = |id: u8| a.iter().find(|x| x.id == id).unwrap();
        assert_eq!((by(5).name.as_str(), by(5).thresh, by(5).raw), ("Reallocated_Sector_Ct", 10, 0));
        assert_eq!(by(9).raw, 20000);
        assert_eq!(by(177).thresh, 5);
        let r = ata_report("sda", a, Some(true));
        assert_eq!((r.kind.as_str(), r.verdict.as_str()), ("ata", "pass"));
        assert_eq!(r.temperature_c, Some(36.0));
        assert_eq!(r.power_on_hours, Some(20000));
    }

    #[test]
    fn ata_failing_attributes() {
        let a = parse_ata_attrs(&buf("ata-smart-data-failing.hex"), Some(&buf("ata-smart-thresholds-failing.hex")));
        assert!(a.iter().find(|x| x.id == 5).unwrap().failing_now);
        let r = ata_report("sdb", a.clone(), Some(true));
        assert_eq!(r.verdict, "fail");
        assert!(r.reasons.iter().any(|x| x.contains("Reallocated_Sector_Ct") && x.contains("threshold 36")), "{:?}", r.reasons);
        assert!(r.reasons.iter().any(|x| x.contains("Current_Pending_Sector 5")), "{:?}", r.reasons);
        // the drive's own verdict alone fails an otherwise clean attribute table
        let clean = parse_ata_attrs(&buf("ata-smart-data-healthy.hex"), None);
        assert_eq!(ata_report("sdc", clean.clone(), Some(false)).verdict, "fail");
        // without thresholds a non-zero pending count only warns
        let nothr = parse_ata_attrs(&buf("ata-smart-data-failing.hex"), None);
        assert_eq!(ata_report("sdb", nothr, None).verdict, "warn");
        assert_eq!(ata_verdict(&[], None).0, "unknown");
    }

    #[test]
    fn ata_return_status_from_sense() {
        assert_eq!(ata_return_status(&buf("ata-sense-return-status-ok.hex")), Some(true));
        assert_eq!(ata_return_status(&buf("ata-sense-return-status-exceeded.hex")), Some(false));
        assert_eq!(ata_return_status(&[0x70; 18]), None); // fixed format has no register block
        assert_eq!(ata_return_status(&[]), None);
    }

    #[test]
    fn sat_cdbs() {
        // SMART READ DATA: PIO data-in, T_DIR=in BYTE_BLOCK=1 T_LENGTH=2 (sector count), one sector, 4f/c2, command b0
        assert_eq!(ata_cdb(SMART_READ_DATA, true, false), [0x85, 0x08, 0x0e, 0, 0xd0, 0, 1, 0, 0, 0, 0x4f, 0, 0xc2, 0, 0xb0, 0]);
        // RETURN STATUS: non-data, CK_COND set so the registers come back in the sense data
        assert_eq!(ata_cdb(SMART_RETURN_STATUS, false, true), [0x85, 0x06, 0x20, 0, 0xda, 0, 0, 0, 0, 0, 0x4f, 0, 0xc2, 0, 0xb0, 0]);
    }

    #[test]
    fn fixture_and_unprivileged_runs_report_unsupported_not_garbage() {
        let ctx = ProbeCtx::fixture("/nonexistent");
        let r = probe(&ctx, "nvme0n1").unwrap();
        assert_eq!((r.kind.as_str(), r.verdict.as_str()), ("unsupported", "unknown"));
        assert!(probe(&ctx, "../etc").is_err());
        assert!(verdicts(&ctx, &[]).is_empty());
    }
}
