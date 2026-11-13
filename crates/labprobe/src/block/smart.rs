//! SMART: ATA PASS-THROUGH(16) via SG_IO, NVMe admin (Identify, Get Log Page 0x02). Owner: P4.

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
}

#[derive(Clone, Debug, Default)]
pub struct SmartReport {
    pub dev: String,
    /// "ata" | "nvme" | "unsupported"
    pub kind: String,
    /// "pass" | "warn" | "fail" | "unknown"
    pub verdict: String,
    pub reasons: Vec<String>,
    pub temperature_c: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub attrs: Vec<SmartAttr>,
    pub nvme: Option<NvmeHealth>,
}

#[derive(Clone, Debug, Default)]
pub struct SmartAll {
    pub devices: Vec<SmartReport>,
}

pub fn probe(_ctx: &ProbeCtx, dev: &str) -> Result<SmartReport, ProbeError> {
    if !super::valid_dev_name(dev) {
        return Err(ProbeError::NotFound(dev.to_string()));
    }
    // STUB(P4)
    Ok(SmartReport { dev: dev.into(), kind: "unsupported".into(), verdict: "unknown".into(), ..Default::default() })
}

pub fn probe_all(ctx: &ProbeCtx) -> Result<SmartAll, ProbeError> {
    let disks = super::probe(ctx, false)?;
    let devices = disks.devices.iter().filter_map(|d| probe(ctx, &d.name).ok()).collect();
    Ok(SmartAll { devices })
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
