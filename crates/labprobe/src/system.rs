//! system: kernel, hostname, uptime, load, boot id, boot mode, image build. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub kernel: String,
    pub cmdline: String,
    pub uptime_s: f64,
    pub load: [f64; 3],
    pub boot_id: String,
    /// "uefi" or "bios"
    pub boot_mode: String,
    /// contents of /etc/i7lab/BUILD first line, if present
    pub image_build: Option<String>,
}

pub fn probe(ctx: &ProbeCtx) -> Result<SystemInfo, ProbeError> {
    let uptime = ctx.read_trim("/proc/uptime").unwrap_or_default();
    let load = ctx.read_trim("/proc/loadavg").unwrap_or_default();
    let mut l = load.split_whitespace().map(|x| x.parse().unwrap_or(0.0));
    Ok(SystemInfo {
        hostname: ctx.read_trim("/proc/sys/kernel/hostname").unwrap_or_default(),
        kernel: ctx.read_trim("/proc/sys/kernel/osrelease").unwrap_or_default(),
        cmdline: ctx.read_trim("/proc/cmdline").unwrap_or_default(),
        uptime_s: uptime.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0),
        load: [l.next().unwrap_or(0.0), l.next().unwrap_or(0.0), l.next().unwrap_or(0.0)],
        boot_id: ctx.read_trim("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
        boot_mode: if ctx.path("/sys/firmware/efi").exists() { "uefi" } else { "bios" }.into(),
        image_build: ctx.read_opt("/etc/i7lab/BUILD").and_then(|s| s.lines().next().map(str::to_string)),
    })
}

impl ToJson for SystemInfo {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_str("hostname", &self.hostname);
        w.field_str("kernel", &self.kernel);
        w.field_str("cmdline", &self.cmdline);
        w.field_f64("uptime_s", self.uptime_s);
        w.key("load");
        w.begin_array();
        for x in self.load {
            w.f64(x);
        }
        w.end_array();
        w.field_str("boot_id", &self.boot_id);
        w.field_str("boot_mode", &self.boot_mode);
        w.field_opt_str("image_build", self.image_build.as_deref());
        w.end_object();
    }
}
