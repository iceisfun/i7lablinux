//! Block devices: enumeration, partition tables, signatures, write gate, test engine, SMART. Owner: P4.
//! Safety model: docs/PLAN.md section 6. `WriteGuard::acquire` is the ONLY way to get a writable handle to a
//! block device anywhere in this workspace.

pub mod enumerate;
pub mod guard;
pub mod image;
pub mod ioctl;
pub mod parttable;
pub mod signatures;
pub mod smart;
pub mod test;

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

pub use guard::{assess, audit_write, decide, Reason, Refusal, Verdict, WriteGuard, WriteRequest, WriteSafety, AUDIT_LOG, LOCK_DIR};
pub use parttable::{PartTable, Partition};
pub use signatures::Signature;
pub use test::{run_test, Pattern, Progress, Region, RegionResult, TestMode, TestReport, TestSpec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskKind {
    Nvme,
    Sata,
    Scsi,
    Usb,
    Virtio,
    Mmc,
    Other,
}

impl DiskKind {
    pub fn name(self) -> &'static str {
        match self {
            DiskKind::Nvme => "nvme",
            DiskKind::Sata => "sata",
            DiskKind::Scsi => "scsi",
            DiskKind::Usb => "usb",
            DiskKind::Virtio => "virtio",
            DiskKind::Mmc => "mmc",
            DiskKind::Other => "other",
        }
    }
}

/// Where `BlockDevice::serial` came from (review feasibility F23). Resolution order: NVMe `device/serial`
/// (trimmed; NVMe pads to 20), virtio `serial`, SCSI VPD page 0x80 (trimmed), ATA IDENTIFY via SAT, the iSerial
/// of the ancestor USB device. WWID stays a separate field (used for confirmation only when no serial exists).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialSource {
    Nvme,
    Virtio,
    Vpd80,
    Ata,
    Usb,
    Mmc,
}

impl SerialSource {
    pub fn name(self) -> &'static str {
        match self {
            SerialSource::Nvme => "nvme",
            SerialSource::Virtio => "virtio",
            SerialSource::Vpd80 => "vpd80",
            SerialSource::Ata => "ata",
            SerialSource::Usb => "usb",
            SerialSource::Mmc => "mmc",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockDevice {
    pub name: String,
    pub devno: (u32, u32),
    pub size_bytes: u64,
    pub logical_block: u32,
    pub physical_block: u32,
    pub kind: DiskKind,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
    pub serial_source: Option<SerialSource>,
    pub wwid: Option<String>,
    pub firmware_rev: Option<String>,
    pub rotational: bool,
    pub removable: bool,
    pub read_only: bool,
    pub partition_table: Option<PartTable>,
    pub partitions: Vec<Partition>,
    pub signatures: Vec<Signature>,
    /// mount points of the disk or any partition
    pub mounts: Vec<String>,
    /// holders (md, dm), swap users
    pub holders: Vec<String>,
    /// the disk or one of its partitions is an active swap area
    pub swap: bool,
    pub boot_media: bool,
    pub write_safety: WriteSafety,
}

#[derive(Clone, Debug, Default)]
pub struct BlockReport {
    pub devices: Vec<BlockDevice>,
    /// (device name, SMART verdict "pass" | "warn" | "fail" | "unknown") for the disks `probe` could ask; filled by
    /// `probe` on the live root only (never by `enumerate`), cached for a minute. Shown as the `smart` field of a device.
    pub smart: Vec<(String, String)>,
}

/// Find the whole disk carrying `partuuid` (GPT unique GUID, or `<MBR signature>-<nn>`), once at daemon start; the
/// result goes into `ProbeCtx::boot_disk`. Scans the partition tables (no udev, so no /dev/disk/by-partuuid).
pub fn resolve_boot_disk(ctx: &ProbeCtx, partuuid: &str) -> Option<(u32, u32)> {
    enumerate::resolve_boot_disk(ctx, partuuid)
}

/// Parse a GPT from LBA 0..=1 (+ entries when present) at `block` bytes per sector.
pub fn parse_gpt(lba0_1: &[u8], block: u32) -> Option<PartTable> {
    parttable::parse(lba0_1, block).map(|x| x.0).filter(|t| t.kind == "gpt")
}

/// Signatures in the first bytes of a device or partition (offsets relative to the buffer).
pub fn detect_signatures(head: &[u8]) -> Vec<Signature> {
    signatures::detect(head)
}

/// Enumerate /sys/block (skip loop/ram/zram/dm unless `all`).
pub fn probe(ctx: &ProbeCtx, all: bool) -> Result<BlockReport, ProbeError> {
    let mut rep = enumerate::enumerate(ctx, all)?;
    if !all {
        rep.smart = smart::verdicts(ctx, &rep.devices);
    }
    Ok(rep)
}

/// Device names accepted from callers: `[A-Za-z0-9_-]{1,32}`, no slashes or dots (prior-art rule).
pub fn valid_dev_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl BlockDevice {
    /// The JSON object of this disk with the SMART verdict (`None` = not asked / not available) as `smart`.
    pub fn write_json_smart(&self, w: &mut JsonWriter, smart: Option<&str>) {
        w.begin_object();
        w.field_str("name", &self.name);
        w.field_str("devno", &format!("{}:{}", self.devno.0, self.devno.1));
        w.field_u64("size_bytes", self.size_bytes);
        w.field_u64("logical_block", self.logical_block as u64);
        w.field_u64("physical_block", self.physical_block as u64);
        w.field_str("kind", self.kind.name());
        w.field_opt_str("model", self.model.as_deref());
        w.field_opt_str("vendor", self.vendor.as_deref());
        w.field_opt_str("serial", self.serial.as_deref());
        w.field_opt_str("serial_source", self.serial_source.map(SerialSource::name));
        w.field_opt_str("wwid", self.wwid.as_deref());
        w.field_opt_str("firmware_rev", self.firmware_rev.as_deref());
        w.field_bool("rotational", self.rotational);
        w.field_bool("removable", self.removable);
        w.field_bool("read_only", self.read_only);
        w.key("partition_table");
        match &self.partition_table {
            Some(t) => t.write_json(w),
            None => w.null(),
        }
        w.key("partitions");
        w.value(&self.partitions);
        w.key("signatures");
        w.value(&self.signatures);
        w.key("mounts");
        w.value(&self.mounts);
        w.key("holders");
        w.value(&self.holders);
        w.field_bool("swap", self.swap);
        w.field_bool("boot_media", self.boot_media);
        w.key("write_safety");
        self.write_safety.write_json(w);
        w.field_opt_str("smart", smart);
        w.end_object();
    }
}

impl ToJson for BlockDevice {
    fn write_json(&self, w: &mut JsonWriter) {
        self.write_json_smart(w, None);
    }
}

impl ToJson for BlockReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("devices");
        w.begin_array();
        for d in &self.devices {
            let v = self.smart.iter().find(|(n, _)| *n == d.name).map(|(_, v)| v.as_str());
            d.write_json_smart(w, v);
        }
        w.end_array();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dev_names() {
        assert!(super::valid_dev_name("nvme0n1"));
        assert!(!super::valid_dev_name("../sda"));
        assert!(!super::valid_dev_name("sda.1"));
        assert!(!super::valid_dev_name(""));
    }
}
