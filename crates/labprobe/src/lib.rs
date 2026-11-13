//! labprobe: typed hardware probes with a stable JSON schema, block enumeration, the block write gate and the
//! block test engine. Contracts: docs/PLAN.md sections 4.2 and 6. Details: docs/PROBES.md.
//! Owners: P3 (probes), P4 (`block`).
//!
//! JSON rules: every top-level report has `"v":1`; keys are the Rust field names; units in the key suffix;
//! unknown values are `null`; arrays are never null. Strings are raw (sanitise at display time).

pub mod block;
pub mod cpu;
pub mod ctx;
pub mod dmi;
pub mod firmware;
pub mod gpu;
pub mod inventory;
pub mod kmsg;
pub mod mem;
pub mod net;
pub mod pci;
pub mod pciids;
pub mod serial;
pub mod system;
pub mod thermal;
pub mod usb;
pub mod usbids;

pub use ctx::{ProbeCtx, ProbeError};
pub use inventory::{inventory, Inventory, Section};

/// Schema version written as `"v"` in every top-level report.
pub const SCHEMA_V: u64 = 1;
