//! labproto: the shared foundation of i7lablinux.
//!
//! Pure protocol code (crypto, JSON, sanitiser, keys, catalogue, argv codec, frame codec, handshake,
//! replay window, reliability, beacon, HTTP auth) plus the Linux plumbing every binary needs
//! (`sys` hand-written libc FFI, `packet` AF_PACKET, `link` frame transports).
//! Contracts: docs/PLAN.md section 4.1. Wire format: docs/PROTOCOL.md.
//! Owners: P1 (pure modules incl. `session`, `local`), P2 (`sys`, `packet`, `link`, `netlink`, `cmdline`).

pub mod args;
pub mod beacon;
pub mod catalog;
pub mod cmdline;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod httpauth;
pub mod json;
pub mod keys;
pub mod local;
pub mod link;
pub mod mac;
pub mod msgs;
pub mod netlink;
pub mod packet;
pub mod reliable;
pub mod replay;
pub mod session;
pub mod status;
pub mod sys;
pub mod text;

pub use mac::Mac;
pub use status::Status;

/// Project version string shared by all binaries.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
