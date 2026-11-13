//! i7labd: the on-host agent. One command registry (`registry`) is called by every front end:
//! ether server (`ether`), HTTP API (`http`), console TUI (`console`) and the local socket (`localsock`).
//! Contracts: docs/PLAN.md section 4.4. Owners: P6a (core), P6b (ether, beacon, net), P7 (http, web), P5 (console).

pub mod audit;
pub mod beacon;
pub mod cmds;
pub mod config;
pub mod console;
pub mod daemon;
pub mod dhcp;
pub mod events;
pub mod ether;
pub mod exec;
pub mod ffi;
pub mod http;
pub mod httpwire;
pub mod jobs;
pub mod limits;
pub mod localsock;
pub mod logring;
pub mod netcfg;
pub mod registry;
pub mod snapshot;
pub mod web;

pub use daemon::{run, Daemon, HostState, KeyPolicy};
pub use events::{Event, EventBus, Snapshot, Snapshots};
pub use registry::{Command, Content, Ctx, Handler, Registry, Reply, Sink, Source};
