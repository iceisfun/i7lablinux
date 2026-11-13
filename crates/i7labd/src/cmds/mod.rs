//! Command handlers, one module per catalogue group. Owner: P6 (P5 owns nothing here; console actions call
//! these through `Registry::dispatch`). Add a handler by adding `(name, fn)` to the module's `TABLE`.

use crate::registry::Handler;

pub mod blk;
pub mod console;
pub mod core;
pub mod exec;
pub mod files;
pub mod jobs;
pub mod keys;
pub mod logs;
pub mod net;
pub mod power;
pub mod probe;
pub mod svc;

pub fn handler_for(name: &str) -> Option<Handler> {
    [
        core::TABLE, probe::TABLE, blk::TABLE, net::TABLE, exec::TABLE, files::TABLE, power::TABLE, svc::TABLE,
        logs::TABLE, console::TABLE, keys::TABLE, jobs::TABLE,
    ]
    .iter()
    .flat_map(|t| t.iter())
    .find(|(n, _)| *n == name)
    .map(|(_, h)| *h)
}

/// Parse options or return BAD_ARGS.
#[macro_export]
macro_rules! opts_or_bad {
    ($ctx:expr, $flags:expr, $valued:expr) => {
        match labproto::args::Opts::parse(&$ctx.args, $flags, $valued) {
            Ok(o) => o,
            Err(e) => return $crate::registry::Reply::error(labproto::Status::BadArgs, &e.to_string()),
        }
    };
}
