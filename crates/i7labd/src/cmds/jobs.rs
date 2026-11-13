//! jobs [ls | kill ID [--force] | out ID [-n BYTES]]: detached `exec --detach` jobs.

use labproto::json::JsonWriter;
use labproto::Status;

use crate::jobs::output_path;
use crate::registry::{Content, Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("jobs", jobs)];

const OUT_DEFAULT: u64 = 64 * 1024;
const OUT_MAX: u64 = 4 << 20;

fn parse_id(s: Option<&String>) -> Result<u32, Reply> {
    s.and_then(|x| x.parse().ok()).ok_or_else(|| Reply::error(Status::BadArgs, "usage: jobs [ls | kill ID | out ID]"))
}

fn jobs(ctx: &mut Ctx) -> Reply {
    let o = crate::opts_or_bad!(ctx, &["force"], &["n"]);
    let pos = o.positional();
    match pos.first().map(String::as_str).unwrap_or("ls") {
        "ls" => {
            let mut w = JsonWriter::new();
            w.begin_object();
            w.field_u64("v", 1);
            w.key("jobs");
            w.begin_array();
            for j in ctx.daemon.jobs.snapshot() {
                w.begin_object();
                w.field_u64("id", j.id as u64);
                w.field_str("cmd", &j.cmd);
                w.field_str("state", &j.state);
                match j.exit_code {
                    Some(c) => w.field_i64("exit", c as i64),
                    None => {
                        w.key("exit");
                        w.null();
                    }
                }
                w.field_u64("started_unix", j.started_unix);
                w.end_object();
            }
            w.end_array();
            w.end_object();
            Reply::json(w.finish())
        }
        "kill" => {
            let id = match parse_id(pos.get(1)) {
                Ok(i) => i,
                Err(r) => return r,
            };
            match ctx.daemon.jobs.kill(id, o.flag("force")) {
                Ok(()) => Reply::ok_empty(),
                Err(e) => Reply::error(Status::NotFound, e),
            }
        }
        "out" => {
            let id = match parse_id(pos.get(1)) {
                Ok(i) => i,
                Err(r) => return r,
            };
            let want: u64 = match o.value("n").map(|v| v.parse::<u64>()) {
                Some(Ok(n)) => n.min(OUT_MAX),
                Some(Err(_)) => return Reply::error(Status::BadArgs, "bad -n"),
                None => OUT_DEFAULT,
            };
            if !ctx.daemon.jobs.snapshot().iter().any(|j| j.id == id) {
                return Reply::error(Status::NotFound, "no such job");
            }
            match std::fs::File::open(output_path(&ctx.daemon.config.run_dir, id)) {
                Ok(mut f) => {
                    use std::io::{Read, Seek, SeekFrom};
                    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                    let _ = f.seek(SeekFrom::Start(len.saturating_sub(want)));
                    let mut buf = Vec::new();
                    let _ = f.take(want).read_to_end(&mut buf);
                    Reply { status: Status::Ok, body: buf, content: Content::Bytes }
                }
                Err(e) => Reply::error(Status::Io, &e.to_string()),
            }
        }
        _ => Reply::error(Status::BadArgs, "usage: jobs [ls | kill ID | out ID]"),
    }
}
