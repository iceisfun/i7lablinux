//! exec, shell (PROTOCOL.md section 7). The runner is `crate::exec`.

use labproto::json::JsonWriter;
use labproto::Status;

use crate::exec::{self, Outcome};
use crate::registry::{Content, Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("exec", exec_cmd), ("shell", shell)];

fn start_error(e: &std::io::Error) -> Reply {
    let st = match e.kind() {
        std::io::ErrorKind::NotFound => Status::NotFound,
        std::io::ErrorKind::PermissionDenied => Status::Eperm,
        _ => Status::Io,
    };
    Reply::error(st, &format!("cannot start: {}", e))
}

fn result(o: Outcome) -> Reply {
    let status = if o.canceled {
        Status::Canceled
    } else if o.truncated {
        Status::TooBig
    } else {
        Status::Ok
    };
    Reply { status, body: exec::outcome_body(&o), content: Content::ExecResult }
}

fn exec_cmd(ctx: &mut Ctx) -> Reply {
    let spec = match exec::parse_args(&ctx.args) {
        Ok(s) => s,
        Err(e) => return Reply::error(Status::BadArgs, &e),
    };
    if spec.detach {
        if spec.tty.is_some() || spec.stdin {
            return Reply::error(Status::BadArgs, "--detach cannot be combined with --tty or --stdin");
        }
        return match ctx.daemon.jobs.start(&spec, &ctx.daemon.config.run_dir) {
            Ok(id) => {
                let mut w = JsonWriter::new();
                w.begin_object();
                w.field_u64("v", 1);
                w.field_u64("job", id as u64);
                w.end_object();
                Reply::json(w.finish())
            }
            Err(e) => start_error(&e),
        };
    }
    match exec::run(&spec, ctx.sink, &ctx.cancel) {
        Ok(o) => result(o),
        Err(e) => start_error(&e),
    }
}

fn shell(ctx: &mut Ctx) -> Reply {
    let (spec, _term) = match exec::parse_shell_args(&ctx.args) {
        Ok(s) => s,
        Err(e) => return Reply::error(Status::BadArgs, &e),
    };
    match exec::run(&spec, ctx.sink, &ctx.cancel) {
        Ok(o) => result(o),
        Err(e) => start_error(&e),
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::tests_support::run_as_admin;
    use labproto::Status;

    #[test]
    fn exec_through_the_registry() {
        let (r, sink) = run_as_admin("exec", &["--", "/bin/sh", "-c", "echo hi; exit 2"]);
        assert_eq!(r.status, Status::Ok);
        assert_eq!(&r.body[..4], &2i32.to_be_bytes());
        assert_eq!(sink.stdout, b"hi\n");
        assert_eq!(run_as_admin("exec", &["/bin/true"]).0.status, Status::BadArgs);
        assert_eq!(run_as_admin("exec", &["--", "/no/such/prog"]).0.status, Status::NotFound);
        assert_eq!(run_as_admin("exec", &["--detach", "--stdin", "--", "/bin/true"]).0.status, Status::BadArgs);
    }
}
