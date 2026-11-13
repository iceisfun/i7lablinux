//! Status codes (PROTOCOL.md section 3.1) and their HTTP / CLI exit mappings (I7LABCTL.md section 5). Owner: P1.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Status {
    Ok = 0,
    Eperm = 1,
    BadArgs = 2,
    Unsupported = 3,
    Busy = 4,
    Refused = 5,
    NotFound = 6,
    Io = 7,
    Timeout = 8,
    TooBig = 9,
    Canceled = 10,
    Exists = 11,
    NotReady = 12,
    StreamGone = 13,
    Internal = 14,
}

impl Status {
    pub const ALL: [Status; 15] = [
        Status::Ok, Status::Eperm, Status::BadArgs, Status::Unsupported, Status::Busy, Status::Refused,
        Status::NotFound, Status::Io, Status::Timeout, Status::TooBig, Status::Canceled, Status::Exists,
        Status::NotReady, Status::StreamGone, Status::Internal,
    ];

    pub fn from_u16(v: u16) -> Option<Status> {
        Status::ALL.get(v as usize).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Eperm => "EPERM",
            Status::BadArgs => "BAD_ARGS",
            Status::Unsupported => "UNSUPPORTED",
            Status::Busy => "BUSY",
            Status::Refused => "REFUSED",
            Status::NotFound => "NOT_FOUND",
            Status::Io => "IO",
            Status::Timeout => "TIMEOUT",
            Status::TooBig => "TOO_BIG",
            Status::Canceled => "CANCELED",
            Status::Exists => "EXISTS",
            Status::NotReady => "NOT_READY",
            Status::StreamGone => "STREAM_GONE",
            Status::Internal => "INTERNAL",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Status::Ok => 200,
            Status::Eperm => 403,
            Status::BadArgs => 400,
            Status::Unsupported => 501,
            Status::Busy | Status::NotReady => 503,
            Status::Refused => 409,
            Status::NotFound => 404,
            Status::Io | Status::Internal | Status::StreamGone => 500,
            Status::Timeout => 504,
            Status::TooBig => 413,
            Status::Canceled => 499,
            Status::Exists => 409,
        }
    }

    /// i7labctl process exit code for a remote status (I7LABCTL.md section 5).
    pub fn cli_exit(self) -> i32 {
        match self {
            Status::Ok => 0,
            Status::Eperm => 5,
            Status::BadArgs => 2,
            Status::Unsupported => 10,
            Status::Busy | Status::NotReady => 9,
            Status::Refused => 7,
            Status::NotFound => 6,
            Status::Timeout => 4,
            Status::Canceled => 130,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        for s in Status::ALL {
            assert_eq!(Status::from_u16(s as u16), Some(s));
        }
        assert_eq!(Status::from_u16(99), None);
    }
}
