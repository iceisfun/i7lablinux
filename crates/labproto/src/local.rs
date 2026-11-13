//! Local control socket codec (/run/i7lab/ctl.sock), shared by the i7labd server (P6a) and the i7labsh `lab`
//! builtin (P8) (review feasibility F11). Owner: P1.
//!
//! Request:  u32 BE length | u16 BE cmd id | argv body (`args::encode_argv`)
//! Reply:    u32 BE length | u16 BE status | i32 BE exit (or 0) | body (JSON or bytes)
//! Authorisation: SO_PEERCRED uid 0 only; role admin, `Source::Local`. One request per connection.

use crate::args::ArgsError;
use crate::status::Status;

pub const PATH: &str = "/run/i7lab/ctl.sock";
/// Same cap as an ether REQ (64 KiB) for requests; replies up to 16 MiB.
pub const MAX_REQ: usize = 64 * 1024;
pub const MAX_REPLY: usize = 16 * 1024 * 1024;

pub fn encode_request(cmd: u16, argv: &[String]) -> Vec<u8> {
    let body = crate::args::encode_argv(argv);
    let mut out = Vec::with_capacity(6 + body.len());
    out.extend_from_slice(&((2 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&cmd.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// `msg` is the frame without the u32 length prefix.
pub fn decode_request(msg: &[u8]) -> Result<(u16, Vec<String>), ArgsError> {
    if msg.len() < 2 {
        return Err(ArgsError::Truncated);
    }
    if msg.len() > MAX_REQ {
        return Err(ArgsError::TooLong);
    }
    let cmd = u16::from_be_bytes([msg[0], msg[1]]);
    Ok((cmd, crate::args::decode_argv(&msg[2..])?))
}

pub fn encode_reply(status: Status, exit: i32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&(status as u16).to_be_bytes());
    out.extend_from_slice(&exit.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn decode_reply(msg: &[u8]) -> Option<(Status, i32, &[u8])> {
    if msg.len() < 6 {
        return None;
    }
    let st = Status::from_u16(u16::from_be_bytes([msg[0], msg[1]]))?;
    let exit = i32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]);
    Some((st, exit, &msg[6..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let r = encode_reply(Status::Refused, 3, b"{}");
        assert_eq!(decode_reply(&r[4..]), Some((Status::Refused, 3, &b"{}"[..])));
        assert!(decode_request(&[0]).is_err());
    }
}
