//! serial: UART ports (/sys/class/tty/ttyS*), USB serial adapters (ttyUSB*, ttyACM*) and the kernel console
//! setting from the command line. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SerialPort {
    pub name: String,
    /// "uart" | "usb-serial" | "cdc-acm"
    pub kind: String,
    /// "16550A" ... for a uart, `None` for adapters
    pub uart_type: Option<String>,
    pub io_port: Option<u32>,
    pub irq: Option<u32>,
    pub driver: Option<String>,
    /// `console=` setting that names this port ("115200n8"), if any
    pub console: Option<String>,
    pub usb_vid: Option<u16>,
    pub usb_pid: Option<u16>,
    pub usb_product: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SerialReport {
    pub ports: Vec<SerialPort>,
}

/// Linux `PORT_*` number -> name (include/uapi/linux/serial_core.h). 0 = no port.
pub fn uart_type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        1 => "8250",
        2 => "16450",
        3 => "16550",
        4 => "16550A",
        5 => "Cirrus",
        6 => "16650",
        7 => "16650V2",
        8 => "16750",
        9 => "StarTech",
        10 => "16950/954",
        11 => "ST16654",
        12 => "XR17D15x",
        13 => "16C950",
        _ => return None,
    })
}

/// `console=ttyS0,115200n8` entries of the kernel command line: (tty name, settings).
pub fn parse_console_args(cmdline: &str) -> Vec<(String, Option<String>)> {
    cmdline
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("console="))
        .map(|v| match v.split_once(',') {
            Some((n, s)) => (n.to_string(), Some(s.to_string())),
            None => (v.to_string(), None),
        })
        .collect()
}

pub fn probe(ctx: &ProbeCtx) -> Result<SerialReport, ProbeError> {
    let consoles = parse_console_args(&ctx.read_opt("/proc/cmdline").unwrap_or_default());
    let mut rep = SerialReport::default();
    let mut names = ctx.list_dir("/sys/class/tty").unwrap_or_default();
    names.sort_by_key(|n| {
        let split = n.find(|c: char| c.is_ascii_digit()).unwrap_or(n.len());
        (n[..split].to_string(), n[split..].parse::<u32>().unwrap_or(0))
    });
    for n in names {
        let base = format!("/sys/class/tty/{}", n);
        let num = |f: &str| ctx.read_opt(&format!("{}/{}", base, f)).and_then(|v| crate::ctx::parse_hex(&v)).map(|v| v as u32);
        let mut p = SerialPort { name: n.clone(), ..Default::default() };
        if n.starts_with("ttyS") {
            let ty = ctx.read_opt(&format!("{}/type", base)).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
            if ty == 0 {
                continue; // no UART behind this node
            }
            p.kind = "uart".into();
            p.uart_type = Some(uart_type_name(ty).map(str::to_string).unwrap_or_else(|| format!("type{}", ty)));
            p.io_port = num("port").or_else(|| num("io_port")).filter(|p| *p != 0);
            p.irq = ctx.read_opt(&format!("{}/irq", base)).and_then(|v| v.parse().ok());
        } else if n.starts_with("ttyUSB") || n.starts_with("ttyACM") {
            p.kind = if n.starts_with("ttyUSB") { "usb-serial" } else { "cdc-acm" }.into();
            p.driver = ctx.link_name(&format!("{}/device/driver", base));
            if let Some(real) = crate::block::enumerate::real_sys_path(ctx, &base) {
                let mut anc = real;
                while let Some(i) = anc.rfind('/') {
                    anc.truncate(i);
                    if ctx.exists(&format!("{}/idVendor", anc)) {
                        p.usb_vid = ctx.read_opt(&format!("{}/idVendor", anc)).and_then(|v| crate::ctx::parse_hex(&v)).map(|v| v as u16);
                        p.usb_pid = ctx.read_opt(&format!("{}/idProduct", anc)).and_then(|v| crate::ctx::parse_hex(&v)).map(|v| v as u16);
                        p.usb_product = ctx.read_opt(&format!("{}/product", anc));
                        break;
                    }
                }
            }
        } else {
            continue;
        }
        p.console = consoles.iter().find(|(c, _)| *c == n).map(|(_, s)| s.clone().unwrap_or_default());
        rep.ports.push(p);
    }
    Ok(rep)
}

impl ToJson for SerialReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("ports");
        w.begin_array();
        for p in &self.ports {
            w.begin_object();
            w.field_str("name", &p.name);
            w.field_str("kind", &p.kind);
            w.field_opt_str("uart_type", p.uart_type.as_deref());
            w.field_opt_u64("io_port", p.io_port.map(u64::from));
            w.field_opt_u64("irq", p.irq.map(u64::from));
            w.field_opt_str("driver", p.driver.as_deref());
            w.field_opt_str("console", p.console.as_deref());
            w.field_opt_u64("usb_vid", p.usb_vid.map(u64::from));
            w.field_opt_u64("usb_pid", p.usb_pid.map(u64::from));
            w.field_opt_str("usb_product", p.usb_product.as_deref());
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_args() {
        assert_eq!(
            parse_console_args("quiet console=tty0 console=ttyS0,115200n8 i7lab.boot=x"),
            vec![("tty0".to_string(), None), ("ttyS0".to_string(), Some("115200n8".to_string()))]
        );
        assert_eq!(uart_type_name(4), Some("16550A"));
        assert_eq!(uart_type_name(0), None);
    }
}
