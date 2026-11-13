//! Which ttys get a fallback console shell. Pure.

use crate::cmdline::Flags;

/// tty1 (the VGA/framebuffer console) plus every serial-style console named on the kernel command line or by
/// `i7lab.serial=`, restricted to nodes that exist. `tty0`/`console` mean "the current VT" and map to tty1.
pub fn shell_ttys(flags: &Flags, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |n: &str| {
        if exists(n) && !out.iter().any(|o| o == n) {
            out.push(n.to_string());
        }
    };
    add("tty1");
    let serial_like = |n: &str| ["ttyS", "hvc", "ttyAMA", "ttyUSB", "ttyACM"].iter().any(|p| n.starts_with(p));
    for c in &flags.consoles {
        if serial_like(c) {
            add(c);
        }
    }
    if let Some(s) = &flags.serial {
        if serial_like(s) {
            add(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vt_and_serial_consoles() {
        let f = Flags::parse("console=tty0 console=ttyS0,115200n8 i7lab.serial=ttyS1");
        let all = |_: &str| true;
        assert_eq!(shell_ttys(&f, &all), vec!["tty1", "ttyS0", "ttyS1"]);
        let only = |n: &str| n == "tty1" || n == "ttyS0";
        assert_eq!(shell_ttys(&f, &only), vec!["tty1", "ttyS0"]);
        assert!(shell_ttys(&f, &|_| false).is_empty());
    }
    #[test]
    fn junk_names_are_ignored() {
        let f = Flags::parse("i7lab.serial=../../etc/passwd console=tty0");
        assert_eq!(shell_ttys(&f, &|_| true), vec!["tty1"]);
    }
}
