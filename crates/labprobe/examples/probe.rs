//! Print the live inventory as JSON (read-only; no writes anywhere).
//!   cargo run -p labprobe --example probe -- [section ...]      sections: system cpu mem dmi pci usb block net thermal firmware smart kmsg gpu serial
//!   cargo run -p labprobe --example probe -- --pci-verbose
//! Run it as root to include the raw DMI table (DIMMs, serial numbers), config space beyond 64 bytes and efivars.

use labprobe::{inventory, ProbeCtx, Section};
use labproto::json::to_json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ctx = ProbeCtx::live();
    if args.iter().any(|a| a == "--pci-verbose") {
        let r = labprobe::pci::probe(&ctx, &labprobe::pci::PciOpts { verbose: true, ..Default::default() });
        match r {
            Ok(r) => println!("{}", to_json(&r)),
            Err(e) => eprintln!("pci: {}", e),
        }
        return;
    }
    let sections: Vec<Section> = if args.is_empty() {
        Section::ALL.to_vec()
    } else {
        args.iter().filter_map(|a| Section::parse(a).or_else(|| {
            eprintln!("unknown section {a}");
            None
        })).collect()
    };
    println!("{}", to_json(&inventory(&ctx, &sections)));
}
