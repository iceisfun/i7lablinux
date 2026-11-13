//! `inv` = all (or selected) sections, each isolated so one failing probe never hides the rest. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    System,
    Cpu,
    Mem,
    Dmi,
    Pci,
    Usb,
    Block,
    Net,
    Thermal,
    Firmware,
    Smart,
    Kmsg,
    Gpu,
    Serial,
}

impl Section {
    pub const ALL: &'static [Section] = &[
        Section::System, Section::Cpu, Section::Mem, Section::Dmi, Section::Pci, Section::Usb, Section::Block,
        Section::Net, Section::Thermal, Section::Firmware, Section::Smart, Section::Kmsg,
        Section::Gpu, Section::Serial,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Section::System => "system",
            Section::Cpu => "cpu",
            Section::Mem => "mem",
            Section::Dmi => "dmi",
            Section::Pci => "pci",
            Section::Usb => "usb",
            Section::Block => "block",
            Section::Net => "net",
            Section::Thermal => "thermal",
            Section::Firmware => "firmware",
            Section::Smart => "smart",
            Section::Kmsg => "kmsg",
            Section::Gpu => "gpu",
            Section::Serial => "serial",
        }
    }

    pub fn parse(s: &str) -> Option<Section> {
        Section::ALL.iter().copied().find(|x| x.name() == s)
    }
}

/// Each section holds its report already serialised to JSON (or the error).
pub struct Inventory {
    pub v: u64,
    pub sections: Vec<(Section, Result<String, ProbeError>)>,
}

fn run<T: ToJson>(r: Result<T, ProbeError>) -> Result<String, ProbeError> {
    r.map(|t| labproto::json::to_json(&t))
}

pub fn inventory(ctx: &ProbeCtx, sections: &[Section]) -> Inventory {
    let mut out = Vec::new();
    for s in sections {
        let r = match s {
            Section::System => run(crate::system::probe(ctx)),
            Section::Cpu => run(crate::cpu::probe(ctx)),
            Section::Mem => run(crate::mem::probe(ctx)),
            Section::Dmi => run(crate::dmi::probe(ctx)),
            Section::Pci => run(crate::pci::probe(ctx, &crate::pci::PciOpts::default())),
            Section::Usb => run(crate::usb::probe(ctx)),
            Section::Block => run(crate::block::probe(ctx, false)),
            Section::Net => run(crate::net::probe(ctx)),
            Section::Thermal => run(crate::thermal::probe(ctx)),
            Section::Firmware => run(crate::firmware::probe(ctx)),
            Section::Smart => run(crate::block::smart::probe_all(ctx)),
            Section::Kmsg => run(crate::kmsg::read(ctx, &crate::kmsg::KmsgOpts::default())),
            Section::Gpu => run(crate::gpu::probe(ctx)),
            Section::Serial => run(crate::serial::probe(ctx)),
        };
        out.push((*s, r));
    }
    Inventory { v: crate::SCHEMA_V, sections: out }
}

impl ToJson for Inventory {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", self.v);
        for (s, r) in &self.sections {
            w.key(s.name());
            match r {
                Ok(json) => w.raw(json),
                Err(e) => {
                    w.begin_object();
                    w.field_str("error", e.code());
                    w.field_str("message", &e.to_string());
                    w.end_object();
                }
            }
        }
        w.end_object();
    }
}
