//! Embedded single-file SPA (PLAN.md section 10). Owner: P7.

pub const INDEX_HTML: &str = include_str!("../web/index.html");

/// Placeholder in `index.html` replaced per boot with the CSP script nonce (each `<script nonce="...">`).
pub const NONCE_TOKEN: &str = "__I7LAB_NONCE__";
