# Vendored terminal widget

Committed copies of two MIT-licensed npm packages, served by the daemon itself (`GET /vendor/...`, no CDN at
runtime) and loaded only when the Terminal tab is opened. Fetched once from the npm registry by the maintainer;
never downloaded at build or run time. To update: fetch the new tarball, verify the registry's sha512 integrity
value, replace the files, update this table, run the web checks.

| package | version | file here | from | sha256 of the file |
|---|---|---|---|---|
| @xterm/xterm | 5.5.0 | `xterm.js` | `package/lib/xterm.js` | `1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495` |
| @xterm/xterm | 5.5.0 | `xterm.css` | `package/css/xterm.css` | `ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6` |
| @xterm/addon-fit | 0.10.0 | `addon-fit.js` | `package/lib/addon-fit.js` | `bdaefa370b1bfc42ee88d46fe6072400902a4d4b2d45cd93438dda9b23c97089` |

Licenses: `LICENSE-xterm` (sha256 `b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd`) and
`LICENSE-addon-fit` (sha256 `e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f`).

Source tarballs (verified against the registry `integrity` sha512 and `shasum` sha1):

- `https://registry.npmjs.org/@xterm/xterm/-/xterm-5.5.0.tgz` sha1 `275fb8f6e14afa6e8a0c05d4ebc94523ff775396`,
  sha256 `bd954fa721872170188cc5d7e83e88db3c83c9a18a4e8d24c2783d26491f59d2`
- `https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.10.0.tgz` sha1 `bebf87fadd74e3af30fdcdeef47030e2592c6f55`,
  sha256 `917ac44972453d5eed52edc1e50260c76398ce48cf2290c2e60671102bba0b33`

Unmodified: the files are byte-identical to the tarball contents (a Rust test checks the sha256 values above).
