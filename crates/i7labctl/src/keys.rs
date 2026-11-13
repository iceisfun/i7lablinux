//! Key discovery (PLAN.md section 5) and `key init|show|export|import|verify`. Owner: P9.
//!
//! Lookup order, first hit wins, per role: `--key FILE`, `$I7LABCTL_KEY`, `$I7LABCTL_KEYDIR/<role>.key` (`--keys DIR`
//! is the same as `$I7LABCTL_KEYDIR` and wins over it), `~/.config/i7labctl/keys/<role>.key` (under sudo: the
//! invoking user's home), `./keys/<role>.key`.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use labproto::keys::{Key, KeyError, Role};

use crate::ClientError;

/// Inputs for the lookup, so it is testable without touching the real environment.
#[derive(Clone, Debug, Default)]
pub struct KeyEnv {
    pub flag_key: Option<PathBuf>,
    pub env_key: Option<PathBuf>,
    pub env_keydir: Option<PathBuf>,
    /// $HOME, or the invoking user's home under sudo (SUDO_USER)
    pub home: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    /// $SUDO_USER and the unmodified $HOME, only to explain a missing key (sudo resets HOME to /root)
    pub sudo_user: Option<String>,
    pub raw_home: Option<PathBuf>,
}

impl KeyEnv {
    pub fn from_process(flag_key: Option<PathBuf>) -> KeyEnv {
        KeyEnv {
            flag_key,
            env_key: std::env::var_os("I7LABCTL_KEY").map(PathBuf::from),
            env_keydir: std::env::var_os("I7LABCTL_KEYDIR").map(PathBuf::from),
            home: real_home(),
            cwd: std::env::current_dir().ok(),
            sudo_user: std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()),
            raw_home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }
}

/// $HOME, or the invoking user's home when running under sudo.
pub fn real_home() -> Option<PathBuf> {
    match std::env::var("SUDO_USER") {
        Ok(u) if !u.is_empty() && u != "root" && !u.contains('/') => {
            let from_passwd = std::fs::read_to_string("/etc/passwd").ok().and_then(|t| {
                t.lines().find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() > 5 && f[0] == u).then(|| PathBuf::from(f[5]))
                })
            });
            Some(from_passwd.unwrap_or_else(|| PathBuf::from(format!("/home/{}", u))))
        }
        _ => std::env::var_os("HOME").map(PathBuf::from),
    }
}

/// The "no key found" error text: every place searched, in order, and the sudo explanation when it applies.
/// Starts with "no <role> key found" (callers match on that prefix).
pub fn missing_message(env: &KeyEnv, role: Option<Role>) -> String {
    let what = match role {
        Some(r) => format!("no {} key found", r.name()),
        None => "no admin or ro key found".to_string(),
    };
    let file = match role {
        Some(r) => format!("{}.key", r.name()),
        None => "<role>.key".to_string(),
    };
    let show = |p: &Option<PathBuf>, none: &str| p.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| none.to_string());
    let mut m = format!("{}. Searched, in this order:\n", what);
    m.push_str(&format!("  1. --key FILE                      {}\n", show(&env.flag_key, "(not given)")));
    m.push_str(&format!("  2. $I7LABCTL_KEY                   {}\n", show(&env.env_key, "(not set)")));
    m.push_str(&format!("  3. $I7LABCTL_KEYDIR (or --keys DIR) {}\n", env.env_keydir.as_ref().map(|d| d.join(&file).display().to_string()).unwrap_or_else(|| "(not set)".into())));
    m.push_str(&format!("  4. ~/.config/i7labctl/keys         {}\n", env.home.as_ref().map(|h| h.join(".config/i7labctl/keys").join(&file).display().to_string()).unwrap_or_else(|| "(no home directory)".into())));
    m.push_str(&format!("  5. ./keys                          {}\n", env.cwd.as_ref().map(|c| c.join("keys").join(&file).display().to_string()).unwrap_or_else(|| "(no current directory)".into())));
    if let (Some(u), Some(h)) = (&env.sudo_user, &env.raw_home) {
        if u != "root" && (h == Path::new("/root") || h.as_os_str().is_empty()) {
            m.push_str(&format!(
                "You are running under sudo (SUDO_USER={}) and sudo changed HOME to {}: your own keys are not in root's home. Run i7labctl without sudo (the HTTP transport needs no root), or use `sudo -E i7labctl ...`, or point --keys DIR / I7LABCTL_KEYDIR at your key directory.\n",
                u,
                h.display()
            ));
        }
    }
    m.push_str("Create keys with: i7labctl key init (or ./scripts/gen-keys)");
    m
}

/// Candidate files for `role`, first hit wins.
pub fn candidates(env: &KeyEnv, role: Role) -> Vec<PathBuf> {
    let file = format!("{}.key", role.name());
    let mut v = Vec::new();
    v.extend(env.flag_key.clone());
    v.extend(env.env_key.clone());
    v.extend(env.env_keydir.as_ref().map(|d| d.join(&file)));
    v.extend(env.home.as_ref().map(|h| h.join(".config/i7labctl/keys").join(&file)));
    v.extend(env.cwd.as_ref().map(|c| c.join("keys").join(&file)));
    v
}

fn load_checked(p: &Path) -> Result<Key, KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::metadata(p)?;
    if md.permissions().mode() & 0o077 != 0 {
        return Err(KeyError::Permissions(p.to_path_buf()));
    }
    Key::parse_line(&std::fs::read_to_string(p)?)
}

/// First readable key for `role`. A candidate that exists but is group/world readable or malformed is an error
/// (never silently skipped: the operator must fix it). A file whose role differs is skipped for explicit
/// `--key`/`$I7LABCTL_KEY` only if it holds the other role (so `--role ro` with `--key admin.key` fails clearly).
pub fn find_key(env: &KeyEnv, role: Role) -> Result<(Key, PathBuf), KeyError> {
    for p in candidates(env, role) {
        if !p.exists() {
            continue;
        }
        let k = load_checked(&p)?;
        if k.role != role {
            // explicit file of the other role: only acceptable when it is the one that was asked for
            if Some(&p) == env.flag_key.as_ref() || Some(&p) == env.env_key.as_ref() {
                continue;
            }
            return Err(KeyError::Format(format!("{} holds a {} key, expected {}", p.display(), k.role.name(), role.name())));
        }
        return Ok((k, p));
    }
    Err(KeyError::Format(missing_message(env, Some(role))))
}

/// Any key at all (flag file regardless of role).
pub fn find_any(env: &KeyEnv) -> Vec<(Key, PathBuf)> {
    let mut v: Vec<(Key, PathBuf)> = Vec::new();
    if let Some(p) = env.flag_key.as_ref().or(env.env_key.as_ref()) {
        if let Ok(k) = load_checked(p) {
            v.push((k, p.clone()));
        }
    }
    for role in [Role::Admin, Role::Ro] {
        if let Ok((k, p)) = find_key(env, role) {
            if !v.iter().any(|(x, _)| x.role == k.role && x.bytes == k.bytes) {
                v.push((k, p));
            }
        }
    }
    v
}

pub fn local_fingerprints(env: &KeyEnv) -> Vec<String> {
    find_any(env).iter().map(|(k, _)| k.fingerprint()).collect()
}

fn key_err(e: KeyError) -> ClientError {
    match e {
        KeyError::Io(e) => ClientError::Auth(format!("cannot read key: {}", e)),
        KeyError::Format(m) => ClientError::Auth(m),
        KeyError::Permissions(p) => ClientError::Auth(format!("{} is readable by group/other: run chmod 600 {}", p.display(), p.display())),
    }
}

/// Choose the key for a request. `role` from `--role` (None: admin if its file exists, else ro). `kid` is the
/// host's advertised `(admin fp, ro fp)`; a host whose key set matches none of our keys is refused with exit 5
/// without sending anything (review F-F20).
pub fn select(env: &KeyEnv, role: Option<Role>, kid: Option<(Option<String>, Option<String>)>) -> Result<(Key, PathBuf), ClientError> {
    // an explicit key file fixes both key and role
    let picked = if let Some(p) = env.flag_key.as_ref() {
        let k = load_checked(p).map_err(key_err)?;
        if role.is_some_and(|r| r != k.role) {
            return Err(ClientError::Usage(format!("--key {} holds a {} key but --role {} was given", p.display(), k.role.name(), role.unwrap().name())));
        }
        (k, p.clone())
    } else {
        match role {
            Some(r) => find_key(env, r).map_err(key_err)?,
            None => match find_key(env, Role::Admin) {
                Ok(x) => x,
                Err(KeyError::Format(m)) if m.starts_with("no admin key found") => find_key(env, Role::Ro).map_err(|e| match e {
                    KeyError::Format(m) if m.starts_with("no ro key found") => ClientError::Auth(missing_message(env, None)),
                    other => key_err(other),
                })?,
                Err(e) => return Err(key_err(e)),
            },
        }
    };
    if let Some((a, r)) = kid {
        if a.is_some() || r.is_some() {
            let fits = |k: &Key| match k.role {
                Role::Admin => a.as_deref() == Some(k.fingerprint().as_str()),
                Role::Ro => r.as_deref() == Some(k.fingerprint().as_str()),
            };
            if fits(&picked.0) {
                return Ok(picked);
            }
            // the other role's key may match (only when the role was not forced)
            if role.is_none() && env.flag_key.is_none() {
                let other = if picked.0.role == Role::Admin { Role::Ro } else { Role::Admin };
                if let Ok((k2, p2)) = find_key(env, other) {
                    if fits(&k2) {
                        return Ok((k2, p2));
                    }
                }
            }
            return Err(ClientError::Auth(format!(
                "host advertises key set a:{} r:{} but your {} key is {} (other-keyset); nothing was sent. Use the keys it was built with, or --no-registry to try anyway",
                a.as_deref().unwrap_or("-"),
                r.as_deref().unwrap_or("-"),
                picked.0.role.name(),
                picked.0.fingerprint()
            )));
        }
    }
    Ok(picked)
}

pub fn default_key_dir(home: &Path) -> PathBuf {
    home.join(".config/i7labctl/keys")
}

// ---------------------------------------------------------------- writing

fn ensure_private_dir(d: &Path) -> std::io::Result<()> {
    if !d.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
    }
    Ok(())
}

/// Write `text` to `p` with mode 0600; `overwrite` replaces an existing file (atomically).
pub fn write_private(p: &Path, text: &str, overwrite: bool) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        ensure_private_dir(d)?;
    }
    if !overwrite {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(p)?;
        return f.write_all(text.as_bytes());
    }
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, p)
}

/// `YYYY-MM-DD` from unix seconds (civil-from-days, proleptic Gregorian).
pub fn date_of(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

pub struct Created {
    pub role: Role,
    pub fingerprint: String,
    pub path: PathBuf,
}

/// A fresh random key set.
pub fn generate_set() -> Result<(Key, Key), ClientError> {
    Ok((Key::generate(Role::Admin)?, Key::generate(Role::Ro)?))
}

/// Does `dir` already hold any key file?
pub fn has_keys(dir: &Path) -> bool {
    ["admin.key", "ro.key", "KEYSET-ID"].iter().any(|f| dir.join(f).exists())
}

/// Write admin.key, ro.key, KEYSET-ID into `dir`. Refuses to overwrite unless `force`; with `force` the old
/// files move to `dir/old/<date>-<ts>/`.
pub fn write_set(dir: &Path, admin: &Key, ro: &Key, force: bool, now: u64) -> Result<Vec<Created>, ClientError> {
    ensure_private_dir(dir)?;
    let existing: Vec<PathBuf> = ["admin.key", "ro.key", "KEYSET-ID"].iter().map(|f| dir.join(f)).filter(|p| p.exists()).collect();
    if !existing.is_empty() {
        if !force {
            return Err(ClientError::Safety(format!("{} already holds keys; use --force to replace them (old ones are kept in {}/old/)", dir.display(), dir.display())));
        }
        let old = dir.join("old").join(format!("{}-{}", date_of(now), now));
        ensure_private_dir(&old)?;
        for p in existing {
            std::fs::rename(&p, old.join(p.file_name().unwrap()))?;
        }
    }
    let mut out = Vec::new();
    for k in [admin, ro] {
        let p = dir.join(format!("{}.key", k.role.name()));
        write_private(&p, &format!("{}\n", k.to_line()), false)?;
        out.push(Created { role: k.role, fingerprint: k.fingerprint(), path: p });
    }
    let id = format!("i7lablinux keyset {} admin={} ro={}\n", date_of(now), admin.fingerprint(), ro.fingerprint());
    write_private(&dir.join("KEYSET-ID"), &id, false)?;
    Ok(out)
}

/// Generate and write a key set into one directory.
pub fn init_dir(dir: &Path, force: bool, now: u64) -> Result<Vec<Created>, ClientError> {
    let (a, r) = generate_set()?;
    write_set(dir, &a, &r, force, now)
}

/// Copy a key line into `dir/<role>.key` (validated first).
pub fn import_into(dir: &Path, line: &str, force: bool) -> Result<Created, ClientError> {
    let k = Key::parse_line(line).map_err(|e| ClientError::Usage(format!("not a key line: {:?}", e)))?;
    let p = dir.join(format!("{}.key", k.role.name()));
    if p.exists() && !force {
        return Err(ClientError::Safety(format!("{} exists; use --force to replace it", p.display())));
    }
    write_private(&p, &format!("{}\n", k.to_line()), true)?;
    Ok(Created { role: k.role, fingerprint: k.fingerprint(), path: p })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("i7ctl-keys-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn order() {
        let env = KeyEnv {
            flag_key: Some("/f".into()),
            env_key: None,
            env_keydir: Some("/d".into()),
            home: Some("/h".into()),
            cwd: Some("/c".into()),
            ..Default::default()
        };
        let c = candidates(&env, Role::Admin);
        assert_eq!(c, vec![PathBuf::from("/f"), "/d/admin.key".into(), "/h/.config/i7labctl/keys/admin.key".into(), "/c/keys/admin.key".into()]);
    }

    #[test]
    fn dates() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(1_794_000_000), "2026-11-06");
        assert_eq!(date_of(951_782_400), "2000-02-29");
    }

    #[test]
    fn init_show_force_and_perms() {
        let d = tmp("init");
        let keys = d.join("keys");
        let made = init_dir(&keys, false, 1_794_000_000).unwrap();
        assert_eq!(made.len(), 2);
        for c in &made {
            assert_eq!(std::fs::metadata(&c.path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777, 0o700);
        let id = std::fs::read_to_string(keys.join("KEYSET-ID")).unwrap();
        assert!(id.contains("2026-11-06") && id.contains(&made[0].fingerprint));
        assert!(!id.contains(&made[0].path.display().to_string()));
        // refuse overwrite
        assert!(matches!(init_dir(&keys, false, 1), Err(ClientError::Safety(_))));
        // force keeps the old set
        let before = std::fs::read_to_string(keys.join("admin.key")).unwrap();
        init_dir(&keys, true, 1_794_000_100).unwrap();
        assert_ne!(std::fs::read_to_string(keys.join("admin.key")).unwrap(), before);
        let olds: Vec<_> = std::fs::read_dir(keys.join("old")).unwrap().collect();
        assert_eq!(olds.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn select_role_defaults_and_kid() {
        let d = tmp("sel");
        let keys = d.join("keys");
        init_dir(&keys, false, 5).unwrap();
        let env = KeyEnv { env_keydir: Some(keys.clone()), ..Default::default() };
        let (k, _) = select(&env, None, None).unwrap();
        assert_eq!(k.role, Role::Admin);
        let (k, _) = select(&env, Some(Role::Ro), None).unwrap();
        assert_eq!(k.role, Role::Ro);
        let admin_fp = find_key(&env, Role::Admin).unwrap().0.fingerprint();
        let ro_fp = find_key(&env, Role::Ro).unwrap().0.fingerprint();
        // matching kid
        assert!(select(&env, None, Some((Some(admin_fp.clone()), Some(ro_fp.clone())))).is_ok());
        // host only knows the ro key of ours: falls back to ro when role not forced
        let (k, _) = select(&env, None, Some((Some("deadbeef".into()), Some(ro_fp.clone())))).unwrap();
        assert_eq!(k.role, Role::Ro);
        // forced role does not fall back
        assert!(matches!(select(&env, Some(Role::Admin), Some((Some("deadbeef".into()), Some(ro_fp)))), Err(ClientError::Auth(_))));
        // nothing matches
        let e = select(&env, None, Some((Some("deadbeef".into()), Some("cafef00d".into())))).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        assert!(e.to_string().contains("other-keyset"));
        // only an ro key present: default role falls to ro
        std::fs::remove_file(keys.join("admin.key")).unwrap();
        assert_eq!(select(&env, None, None).unwrap().0.role, Role::Ro);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_key_message_names_the_fix_and_perms_are_enforced() {
        let d = tmp("none");
        let env = KeyEnv { env_keydir: Some(d.join("nothing")), ..Default::default() };
        let e = select(&env, None, None).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        assert!(e.to_string().contains("key init"));
        // loose permissions are refused
        let keys = d.join("keys");
        init_dir(&keys, false, 5).unwrap();
        std::fs::set_permissions(keys.join("admin.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let env = KeyEnv { env_keydir: Some(keys), ..Default::default() };
        let e = select(&env, Some(Role::Admin), None).unwrap_err();
        assert!(e.to_string().contains("chmod 600"), "{}", e);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_key_error_names_every_place_searched_in_order() {
        let env = KeyEnv { env_keydir: Some("/nowhere/kd".into()), home: Some("/home/al".into()), cwd: Some("/work/x".into()), ..Default::default() };
        let m = missing_message(&env, Some(Role::Admin));
        assert!(m.starts_with("no admin key found"), "{}", m);
        let at = |needle: &str| m.find(needle).unwrap_or_else(|| panic!("{} missing from: {}", needle, m));
        let order = [at("--key FILE"), at("$I7LABCTL_KEY "), at("$I7LABCTL_KEYDIR"), at("/nowhere/kd/admin.key"), at("~/.config/i7labctl/keys"), at("/home/al/.config/i7labctl/keys/admin.key"), at("./keys"), at("/work/x/keys/admin.key")];
        assert!(order.windows(2).all(|w| w[0] < w[1]), "places out of order: {}", m);
        assert!(m.contains("--keys DIR") && m.contains("key init"));
        assert!(!m.contains("sudo"), "no sudo talk without sudo: {}", m);
        // through select: same text, exit 5
        let e = select(&KeyEnv { env_keydir: Some("/nowhere/kd".into()), ..Default::default() }, Some(Role::Admin), None).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        assert!(e.to_string().contains("$I7LABCTL_KEYDIR"), "{}", e);
        let e = select(&KeyEnv { home: Some("/nonexistent-home".into()), ..Default::default() }, None, None).unwrap_err();
        assert!(e.to_string().contains("no admin or ro key found") && e.to_string().contains("~/.config/i7labctl/keys"), "{}", e);
    }

    #[test]
    fn under_sudo_with_root_home_the_error_explains_it() {
        let env = KeyEnv { home: Some("/root".into()), sudo_user: Some("alice".into()), raw_home: Some("/root".into()), ..Default::default() };
        let m = missing_message(&env, Some(Role::Ro));
        assert!(m.contains("SUDO_USER=alice") && m.contains("sudo changed HOME to /root"), "{}", m);
        assert!(m.contains("without sudo") && m.contains("sudo -E") && m.contains("I7LABCTL_KEYDIR"), "{}", m);
        // sudo that kept the user's HOME is not blamed
        let env = KeyEnv { sudo_user: Some("alice".into()), raw_home: Some("/home/alice".into()), ..Default::default() };
        assert!(!missing_message(&env, Some(Role::Ro)).contains("sudo changed"));
    }

    #[test]
    fn generated_keys_and_import() {
        let d = tmp("import");
        let made = init_dir(&d.join("k"), false, 5).unwrap();
        assert_eq!(made[0].role, Role::Admin);
        let line = Key { role: Role::Ro, bytes: [5; 32] }.to_line();
        let c = import_into(&d.join("imp"), &line, false).unwrap();
        assert_eq!(c.role, Role::Ro);
        assert!(import_into(&d.join("imp"), &line, false).is_err());
        assert!(import_into(&d.join("imp"), "garbage", true).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
