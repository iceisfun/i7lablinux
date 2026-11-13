//! Shell completion scripts generated from the subcommand table (the same table that drives `help`).
//! Host selectors come from `i7labctl __hosts` (registry MACs, hostnames, board serials, aliases). Owner: P9.

use crate::cli::SUBS;

const GLOBAL_LONG: &[&str] = &[
    "--host", "--ether", "--cmd", "--http", "--ssh", "--transport", "--iface", "--vlan", "--role", "--key", "--keys", "--timeout", "--retries", "--json", "--quiet", "--no-color", "--registry", "--no-registry", "--yes", "--link", "--help", "--version",
];

fn all_names() -> String {
    SUBS.iter().map(|s| s.name).collect::<Vec<_>>().join(" ")
}

fn opts_of(name: &str) -> String {
    SUBS.iter().find(|s| s.name == name).map(|s| s.opts.join(" ")).unwrap_or_default()
}

pub fn bash() -> String {
    let mut s = String::from("# bash completion for i7labctl (generated: i7labctl completions bash)\n_i7labctl() {\n  local cur prev cmd i\n  COMPREPLY=()\n  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n  prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n  cmd=\"\"\n  for ((i=1; i<COMP_CWORD; i++)); do\n    case \"${COMP_WORDS[i]}\" in\n      -*) ;;\n      *) cmd=\"${COMP_WORDS[i]}\"; break ;;\n    esac\n  done\n");
    s.push_str(&format!("  local global=\"{}\"\n", GLOBAL_LONG.join(" ")));
    s.push_str(&format!("  local commands=\"{}\"\n", all_names()));
    s.push_str("  case \"$prev\" in\n    --role) COMPREPLY=( $(compgen -W \"admin ro\" -- \"$cur\") ); return ;;\n    --transport) COMPREPLY=( $(compgen -W \"auto ether http ssh\" -- \"$cur\") ); return ;;\n    --key|--registry|--file|--image|--stdin) COMPREPLY=( $(compgen -f -- \"$cur\") ); return ;;\n    --iface|-i) COMPREPLY=( $(compgen -W \"$(ls /sys/class/net 2>/dev/null)\" -- \"$cur\") ); return ;;\n    --host|-H|--ether) COMPREPLY=( $(compgen -W \"$(i7labctl __hosts 2>/dev/null)\" -- \"$cur\") ); return ;;\n  esac\n");
    s.push_str("  if [ -z \"$cmd\" ]; then\n    if [[ \"$cur\" == -* ]]; then COMPREPLY=( $(compgen -W \"$global\" -- \"$cur\") ); else COMPREPLY=( $(compgen -W \"$commands\" -- \"$cur\") ); fi\n    return\n  fi\n  case \"$cmd\" in\n");
    for c in SUBS {
        let verbs = c.verbs.join(" ");
        s.push_str(&format!(
            "    {})\n      if [[ \"$cur\" == -* ]]; then COMPREPLY=( $(compgen -W \"{} $global\" -- \"$cur\") )\n      else COMPREPLY=( $(compgen -W \"{} $(i7labctl __hosts 2>/dev/null)\" -- \"$cur\") ); fi ;;\n",
            c.name,
            opts_of(c.name),
            verbs
        ));
    }
    s.push_str("  esac\n}\ncomplete -F _i7labctl i7labctl\n");
    s
}

pub fn zsh() -> String {
    let mut s = String::from("#compdef i7labctl\n# zsh completion for i7labctl (generated: i7labctl completions zsh)\n_i7labctl() {\n  local -a commands global\n  commands=(\n");
    for c in SUBS {
        s.push_str(&format!("    '{}:{}'\n", c.name, c.summary.replace('\'', "")));
    }
    s.push_str("  )\n");
    s.push_str(&format!("  global=({})\n", GLOBAL_LONG.iter().map(|g| format!("'{}'", g)).collect::<Vec<_>>().join(" ")));
    s.push_str("  if (( CURRENT == 2 )); then\n    _describe 'command' commands\n    _values 'global option' $global\n    return\n  fi\n  local -a hosts\n  hosts=( ${(f)\"$(i7labctl __hosts 2>/dev/null)\"} )\n  case \"$words[2]\" in\n");
    for c in SUBS {
        let o = c.opts.iter().map(|x| format!("'{}'", x)).collect::<Vec<_>>().join(" ");
        let v = c.verbs.iter().map(|x| format!("'{}'", x)).collect::<Vec<_>>().join(" ");
        s.push_str(&format!("    {})\n      _values 'argument' {} {} $hosts $global ;;\n", c.name, if o.is_empty() { String::new() } else { o }, v));
    }
    s.push_str("  esac\n}\n_i7labctl \"$@\"\n");
    s
}

pub fn fish() -> String {
    let mut s = String::from("# fish completion for i7labctl (generated: i7labctl completions fish)\ncomplete -c i7labctl -f\n");
    s.push_str("complete -c i7labctl -n '__fish_use_subcommand' -a \"");
    s.push_str(&all_names());
    s.push_str("\"\n");
    for c in SUBS {
        s.push_str(&format!("complete -c i7labctl -n '__fish_use_subcommand' -a '{}' -d '{}'\n", c.name, c.summary.replace('\'', "")));
        for o in c.opts {
            if let Some(long) = o.strip_prefix("--") {
                s.push_str(&format!("complete -c i7labctl -n '__fish_seen_subcommand_from {}' -l {}\n", c.name, long));
            } else if let Some(short) = o.strip_prefix('-') {
                s.push_str(&format!("complete -c i7labctl -n '__fish_seen_subcommand_from {}' -s {}\n", c.name, short));
            }
        }
        for v in c.verbs {
            s.push_str(&format!("complete -c i7labctl -n '__fish_seen_subcommand_from {}' -a '{}'\n", c.name, v));
        }
        if c.transports.contains('E') || c.transports.contains('H') {
            s.push_str(&format!("complete -c i7labctl -n '__fish_seen_subcommand_from {}' -a '(i7labctl __hosts 2>/dev/null)'\n", c.name));
        }
    }
    for g in GLOBAL_LONG {
        s.push_str(&format!("complete -c i7labctl -l {}\n", &g[2..]));
    }
    s
}

pub fn script(shell: &str) -> Option<String> {
    match shell {
        "bash" => Some(bash()),
        "zsh" => Some(zsh()),
        "fish" => Some(fish()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_shells_mention_every_command() {
        for (name, text) in [("bash", bash()), ("zsh", zsh()), ("fish", fish())] {
            for c in SUBS {
                assert!(text.contains(c.name), "{} completion lacks {}", name, c.name);
            }
            assert!(text.contains("__hosts"), "{}", name);
        }
        assert!(script("powershell").is_none());
    }

    #[test]
    fn bash_script_is_valid_bash() {
        let Ok(mut child) = std::process::Command::new("bash").arg("-n").stdin(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn() else {
            eprintln!("SKIPPED: no bash");
            return;
        };
        use std::io::Write;
        child.stdin.take().unwrap().write_all(bash().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}
