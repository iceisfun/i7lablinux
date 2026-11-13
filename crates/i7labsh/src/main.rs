//! i7labsh binary: `i7labsh` (interactive), `i7labsh -l` (login shell: banner), `i7labsh -c 'line'`,
//! `i7labsh FILE` (run a script), `i7labsh -h`.

use std::io::IsTerminal;

const HELP: &str = "usage: i7labsh [-l] | -c LINE | FILE\n  no args   interactive shell (line editor on a terminal, plain lines otherwise)\n  -l        login shell: print the banner first\n  -c LINE   run LINE (may hold several lines) and exit with its status\n  FILE      run a script\nThe builtins are listed by `help`.\n";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("-h") | Some("--help") => {
            print!("{HELP}");
            0
        }
        Some("-c") => match args.get(1) {
            Some(line) => {
                let mut sh = i7labsh::Shell::new(false);
                sh.run_line(line)
            }
            None => {
                eprint!("i7labsh: -c needs an argument\n{HELP}");
                2
            }
        },
        Some("-l") => {
            let mut sh = i7labsh::Shell::new(true);
            if std::io::stdin().is_terminal() {
                print!("{}", i7labsh::repl::banner());
            }
            sh.repl()
        }
        Some(f) if !f.starts_with('-') => match std::fs::read_to_string(f) {
            Ok(text) => {
                let mut sh = i7labsh::Shell::new(false);
                sh.run_line(&text)
            }
            Err(e) => {
                eprintln!("i7labsh: {f}: {e}");
                127
            }
        },
        Some(other) => {
            eprint!("i7labsh: unknown option {other}\n{HELP}");
            2
        }
        None => i7labsh::Shell::new(true).repl(),
    };
    std::process::exit(code);
}
