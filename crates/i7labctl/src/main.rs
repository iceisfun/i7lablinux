fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(i7labctl::main_with_args(args));
}
