use std::process::ExitCode;

fn main() -> ExitCode {
    let code = hardening_gate::cli::run_with_args(std::env::args().skip(1));
    ExitCode::from(code as u8)
}
