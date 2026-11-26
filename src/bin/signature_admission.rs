use release_signature_admission::{AdmissionEngine, AdmissionRequest, E_CONFIG_IO, E_REQUEST_IO};
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: signature-admission --config <policy.json> --request <request.json>

The request file may be '-' to read from stdin. The command prints the complete
policy chain as JSON and exits 0 for allow, 1 for deny, and 2 for invalid input.
";

enum Command {
    Run(Args),
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    config: String,
    request: String,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Command::Run(args)) => args,
        Ok(Command::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Command::Version) => {
            println!("signature-admission {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let config = match fs::read_to_string(&args.config) {
        Ok(config) => config,
        Err(error) => {
            return print_error(E_CONFIG_IO, &format!("cannot read policy config: {error}"))
        }
    };
    let request = match read_request(&args.request) {
        Ok(request) => request,
        Err(error) => return print_error(E_REQUEST_IO, &format!("cannot read request: {error}")),
    };

    let engine = match AdmissionEngine::from_json_str(&config) {
        Ok(engine) => engine,
        Err(error) => return print_error(error.code(), error.message()),
    };
    let request = match AdmissionRequest::from_json_str(&request) {
        Ok(request) => request,
        Err(error) => return print_error(error.code(), error.message()),
    };
    let report = engine.evaluate(&request);
    println!("{}", report.to_json_string_pretty());
    if report.is_allowed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut config = None;
    let mut request = None;
    let mut positional = Vec::new();
    let mut arguments = arguments.peekable();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--config" => {
                config = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--config requires a path".to_string())?,
                );
            }
            "--request" => {
                request = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--request requires a path".to_string())?,
                );
            }
            value if value.starts_with('-') && value != "-" => {
                return Err(format!("unknown option {value}"));
            }
            value => positional.push(value.to_string()),
        }
    }

    if config.is_none() && !positional.is_empty() {
        config = Some(positional.remove(0));
    }
    if request.is_none() && !positional.is_empty() {
        request = Some(positional.remove(0));
    }
    if !positional.is_empty() {
        return Err("too many positional arguments".to_string());
    }
    match (config, request) {
        (Some(config), Some(request)) => Ok(Command::Run(Args { config, request })),
        _ => Err("both --config and --request are required".to_string()),
    }
}

fn read_request(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        fs::read_to_string(path)
    }
}

fn print_error(code: &str, message: &str) -> ExitCode {
    println!(
        "{}",
        serde_json::json!({
            "decision": "error",
            "error": { "code": code, "message": message }
        })
    );
    ExitCode::from(2)
}
