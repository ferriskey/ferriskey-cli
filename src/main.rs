use clap::Parser;
use ferriskey_cli_commands::Cli;
use ferriskey_cli_core::run;

fn main() {
    if let Err(err) = run(Cli::parse()) {
        eprintln!("error: {err}");
        std::process::exit(err.exit_code());
    }
}
