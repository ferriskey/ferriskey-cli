use clap::Parser;
use ferriskey_cli_core::CliCoreError;
use ferriskey_cli_core::run;
use ferriskey_commands::Cli;

fn main() -> Result<(), Box<CliCoreError>> {
    run(Cli::parse()).map_err(Box::new)
}
