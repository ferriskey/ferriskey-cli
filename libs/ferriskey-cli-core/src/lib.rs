mod client;
mod config;
mod context;

use ferriskey_commands::{Cli, Commands};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CliCoreError>;

#[derive(Debug, Error)]
pub enum CliCoreError {
    #[error(transparent)]
    Client(#[from] client::ClientCommandError),
    #[error(transparent)]
    Context(#[from] context::ContextCommandError),
    #[error("command '{0}' is not implemented yet")]
    UnimplementedCommand(&'static str),
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Context(command) => Ok(context::run(cli.output.as_str(), command)?),
        Commands::Realm(_) => Err(CliCoreError::UnimplementedCommand("realm")),
        Commands::Client(command) => Ok(client::run(
            cli.output.as_str(),
            cli.context.as_deref(),
            command,
        )?),
        Commands::User(_) => Err(CliCoreError::UnimplementedCommand("user")),
    }
}
