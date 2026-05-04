mod client;
mod config;
mod context;
mod realm;
mod user;

use config::StoredContext;
use ferriskey_commands::{Cli, Commands};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CliCoreError>;

#[derive(Debug, Error)]
pub enum CliCoreError {
    #[error(transparent)]
    Client(#[from] client::ClientCommandError),
    #[error(transparent)]
    Context(#[from] context::ContextCommandError),
    #[error(transparent)]
    Realm(#[from] realm::RealmCommandError),
    #[error(transparent)]
    User(#[from] user::UserCommandError),
}

pub fn run(cli: Cli) -> Result<()> {
    let inline_context = build_inline_context(&cli);
    match cli.command {
        Commands::Context(command) => Ok(context::run(cli.output.as_str(), command)?),
        Commands::Realm(command) => Ok(realm::run(
            cli.output.as_str(),
            cli.context.as_deref(),
            inline_context,
            command,
        )?),
        Commands::Client(command) => Ok(client::run(
            cli.output.as_str(),
            cli.context.as_deref(),
            inline_context,
            command,
        )?),
        Commands::User(command) => Ok(user::run(
            cli.output.as_str(),
            cli.context.as_deref(),
            inline_context,
            command,
        )?),
    }
}

fn build_inline_context(cli: &Cli) -> Option<StoredContext> {
    match (&cli.url, &cli.client_id, &cli.client_secret) {
        (Some(url), Some(client_id), Some(client_secret)) => Some(StoredContext {
            url: url.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            realm: cli.realm.clone(),
        }),
        _ => None,
    }
}
