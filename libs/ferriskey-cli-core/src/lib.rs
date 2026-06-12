mod auth;
mod client;
mod config;
mod context;
mod credentials;
mod import;
mod realm;
mod session;
mod source;
mod user;

use config::StoredContext;
use ferriskey_cli_commands::{Cli, Commands};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CliCoreError>;

#[derive(Debug, Error)]
pub enum CliCoreError {
    #[error(transparent)]
    Client(#[from] client::ClientCommandError),
    #[error(transparent)]
    Context(#[from] context::ContextCommandError),
    #[error(transparent)]
    Login(#[from] auth::LoginCommandError),
    #[error(transparent)]
    Realm(#[from] realm::RealmCommandError),
    #[error(transparent)]
    Source(#[from] source::SourceCommandError),
    #[error(transparent)]
    User(#[from] user::UserCommandError),
}

impl CliCoreError {
    /// Process exit code for this error. Defaults to 1; Ctrl-C during login
    /// surfaces as 130 (the conventional value for SIGINT).
    pub fn exit_code(&self) -> i32 {
        match self {
            CliCoreError::Login(err) => err.exit_code(),
            _ => 1,
        }
    }
}

#[allow(clippy::result_large_err)]
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
        Commands::Source(command) => Ok(source::run(cli.output.as_str(), command)?),
        Commands::Login(command) => Ok(auth::run(
            cli.context.as_deref(),
            cli.url.as_deref(),
            cli.client_id.as_deref(),
            cli.realm.as_deref(),
            command,
        )?),
    }
}

fn build_inline_context(cli: &Cli) -> Option<StoredContext> {
    match (&cli.url, &cli.client_id) {
        (Some(url), Some(client_id)) => Some(StoredContext {
            url: url.clone(),
            client_id: client_id.clone(),
            client_secret: cli.client_secret.clone(),
            realm: cli.realm.clone(),
        }),
        _ => None,
    }
}
