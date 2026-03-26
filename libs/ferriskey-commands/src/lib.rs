mod client;
mod context;
mod realm;
mod user;

pub use self::client::{ClientCommand, ClientListArgs, ClientSubcommand};
pub use self::context::{
    ContextAddArgs, ContextCommand, ContextRemoveArgs, ContextSubcommand, ContextUseArgs,
};
use clap::{Parser, Subcommand};

/// FerrisKey CLI.
#[derive(Debug, Parser)]
#[command(name = "ferriskey", about = "FerrisKey CLI")]
pub struct Cli {
    /// Override the active context for this command.
    #[arg(long)]
    pub context: Option<String>,

    /// Output format.
    #[arg(long, short = 'o', value_parser = ["table", "json", "yaml"], default_value = "table")]
    pub output: String,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level FerrisKey commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage connection contexts.
    Context(context::ContextCommand),
    /// Manage realms.
    Realm(realm::RealmCommand),
    /// Manage OAuth2 clients.
    Client(client::ClientCommand),
    /// Manage users.
    User(user::UserCommand),
}
