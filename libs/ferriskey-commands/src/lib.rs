mod client;
mod context;
mod realm;
mod user;

pub use self::client::{
    ClientCommand, ClientCreateArgs, ClientGetArgs, ClientListArgs, ClientSubcommand, ClientType,
};
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

    /// FerrisKey server URL (overrides context file).
    #[arg(long, env = "FERRISKEY_URL")]
    pub url: Option<String>,

    /// Client ID used for authentication (overrides context file).
    #[arg(long, env = "FERRISKEY_CLIENT_ID")]
    pub client_id: Option<String>,

    /// Client secret used for authentication (overrides context file).
    #[arg(long, env = "FERRISKEY_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    /// Default realm (overrides context file).
    #[arg(long, env = "FERRISKEY_REALM")]
    pub realm: Option<String>,

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
