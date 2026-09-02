mod client;
mod context;
mod login;
mod realm;
mod source;
mod user;

pub use self::client::{
    ClientCommand, ClientCreateArgs, ClientDeleteArgs, ClientGetArgs, ClientListArgs,
    ClientSubcommand, ClientType,
};
pub use self::context::{
    ContextAddArgs, ContextCommand, ContextRemoveArgs, ContextSubcommand, ContextUseArgs,
};
pub use self::login::LoginCommand;
pub use self::realm::{
    ImportSource, RealmCommand, RealmDeleteArgs, RealmImportArgs, RealmNameArgs, RealmRoleCommand,
    RealmRoleCreateArgs, RealmRoleListArgs, RealmRoleSubcommand, RealmSubcommand,
};
pub use self::source::{
    SourceAddArgs, SourceCommand, SourceKind, SourceRemoveArgs, SourceSubcommand,
};
pub use self::user::{
    UserCommand, UserCreateArgs, UserDeleteArgs, UserGetArgs, UserListArgs, UserSubcommand,
};
use clap::{Parser, Subcommand};

/// FerrisKey CLI.
#[derive(Debug, Parser)]
#[command(name = "ferris-ctl", about = "FerrisKey CLI")]
pub struct Cli {
    /// Override the active context for this command.
    #[arg(long, global = true)]
    pub context: Option<String>,

    /// Output format.
    #[arg(long, short = 'o', global = true, value_parser = ["table", "json", "yaml"], default_value = "table")]
    pub output: String,

    /// FerrisKey server URL (overrides context file).
    #[arg(long, global = true, env = "FERRISKEY_URL")]
    pub url: Option<String>,

    /// Client ID used for authentication (overrides context file).
    #[arg(long, global = true, env = "FERRISKEY_CLIENT_ID")]
    pub client_id: Option<String>,

    /// Client secret used for authentication (overrides context file).
    #[arg(long, global = true, env = "FERRISKEY_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    /// Default realm (overrides context file).
    #[arg(long, global = true, env = "FERRISKEY_REALM")]
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
    /// Manage reusable import sources.
    Source(source::SourceCommand),
    /// Sign in via the OAuth 2.0 Device Authorization Grant.
    Login(login::LoginCommand),
    /// Remove the stored login session (deletes the credentials file).
    Logout,
}
