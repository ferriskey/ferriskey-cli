use clap::{Args, Subcommand};

/// Manage OAuth2 clients.
#[derive(Debug, Args)]
pub struct ClientCommand {
    /// Client command to execute.
    #[command(subcommand)]
    pub command: ClientSubcommand,
}

/// Available client commands.
#[derive(Debug, Subcommand)]
pub enum ClientSubcommand {
    /// List clients in a realm.
    List(ClientListArgs),
    /// Show client details.
    Get(ClientGetArgs),
    /// Create a client.
    Create(ClientCreateArgs),
    /// Delete a client.
    Delete(ClientDeleteArgs),
}

/// Arguments for listing clients.
#[derive(Debug, Args)]
pub struct ClientListArgs {
    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for retrieving a client.
#[derive(Debug, Args)]
pub struct ClientGetArgs {
    /// Client identifier.
    pub client_id: String,

    /// Realm name.
    #[arg(long)]
    pub realm: String,
}

/// Arguments for creating a client.
#[derive(Debug, Args)]
pub struct ClientCreateArgs {
    /// Client name.
    pub name: String,

    /// Realm name.
    #[arg(long)]
    pub realm: String,
}

/// Arguments for deleting a client.
#[derive(Debug, Args)]
pub struct ClientDeleteArgs {
    /// Client identifier.
    pub client_id: String,

    /// Realm name.
    #[arg(long)]
    pub realm: String,
}
