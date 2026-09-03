use clap::{Args, Subcommand, ValueEnum};

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
    /// Print a confidential client's secret to stdout.
    Secret(ClientSecretArgs),
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

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for creating a client.
#[derive(Debug, Args)]
pub struct ClientCreateArgs {
    /// Client name.
    pub name: String,

    /// Client identifier. Defaults to the client name.
    #[arg(long = "client-id")]
    pub client_id: Option<String>,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// Client type.
    #[arg(long = "type", value_enum, default_value_t = ClientType::Public)]
    pub client_type: ClientType,

    /// Whether the client is enabled.
    #[arg(long, default_value_t = false)]
    pub enabled: bool,

    /// Protocol used by the client.
    #[arg(long, default_value = "openid-connect")]
    pub protocol: String,

    /// Whether direct access grants are enabled.
    #[arg(long = "direct-access-grants", default_value_t = false)]
    pub direct_access_grants_enabled: bool,
}

/// Arguments for reading a client's secret.
#[derive(Debug, Args)]
pub struct ClientSecretArgs {
    /// Client identifier.
    pub client_id: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Supported client types.
#[derive(Clone, Debug, ValueEnum)]
pub enum ClientType {
    /// Public client.
    Public,
    /// Confidential client.
    Confidential,
    /// System client.
    System,
}

/// Arguments for deleting a client.
#[derive(Debug, Args)]
pub struct ClientDeleteArgs {
    /// Client identifier.
    pub client_id: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// Skip the confirmation prompt (required in non-interactive shells).
    #[arg(long, short = 'f', default_value_t = false)]
    pub force: bool,
}
