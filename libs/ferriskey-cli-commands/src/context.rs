use clap::{Args, Subcommand};

/// Manage connection contexts.
#[derive(Debug, Args)]
pub struct ContextCommand {
    /// Context command to execute.
    #[command(subcommand)]
    pub command: ContextSubcommand,
}

/// Available context commands.
#[derive(Debug, Subcommand)]
pub enum ContextSubcommand {
    /// List available contexts.
    List,
    /// Show the context configuration file path.
    Path,
    /// Switch the active context.
    Use(ContextUseArgs),
    /// Show the active context.
    Current,
    /// Add a new context.
    Add(ContextAddArgs),
    /// Remove a context.
    Remove(ContextRemoveArgs),
}

/// Arguments for switching the active context.
#[derive(Debug, Args)]
pub struct ContextUseArgs {
    /// Context name.
    pub name: String,
}

/// Arguments for adding a context.
#[derive(Debug, Args)]
pub struct ContextAddArgs {
    /// Context name.
    pub name: String,

    /// FerrisKey server URL.
    #[arg(long)]
    pub url: String,

    /// OAuth2 client identifier.
    #[arg(long = "client-id")]
    pub client_id: String,

    /// OAuth2 client secret.
    #[arg(long = "client-secret")]
    pub client_secret: String,

    /// Default realm for this context.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for removing a context.
#[derive(Debug, Args)]
pub struct ContextRemoveArgs {
    /// Context name.
    pub name: String,
}
