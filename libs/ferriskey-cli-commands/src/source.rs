use clap::{Args, Subcommand, ValueEnum};

/// Manage reusable import sources.
#[derive(Debug, Args)]
pub struct SourceCommand {
    /// Source command to execute.
    #[command(subcommand)]
    pub command: SourceSubcommand,
}

/// Available source commands.
#[derive(Debug, Subcommand)]
pub enum SourceSubcommand {
    /// List configured sources.
    List,
    /// Add (or overwrite) a source.
    Add(SourceAddArgs),
    /// Remove a source.
    Remove(SourceRemoveArgs),
}

/// Kind of an import source.
#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SourceKind {
    Keycloak,
    Zitadel,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Keycloak => "keycloak",
            SourceKind::Zitadel => "zitadel",
        }
    }
}

/// Arguments for adding a source.
#[derive(Debug, Args)]
pub struct SourceAddArgs {
    /// Source name.
    pub name: String,

    /// Source kind.
    #[arg(long = "kind", value_enum)]
    pub kind: SourceKind,

    /// Base URL of the source instance.
    #[arg(long)]
    pub url: String,

    /// Source realm name (Keycloak).
    #[arg(long)]
    pub realm: Option<String>,

    /// Client id used to authenticate against the source (Keycloak client credentials).
    #[arg(long = "client-id")]
    pub client_id: Option<String>,

    /// Client secret used to authenticate against the source (Keycloak client credentials).
    #[arg(long = "client-secret")]
    pub client_secret: Option<String>,

    /// Bearer token / personal access token (Zitadel PAT, or a ready Keycloak token).
    #[arg(long)]
    pub token: Option<String>,

    /// Organization id (Zitadel). When omitted, all organizations are imported.
    #[arg(long = "org-id")]
    pub org_id: Option<String>,
}

/// Arguments for removing a source.
#[derive(Debug, Args)]
pub struct SourceRemoveArgs {
    /// Source name.
    pub name: String,
}
