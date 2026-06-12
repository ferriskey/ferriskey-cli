use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

/// Manage realms.
#[derive(Debug, Args)]
pub struct RealmCommand {
    /// Realm command to execute.
    #[command(subcommand)]
    pub command: RealmSubcommand,
}

/// Available realm commands.
#[derive(Debug, Subcommand)]
pub enum RealmSubcommand {
    /// List realms.
    List,
    /// Show realm details.
    Get(RealmNameArgs),
    /// Create a realm.
    Create(RealmNameArgs),
    /// Delete a realm.
    Delete(RealmNameArgs),
    /// Import a realm (settings, clients, roles, users) from an external source.
    Import(RealmImportArgs),
}

/// Arguments using a realm name.
#[derive(Debug, Args)]
pub struct RealmNameArgs {
    /// Realm name.
    pub name: String,
}

/// Source to import a realm from.
#[derive(Clone, Debug, ValueEnum)]
pub enum ImportSource {
    /// A FerrisKey-native realm description (YAML or TOML file).
    Config,
    /// A live Keycloak instance, read through its Admin REST API.
    Keycloak,
    /// A live Zitadel instance, read through its Management API.
    Zitadel,
}

/// Arguments for `realm import`.
#[derive(Debug, Args)]
pub struct RealmImportArgs {
    /// Source kind to import from. Optional when `--source-ref` is given (the
    /// kind is then read from the stored source).
    #[arg(long = "from", value_enum)]
    pub source: Option<ImportSource>,

    /// Name of a stored source (see `ferris-ctl source add`). Inline `--source-*`
    /// flags override individual fields of the stored source.
    #[arg(long = "source-ref")]
    pub source_ref: Option<String>,

    /// Path to the realm description file (required for `--from config`).
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Base URL of the source instance (required for `--from keycloak|zitadel`).
    #[arg(long = "source-url")]
    pub source_url: Option<String>,

    /// Source realm name (Keycloak).
    #[arg(long = "source-realm")]
    pub source_realm: Option<String>,

    /// Source organization id (Zitadel) — sent as the `x-zitadel-orgid` header to
    /// scope the Management API to that organization.
    #[arg(long = "source-org")]
    pub source_org: Option<String>,

    /// Client id used to authenticate against the source (Keycloak client credentials).
    #[arg(long = "source-client-id")]
    pub source_client_id: Option<String>,

    /// Client secret used to authenticate against the source (Keycloak client credentials).
    #[arg(long = "source-client-secret")]
    pub source_client_secret: Option<String>,

    /// Bearer token / personal access token for the source (Zitadel PAT, or a ready Keycloak token).
    #[arg(long = "source-token")]
    pub source_token: Option<String>,

    /// Override the name of the realm created in FerrisKey (defaults to the source realm name).
    #[arg(long = "target-realm")]
    pub target_realm: Option<String>,

    /// Resolve and print the planned realm without calling the FerrisKey API.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}
