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
    Delete(RealmDeleteArgs),
    /// Manage realm roles.
    Role(RealmRoleCommand),
    /// Import a realm (settings, clients, roles, users) from an external source.
    Import(RealmImportArgs),
}

/// Manage realm roles.
#[derive(Debug, Args)]
pub struct RealmRoleCommand {
    /// Role command to execute.
    #[command(subcommand)]
    pub command: RealmRoleSubcommand,
}

/// Available realm role commands.
#[derive(Debug, Subcommand)]
pub enum RealmRoleSubcommand {
    /// Create a realm or client role.
    Create(RealmRoleCreateArgs),
    /// List realm or client roles.
    List(RealmRoleListArgs),
    /// Show a realm or client role's details.
    Get(RealmRoleGetArgs),
    /// Delete a realm or client role.
    Delete(RealmRoleDeleteArgs),
}

/// Arguments for `realm role create`.
#[derive(Debug, Args)]
pub struct RealmRoleCreateArgs {
    /// Role name.
    pub name: String,

    /// Role description.
    #[arg(long)]
    pub description: Option<String>,

    /// Permission granted by the role. Repeat for multiple permissions.
    #[arg(long = "permission")]
    pub permissions: Vec<String>,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// Create a client role instead of a realm role, scoped to this client id.
    #[arg(long)]
    pub client: Option<String>,
}

/// Arguments for `realm role list`.
#[derive(Debug, Args)]
pub struct RealmRoleListArgs {
    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// List roles of this client instead of realm roles.
    #[arg(long)]
    pub client: Option<String>,
}

/// Arguments for `realm role get`.
#[derive(Debug, Args)]
pub struct RealmRoleGetArgs {
    /// Role name.
    pub name: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// Look up a client role instead of a realm role, scoped to this client id.
    #[arg(long)]
    pub client: Option<String>,
}

/// Arguments for `realm role delete`.
#[derive(Debug, Args)]
pub struct RealmRoleDeleteArgs {
    /// Role name.
    pub name: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// Delete a client role instead of a realm role, scoped to this client id.
    #[arg(long)]
    pub client: Option<String>,

    /// Skip the confirmation prompt (required in non-interactive shells).
    #[arg(long, short = 'f', default_value_t = false)]
    pub force: bool,
}

/// Arguments using a realm name.
#[derive(Debug, Args)]
pub struct RealmNameArgs {
    /// Realm name.
    pub name: String,
}

/// Arguments for `realm delete`.
#[derive(Debug, Args)]
pub struct RealmDeleteArgs {
    /// Realm name.
    pub name: String,

    /// Skip the confirmation prompt (required in non-interactive shells).
    #[arg(long, short = 'f', default_value_t = false)]
    pub force: bool,
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
    /// A Supabase project, read through its Auth (GoTrue) Admin API. Users
    /// only: Supabase has no client or role catalogue. Password hashes are
    /// carried over when `--source-passwords` points at a CSV export of
    /// `auth.users`; without it, imported users need a password reset.
    Supabase,
}

/// Arguments for `realm import`.
#[derive(Debug, Default, Args)]
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

    /// Bearer token / personal access token for the source (Zitadel PAT,
    /// Supabase `service_role` key, or a ready Keycloak token).
    #[arg(long = "source-token")]
    pub source_token: Option<String>,

    /// Import users an operator soft-deleted (Supabase). Dropped by default:
    /// their `deleted_at` is set but the row survives, so a plain import would
    /// resurrect accounts somebody removed on purpose.
    #[arg(long = "source-include-deleted", default_value_t = false)]
    pub source_include_deleted: bool,

    /// Import anonymous sign-in sessions (Supabase). Dropped by default: they
    /// are real rows with neither an email nor a phone number.
    #[arg(long = "source-include-anonymous", default_value_t = false)]
    pub source_include_anonymous: bool,

    /// Import users who never confirmed an email or a phone number (Supabase).
    /// Dropped by default.
    #[arg(long = "source-include-unconfirmed", default_value_t = false)]
    pub source_include_unconfirmed: bool,

    /// Carry Supabase passwords over, read from a CSV export of the `auth.users`
    /// table (`select id, encrypted_password from auth.users`). The Auth Admin
    /// API never serves those hashes, so the export is the only way to get them.
    /// Only bcrypt hashes FerrisKey accepts are imported; every other account
    /// arrives without credentials and needs a password reset.
    #[arg(long = "source-passwords", value_name = "FILE")]
    pub source_passwords: Option<PathBuf>,

    /// Override the name of the realm created in FerrisKey (defaults to the source realm name).
    #[arg(long = "target-realm")]
    pub target_realm: Option<String>,

    /// Resolve and print the planned realm without calling the FerrisKey API.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}
