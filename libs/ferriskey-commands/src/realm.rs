use clap::{Args, Subcommand};

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
}

/// Arguments using a realm name.
#[derive(Debug, Args)]
pub struct RealmNameArgs {
    /// Realm name.
    pub name: String,
}
