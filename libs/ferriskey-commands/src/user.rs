
use clap::{Args, Subcommand};

/// Manage users.
#[derive(Debug, Args)]
pub struct UserCommand {
    /// User command to execute.
    #[command(subcommand)]
    pub command: UserSubcommand,
}

/// Available user commands.
#[derive(Debug, Subcommand)]
pub enum UserSubcommand {
    /// List users in a realm.
    List(UserListArgs),
    /// Show user details.
    Get(UserGetArgs),
    /// Create a user.
    Create(UserCreateArgs),
    /// Delete a user.
    Delete(UserDeleteArgs),
}

/// Arguments for listing users.
#[derive(Debug, Args)]
pub struct UserListArgs {
    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for retrieving a user.
#[derive(Debug, Args)]
pub struct UserGetArgs {
    /// Username.
    pub username: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for creating a user.
#[derive(Debug, Args)]
pub struct UserCreateArgs {
    /// Username.
    pub username: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// User email.
    #[arg(long)]
    pub email: Option<String>,

    /// User first name.
    #[arg(long)]
    pub firstname: Option<String>,

    /// User last name.
    #[arg(long)]
    pub lastname: Option<String>,
}

/// Arguments for deleting a user.
#[derive(Debug, Args)]
pub struct UserDeleteArgs {
    /// Username.
    pub username: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}
