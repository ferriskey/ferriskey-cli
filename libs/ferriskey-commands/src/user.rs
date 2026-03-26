
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
    /// Realm name.
    #[arg(long)]
    pub realm: String,
}

/// Arguments for retrieving a user.
#[derive(Debug, Args)]
pub struct UserGetArgs {
    /// Username.
    pub username: String,

    /// Realm name.
    #[arg(long)]
    pub realm: String,
}

/// Arguments for creating a user.
#[derive(Debug, Args)]
pub struct UserCreateArgs {
    /// Username.
    pub username: String,

    /// Realm name.
    #[arg(long)]
    pub realm: String,

    /// User email.
    #[arg(long)]
    pub email: String,

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

    /// Realm name.
    #[arg(long)]
    pub realm: String,
}
