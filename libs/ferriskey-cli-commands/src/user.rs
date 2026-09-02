
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
    /// Assign a realm role to a user.
    AssignRole(UserAssignRoleArgs),
    /// Remove a realm role from a user.
    RemoveRole(UserRemoveRoleArgs),
    /// List the realm roles assigned to a user.
    Roles(UserRolesArgs),
    /// Set a user's password.
    SetPassword(UserSetPasswordArgs),
}

/// Arguments for assigning a realm role to a user.
#[derive(Debug, Args)]
pub struct UserAssignRoleArgs {
    /// Username.
    pub username: String,

    /// Realm role name to assign.
    pub role: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for removing a realm role from a user.
#[derive(Debug, Args)]
pub struct UserRemoveRoleArgs {
    /// Username.
    pub username: String,

    /// Realm role name to remove.
    pub role: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for listing a user's realm roles.
#[derive(Debug, Args)]
pub struct UserRolesArgs {
    /// Username.
    pub username: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,
}

/// Arguments for setting a user's password.
#[derive(Debug, Args)]
pub struct UserSetPasswordArgs {
    /// Username.
    pub username: String,

    /// Realm name. Defaults to the selected context realm.
    #[arg(long)]
    pub realm: Option<String>,

    /// New password. Prefer `--stdin` — a value here lands in shell history
    /// and the process list.
    #[arg(long, conflicts_with = "stdin")]
    pub password: Option<String>,

    /// Read the new password from stdin (trailing newline trimmed).
    #[arg(long, default_value_t = false)]
    pub stdin: bool,

    /// Require the user to change this password on next login.
    #[arg(long, default_value_t = false)]
    pub temporary: bool,
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

    /// Skip the confirmation prompt (required in non-interactive shells).
    #[arg(long, short = 'f', default_value_t = false)]
    pub force: bool,
}
