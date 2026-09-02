use std::io::Read;

use ferriskey_cli_client::{
    CreateUserRequest, CreatedRole, FerriskeyClient, FerriskeyClientError, SetPasswordRequest,
    UserRepresentation,
};
use ferriskey_cli_commands::{
    UserAssignRoleArgs, UserCommand, UserCreateArgs, UserDeleteArgs, UserGetArgs, UserListArgs,
    UserRemoveRoleArgs, UserRolesArgs, UserSetPasswordArgs, UserSubcommand,
};
use serde::Serialize;
use thiserror::Error;

use crate::confirm::{self, confirm};
use crate::config::{ConfigError, FileContextRepository, StoredContext};
use crate::session::{self, SessionError};

type Result<T> = std::result::Result<T, UserCommandError>;

pub fn run(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    command: UserCommand,
) -> Result<()> {
    match command.command {
        UserSubcommand::List(args) => {
            list_users(output_format, context_override, inline_context, args)
        }
        UserSubcommand::Get(args) => {
            get_user(output_format, context_override, inline_context, args)
        }
        UserSubcommand::Create(args) => {
            create_user(output_format, context_override, inline_context, args)
        }
        UserSubcommand::Delete(args) => {
            delete_user(output_format, context_override, inline_context, args)
        }
        UserSubcommand::AssignRole(args) => {
            assign_role(output_format, context_override, inline_context, args)
        }
        UserSubcommand::RemoveRole(args) => {
            remove_role(output_format, context_override, inline_context, args)
        }
        UserSubcommand::Roles(args) => {
            list_user_roles(output_format, context_override, inline_context, args)
        }
        UserSubcommand::SetPassword(args) => {
            set_password(output_format, context_override, inline_context, args)
        }
    }
}

#[derive(Debug, Error)]
pub enum UserCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Confirm(#[from] confirm::ConfirmError),
    #[error("context '{0}' does not exist")]
    ContextNotFound(String),
    #[error("no active context is configured")]
    NoActiveContext,
    #[error(
        "realm is required: pass '--realm' or configure a default realm on the selected context"
    )]
    MissingRealm,
    #[error(
        "auth realm is required: configure a default realm on the selected context ('ferris-ctl context add --realm <realm>')"
    )]
    MissingAuthRealm,
    #[error("user '{0}' not found")]
    UserNotFound(String),
    #[error("role '{0}' not found in realm")]
    RoleNotFound(String),
    #[error("pass exactly one of '--password' or '--stdin'")]
    InvalidPasswordSource,
    #[error("failed to read password from stdin")]
    ReadStdin {
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported output format: {0}")]
    UnsupportedOutputFormat(String),
    #[error("failed to serialize JSON output")]
    SerializeJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize YAML output")]
    SerializeYaml {
        #[source]
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Serialize)]
struct UserView {
    id: String,
    username: String,
    firstname: String,
    lastname: String,
    email: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct RoleView {
    id: String,
    name: String,
}

fn to_role_view(role: CreatedRole) -> RoleView {
    RoleView {
        id: role.id,
        name: role.name,
    }
}

fn resolve_context(
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
) -> Result<StoredContext> {
    if let Some(ctx) = inline_context {
        return Ok(ctx);
    }
    let repository = FileContextRepository::new()?;
    let store = repository.load()?;
    let context_name = match context_override {
        Some(name) => name.to_owned(),
        None => store
            .current_context
            .clone()
            .ok_or(UserCommandError::NoActiveContext)?,
    };
    store
        .contexts
        .get(&context_name)
        .cloned()
        .ok_or(UserCommandError::ContextNotFound(context_name))
}

fn resolve_realm(context: &StoredContext, realm: Option<String>) -> Result<String> {
    realm
        .or_else(|| context.realm.clone())
        .ok_or(UserCommandError::MissingRealm)
}

/// Authenticate against the context's home realm — where the context's
/// client_id/client_secret are registered — regardless of which realm the
/// command targets via `--realm`. The server, not the CLI, decides whether
/// the resulting token can act on the target realm.
fn auth_client(context: &StoredContext) -> Result<FerriskeyClient> {
    let auth_realm = context
        .realm
        .as_deref()
        .ok_or(UserCommandError::MissingAuthRealm)?;
    Ok(session::authenticated_client(context, auth_realm)?)
}

fn find_user(client: &FerriskeyClient, realm: &str, username: &str) -> Result<UserRepresentation> {
    let mut results = client.find_users_by_username(realm, username)?;
    results
        .drain(..)
        .find(|u| u.username == username)
        .ok_or_else(|| UserCommandError::UserNotFound(username.to_owned()))
}

fn to_view(user: UserRepresentation) -> UserView {
    UserView {
        id: user.id,
        username: user.username,
        firstname: user.firstname.unwrap_or_default(),
        lastname: user.lastname.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        enabled: user.enabled,
    }
}

fn list_users(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserListArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let users = client.list_users(&realm)?;
    let views: Vec<UserView> = users.into_iter().map(to_view).collect();
    render_user_list(output_format, &views)
}

fn get_user(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserGetArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let user = find_user(&client, &realm, &args.username)?;
    render_user(output_format, to_view(user))
}

fn create_user(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserCreateArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let request = CreateUserRequest {
        username: args.username,
        firstname: args.firstname,
        lastname: args.lastname,
        email: args.email,
        email_verified: None,
    };
    let user = client.create_user(&realm, &request)?;
    render_user(output_format, to_view(user))
}

fn delete_user(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserDeleteArgs,
) -> Result<()> {
    confirm(
        &format!("Delete user '{}'?", args.username),
        args.force,
    )?;
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let user = find_user(&client, &realm, &args.username)?;
    client.delete_user(&realm, &user.id)?;
    render_message(output_format, &format!("user '{}' deleted", args.username))
}

fn resolve_role(client: &FerriskeyClient, realm: &str, role_name: &str) -> Result<CreatedRole> {
    client
        .list_realm_roles(realm)?
        .into_iter()
        .find(|r| r.name == role_name)
        .ok_or_else(|| UserCommandError::RoleNotFound(role_name.to_owned()))
}

fn assign_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserAssignRoleArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let user = find_user(&client, &realm, &args.username)?;
    let role = resolve_role(&client, &realm, &args.role)?;
    client.assign_user_role(&realm, &user.id, &role.id)?;
    render_message(
        output_format,
        &format!(
            "role '{}' assigned to user '{}'",
            args.role, args.username
        ),
    )
}

fn remove_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserRemoveRoleArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = authenticate(&context, &realm)?;
    let user = find_user(&client, &realm, &args.username)?;
    let role = resolve_role(&client, &realm, &args.role)?;
    client.remove_user_role(&realm, &user.id, &role.id)?;
    render_message(
        output_format,
        &format!(
            "role '{}' removed from user '{}'",
            args.role, args.username
        ),
    )
}

fn list_user_roles(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserRolesArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = authenticate(&context, &realm)?;
    let user = find_user(&client, &realm, &args.username)?;
    let roles = client.list_user_roles(&realm, &user.id)?;
    let views: Vec<RoleView> = roles.into_iter().map(to_role_view).collect();
    render_role_list(output_format, &views)
}

/// Where `set-password` reads the new password from — resolved before any
/// I/O so the "exactly one source" rule stays pure and testable.
#[derive(Debug, PartialEq, Eq)]
enum PasswordSource {
    Literal(String),
    Stdin,
}

fn resolve_password_source(
    password: Option<String>,
    stdin: bool,
) -> Result<PasswordSource> {
    match (password, stdin) {
        (Some(password), false) => Ok(PasswordSource::Literal(password)),
        (None, true) => Ok(PasswordSource::Stdin),
        _ => Err(UserCommandError::InvalidPasswordSource),
    }
}

fn set_password(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: UserSetPasswordArgs,
) -> Result<()> {
    let value = match resolve_password_source(args.password, args.stdin)? {
        PasswordSource::Literal(password) => password,
        PasswordSource::Stdin => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|source| UserCommandError::ReadStdin { source })?;
            buf.trim_end_matches(['\n', '\r']).to_owned()
        }
    };

    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = authenticate(&context, &realm)?;
    let user = find_user(&client, &realm, &args.username)?;
    client.set_user_password(
        &realm,
        &user.id,
        &SetPasswordRequest {
            value,
            temporary: args.temporary,
        },
    )?;
    render_message(
        output_format,
        &format!("password set for user '{}'", args.username),
    )
}

fn render_user_list(output_format: &str, users: &[UserView]) -> Result<()> {
    match output_format {
        "table" => {
            let username_width = users
                .iter()
                .map(|u| u.username.len())
                .max()
                .unwrap_or(0)
                .max("USERNAME".len());
            let email_width = users
                .iter()
                .map(|u| u.email.len())
                .max()
                .unwrap_or(0)
                .max("EMAIL".len());
            let id_width = users
                .iter()
                .map(|u| u.id.len())
                .max()
                .unwrap_or(0)
                .max("ID".len());

            println!(
                "{:<username_width$}  {:<email_width$}  {:<id_width$}  ENABLED",
                "USERNAME", "EMAIL", "ID"
            );
            for u in users {
                println!(
                    "{:<username_width$}  {:<email_width$}  {:<id_width$}  {}",
                    u.username, u.email, u.id, u.enabled
                );
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(users)
                    .map_err(|source| UserCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(users)
                    .map_err(|source| UserCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(UserCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_user(output_format: &str, user: UserView) -> Result<()> {
    match output_format {
        "table" => {
            println!("id: {}", user.id);
            println!("username: {}", user.username);
            println!("firstname: {}", user.firstname);
            println!("lastname: {}", user.lastname);
            println!("email: {}", user.email);
            println!("enabled: {}", user.enabled);
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&user)
                    .map_err(|source| UserCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&user)
                    .map_err(|source| UserCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(UserCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_role_list(output_format: &str, roles: &[RoleView]) -> Result<()> {
    match output_format {
        "table" => {
            let name_width = roles
                .iter()
                .map(|r| r.name.len())
                .max()
                .unwrap_or(0)
                .max("NAME".len());
            let id_width = roles
                .iter()
                .map(|r| r.id.len())
                .max()
                .unwrap_or(0)
                .max("ID".len());

            println!("{:<name_width$}  {:<id_width$}", "NAME", "ID");
            for r in roles {
                println!("{:<name_width$}  {:<id_width$}", r.name, r.id);
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(roles)
                    .map_err(|source| UserCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(roles)
                    .map_err(|source| UserCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(UserCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_message(output_format: &str, message: &str) -> Result<()> {
    match output_format {
        "table" => {
            println!("{message}");
            Ok(())
        }
        "json" => {
            println!("{}", serde_json::json!({ "message": message }));
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({ "message": message }))
                    .map_err(|source| UserCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(UserCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoredContext;
    use ferriskey_cli_client::UserRepresentation;

    fn make_context(realm: Option<&str>) -> StoredContext {
        StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: Some("secret".to_owned()),
            realm: realm.map(str::to_owned),
        }
    }

    #[test]
    fn auth_client_requires_realm_on_context() {
        // Regression: auth_client must authenticate against the context's
        // home realm, never a command's target `--realm` (which it doesn't
        // even take as a parameter) — a context without a home realm can't
        // authenticate at all, regardless of any target realm resolved
        // elsewhere.
        let context = make_context(None);
        let err = auth_client(&context).expect_err("missing realm should error");
        assert!(matches!(err, UserCommandError::MissingAuthRealm));
    }

    #[test]
    fn resolve_realm_prefers_explicit_argument() {
        let context = make_context(Some("master"));
        let realm = resolve_realm(&context, Some("other".to_owned())).expect("resolved");
        assert_eq!(realm, "other");
    }

    #[test]
    fn resolve_realm_falls_back_to_context_default() {
        let context = make_context(Some("master"));
        let realm = resolve_realm(&context, None).expect("resolved");
        assert_eq!(realm, "master");
    }

    #[test]
    fn resolve_realm_errors_when_missing_everywhere() {
        let context = make_context(None);
        let err = resolve_realm(&context, None).expect_err("realm should be required");
        assert!(matches!(err, UserCommandError::MissingRealm));
    }

    #[test]
    fn to_view_fills_optional_fields_with_defaults() {
        let user = UserRepresentation {
            id: "uuid-123".to_owned(),
            username: "alice".to_owned(),
            firstname: None,
            lastname: None,
            email: None,
            enabled: true,
        };
        let view = to_view(user);
        assert_eq!(view.id, "uuid-123");
        assert_eq!(view.username, "alice");
        assert_eq!(view.firstname, "");
        assert_eq!(view.lastname, "");
        assert_eq!(view.email, "");
        assert!(view.enabled);
    }

    #[test]
    fn to_view_preserves_present_fields() {
        let user = UserRepresentation {
            id: "uuid-456".to_owned(),
            username: "bob".to_owned(),
            firstname: Some("Bob".to_owned()),
            lastname: Some("Smith".to_owned()),
            email: Some("bob@example.com".to_owned()),
            enabled: false,
        };
        let view = to_view(user);
        assert_eq!(view.firstname, "Bob");
        assert_eq!(view.lastname, "Smith");
        assert_eq!(view.email, "bob@example.com");
        assert!(!view.enabled);
    }

    #[test]
    fn render_user_list_table_succeeds() {
        let users = vec![UserView {
            id: "uuid-1".to_owned(),
            username: "alice".to_owned(),
            firstname: "Alice".to_owned(),
            lastname: "Wonder".to_owned(),
            email: "alice@example.com".to_owned(),
            enabled: true,
        }];
        assert!(render_user_list("table", &users).is_ok());
    }

    #[test]
    fn render_user_list_table_empty_succeeds() {
        assert!(render_user_list("table", &[]).is_ok());
    }

    #[test]
    fn render_user_list_rejects_unknown_format() {
        let err = render_user_list("xml", &[]).expect_err("unknown format should error");
        assert!(matches!(err, UserCommandError::UnsupportedOutputFormat(_)));
    }

    #[test]
    fn to_role_view_maps_id_and_name() {
        let role = CreatedRole {
            id: "r-1".to_owned(),
            name: "admin".to_owned(),
        };
        let view = to_role_view(role);
        assert_eq!(view.id, "r-1");
        assert_eq!(view.name, "admin");
    }

    #[test]
    fn render_role_list_table_and_json_succeed() {
        let roles = vec![RoleView {
            id: "r-1".to_owned(),
            name: "admin".to_owned(),
        }];
        assert!(render_role_list("table", &roles).is_ok());
        assert!(render_role_list("json", &roles).is_ok());
        assert!(render_role_list("table", &[]).is_ok());
    }

    #[test]
    fn resolve_password_source_accepts_literal_password() {
        let source = resolve_password_source(Some("secret".to_owned()), false).expect("resolved");
        assert_eq!(source, PasswordSource::Literal("secret".to_owned()));
    }

    #[test]
    fn resolve_password_source_accepts_stdin() {
        let source = resolve_password_source(None, true).expect("resolved");
        assert_eq!(source, PasswordSource::Stdin);
    }

    #[test]
    fn resolve_password_source_rejects_neither() {
        let err = resolve_password_source(None, false).expect_err("should require a source");
        assert!(matches!(err, UserCommandError::InvalidPasswordSource));
    }

    #[test]
    fn resolve_password_source_rejects_both() {
        let err = resolve_password_source(Some("secret".to_owned()), true)
            .expect_err("should reject both sources");
        assert!(matches!(err, UserCommandError::InvalidPasswordSource));
    }
}
