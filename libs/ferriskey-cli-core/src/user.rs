use ferriskey_client::{
    CreateUserRequest, FerriskeyClient, FerriskeyClientError, UserRepresentation,
};
use ferriskey_commands::{
    UserCommand, UserCreateArgs, UserDeleteArgs, UserGetArgs, UserListArgs, UserSubcommand,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::{ConfigError, FileContextRepository, StoredContext};

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
    }
}

#[derive(Debug, Error)]
pub enum UserCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
    #[error("context '{0}' does not exist")]
    ContextNotFound(String),
    #[error("no active context is configured")]
    NoActiveContext,
    #[error(
        "realm is required: pass '--realm' or configure a default realm on the selected context"
    )]
    MissingRealm,
    #[error("user '{0}' not found")]
    UserNotFound(String),
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

fn authenticate(context: &StoredContext, realm: &str) -> Result<FerriskeyClient> {
    let unauthenticated = FerriskeyClient::new(context.url.clone(), "", "")?;
    let token = unauthenticated.exchange_client_credentials(
        realm,
        context.client_id.as_str(),
        context.client_secret.as_str(),
    )?;
    Ok(FerriskeyClient::new(
        context.url.clone(),
        "",
        token.access_token,
    )?)
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
    let client = authenticate(&context, &realm)?;
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
    let client = authenticate(&context, &realm)?;
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
    let client = authenticate(&context, &realm)?;
    let request = CreateUserRequest {
        username: args.username,
        firstname: args.firstname,
        lastname: args.lastname,
        email: args.email,
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
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = authenticate(&context, &realm)?;
    let user = find_user(&client, &realm, &args.username)?;
    client.delete_user(&realm, &user.id)?;
    render_message(output_format, &format!("user '{}' deleted", args.username))
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
    use ferriskey_client::UserRepresentation;

    fn make_context(realm: Option<&str>) -> StoredContext {
        StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: "secret".to_owned(),
            realm: realm.map(str::to_owned),
        }
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
}
