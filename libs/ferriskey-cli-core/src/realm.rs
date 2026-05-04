use ferriskey_client::{CreateRealmRequest, FerriskeyClient, FerriskeyClientError, Realm};
use ferriskey_commands::{RealmCommand, RealmNameArgs, RealmSubcommand};
use serde::Serialize;
use thiserror::Error;

use crate::config::{ConfigError, FileContextRepository, StoredContext};

type Result<T> = std::result::Result<T, RealmCommandError>;

pub fn run(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    command: RealmCommand,
) -> Result<()> {
    match command.command {
        RealmSubcommand::List => list_realms(output_format, context_override, inline_context),
        RealmSubcommand::Get(args) => get_realm(output_format, context_override, inline_context, args),
        RealmSubcommand::Create(args) => {
            create_realm(output_format, context_override, inline_context, args)
        }
        RealmSubcommand::Delete(args) => {
            delete_realm(output_format, context_override, inline_context, args)
        }
    }
}

#[derive(Debug, Error)]
pub enum RealmCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
    #[error("context '{0}' does not exist")]
    ContextNotFound(String),
    #[error("no active context is configured")]
    NoActiveContext,
    #[error(
        "auth realm is required: pass '--realm' or configure a default realm on the selected context"
    )]
    MissingAuthRealm,
    #[error("realm '{0}' not found")]
    RealmNotFound(String),
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
struct RealmView {
    id: String,
    name: String,
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
            .ok_or(RealmCommandError::NoActiveContext)?,
    };
    store
        .contexts
        .get(&context_name)
        .cloned()
        .ok_or(RealmCommandError::ContextNotFound(context_name))
}

fn auth_client(context: &StoredContext) -> Result<FerriskeyClient> {
    let auth_realm = context
        .realm
        .as_deref()
        .ok_or(RealmCommandError::MissingAuthRealm)?;
    let unauthenticated = FerriskeyClient::new(context.url.clone(), "", "")?;
    let token = unauthenticated.exchange_client_credentials(
        auth_realm,
        context.client_id.as_str(),
        context.client_secret.as_str(),
    )?;
    Ok(FerriskeyClient::new(
        context.url.clone(),
        "",
        token.access_token,
    )?)
}

fn to_view(realm: Realm) -> RealmView {
    RealmView {
        id: realm.id,
        name: realm.name,
    }
}

fn list_realms(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let auth_realm = context
        .realm
        .clone()
        .ok_or(RealmCommandError::MissingAuthRealm)?;
    let client = auth_client(&context)?;
    let realms = client.list_realms(&auth_realm)?;
    let views: Vec<RealmView> = realms.into_iter().map(to_view).collect();
    render_realm_list(output_format, &views)
}

fn get_realm(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmNameArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let client = auth_client(&context)?;
    let realm = client.get_realm(&args.name)?;
    render_realm(output_format, to_view(realm))
}

fn create_realm(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmNameArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let client = auth_client(&context)?;
    let request = CreateRealmRequest { name: args.name };
    let realm = client.create_realm(&request)?;
    render_realm(output_format, to_view(realm))
}

fn delete_realm(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmNameArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let client = auth_client(&context)?;
    client.delete_realm(&args.name)?;
    render_message(output_format, &format!("realm '{}' deleted", args.name))
}

fn render_realm_list(output_format: &str, realms: &[RealmView]) -> Result<()> {
    match output_format {
        "table" => {
            let name_width = realms
                .iter()
                .map(|r| r.name.len())
                .max()
                .unwrap_or(0)
                .max("NAME".len());
            let id_width = realms
                .iter()
                .map(|r| r.id.len())
                .max()
                .unwrap_or(0)
                .max("ID".len());

            println!("{:<name_width$}  {:<id_width$}", "NAME", "ID");
            for r in realms {
                println!("{:<name_width$}  {:<id_width$}", r.name, r.id);
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(realms)
                    .map_err(|source| RealmCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(realms)
                    .map_err(|source| RealmCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_realm(output_format: &str, realm: RealmView) -> Result<()> {
    match output_format {
        "table" => {
            println!("id: {}", realm.id);
            println!("name: {}", realm.name);
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&realm)
                    .map_err(|source| RealmCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&realm)
                    .map_err(|source| RealmCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
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
                    .map_err(|source| RealmCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}
