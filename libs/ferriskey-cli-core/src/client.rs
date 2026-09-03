use ferriskey_cli_client::{
    ClientRepresentation, CreateClientRequest, CreatedClient, FerriskeyClient, FerriskeyClientError,
};
use ferriskey_cli_commands::{
    ClientCommand, ClientCreateArgs, ClientDeleteArgs, ClientGetArgs, ClientListArgs,
    ClientSecretArgs, ClientSubcommand, ClientType,
};
use serde::Serialize;
use thiserror::Error;

use crate::confirm::{self, confirm};
use crate::config::{ConfigError, ContextStore, FileContextRepository, StoredContext};
use crate::session::{self, SessionError};

type Result<T> = std::result::Result<T, ClientCommandError>;

pub fn run(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    command: ClientCommand,
) -> Result<()> {
    match command.command {
        ClientSubcommand::List(args) => {
            list_clients(output_format, context_override, inline_context, args)
        }
        ClientSubcommand::Get(args) => {
            get_client(output_format, context_override, inline_context, args)
        }
        ClientSubcommand::Create(args) => {
            create_client(output_format, context_override, inline_context, args)
        }
        ClientSubcommand::Delete(args) => {
            delete_client(output_format, context_override, inline_context, args)
        }
        ClientSubcommand::Secret(args) => {
            get_client_secret(context_override, inline_context, args)
        }
    }
}

#[derive(Debug, Error)]
pub enum ClientCommandError {
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
    #[error("client '{0}' not found")]
    ClientNotFound(String),
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

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ClientView {
    id: String,
    client_id: String,
    name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ClientDetailView {
    id: String,
    client_id: String,
    name: String,
    realm: String,
    enabled: bool,
    protocol: String,
    public_client: bool,
    service_accounts_enabled: bool,
    direct_access_grants_enabled: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CreatedClientView {
    id: String,
    client_id: String,
    name: String,
    realm: String,
    client_type: String,
    enabled: bool,
    public_client: bool,
    direct_access_grants_enabled: bool,
    service_account_enabled: bool,
    protocol: String,
}

fn delete_client(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: ClientDeleteArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let client = auth_client(&context)?;
    let found = client
        .get_client(&realm, &args.client_id)?
        .ok_or_else(|| ClientCommandError::ClientNotFound(args.client_id.clone()))?;
    let uuid = found
        .id
        .clone()
        .ok_or_else(|| ClientCommandError::ClientNotFound(args.client_id.clone()))?;
    let resolved_client_id = found.client_id.unwrap_or_else(|| args.client_id.clone());

    // Show what is actually about to be deleted, not just what was asked
    // for — the two can differ if the lookup resolved something unexpected.
    confirm(
        &format!("Delete client '{resolved_client_id}' (id: {uuid})?"),
        args.force,
    )?;
    client.delete_client(&realm, &uuid)?;
    render_message(
        output_format,
        &format!("client '{resolved_client_id}' deleted"),
    )
}

fn get_client(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: ClientGetArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let client = auth_client(&context)?;
    let result = client
        .get_client(&realm, &args.client_id)?
        .ok_or_else(|| ClientCommandError::ClientNotFound(args.client_id.clone()))?;

    render_client_detail(output_format, to_detail_view(result, realm))
}

/// Reads a confidential client's secret. Deliberately ignores `--output`:
/// the secret is printed bare on stdout so it can be piped or captured
/// directly (`ferris-ctl client secret x > secret.txt`), with everything
/// else — status, prompts, errors — kept on stderr.
fn get_client_secret(
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: ClientSecretArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let client = auth_client(&context)?;
    let found = client
        .get_client(&realm, &args.client_id)?
        .ok_or_else(|| ClientCommandError::ClientNotFound(args.client_id.clone()))?;
    let uuid = found
        .id
        .ok_or_else(|| ClientCommandError::ClientNotFound(args.client_id.clone()))?;
    let secret = client.get_client_secret(&realm, &uuid)?;
    println!("{secret}");
    Ok(())
}

fn list_clients(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: ClientListArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let client = auth_client(&context)?;
    let clients = client.list_clients(&realm)?;
    let views = clients.into_iter().map(to_view).collect::<Vec<_>>();

    render_client_list(output_format, &views)
}

fn create_client(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: ClientCreateArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let client = auth_client(&context)?;
    let request = build_create_client_request(args);
    let created = client.create_client(&realm, &request)?;

    render_created_client(output_format, to_created_view(created, realm, request))
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
    select_context(&store, context_override)
}

fn select_context(store: &ContextStore, context_override: Option<&str>) -> Result<StoredContext> {
    let context_name = match context_override {
        Some(name) => name.to_owned(),
        None => store
            .current_context
            .clone()
            .ok_or(ClientCommandError::NoActiveContext)?,
    };

    store
        .contexts
        .get(&context_name)
        .cloned()
        .ok_or(ClientCommandError::ContextNotFound(context_name))
}

fn resolve_realm(context: &StoredContext, realm: Option<String>) -> Result<String> {
    realm
        .or_else(|| context.realm.clone())
        .ok_or(ClientCommandError::MissingRealm)
}

/// Authenticate against the context's home realm — where the context's
/// client_id/client_secret are registered — regardless of which realm the
/// command targets via `--realm`. The server, not the CLI, decides whether
/// the resulting token can act on the target realm.
fn auth_client(context: &StoredContext) -> Result<FerriskeyClient> {
    let auth_realm = context
        .realm
        .as_deref()
        .ok_or(ClientCommandError::MissingAuthRealm)?;
    Ok(session::authenticated_client(context, auth_realm)?)
}

fn to_view(client: ClientRepresentation) -> ClientView {
    ClientView {
        id: client.id.unwrap_or_default(),
        client_id: client.client_id.unwrap_or_default(),
        name: client.name.unwrap_or_default(),
    }
}

fn to_detail_view(client: ClientRepresentation, realm: String) -> ClientDetailView {
    ClientDetailView {
        id: client.id.unwrap_or_default(),
        client_id: client.client_id.unwrap_or_default(),
        name: client.name.unwrap_or_default(),
        realm,
        enabled: client.enabled.unwrap_or(false),
        protocol: client.protocol.unwrap_or_default(),
        public_client: client.public_client.unwrap_or(false),
        service_accounts_enabled: client.service_accounts_enabled.unwrap_or(false),
        direct_access_grants_enabled: client.direct_access_grants_enabled.unwrap_or(false),
    }
}

fn render_client_detail(output_format: &str, client: ClientDetailView) -> Result<()> {
    match output_format {
        "table" => {
            println!("id: {}", client.id);
            println!("client_id: {}", client.client_id);
            println!("name: {}", client.name);
            println!("realm: {}", client.realm);
            println!("enabled: {}", client.enabled);
            println!("protocol: {}", client.protocol);
            println!("public_client: {}", client.public_client);
            println!(
                "service_accounts_enabled: {}",
                client.service_accounts_enabled
            );
            println!(
                "direct_access_grants_enabled: {}",
                client.direct_access_grants_enabled
            );
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&client)
                    .map_err(|source| ClientCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&client)
                    .map_err(|source| ClientCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ClientCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn build_create_client_request(args: ClientCreateArgs) -> CreateClientRequest {
    let client_id = args.client_id.unwrap_or_else(|| args.name.clone());
    let (client_type, public_client, service_account_enabled) =
        client_type_settings(&args.client_type);

    CreateClientRequest {
        client_id,
        client_type,
        enabled: args.enabled,
        name: args.name,
        protocol: args.protocol,
        public_client,
        service_account_enabled,
        direct_access_grants_enabled: args.direct_access_grants_enabled,
        oauth_device_code_grant_enabled: false,
    }
}

fn client_type_settings(client_type: &ClientType) -> (String, bool, bool) {
    match client_type {
        ClientType::Public => ("public".to_owned(), true, false),
        ClientType::Confidential => ("confidential".to_owned(), false, true),
        ClientType::System => ("system".to_owned(), false, true),
    }
}

fn to_created_view(
    client: CreatedClient,
    realm: String,
    request: CreateClientRequest,
) -> CreatedClientView {
    CreatedClientView {
        id: client.id,
        client_id: client.client_id,
        name: client.name,
        realm,
        client_type: request.client_type,
        enabled: request.enabled,
        public_client: request.public_client,
        direct_access_grants_enabled: request.direct_access_grants_enabled,
        service_account_enabled: request.service_account_enabled,
        protocol: request.protocol,
    }
}

fn render_client_list(output_format: &str, clients: &[ClientView]) -> Result<()> {
    match output_format {
        "table" => {
            for line in build_client_table_lines(clients) {
                println!("{line}");
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(clients)
                    .map_err(|source| ClientCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(clients)
                    .map_err(|source| ClientCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ClientCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_created_client(output_format: &str, client: CreatedClientView) -> Result<()> {
    match output_format {
        "table" => {
            println!(
                "client '{}' created in realm '{}'",
                client.client_id, client.realm
            );
            println!("id: {}", client.id);
            println!("name: {}", client.name);
            println!("client_type: {}", client.client_type);
            println!("protocol: {}", client.protocol);
            println!("public_client: {}", client.public_client);
            println!(
                "direct_access_grants_enabled: {}",
                client.direct_access_grants_enabled
            );
            println!(
                "service_account_enabled: {}",
                client.service_account_enabled
            );
            println!("enabled: {}", client.enabled);
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&client)
                    .map_err(|source| ClientCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&client)
                    .map_err(|source| ClientCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ClientCommandError::UnsupportedOutputFormat(
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
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "message": message }))
                    .map_err(|source| ClientCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({ "message": message }))
                    .map_err(|source| ClientCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ClientCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn build_client_table_lines(clients: &[ClientView]) -> Vec<String> {
    let client_id_width = clients
        .iter()
        .map(|client| client.client_id.len())
        .max()
        .unwrap_or(0)
        .max("CLIENT_ID".len());
    let id_width = clients
        .iter()
        .map(|client| client.id.len())
        .max()
        .unwrap_or(0)
        .max("ID".len());

    let mut lines = Vec::with_capacity(clients.len() + 1);
    lines.push(format!(
        "{:<client_id_width$}  {:<id_width$}  NAME",
        "CLIENT_ID", "ID"
    ));

    for client in clients {
        lines.push(format!(
            "{:<client_id_width$}  {:<id_width$}  {}",
            client.client_id, client.id, client.name
        ));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoredContext;
    use std::collections::BTreeMap;

    #[test]
    fn auth_client_requires_realm_on_context() {
        // Regression: auth_client must authenticate against the context's
        // home realm, never a command's target `--realm` (which it doesn't
        // even take as a parameter) — a context without a home realm can't
        // authenticate at all, regardless of any target realm resolved
        // elsewhere.
        let context = StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: Some("secret".to_owned()),
            realm: None,
        };
        let err = auth_client(&context).expect_err("missing realm should error");
        assert!(matches!(err, ClientCommandError::MissingAuthRealm));
    }

    #[test]
    fn select_context_uses_active_context_by_default() {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "local".to_owned(),
            StoredContext {
                url: "http://localhost:3333".to_owned(),
                client_id: "cli".to_owned(),
                client_secret: Some("secret".to_owned()),
                realm: Some("master".to_owned()),
            },
        );
        let store = ContextStore {
            current_context: Some("local".to_owned()),
            contexts,
            ..Default::default()
        };

        let context = select_context(&store, None).expect("context selected");

        assert_eq!(context.url, "http://localhost:3333");
    }

    #[test]
    fn select_context_prefers_override() {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "local".to_owned(),
            StoredContext {
                url: "http://localhost:3333".to_owned(),
                client_id: "cli".to_owned(),
                client_secret: Some("secret".to_owned()),
                realm: None,
            },
        );
        contexts.insert(
            "prod".to_owned(),
            StoredContext {
                url: "https://iam.example.com".to_owned(),
                client_id: "ops".to_owned(),
                client_secret: Some("secret".to_owned()),
                realm: None,
            },
        );
        let store = ContextStore {
            current_context: Some("local".to_owned()),
            contexts,
            ..Default::default()
        };

        let context = select_context(&store, Some("prod")).expect("context selected");

        assert_eq!(context.url, "https://iam.example.com");
    }

    #[test]
    fn resolve_realm_prefers_explicit_argument() {
        let context = StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: Some("secret".to_owned()),
            realm: Some("master".to_owned()),
        };

        let realm = resolve_realm(&context, Some("other".to_owned())).expect("realm resolved");

        assert_eq!(realm, "other");
    }

    #[test]
    fn resolve_realm_falls_back_to_context_default() {
        let context = StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: Some("secret".to_owned()),
            realm: Some("master".to_owned()),
        };

        let realm = resolve_realm(&context, None).expect("realm resolved");

        assert_eq!(realm, "master");
    }

    #[test]
    fn resolve_realm_errors_when_missing_everywhere() {
        let context = StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: Some("secret".to_owned()),
            realm: None,
        };

        let error = resolve_realm(&context, None).expect_err("realm should be required");

        assert!(matches!(error, ClientCommandError::MissingRealm));
    }

    #[test]
    fn build_create_client_request_uses_cli_defaults() {
        let request = build_create_client_request(ClientCreateArgs {
            name: "my-app".to_owned(),
            client_id: None,
            realm: None,
            client_type: ClientType::Public,
            enabled: false,
            protocol: "openid-connect".to_owned(),
            direct_access_grants_enabled: false,
        });

        assert_eq!(request.client_id, "my-app");
        assert_eq!(request.name, "my-app");
        assert_eq!(request.client_type, "public");
        assert_eq!(request.protocol, "openid-connect");
        assert!(request.public_client);
        assert!(!request.service_account_enabled);
        assert!(!request.enabled);
        assert!(!request.direct_access_grants_enabled);
    }

    #[test]
    fn build_create_client_request_supports_confidential_clients() {
        let request = build_create_client_request(ClientCreateArgs {
            name: "my-app".to_owned(),
            client_id: Some("my-client-id".to_owned()),
            realm: None,
            client_type: ClientType::Confidential,
            enabled: true,
            protocol: "openid-connect".to_owned(),
            direct_access_grants_enabled: true,
        });

        assert_eq!(request.client_id, "my-client-id");
        assert_eq!(request.client_type, "confidential");
        assert!(!request.public_client);
        assert!(request.service_account_enabled);
        assert!(request.enabled);
        assert!(request.direct_access_grants_enabled);
    }
}
