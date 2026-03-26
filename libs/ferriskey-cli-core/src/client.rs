use ferriskey_client::{
    ClientRepresentation, CreateClientRequest, CreatedClient, FerriskeyClient, FerriskeyClientError,
};
use ferriskey_commands::{
    ClientCommand, ClientCreateArgs, ClientListArgs, ClientSubcommand, ClientType,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::{ConfigError, ContextStore, FileContextRepository, StoredContext};

type Result<T> = std::result::Result<T, ClientCommandError>;

pub fn run(
    output_format: &str,
    context_override: Option<&str>,
    command: ClientCommand,
) -> Result<()> {
    match command.command {
        ClientSubcommand::List(args) => list_clients(output_format, context_override, args),
        ClientSubcommand::Get(_) => Err(ClientCommandError::Unimplemented("client get")),
        ClientSubcommand::Create(args) => create_client(output_format, context_override, args),
        ClientSubcommand::Delete(_) => Err(ClientCommandError::Unimplemented("client delete")),
    }
}

#[derive(Debug, Error)]
pub enum ClientCommandError {
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
    #[error("command '{0}' is not implemented yet")]
    Unimplemented(&'static str),
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ClientView {
    id: String,
    client_id: String,
    name: String,
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

fn list_clients(
    output_format: &str,
    context_override: Option<&str>,
    args: ClientListArgs,
) -> Result<()> {
    let repository = FileContextRepository::new()?;
    let store = repository.load()?;
    let context = select_context(&store, context_override)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let auth_client = FerriskeyClient::new(context.url.clone(), "", "")?;
    let token = auth_client.exchange_client_credentials(
        realm.as_str(),
        context.client_id.as_str(),
        context.client_secret.as_str(),
    )?;
    let client = FerriskeyClient::new(context.url, "", token.access_token)?;
    let clients = client.list_clients(&realm)?;
    let views = clients.into_iter().map(to_view).collect::<Vec<_>>();

    render_client_list(output_format, &views)
}

fn create_client(
    output_format: &str,
    context_override: Option<&str>,
    args: ClientCreateArgs,
) -> Result<()> {
    let repository = FileContextRepository::new()?;
    let store = repository.load()?;
    let context = select_context(&store, context_override)?;
    let realm = resolve_realm(&context, args.realm.clone())?;
    let auth_client = FerriskeyClient::new(context.url.clone(), "", "")?;
    let token = auth_client.exchange_client_credentials(
        realm.as_str(),
        context.client_id.as_str(),
        context.client_secret.as_str(),
    )?;
    let client = FerriskeyClient::new(context.url, "", token.access_token)?;
    let request = build_create_client_request(args);
    let created = client.create_client(&realm, &request)?;

    render_created_client(output_format, to_created_view(created, realm, request))
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

fn to_view(client: ClientRepresentation) -> ClientView {
    ClientView {
        id: client.id.unwrap_or_default(),
        client_id: client.client_id.unwrap_or_default(),
        name: client.name.unwrap_or_default(),
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
    fn select_context_uses_active_context_by_default() {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "local".to_owned(),
            StoredContext {
                url: "http://localhost:3333".to_owned(),
                client_id: "cli".to_owned(),
                client_secret: "secret".to_owned(),
                realm: Some("master".to_owned()),
            },
        );
        let store = ContextStore {
            current_context: Some("local".to_owned()),
            contexts,
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
                client_secret: "secret".to_owned(),
                realm: None,
            },
        );
        contexts.insert(
            "prod".to_owned(),
            StoredContext {
                url: "https://iam.example.com".to_owned(),
                client_id: "ops".to_owned(),
                client_secret: "secret".to_owned(),
                realm: None,
            },
        );
        let store = ContextStore {
            current_context: Some("local".to_owned()),
            contexts,
        };

        let context = select_context(&store, Some("prod")).expect("context selected");

        assert_eq!(context.url, "https://iam.example.com");
    }

    #[test]
    fn resolve_realm_prefers_explicit_argument() {
        let context = StoredContext {
            url: "http://localhost:3333".to_owned(),
            client_id: "cli".to_owned(),
            client_secret: "secret".to_owned(),
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
            client_secret: "secret".to_owned(),
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
            client_secret: "secret".to_owned(),
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
