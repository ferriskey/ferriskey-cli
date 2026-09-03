use ferriskey_cli_client::{
    CreateRealmRequest, CreateRoleRequest, CreatedRole, FerriskeyClient, FerriskeyClientError,
    Realm,
};
use ferriskey_cli_commands::{
    RealmCommand, RealmDeleteArgs, RealmImportArgs, RealmNameArgs, RealmRoleCommand,
    RealmRoleCreateArgs, RealmRoleDeleteArgs, RealmRoleGetArgs, RealmRoleListArgs,
    RealmRoleSubcommand, RealmSubcommand,
};
use serde::Serialize;
use thiserror::Error;

use crate::confirm::{self, confirm};
use crate::config::{ConfigError, FileContextRepository, StoredContext};
use crate::import::{self, ImportReport, RealmBlueprint};
use crate::session::{self, SessionError};

type Result<T> = std::result::Result<T, RealmCommandError>;

impl From<import::ImportError> for RealmCommandError {
    fn from(error: import::ImportError) -> Self {
        RealmCommandError::Import(Box::new(error))
    }
}

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
        RealmSubcommand::Role(command) => {
            run_role(output_format, context_override, inline_context, command)
        }
        RealmSubcommand::Import(args) => {
            import_realm(output_format, context_override, inline_context, args)
        }
    }
}

fn run_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    command: RealmRoleCommand,
) -> Result<()> {
    match command.command {
        RealmRoleSubcommand::Create(args) => {
            create_role(output_format, context_override, inline_context, args)
        }
        RealmRoleSubcommand::List(args) => {
            list_roles(output_format, context_override, inline_context, args)
        }
        RealmRoleSubcommand::Get(args) => {
            get_role(output_format, context_override, inline_context, args)
        }
        RealmRoleSubcommand::Delete(args) => {
            delete_role(output_format, context_override, inline_context, args)
        }
    }
}

#[derive(Debug, Error)]
pub enum RealmCommandError {
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
        "auth realm is required: pass '--realm' or configure a default realm on the selected context"
    )]
    MissingAuthRealm,
    #[error("realm '{0}' not found")]
    RealmNotFound(String),
    #[error("client '{0}' not found in realm")]
    ClientNotFound(String),
    #[error("role '{0}' not found")]
    RoleNotFound(String),
    #[error(transparent)]
    Import(Box<import::ImportError>),
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
    Ok(session::authenticated_client(context, auth_realm)?)
}

/// Resolve the realm a command operates on: the explicit `--realm` argument,
/// falling back to the context's default realm.
fn resolve_realm(context: &StoredContext, realm: Option<String>) -> Result<String> {
    realm
        .or_else(|| context.realm.clone())
        .ok_or(RealmCommandError::MissingAuthRealm)
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
    args: RealmDeleteArgs,
) -> Result<()> {
    confirm(
        &format!(
            "Delete realm '{}'? This permanently removes its clients, users, and roles.",
            args.name
        ),
        args.force,
    )?;
    let context = resolve_context(context_override, inline_context)?;
    let client = auth_client(&context)?;
    client.delete_realm(&args.name)?;
    render_message(output_format, &format!("realm '{}' deleted", args.name))
}

/// Resolve a client id (e.g. `my-app`) to the client's uuid, as required by
/// the client-role endpoints.
fn resolve_client_uuid(client: &FerriskeyClient, realm: &str, client_id: &str) -> Result<String> {
    client
        .get_client(realm, client_id)?
        .and_then(|found| found.id)
        .ok_or_else(|| RealmCommandError::ClientNotFound(client_id.to_owned()))
}

/// List roles in the scope selected by `--client`: a specific client's roles
/// when given, realm roles otherwise.
fn list_roles_in_scope(
    client: &FerriskeyClient,
    realm: &str,
    client_id: Option<&str>,
) -> Result<Vec<CreatedRole>> {
    match client_id {
        Some(client_id) => {
            let uuid = resolve_client_uuid(client, realm, client_id)?;
            Ok(client.list_client_roles(realm, &uuid)?)
        }
        None => Ok(client.list_realm_roles(realm)?),
    }
}

fn create_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmRoleCreateArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let request = CreateRoleRequest {
        name: args.name,
        description: args.description,
        permissions: args.permissions,
    };
    let role = match args.client {
        Some(client_id) => {
            let uuid = resolve_client_uuid(&client, &realm, &client_id)?;
            client.create_client_role(&realm, &uuid, &request)?
        }
        None => client.create_role(&realm, &request)?,
    };
    render_role(output_format, to_role_view(role))
}

fn list_roles(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmRoleListArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let roles = list_roles_in_scope(&client, &realm, args.client.as_deref())?;
    let views: Vec<RoleView> = roles.into_iter().map(to_role_view).collect();
    render_role_list(output_format, &views)
}

fn get_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmRoleGetArgs,
) -> Result<()> {
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let role = list_roles_in_scope(&client, &realm, args.client.as_deref())?
        .into_iter()
        .find(|r| r.name == args.name)
        .ok_or_else(|| RealmCommandError::RoleNotFound(args.name.clone()))?;
    render_role(output_format, to_role_view(role))
}

fn delete_role(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmRoleDeleteArgs,
) -> Result<()> {
    confirm(&format!("Delete role '{}'?", args.name), args.force)?;
    let context = resolve_context(context_override, inline_context)?;
    let realm = resolve_realm(&context, args.realm)?;
    let client = auth_client(&context)?;
    let role = list_roles_in_scope(&client, &realm, args.client.as_deref())?
        .into_iter()
        .find(|r| r.name == args.name)
        .ok_or_else(|| RealmCommandError::RoleNotFound(args.name.clone()))?;
    // A role id is unique across both realm and client scopes, so deletion
    // doesn't need to be scoped the way create/list do.
    client.delete_role(&realm, &role.id)?;
    render_message(output_format, &format!("role '{}' deleted", args.name))
}

fn import_realm(
    output_format: &str,
    context_override: Option<&str>,
    inline_context: Option<StoredContext>,
    args: RealmImportArgs,
) -> Result<()> {
    let source = import::sources::source_from_args(&args)?;
    let mut blueprints = source.fetch()?;

    // --target-realm only makes sense for a single resolved realm; a source that
    // yields several (e.g. all Zitadel orgs) keeps the per-source names.
    if let Some(name) = &args.target_realm {
        match blueprints.len() {
            1 => blueprints[0].name = name.clone(),
            n if n > 1 => eprintln!(
                "note: --target-realm ignored ({n} realms resolved; keeping source names)"
            ),
            _ => {}
        }
    }

    // Dry-run resolves and prints the blueprints without touching FerrisKey,
    // so it needs neither a configured context nor authentication.
    if args.dry_run {
        return render_blueprints(output_format, &blueprints);
    }

    let context = resolve_context(context_override, inline_context)?;
    let client = auth_client(&context)?;
    let reports = blueprints
        .iter()
        .map(|blueprint| import::apply::apply_blueprint(&client, blueprint, false))
        .collect::<std::result::Result<Vec<ImportReport>, _>>()?;
    render_reports(output_format, &reports)
}

fn render_blueprints(output_format: &str, blueprints: &[RealmBlueprint]) -> Result<()> {
    match output_format {
        "table" => {
            for (index, blueprint) in blueprints.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                println!("realm:    {}", blueprint.name);
                println!(
                    "settings: {}",
                    if blueprint.settings.is_some() { "yes" } else { "no" }
                );
                println!("roles:    {}", blueprint.roles.len());
                println!("clients:  {}", blueprint.clients.len());
                println!("users:    {}", blueprint.users.len());
            }
            Ok(())
        }
        "json" => render_json(blueprints),
        "yaml" => render_yaml(blueprints),
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_reports(output_format: &str, reports: &[ImportReport]) -> Result<()> {
    match output_format {
        "table" => {
            for (index, report) in reports.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                println!("realm '{}' imported", report.realm);
                println!("  realm created:        {}", report.realm_created);
                println!("  settings applied:     {}", report.settings_applied);
                println!("  roles created:        {}", report.roles_created);
                println!("  clients created:      {}", report.clients_created);
                println!("  redirect uris added:  {}", report.redirects_created);
                println!(
                    "  post-logout uris added: {}",
                    report.post_logout_redirects_created
                );
                println!("  web origins added:    {}", report.web_origins_created);
                println!(
                    "  client settings applied: {}",
                    report.client_settings_applied
                );
                println!("  client roles created: {}", report.client_roles_created);
                println!("  users created:        {}", report.users_created);
                println!("  role assignments:     {}", report.role_assignments);
                println!("  already present:      {}", report.already_present);
                if !report.warnings.is_empty() {
                    println!("  warnings:");
                    for warning in &report.warnings {
                        println!("    - {warning}");
                    }
                }
            }
            Ok(())
        }
        "json" => render_json(reports),
        "yaml" => render_yaml(reports),
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

/// Serializes a collection as a JSON array. `realm import` can resolve one or
/// many realms, so the shape is kept stable (always an array) for scripting,
/// regardless of how many were resolved.
fn render_json<T: Serialize>(items: &[T]) -> Result<()> {
    let json = serde_json::to_string_pretty(items)
        .map_err(|source| RealmCommandError::SerializeJson { source })?;
    println!("{json}");
    Ok(())
}

fn render_yaml<T: Serialize>(items: &[T]) -> Result<()> {
    let yaml =
        serde_yaml::to_string(items).map_err(|source| RealmCommandError::SerializeYaml { source })?;
    println!("{yaml}");
    Ok(())
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

fn render_role(output_format: &str, role: RoleView) -> Result<()> {
    match output_format {
        "table" => {
            println!("id: {}", role.id);
            println!("name: {}", role.name);
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role)
                    .map_err(|source| RealmCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&role)
                    .map_err(|source| RealmCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(RealmCommandError::UnsupportedOutputFormat(
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
                    .map_err(|source| RealmCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(roles)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoredContext;
    use ferriskey_cli_client::Realm;

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
        let context = make_context(None);
        let err = auth_client(&context).expect_err("missing realm should error");
        assert!(matches!(err, RealmCommandError::MissingAuthRealm));
    }

    #[test]
    fn to_view_maps_id_and_name() {
        let realm = Realm {
            id: "abc-123".to_owned(),
            name: "master".to_owned(),
        };
        let view = to_view(realm);
        assert_eq!(view.id, "abc-123");
        assert_eq!(view.name, "master");
    }

    #[test]
    fn render_realm_list_table_succeeds() {
        let realms = vec![
            RealmView {
                id: "abc".to_owned(),
                name: "master".to_owned(),
            },
            RealmView {
                id: "def-long-id".to_owned(),
                name: "dev".to_owned(),
            },
        ];
        assert!(render_realm_list("table", &realms).is_ok());
    }

    #[test]
    fn render_realm_list_table_empty_succeeds() {
        assert!(render_realm_list("table", &[]).is_ok());
    }

    #[test]
    fn render_realm_list_json_succeeds() {
        let realms = vec![RealmView {
            id: "abc".to_owned(),
            name: "master".to_owned(),
        }];
        assert!(render_realm_list("json", &realms).is_ok());
    }

    #[test]
    fn render_realm_list_rejects_unknown_format() {
        let err = render_realm_list("xml", &[]).expect_err("unknown format should error");
        assert!(matches!(err, RealmCommandError::UnsupportedOutputFormat(_)));
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
    fn render_role_list_rejects_unknown_format() {
        let err = render_role_list("xml", &[]).expect_err("unknown format should error");
        assert!(matches!(err, RealmCommandError::UnsupportedOutputFormat(_)));
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
}
