//! Replays a [`RealmBlueprint`] against the FerrisKey API.
//!
//! The API exposes no bulk import, so entities are created one by one in
//! dependency order: realm, then settings, realm roles, clients (with their
//! redirect URIs and client roles), and finally users with their role
//! assignments. An import can be re-run to converge: what the realm already
//! has is read first and skipped, counted in [`ImportReport::already_present`]
//! with a warning naming it.
//!
//! Convergence is built on those reads rather than on classifying the create
//! error, because the server's answer to a duplicate is not uniform: a realm
//! gets a clean `409`, a duplicate user or web origin a `400` naming the
//! clash, a role or a client a bare `500` carrying nothing to distinguish it
//! from a genuine failure, and a duplicate redirect URI a `201` that quietly
//! stores a second row. [`is_conflict`] stays as the fallback for the
//! recognizable cases and for the race between the read and the create.

use std::collections::{HashMap, HashSet};

use ferriskey_cli_client::{
    ClientUriEntry, CreateClientRequest, CreateRedirectUriRequest, CreateRoleRequest,
    CreateUserRequest, CreateWebOriginRequest, FerriskeyClient, FerriskeyClientError,
};
use reqwest::StatusCode;

use super::{
    ClientBlueprint, ClientSecretEntry, ImportError, ImportReport, RealmBlueprint, RoleBlueprint,
};

/// Apply `blueprint` to the FerrisKey instance behind `client`.
///
/// In `dry_run` mode no request is sent; the returned report tallies what would
/// have been created.
pub fn apply_blueprint(
    client: &FerriskeyClient,
    blueprint: &RealmBlueprint,
    dry_run: bool,
) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport {
        realm: blueprint.name.clone(),
        dry_run,
        ..Default::default()
    };

    if dry_run {
        report.realm_created = true;
        report.settings_applied = blueprint
            .settings
            .as_ref()
            .is_some_and(|s| !s.to_request().is_empty());
        report.roles_created = blueprint.roles.len();
        report.clients_created = blueprint.clients.len();
        report.redirects_created = blueprint.clients.iter().map(|c| c.redirect_uris.len()).sum();
        report.post_logout_redirects_created = blueprint
            .clients
            .iter()
            .map(|c| c.post_logout_redirect_uris.len())
            .sum();
        report.web_origins_created = blueprint.clients.iter().map(|c| c.web_origins.len()).sum();
        report.client_settings_applied = blueprint
            .clients
            .iter()
            .filter(|c| !c.to_settings_request().is_empty())
            .count();
        report.client_roles_created = blueprint.clients.iter().map(|c| c.roles.len()).sum();
        report.users_created = blueprint.users.len();
        report.role_assignments = blueprint.users.iter().map(|u| u.roles.len()).sum();
        return Ok(report);
    }

    let realm = blueprint.name.as_str();

    // 1. Realm. Existence is checked before creating rather than deduced from
    // the create error: what a duplicate looks like varies per entity and per
    // server version (a clean 409 here, an opaque 500 there, a silent second
    // row elsewhere), and a replay has to converge regardless. `is_conflict`
    // stays as a fallback for the race between the check and the create.
    if client.get_realm(realm).is_ok() {
        report.already_present += 1;
        report
            .warnings
            .push(format!("realm '{realm}' already exists, reusing it"));
    } else {
        match client.create_realm(&ferriskey_cli_client::CreateRealmRequest {
            name: realm.to_owned(),
        }) {
            Ok(_) => report.realm_created = true,
            Err(e) if is_conflict(&e) => {
                report.already_present += 1;
                report
                    .warnings
                    .push(format!("realm '{realm}' already exists, reusing it"));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // 2. Settings.
    if let Some(settings) = &blueprint.settings {
        let request = settings.to_request();
        if !request.is_empty() {
            client.update_realm_settings(realm, &request)?;
            report.settings_applied = true;
        }
    }

    // 3. Realm roles. Track name -> id so we can assign them to users later,
    // seeded with the roles the realm already has so a replay skips them
    // instead of re-posting a name the server rejects with a bare 500.
    let mut role_ids: HashMap<String, String> = HashMap::new();
    let needs_realm_roles = !blueprint.roles.is_empty()
        || blueprint
            .users
            .iter()
            .flat_map(|u| &u.roles)
            .any(|spec| matches!(parse_role_ref(spec), RoleRef::Realm(_)));
    let mut realm_roles_listed = false;
    if needs_realm_roles {
        match client.list_realm_roles(realm) {
            Ok(existing) => {
                realm_roles_listed = true;
                for role in existing {
                    role_ids.insert(role.name, role.id);
                }
            }
            Err(e) => report
                .warnings
                .push(format!("could not list realm roles: {e}")),
        }
    }

    for role in &blueprint.roles {
        if role_ids.contains_key(&role.name) {
            report.already_present += 1;
            report
                .warnings
                .push(format!("realm role '{}' already exists", role.name));
            continue;
        }
        match client.create_role(realm, &role_request(role)) {
            Ok(created) => {
                role_ids.insert(created.name, created.id);
                report.roles_created += 1;
            }
            Err(e) if is_conflict(&e) => {
                report.already_present += 1;
                report
                    .warnings
                    .push(format!("realm role '{}' already exists", role.name));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Backfill ids for roles referenced by users but neither created nor listed
    // above — only reachable when the listing itself failed.
    let missing_role_ref = blueprint
        .users
        .iter()
        .flat_map(|u| &u.roles)
        .any(|name| !role_ids.contains_key(name));
    if !realm_roles_listed && missing_role_ref {
        match client.list_realm_roles(realm) {
            Ok(existing) => {
                for role in existing {
                    role_ids.entry(role.name).or_insert(role.id);
                }
            }
            Err(e) => report
                .warnings
                .push(format!("could not list realm roles for assignment: {e}")),
        }
    }

    // 4. Clients, with their redirect URIs and client-scoped roles. Track
    // client_id -> uuid and (client_id, role name) -> role id so client roles
    // can be assigned to users afterward, same as realm roles above.
    let mut client_uuids: HashMap<String, String> = HashMap::new();
    let mut client_role_ids: HashMap<(String, String), String> = HashMap::new();

    let mut existing_clients: HashMap<String, String> = HashMap::new();
    if !blueprint.clients.is_empty() {
        match client.list_clients(realm) {
            Ok(existing) => {
                for existing_client in existing {
                    if let (Some(client_id), Some(id)) =
                        (existing_client.client_id, existing_client.id)
                    {
                        existing_clients.insert(client_id, id);
                    }
                }
            }
            Err(e) => report.warnings.push(format!("could not list clients: {e}")),
        }
    }

    // Clients whose roles were listed here, so the backfill below can skip them.
    let mut client_roles_listed: HashSet<String> = HashSet::new();

    for client_bp in &blueprint.clients {
        let existing_uuid = existing_clients.get(&client_bp.client_id).cloned();
        let Some(client_uuid) =
            resolve_client(client, realm, client_bp, existing_uuid, &mut report)?
        else {
            continue;
        };
        client_uuids.insert(client_bp.client_id.clone(), client_uuid.clone());

        if client_bp.client_type == "confidential" {
            match client.get_client_secret(realm, &client_uuid) {
                Ok(secret) => report.client_secrets.push(ClientSecretEntry {
                    client_id: client_bp.client_id.clone(),
                    secret,
                }),
                Err(e) => report.warnings.push(format!(
                    "could not read secret of client '{}': {e}",
                    client_bp.client_id
                )),
            }
        }

        // Redirects, post-logout redirects and web origins are matched on their
        // value: the redirect endpoint happily stores a duplicate, so a replay
        // would otherwise grow the list on every run.
        let existing_redirects = if client_bp.redirect_uris.is_empty() {
            HashSet::new()
        } else {
            existing_values(
                client.list_client_redirects(realm, &client_uuid),
                "redirect uris",
                &client_bp.client_id,
                &mut report,
            )
        };
        for uri in &client_bp.redirect_uris {
            if existing_redirects.contains(uri) {
                report.already_present += 1;
                report.warnings.push(format!(
                    "redirect '{uri}' already exists on client '{}'",
                    client_bp.client_id
                ));
                continue;
            }
            let request = CreateRedirectUriRequest {
                value: uri.clone(),
                enabled: true,
            };
            match client.add_client_redirect(realm, &client_uuid, &request) {
                Ok(()) => report.redirects_created += 1,
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report.warnings.push(format!(
                        "redirect '{uri}' already exists on client '{}'",
                        client_bp.client_id
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        let existing_post_logout = if client_bp.post_logout_redirect_uris.is_empty() {
            HashSet::new()
        } else {
            existing_values(
                client.list_client_post_logout_redirects(realm, &client_uuid),
                "post-logout redirects",
                &client_bp.client_id,
                &mut report,
            )
        };
        for uri in &client_bp.post_logout_redirect_uris {
            if existing_post_logout.contains(uri) {
                report.already_present += 1;
                report.warnings.push(format!(
                    "post-logout redirect '{uri}' already exists on client '{}'",
                    client_bp.client_id
                ));
                continue;
            }
            let request = CreateRedirectUriRequest {
                value: uri.clone(),
                enabled: true,
            };
            match client.add_client_post_logout_redirect(realm, &client_uuid, &request) {
                Ok(()) => report.post_logout_redirects_created += 1,
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report.warnings.push(format!(
                        "post-logout redirect '{uri}' already exists on client '{}'",
                        client_bp.client_id
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        let existing_origins = if client_bp.web_origins.is_empty() {
            HashSet::new()
        } else {
            existing_values(
                client.list_client_web_origins(realm, &client_uuid),
                "web origins",
                &client_bp.client_id,
                &mut report,
            )
        };
        for origin in &client_bp.web_origins {
            if existing_origins.contains(origin) {
                report.already_present += 1;
                report.warnings.push(format!(
                    "web origin '{origin}' already exists on client '{}'",
                    client_bp.client_id
                ));
                continue;
            }
            let request = CreateWebOriginRequest {
                value: origin.clone(),
            };
            match client.add_client_web_origin(realm, &client_uuid, &request) {
                Ok(()) => report.web_origins_created += 1,
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report.warnings.push(format!(
                        "web origin '{origin}' already exists on client '{}'",
                        client_bp.client_id
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        let settings_request = client_bp.to_settings_request();
        if !settings_request.is_empty() {
            client.update_client_settings(realm, &client_uuid, &settings_request)?;
            report.client_settings_applied += 1;
        }

        if !client_bp.roles.is_empty() {
            match client.list_client_roles(realm, &client_uuid) {
                Ok(existing) => {
                    client_roles_listed.insert(client_bp.client_id.clone());
                    for role in existing {
                        client_role_ids
                            .entry((client_bp.client_id.clone(), role.name))
                            .or_insert(role.id);
                    }
                }
                Err(e) => report.warnings.push(format!(
                    "could not list roles of client '{}': {e}",
                    client_bp.client_id
                )),
            }
        }

        for role in &client_bp.roles {
            let key = (client_bp.client_id.clone(), role.name.clone());
            if client_role_ids.contains_key(&key) {
                report.already_present += 1;
                report.warnings.push(format!(
                    "client role '{}' already exists on client '{}'",
                    role.name, client_bp.client_id
                ));
                continue;
            }
            match client.create_client_role(realm, &client_uuid, &role_request(role)) {
                Ok(created) => {
                    client_role_ids.insert((client_bp.client_id.clone(), created.name), created.id);
                    report.client_roles_created += 1;
                }
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report.warnings.push(format!(
                        "client role '{}' already exists on client '{}'",
                        role.name, client_bp.client_id
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    // Backfill ids for client roles referenced by users but neither created nor
    // listed above — same rationale as the realm-role backfill.
    let missing_client_role_ref = blueprint.users.iter().flat_map(|u| &u.roles).any(|spec| {
        matches!(
            parse_role_ref(spec),
            RoleRef::Client { client_id, role }
                if !client_role_ids.contains_key(&(client_id.to_owned(), role.to_owned()))
        )
    });
    if missing_client_role_ref {
        for (client_id, uuid) in &client_uuids {
            if client_roles_listed.contains(client_id) {
                continue;
            }
            match client.list_client_roles(realm, uuid) {
                Ok(existing) => {
                    for role in existing {
                        client_role_ids
                            .entry((client_id.clone(), role.name))
                            .or_insert(role.id);
                    }
                }
                Err(e) => report.warnings.push(format!(
                    "could not list roles of client '{client_id}' for assignment: {e}"
                )),
            }
        }
    }

    // 5. Users, with realm-role assignments.
    for user in &blueprint.users {
        let existing_user = match find_existing_user(client, realm, &user.username) {
            Ok(found) => found,
            Err(e) => {
                report
                    .warnings
                    .push(format!("could not look up user '{}': {e}", user.username));
                None
            }
        };

        let (user_id, user_existed) = match existing_user {
            Some(id) => {
                report.already_present += 1;
                report
                    .warnings
                    .push(format!("user '{}' already exists, reusing it", user.username));
                (Some(id), true)
            }
            None => match client.create_user(realm, &user_request(user)) {
                Ok(created) => {
                    report.users_created += 1;
                    (Some(created.id), false)
                }
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report
                        .warnings
                        .push(format!("user '{}' already exists, reusing it", user.username));
                    (
                        resolve_existing_user(client, realm, &user.username, &mut report),
                        true,
                    )
                }
                Err(e) => return Err(e.into()),
            },
        };

        let Some(user_id) = user_id else { continue };

        // A second assignment of a role the user already holds is a duplicate
        // write server-side, so an existing user's roles are read first.
        let assigned_roles: HashSet<String> = if user_existed && !user.roles.is_empty() {
            match client.list_user_roles(realm, &user_id) {
                Ok(roles) => roles.into_iter().map(|role| role.id).collect(),
                Err(e) => {
                    report.warnings.push(format!(
                        "could not list roles of user '{}': {e}",
                        user.username
                    ));
                    HashSet::new()
                }
            }
        } else {
            HashSet::new()
        };

        for role_spec in &user.roles {
            let role_id = match parse_role_ref(role_spec) {
                RoleRef::Realm(name) => match role_ids.get(name) {
                    Some(role_id) => Some(role_id),
                    None => {
                        report.warnings.push(format!(
                            "role '{name}' not found, cannot assign it to user '{}'",
                            user.username
                        ));
                        None
                    }
                },
                RoleRef::Client { client_id, role } => {
                    match client_role_ids.get(&(client_id.to_owned(), role.to_owned())) {
                        Some(role_id) => Some(role_id),
                        None => {
                            return Err(ImportError::UnresolvedClientRole {
                                client_id: client_id.to_owned(),
                                role: role.to_owned(),
                                username: user.username.clone(),
                            });
                        }
                    }
                }
            };

            let Some(role_id) = role_id else { continue };
            if assigned_roles.contains(role_id) {
                report.already_present += 1;
                report.warnings.push(format!(
                    "user '{}' already has role '{role_spec}'",
                    user.username
                ));
                continue;
            }
            match client.assign_user_role(realm, &user_id, role_id) {
                Ok(()) => report.role_assignments += 1,
                Err(e) if is_conflict(&e) => {
                    report.already_present += 1;
                    report.warnings.push(format!(
                        "user '{}' already has role '{role_spec}'",
                        user.username
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    Ok(report)
}

/// Resolves a client to its UUID, creating it when the realm doesn't have it
/// yet. `existing_uuid` is the UUID found in the realm's client list, if any;
/// when it is set nothing is created, since this server reports a duplicate
/// client as an opaque 500 that `is_conflict` cannot tell from a real failure.
fn resolve_client(
    client: &FerriskeyClient,
    realm: &str,
    client_bp: &ClientBlueprint,
    existing_uuid: Option<String>,
    report: &mut ImportReport,
) -> Result<Option<String>, ImportError> {
    if let Some(uuid) = existing_uuid {
        report.already_present += 1;
        report
            .warnings
            .push(format!("client '{}' already exists, reusing it", client_bp.client_id));
        return Ok(Some(uuid));
    }

    match client.create_client(realm, &client_request(client_bp)) {
        Ok(created) => {
            report.clients_created += 1;
            Ok(Some(created.id))
        }
        Err(e) if is_conflict(&e) => {
            report.already_present += 1;
            report
                .warnings
                .push(format!("client '{}' already exists, reusing it", client_bp.client_id));
            match client.get_client(realm, &client_bp.client_id)? {
                Some(existing) => match existing.id {
                    Some(id) => Ok(Some(id)),
                    None => {
                        report.warnings.push(format!(
                            "existing client '{}' has no id, skipping its redirects/roles",
                            client_bp.client_id
                        ));
                        Ok(None)
                    }
                },
                None => {
                    report.warnings.push(format!(
                        "could not resolve existing client '{}', skipping its redirects/roles",
                        client_bp.client_id
                    ));
                    Ok(None)
                }
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// The id of `username` in `realm`, or `None` when the realm has no such user.
/// The server ignores the `username` query filter on some versions, so the
/// match is confirmed client-side.
fn find_existing_user(
    client: &FerriskeyClient,
    realm: &str,
    username: &str,
) -> Result<Option<String>, FerriskeyClientError> {
    Ok(client
        .find_users_by_username(realm, username)?
        .into_iter()
        .find(|u| u.username == username)
        .map(|u| u.id))
}

/// The values already registered on a client, as a set to match a blueprint
/// against. A failed read degrades to an empty set: the create below then runs
/// and its own error handling decides, rather than the whole import aborting.
fn existing_values(
    result: Result<Vec<ClientUriEntry>, FerriskeyClientError>,
    what: &str,
    client_id: &str,
    report: &mut ImportReport,
) -> HashSet<String> {
    match result {
        Ok(entries) => entries.into_iter().map(|entry| entry.value).collect(),
        Err(e) => {
            report
                .warnings
                .push(format!("could not list {what} of client '{client_id}': {e}"));
            HashSet::new()
        }
    }
}

fn resolve_existing_user(
    client: &FerriskeyClient,
    realm: &str,
    username: &str,
    report: &mut ImportReport,
) -> Option<String> {
    match find_existing_user(client, realm, username) {
        Ok(found) => found,
        Err(e) => {
            report
                .warnings
                .push(format!("could not resolve existing user '{username}': {e}"));
            None
        }
    }
}

/// A `UserBlueprint.roles` entry: a plain name for a realm role, or
/// `client_id:role_name` for a role scoped to that client.
#[derive(Debug, PartialEq, Eq)]
enum RoleRef<'a> {
    Realm(&'a str),
    Client { client_id: &'a str, role: &'a str },
}

fn parse_role_ref(spec: &str) -> RoleRef<'_> {
    match spec.split_once(':') {
        Some((client_id, role)) => RoleRef::Client { client_id, role },
        None => RoleRef::Realm(spec),
    }
}

fn role_request(role: &RoleBlueprint) -> CreateRoleRequest {
    CreateRoleRequest {
        name: role.name.clone(),
        description: role.description.clone(),
        permissions: role.permissions.clone(),
    }
}

fn client_request(client_bp: &ClientBlueprint) -> CreateClientRequest {
    CreateClientRequest {
        client_id: client_bp.client_id.clone(),
        client_type: client_bp.client_type.clone(),
        direct_access_grants_enabled: client_bp.direct_access_grants_enabled,
        enabled: client_bp.enabled,
        name: client_bp.name.clone().unwrap_or_else(|| client_bp.client_id.clone()),
        protocol: client_bp.protocol.clone(),
        public_client: client_bp.public_client,
        service_account_enabled: client_bp.service_account_enabled,
        oauth_device_code_grant_enabled: client_bp.device_authorization_grant_enabled,
    }
}

fn user_request(user: &super::UserBlueprint) -> CreateUserRequest {
    CreateUserRequest {
        username: user.username.clone(),
        firstname: user.firstname.clone(),
        lastname: user.lastname.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
    }
}

/// Whether an API error means "this entity already exists" — treated as a skip.
///
/// Some already-deployed servers surface a duplicate-key unique-constraint
/// violation as a raw `500` instead of a proper `409` (e.g. `realms_name_key`
/// on a duplicate realm name); recognizing it here lets an import converge on
/// replay without needing every server upgraded first.
fn is_conflict(error: &FerriskeyClientError) -> bool {
    matches!(
        error,
        FerriskeyClientError::Api { status, body }
            if *status == StatusCode::CONFLICT
                || (*status == StatusCode::BAD_REQUEST
                    && (body.to_lowercase().contains("exist")
                        || body.to_lowercase().contains("already registered")))
                || (*status == StatusCode::INTERNAL_SERVER_ERROR
                    && body.to_lowercase().contains("unique constraint"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{
        ClientBlueprint, RealmBlueprint, RealmSettingsBlueprint, RoleBlueprint, UserBlueprint,
    };

    fn sample_blueprint() -> RealmBlueprint {
        RealmBlueprint {
            name: "acme".to_owned(),
            settings: Some(RealmSettingsBlueprint {
                access_token_lifetime: Some(300),
                ..Default::default()
            }),
            roles: vec![RoleBlueprint {
                name: "admin".to_owned(),
                ..Default::default()
            }],
            clients: vec![ClientBlueprint {
                client_id: "web".to_owned(),
                name: None,
                client_type: "public".to_owned(),
                protocol: "openid-connect".to_owned(),
                enabled: true,
                public_client: true,
                service_account_enabled: false,
                direct_access_grants_enabled: false,
                redirect_uris: vec!["https://a/*".to_owned(), "https://b/*".to_owned()],
                post_logout_redirect_uris: vec!["https://a/bye".to_owned()],
                web_origins: vec!["https://a".to_owned()],
                device_authorization_grant_enabled: false,
                require_pkce: Some(true),
                access_token_lifetime: None,
                refresh_token_lifetime: None,
                id_token_lifetime: None,
                temporary_token_lifetime: None,
                roles: vec![RoleBlueprint {
                    name: "viewer".to_owned(),
                    ..Default::default()
                }],
            }],
            users: vec![UserBlueprint {
                username: "alice".to_owned(),
                email: None,
                firstname: None,
                lastname: None,
                email_verified: None,
                roles: vec!["admin".to_owned()],
            }],
        }
    }

    #[test]
    fn dry_run_tallies_planned_actions_without_network() {
        // base_url only needs to be a valid URL; no request is made in dry-run.
        let client = FerriskeyClient::new("http://localhost:3333", "", "").unwrap();
        let report = apply_blueprint(&client, &sample_blueprint(), true).unwrap();

        assert!(report.dry_run);
        assert!(report.realm_created);
        assert!(report.settings_applied);
        assert_eq!(report.roles_created, 1);
        assert_eq!(report.clients_created, 1);
        assert_eq!(report.redirects_created, 2);
        assert_eq!(report.post_logout_redirects_created, 1);
        assert_eq!(report.web_origins_created, 1);
        assert_eq!(report.client_settings_applied, 1);
        assert_eq!(report.client_roles_created, 1);
        assert_eq!(report.users_created, 1);
        assert_eq!(report.role_assignments, 1);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn dry_run_empty_settings_not_counted() {
        let mut bp = sample_blueprint();
        bp.settings = Some(RealmSettingsBlueprint::default());
        let client = FerriskeyClient::new("http://localhost:3333", "", "").unwrap();
        let report = apply_blueprint(&client, &bp, true).unwrap();
        assert!(!report.settings_applied);
    }

    fn api_error(status: StatusCode, body: &str) -> FerriskeyClientError {
        FerriskeyClientError::Api {
            status,
            body: body.to_owned(),
        }
    }

    #[test]
    fn is_conflict_recognizes_409() {
        assert!(is_conflict(&api_error(StatusCode::CONFLICT, "")));
    }

    #[test]
    fn is_conflict_recognizes_400_with_exist_in_body() {
        assert!(is_conflict(&api_error(
            StatusCode::BAD_REQUEST,
            "realm already exists"
        )));
    }

    #[test]
    fn is_conflict_recognizes_400_web_origin_already_registered() {
        // Observed live: a duplicate web origin doesn't say "exist" at all.
        assert!(is_conflict(&api_error(
            StatusCode::BAD_REQUEST,
            "Invalid web origin: this origin is already registered for the client"
        )));
    }

    #[test]
    fn is_conflict_recognizes_500_unique_constraint_violation() {
        // A raw Postgres unique-constraint violation surfaced as a 500 by
        // older, not-yet-patched servers (e.g. a duplicate realm name).
        assert!(is_conflict(&api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "duplicate key value violates unique constraint \"realms_name_key\""
        )));
    }

    #[test]
    fn is_conflict_rejects_unrelated_500() {
        assert!(!is_conflict(&api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error"
        )));
    }

    #[test]
    fn is_conflict_rejects_unrelated_400() {
        assert!(!is_conflict(&api_error(StatusCode::BAD_REQUEST, "invalid input")));
    }

    #[test]
    fn existing_values_collects_registered_uris() {
        let mut report = ImportReport::default();
        let values = existing_values(
            Ok(vec![
                ClientUriEntry {
                    id: Some("1".to_owned()),
                    value: "https://a/callback".to_owned(),
                },
                ClientUriEntry {
                    id: None,
                    value: "https://b/callback".to_owned(),
                },
            ]),
            "redirect uris",
            "web",
            &mut report,
        );

        assert!(values.contains("https://a/callback"));
        assert!(values.contains("https://b/callback"));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn existing_values_warns_and_degrades_to_empty_on_read_failure() {
        let mut report = ImportReport::default();
        let values = existing_values(
            Err(api_error(StatusCode::FORBIDDEN, "nope")),
            "web origins",
            "web",
            &mut report,
        );

        // Empty, so the create below still runs and decides for itself rather
        // than the whole import aborting on a failed read.
        assert!(values.is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("could not list web origins of client 'web'"));
    }

    #[test]
    fn parse_role_ref_plain_name_is_realm_role() {
        assert_eq!(parse_role_ref("admin"), RoleRef::Realm("admin"));
    }

    #[test]
    fn parse_role_ref_qualified_name_is_client_role() {
        assert_eq!(
            parse_role_ref("myapp:viewer"),
            RoleRef::Client {
                client_id: "myapp",
                role: "viewer"
            }
        );
    }
}
