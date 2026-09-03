//! Replays a [`RealmBlueprint`] against the FerrisKey API.
//!
//! The API exposes no bulk import, so entities are created one by one in
//! dependency order: realm, then settings, realm roles, clients (with their
//! redirect URIs and client roles), and finally users with their role
//! assignments. An entity that already exists is treated as a skip with a
//! warning rather than a hard error, so an import can be re-run to converge.

use std::collections::HashMap;

use ferriskey_cli_client::{
    CreateClientRequest, CreateRedirectUriRequest, CreateRoleRequest, CreateUserRequest,
    CreateWebOriginRequest, FerriskeyClient, FerriskeyClientError,
};
use reqwest::StatusCode;

use super::{ClientBlueprint, ImportError, ImportReport, RealmBlueprint, RoleBlueprint};

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

    // 1. Realm.
    match client.create_realm(&ferriskey_cli_client::CreateRealmRequest { name: realm.to_owned() })
    {
        Ok(_) => report.realm_created = true,
        Err(e) if is_conflict(&e) => {
            report.already_present += 1;
            report
                .warnings
                .push(format!("realm '{realm}' already exists, reusing it"));
        }
        Err(e) => return Err(e.into()),
    }

    // 2. Settings.
    if let Some(settings) = &blueprint.settings {
        let request = settings.to_request();
        if !request.is_empty() {
            client.update_realm_settings(realm, &request)?;
            report.settings_applied = true;
        }
    }

    // 3. Realm roles. Track name -> id so we can assign them to users later.
    let mut role_ids: HashMap<String, String> = HashMap::new();
    for role in &blueprint.roles {
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

    // Backfill ids for roles referenced by users but skipped above (already existing).
    let missing_role_ref = blueprint
        .users
        .iter()
        .flat_map(|u| &u.roles)
        .any(|name| !role_ids.contains_key(name));
    if missing_role_ref {
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

    // 4. Clients, with their redirect URIs and client-scoped roles.
    for client_bp in &blueprint.clients {
        let Some(client_uuid) = resolve_client(client, realm, client_bp, &mut report)? else {
            continue;
        };

        for uri in &client_bp.redirect_uris {
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

        for uri in &client_bp.post_logout_redirect_uris {
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

        for origin in &client_bp.web_origins {
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

        for role in &client_bp.roles {
            match client.create_client_role(realm, &client_uuid, &role_request(role)) {
                Ok(_) => report.client_roles_created += 1,
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

    // 5. Users, with realm-role assignments.
    for user in &blueprint.users {
        let user_id = match client.create_user(realm, &user_request(user)) {
            Ok(created) => {
                report.users_created += 1;
                Some(created.id)
            }
            Err(e) if is_conflict(&e) => {
                report.already_present += 1;
                report
                    .warnings
                    .push(format!("user '{}' already exists, reusing it", user.username));
                resolve_existing_user(client, realm, &user.username, &mut report)
            }
            Err(e) => return Err(e.into()),
        };

        let Some(user_id) = user_id else { continue };
        for role_name in &user.roles {
            match role_ids.get(role_name) {
                Some(role_id) => match client.assign_user_role(realm, &user_id, role_id) {
                    Ok(()) => report.role_assignments += 1,
                    Err(e) if is_conflict(&e) => {
                        report.already_present += 1;
                        report.warnings.push(format!(
                            "user '{}' already has role '{role_name}'",
                            user.username
                        ));
                    }
                    Err(e) => return Err(e.into()),
                },
                None => report.warnings.push(format!(
                    "role '{role_name}' not found, cannot assign it to user '{}'",
                    user.username
                )),
            }
        }
    }

    Ok(report)
}

/// Creates a client, returning its UUID. On conflict, resolves the existing
/// client's UUID so its redirects/roles can still be applied.
fn resolve_client(
    client: &FerriskeyClient,
    realm: &str,
    client_bp: &ClientBlueprint,
    report: &mut ImportReport,
) -> Result<Option<String>, ImportError> {
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

fn resolve_existing_user(
    client: &FerriskeyClient,
    realm: &str,
    username: &str,
    report: &mut ImportReport,
) -> Option<String> {
    match client.find_users_by_username(realm, username) {
        Ok(users) => users.into_iter().find(|u| u.username == username).map(|u| u.id),
        Err(e) => {
            report
                .warnings
                .push(format!("could not resolve existing user '{username}': {e}"));
            None
        }
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
}
