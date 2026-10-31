//! Reads a realm from a live Keycloak instance through its Admin REST API.
//!
//! Authentication uses the OpenID Connect token endpoint of the source realm
//! (client-credentials grant), unless a ready bearer token is supplied with
//! `--source-token`. Entities are then read from `/admin/realms/{realm}/...`.
//!
//! User password hashes are never exported by Keycloak, so users are recreated
//! without credentials. Each user's direct realm and client role mappings are
//! read from `/users/{id}/role-mappings`; composite and group-inherited roles
//! are not expanded.

use std::collections::{HashMap, HashSet};

use reqwest::blocking::Client;
use serde::Deserialize;

use crate::import::{
    ClientBlueprint, ImportError, RealmBlueprint, RealmSettingsBlueprint, RealmSource, RoleBlueprint,
};

const SOURCE: &str = "keycloak";
const USER_PAGE_SIZE: usize = 100;

enum Auth {
    Token(String),
    ClientCredentials { client_id: String, client_secret: String },
}

pub struct KeycloakSource {
    base_url: String,
    realm: String,
    auth: Auth,
    http: Client,
}

impl KeycloakSource {
    /// Builds the source from resolved option values (inline flags already merged
    /// over any stored source).
    pub fn build(
        base_url: Option<String>,
        realm: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        token: Option<String>,
    ) -> Result<Self, ImportError> {
        let base_url = base_url
            .ok_or(ImportError::MissingArg("--source-url"))?
            .trim_end_matches('/')
            .to_owned();
        let realm = realm.ok_or(ImportError::MissingArg("--source-realm"))?;

        let auth = if let Some(token) = token {
            Auth::Token(token)
        } else {
            Auth::ClientCredentials {
                client_id: client_id.ok_or(ImportError::MissingArg("--source-client-id"))?,
                client_secret: client_secret
                    .ok_or(ImportError::MissingArg("--source-client-secret"))?,
            }
        };

        Ok(Self {
            base_url,
            realm,
            auth,
            http: Client::new(),
        })
    }

    fn access_token(&self) -> Result<String, ImportError> {
        match &self.auth {
            Auth::Token(token) => Ok(token.clone()),
            Auth::ClientCredentials {
                client_id,
                client_secret,
            } => {
                let url = format!(
                    "{}/realms/{}/protocol/openid-connect/token",
                    self.base_url, self.realm
                );
                let response = self
                    .http
                    .post(url)
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", client_id.as_str()),
                        ("client_secret", client_secret.as_str()),
                    ])
                    .send()?;
                let response = check(response)?;
                Ok(response.json::<TokenResponse>()?.access_token)
            }
        }
    }

    fn get<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        path: &str,
    ) -> Result<T, ImportError> {
        let url = format!("{}/admin/realms/{}{}", self.base_url, self.realm, path);
        let response = self.http.get(url).bearer_auth(token).send()?;
        Ok(check(response)?.json::<T>()?)
    }
}

impl RealmSource for KeycloakSource {
    fn fetch(&self) -> Result<Vec<RealmBlueprint>, ImportError> {
        let token = self.access_token()?;

        let realm_rep: KcRealm = self.get(&token, "")?;
        let kc_clients: Vec<KcClient> = self.get(&token, "/clients")?;
        let kc_roles: Vec<KcRole> = self.get(&token, "/roles")?;

        let mut catalogue = RoleCatalogue {
            realm: kc_roles.iter().map(|role| role.name.clone()).collect(),
            clients: HashSet::new(),
        };

        let clients = kc_clients
            .into_iter()
            .map(|client| {
                let client_roles: Vec<RoleBlueprint> = self
                    .get::<Vec<KcRole>>(&token, &format!("/clients/{}/roles", client.id))
                    .unwrap_or_default()
                    .into_iter()
                    .map(map_role)
                    .collect();
                for role in &client_roles {
                    catalogue
                        .clients
                        .insert((client.client_id.clone(), role.name.clone()));
                }
                map_client(client, client_roles)
            })
            .collect();

        let mut users = Vec::new();
        let mut first = 0;
        loop {
            let page: Vec<KcUser> =
                self.get(&token, &format!("/users?first={first}&max={USER_PAGE_SIZE}"))?;
            let count = page.len();
            for user in page {
                let mappings: KcRoleMappings =
                    self.get(&token, &format!("/users/{}/role-mappings", user.id))?;
                let (roles, skipped) = map_role_mappings(&mappings, &catalogue);
                for reason in skipped {
                    eprintln!("note: user '{}': {reason}", user.username);
                }
                users.push(map_user(user, roles));
            }
            if count < USER_PAGE_SIZE {
                break;
            }
            first += USER_PAGE_SIZE;
        }

        let settings = map_settings(&realm_rep);
        Ok(vec![RealmBlueprint {
            name: realm_rep.realm.unwrap_or_else(|| self.realm.clone()),
            settings: Some(settings),
            roles: kc_roles.into_iter().map(map_role).collect(),
            clients,
            users,
        }])
    }
}

fn check(
    response: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response, ImportError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        Err(ImportError::Source {
            provider: SOURCE,
            status,
            body,
        })
    }
}

fn map_settings(realm: &KcRealm) -> RealmSettingsBlueprint {
    RealmSettingsBlueprint {
        access_token_lifetime: realm.access_token_lifespan,
        user_registration_enabled: realm.registration_allowed,
        forgot_password_enabled: realm.reset_password_allowed,
        remember_me_enabled: realm.remember_me,
        email_verification_enabled: realm.verify_email,
        ..Default::default()
    }
}

fn map_role(role: KcRole) -> RoleBlueprint {
    RoleBlueprint {
        name: role.name,
        description: role.description,
        permissions: Vec::new(),
    }
}

fn map_client(client: KcClient, roles: Vec<RoleBlueprint>) -> ClientBlueprint {
    let public_client = client.public_client.unwrap_or(false);
    ClientBlueprint {
        client_id: client.client_id,
        name: client.name,
        client_type: if public_client {
            "public".to_owned()
        } else {
            "confidential".to_owned()
        },
        protocol: client.protocol.unwrap_or_else(|| "openid-connect".to_owned()),
        enabled: client.enabled.unwrap_or(true),
        public_client,
        service_account_enabled: client.service_accounts_enabled.unwrap_or(false),
        direct_access_grants_enabled: client.direct_access_grants_enabled.unwrap_or(false),
        redirect_uris: client.redirect_uris.unwrap_or_default(),
        // Keycloak carries these under a free-form `attributes` map with
        // Keycloak-specific keys, not a plain field — not extracted here.
        post_logout_redirect_uris: Vec::new(),
        web_origins: Vec::new(),
        device_authorization_grant_enabled: false,
        require_pkce: None,
        access_token_lifetime: None,
        refresh_token_lifetime: None,
        id_token_lifetime: None,
        temporary_token_lifetime: None,
        roles,
    }
}

/// What the import creates, so a mapping can be checked against it: a user
/// can only be given a role the target realm will actually hold.
struct RoleCatalogue {
    realm: HashSet<String>,
    clients: HashSet<(String, String)>,
}

/// Turns a user's direct Keycloak mappings into blueprint role references
/// (`name` for a realm role, `client_id:name` for a client role).
///
/// A blueprint separates the client from the role at the first `:`, so a realm
/// role or a client id containing one cannot be written down; those, and any
/// role the import does not create, come back as skip reasons instead.
fn map_role_mappings(
    mappings: &KcRoleMappings,
    catalogue: &RoleCatalogue,
) -> (Vec<String>, Vec<String>) {
    let mut roles = Vec::new();
    let mut skipped = Vec::new();

    for role in mappings.realm_mappings.iter().flatten() {
        if role.name.contains(':') {
            skipped.push(format!(
                "realm role '{}' skipped: a ':' in the name is reserved for client roles",
                role.name
            ));
        } else if !catalogue.realm.contains(&role.name) {
            skipped.push(format!(
                "realm role '{}' skipped: it is not part of the import",
                role.name
            ));
        } else {
            roles.push(role.name.clone());
        }
    }

    let mut clients: Vec<(&String, &KcClientMapping)> =
        mappings.client_mappings.iter().flatten().collect();
    clients.sort_by_key(|(key, _)| key.as_str());
    for (key, entry) in clients {
        let client_id = entry.client.as_deref().unwrap_or(key);
        for role in &entry.mappings {
            if client_id.contains(':') {
                skipped.push(format!(
                    "client role '{client_id}:{}' skipped: a ':' in the client id is reserved \
                     as the client/role separator",
                    role.name
                ));
            } else if !catalogue
                .clients
                .contains(&(client_id.to_owned(), role.name.clone()))
            {
                skipped.push(format!(
                    "client role '{client_id}:{}' skipped: it is not part of the import",
                    role.name
                ));
            } else {
                roles.push(format!("{client_id}:{}", role.name));
            }
        }
    }

    (roles, skipped)
}

fn map_user(user: KcUser, roles: Vec<String>) -> crate::import::UserBlueprint {
    crate::import::UserBlueprint {
        username: user.username,
        id: None,
        email: user.email,
        firstname: user.first_name,
        lastname: user.last_name,
        email_verified: user.email_verified,
        roles,
        credential: None,
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct KcRealm {
    realm: Option<String>,
    #[serde(rename = "accessTokenLifespan")]
    access_token_lifespan: Option<i64>,
    #[serde(rename = "registrationAllowed")]
    registration_allowed: Option<bool>,
    #[serde(rename = "resetPasswordAllowed")]
    reset_password_allowed: Option<bool>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(rename = "verifyEmail")]
    verify_email: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct KcClient {
    id: String,
    #[serde(rename = "clientId")]
    client_id: String,
    name: Option<String>,
    enabled: Option<bool>,
    protocol: Option<String>,
    #[serde(rename = "publicClient")]
    public_client: Option<bool>,
    #[serde(rename = "serviceAccountsEnabled")]
    service_accounts_enabled: Option<bool>,
    #[serde(rename = "directAccessGrantsEnabled")]
    direct_access_grants_enabled: Option<bool>,
    #[serde(rename = "redirectUris")]
    redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct KcRole {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct KcRoleMappings {
    #[serde(rename = "realmMappings")]
    realm_mappings: Option<Vec<KcRole>>,
    #[serde(rename = "clientMappings")]
    client_mappings: Option<HashMap<String, KcClientMapping>>,
}

#[derive(Debug, Deserialize)]
struct KcClientMapping {
    client: Option<String>,
    #[serde(default)]
    mappings: Vec<KcRole>,
}

#[derive(Debug, Deserialize)]
struct KcUser {
    id: String,
    username: String,
    email: Option<String>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "emailVerified")]
    email_verified: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_keycloak_client_to_blueprint() {
        let kc = KcClient {
            id: "uuid-1".to_owned(),
            client_id: "web".to_owned(),
            name: Some("Web".to_owned()),
            enabled: Some(true),
            protocol: Some("openid-connect".to_owned()),
            public_client: Some(true),
            service_accounts_enabled: Some(false),
            direct_access_grants_enabled: Some(true),
            redirect_uris: Some(vec!["https://a/*".to_owned()]),
        };
        let bp = map_client(kc, vec![]);
        assert_eq!(bp.client_id, "web");
        assert_eq!(bp.client_type, "public");
        assert!(bp.public_client);
        assert!(bp.direct_access_grants_enabled);
        assert_eq!(bp.redirect_uris, vec!["https://a/*".to_owned()]);
    }

    #[test]
    fn maps_realm_settings() {
        let realm = KcRealm {
            realm: Some("acme".to_owned()),
            access_token_lifespan: Some(300),
            registration_allowed: Some(true),
            reset_password_allowed: Some(false),
            remember_me: None,
            verify_email: Some(true),
        };
        let settings = map_settings(&realm);
        assert_eq!(settings.access_token_lifetime, Some(300));
        assert_eq!(settings.user_registration_enabled, Some(true));
        assert_eq!(settings.email_verification_enabled, Some(true));
        assert!(settings.remember_me_enabled.is_none());
    }

    fn catalogue() -> RoleCatalogue {
        RoleCatalogue {
            realm: ["admin", "default-roles-acme", "ops:oncall"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            clients: [("web", "viewer"), ("urn:app", "editor")]
                .into_iter()
                .map(|(client, role)| (client.to_owned(), role.to_owned()))
                .collect(),
        }
    }

    fn mappings(json: &str) -> KcRoleMappings {
        serde_json::from_str(json).expect("role mappings")
    }

    #[test]
    fn reads_a_keycloak_role_mappings_payload() {
        let parsed = mappings(
            r#"{
                "realmMappings": [{"id": "r1", "name": "admin", "composite": false}],
                "clientMappings": {
                    "web": {"id": "c1", "client": "web", "mappings": [{"id": "r2", "name": "viewer"}]}
                }
            }"#,
        );
        let (roles, skipped) = map_role_mappings(&parsed, &catalogue());
        assert_eq!(roles, vec!["admin".to_owned(), "web:viewer".to_owned()]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_user_without_mappings_gets_no_roles() {
        let (roles, skipped) = map_role_mappings(&mappings("{}"), &catalogue());
        assert!(roles.is_empty());
        assert!(skipped.is_empty());
    }

    #[test]
    fn skips_and_reports_a_role_the_import_does_not_create() {
        let parsed = mappings(
            r#"{
                "realmMappings": [{"name": "admin"}, {"name": "ghost"}],
                "clientMappings": {
                    "web": {"client": "web", "mappings": [{"name": "viewer"}, {"name": "ghost"}]}
                }
            }"#,
        );
        let (roles, skipped) = map_role_mappings(&parsed, &catalogue());
        assert_eq!(roles, vec!["admin".to_owned(), "web:viewer".to_owned()]);
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("realm role 'ghost'"));
        assert!(skipped[1].contains("client role 'web:ghost'"));
    }

    #[test]
    fn skips_names_a_blueprint_cannot_express() {
        let parsed = mappings(
            r#"{
                "realmMappings": [{"name": "ops:oncall"}],
                "clientMappings": {
                    "urn:app": {"client": "urn:app", "mappings": [{"name": "editor"}]}
                }
            }"#,
        );
        let (roles, skipped) = map_role_mappings(&parsed, &catalogue());
        assert!(roles.is_empty());
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("realm role 'ops:oncall'"));
        assert!(skipped[1].contains("urn:app"));
    }

    #[test]
    fn client_mappings_come_out_in_a_stable_order() {
        let mut catalogue = catalogue();
        catalogue
            .clients
            .insert(("api".to_owned(), "reader".to_owned()));
        let parsed = mappings(
            r#"{"clientMappings": {
                "web": {"client": "web", "mappings": [{"name": "viewer"}]},
                "api": {"client": "api", "mappings": [{"name": "reader"}]}
            }}"#,
        );
        let (roles, _) = map_role_mappings(&parsed, &catalogue);
        assert_eq!(
            roles,
            vec!["api:reader".to_owned(), "web:viewer".to_owned()]
        );
    }

    #[test]
    fn map_user_carries_the_resolved_roles() {
        let user = KcUser {
            id: "u1".to_owned(),
            username: "alice".to_owned(),
            email: None,
            first_name: None,
            last_name: None,
            email_verified: None,
        };
        let bp = map_user(user, vec!["admin".to_owned()]);
        assert_eq!(bp.roles, vec!["admin".to_owned()]);
    }
}
