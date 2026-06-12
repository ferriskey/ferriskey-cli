//! Reads a realm from a live Keycloak instance through its Admin REST API.
//!
//! Authentication uses the OpenID Connect token endpoint of the source realm
//! (client-credentials grant), unless a ready bearer token is supplied with
//! `--source-token`. Entities are then read from `/admin/realms/{realm}/...`.
//!
//! User password hashes are never exported by Keycloak, so users are recreated
//! without credentials. User role mappings are not imported in this iteration
//! (roles themselves are created).

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

        let clients = kc_clients
            .into_iter()
            .map(|client| {
                let client_roles = self
                    .get::<Vec<KcRole>>(&token, &format!("/clients/{}/roles", client.id))
                    .unwrap_or_default()
                    .into_iter()
                    .map(map_role)
                    .collect();
                map_client(client, client_roles)
            })
            .collect();

        let mut users = Vec::new();
        let mut first = 0;
        loop {
            let page: Vec<KcUser> =
                self.get(&token, &format!("/users?first={first}&max={USER_PAGE_SIZE}"))?;
            let count = page.len();
            users.extend(page.into_iter().map(map_user));
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
        roles,
    }
}

fn map_user(user: KcUser) -> crate::import::UserBlueprint {
    crate::import::UserBlueprint {
        username: user.username,
        email: user.email,
        firstname: user.first_name,
        lastname: user.last_name,
        email_verified: user.email_verified,
        roles: Vec::new(),
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

#[derive(Debug, Deserialize)]
struct KcUser {
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
}
