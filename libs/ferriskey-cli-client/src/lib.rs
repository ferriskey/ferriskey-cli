use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FerriskeyClientError {
    #[error("invalid base url: {0}")]
    InvalidBaseUrl(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api request failed with status {status}: {body}")]
    Api { status: StatusCode, body: String },
}

#[derive(Debug, Clone)]
pub struct FerriskeyClient {
    http: Client,
    base_url: String,
    api_prefix: String,
    token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Realm {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientRepresentation {
    pub id: Option<String>,
    #[serde(rename = "clientId", alias = "client_id")]
    pub client_id: Option<String>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub protocol: Option<String>,
    #[serde(rename = "publicClient", alias = "public_client")]
    pub public_client: Option<bool>,
    #[serde(rename = "serviceAccountsEnabled", alias = "service_account_enabled")]
    pub service_accounts_enabled: Option<bool>,
    #[serde(
        rename = "directAccessGrantsEnabled",
        alias = "direct_access_grants_enabled"
    )]
    pub direct_access_grants_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserRepresentation {
    pub id: String,
    pub username: String,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub email: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ClientInRealm {
    pub realm: String,
    pub client: ClientRepresentation,
}

#[derive(Debug, Clone)]
pub struct UserInRealm {
    pub realm: String,
    pub user: UserRepresentation,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtToken {
    pub access_token: String,
    pub expires_in: i32,
    pub id_token: Option<String>,
    pub refresh_token: String,
    pub token_type: String,
    #[serde(default)]
    pub refresh_expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthErrorPayload {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Result of a single poll against the device-code token endpoint.
#[derive(Debug)]
pub enum DeviceTokenError {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    InvalidGrant,
    InvalidClient,
    /// Any other oauth-defined error in the 400 body.
    Other {
        code: String,
        description: Option<String>,
    },
    /// Non-400 status (5xx, etc.) — caller should backoff & retry until global timeout.
    Transient(FerriskeyClientError),
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRealmRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub client_type: String,
    pub direct_access_grants_enabled: bool,
    pub enabled: bool,
    pub name: String,
    pub protocol: String,
    pub public_client: bool,
    pub service_account_enabled: bool,
    pub oauth_device_code_grant_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedClient {
    pub id: String,
    pub client_id: String,
    pub name: String,
}

/// Partial update of a realm's settings. Only the fields that are `Some` are sent,
/// mirroring the backend `UpdateRealmSettingValidator` (all-optional) payload.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateRealmSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_signing_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_registration_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgot_password_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_link_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_link_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkey_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compass_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporary_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verification_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verification_ttl_hours: Option<i64>,
}

impl UpdateRealmSettingsRequest {
    /// Returns true when no field is set (nothing to send).
    pub fn is_empty(&self) -> bool {
        self.default_signing_algorithm.is_none()
            && self.user_registration_enabled.is_none()
            && self.forgot_password_enabled.is_none()
            && self.remember_me_enabled.is_none()
            && self.magic_link_enabled.is_none()
            && self.magic_link_ttl.is_none()
            && self.passkey_enabled.is_none()
            && self.compass_enabled.is_none()
            && self.access_token_lifetime.is_none()
            && self.refresh_token_lifetime.is_none()
            && self.id_token_lifetime.is_none()
            && self.temporary_token_lifetime.is_none()
            && self.email_verification_enabled.is_none()
            && self.email_verification_ttl_hours.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedRole {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRedirectUriRequest {
    pub value: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateWebOriginRequest {
    pub value: String,
}

/// Partial update of a client's PKCE requirement and token lifetimes. Only the
/// fields that are `Some` are sent. Applied via `PATCH`, unlike the rest of the
/// client's settings which are only settable at creation time.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateClientSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporary_token_lifetime: Option<i64>,
}

impl UpdateClientSettingsRequest {
    /// Returns true when no field is set (nothing to send).
    pub fn is_empty(&self) -> bool {
        self.require_pkce.is_none()
            && self.access_token_lifetime.is_none()
            && self.refresh_token_lifetime.is_none()
            && self.id_token_lifetime.is_none()
            && self.temporary_token_lifetime.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SetPasswordRequest {
    pub value: String,
    pub temporary: bool,
}

impl FerriskeyClient {
    pub fn new(
        base_url: impl Into<String>,
        api_prefix: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, FerriskeyClientError> {
        let base_url = base_url.into();
        let api_prefix = api_prefix.into();
        let token = token.into();

        if reqwest::Url::parse(&base_url).is_err() {
            return Err(FerriskeyClientError::InvalidBaseUrl(base_url));
        }

        Ok(Self {
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_prefix: normalize_prefix(&api_prefix),
            token,
        })
    }

    pub fn list_realms(&self, auth_realm: &str) -> Result<Vec<Realm>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!(
            "realms/{auth_realm}/users/@me/realms"
        )))
    }

    pub fn get_realm(&self, name: &str) -> Result<Realm, FerriskeyClientError> {
        self.get_json(&self.endpoint(&format!("realms/{name}")))
    }

    pub fn create_realm(
        &self,
        request: &CreateRealmRequest,
    ) -> Result<Realm, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint("realms"))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<Realm>()?)
    }

    pub fn delete_realm(&self, name: &str) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .delete(self.endpoint(&format!("realms/{name}")))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn list_clients(
        &self,
        realm: &str,
    ) -> Result<Vec<ClientRepresentation>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!("realms/{realm}/clients")))
    }

    pub fn delete_client(
        &self,
        realm: &str,
        uuid: &str,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .delete(self.endpoint(&format!("realms/{realm}/clients/{uuid}")))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    /// The server ignores the `clientId` query filter on this route and
    /// always returns the full list, so the match is done client-side.
    pub fn get_client(
        &self,
        realm: &str,
        client_id: &str,
    ) -> Result<Option<ClientRepresentation>, FerriskeyClientError> {
        let results = self.list_clients(realm)?;
        Ok(results
            .into_iter()
            .find(|client| client.client_id.as_deref() == Some(client_id)))
    }

    pub fn list_users(&self, realm: &str) -> Result<Vec<UserRepresentation>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!("realms/{realm}/users")))
    }

    pub fn find_users_by_username(
        &self,
        realm: &str,
        username: &str,
    ) -> Result<Vec<UserRepresentation>, FerriskeyClientError> {
        let url = format!(
            "{}?username={}",
            self.endpoint(&format!("realms/{realm}/users")),
            username
        );
        self.get_list(&url)
    }

    pub fn create_user(
        &self,
        realm: &str,
        request: &CreateUserRequest,
    ) -> Result<UserRepresentation, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/users")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        self.extract_envelope(response)
    }

    pub fn delete_user(&self, realm: &str, user_id: &str) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .delete(self.endpoint(&format!("realms/{realm}/users/{user_id}")))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn list_clients_all_realms(
        &self,
        auth_realm: &str,
    ) -> Result<Vec<ClientInRealm>, FerriskeyClientError> {
        let realms = self.list_realms(auth_realm)?;
        let mut out = Vec::new();

        for realm in realms {
            let realm_name = realm.name;
            let clients = self.list_clients(&realm_name)?;
            out.extend(clients.into_iter().map(|client| ClientInRealm {
                realm: realm_name.clone(),
                client,
            }));
        }

        Ok(out)
    }

    pub fn list_users_all_realms(
        &self,
        auth_realm: &str,
    ) -> Result<Vec<UserInRealm>, FerriskeyClientError> {
        let realms = self.list_realms(auth_realm)?;
        let mut out = Vec::new();

        for realm in realms {
            let realm_name = realm.name;
            let users = self.list_users(&realm_name)?;
            out.extend(users.into_iter().map(|user| UserInRealm {
                realm: realm_name.clone(),
                user,
            }));
        }

        Ok(out)
    }

    pub fn create_client(
        &self,
        realm: &str,
        request: &CreateClientRequest,
    ) -> Result<CreatedClient, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/clients")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<CreatedClient>()?)
    }

    pub fn update_realm_settings(
        &self,
        realm: &str,
        request: &UpdateRealmSettingsRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .put(self.endpoint(&format!("realms/{realm}/settings")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn create_role(
        &self,
        realm: &str,
        request: &CreateRoleRequest,
    ) -> Result<CreatedRole, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/roles")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        self.extract_envelope(response)
    }

    pub fn list_realm_roles(&self, realm: &str) -> Result<Vec<CreatedRole>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!("realms/{realm}/roles")))
    }

    pub fn delete_role(&self, realm: &str, role_id: &str) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .delete(self.endpoint(&format!("realms/{realm}/roles/{role_id}")))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn list_client_roles(
        &self,
        realm: &str,
        client_uuid: &str,
    ) -> Result<Vec<CreatedRole>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!("realms/{realm}/clients/{client_uuid}/roles")))
    }

    pub fn create_client_role(
        &self,
        realm: &str,
        client_uuid: &str,
        request: &CreateRoleRequest,
    ) -> Result<CreatedRole, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/clients/{client_uuid}/roles")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        // Unlike `create_role`, this endpoint returns the created role as a
        // bare object, not wrapped in a `{"data": ...}` envelope.
        Ok(response.json::<CreatedRole>()?)
    }

    pub fn add_client_redirect(
        &self,
        realm: &str,
        client_uuid: &str,
        request: &CreateRedirectUriRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/clients/{client_uuid}/redirects")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn add_client_post_logout_redirect(
        &self,
        realm: &str,
        client_uuid: &str,
        request: &CreateRedirectUriRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!(
                "realms/{realm}/clients/{client_uuid}/post-logout-redirects"
            )))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn add_client_web_origin(
        &self,
        realm: &str,
        client_uuid: &str,
        request: &CreateWebOriginRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/clients/{client_uuid}/web-origins")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    /// Update a client's PKCE requirement / token lifetimes. Unlike most of a
    /// client's settings (only settable at creation), these are only settable
    /// via this PATCH.
    pub fn update_client_settings(
        &self,
        realm: &str,
        client_uuid: &str,
        request: &UpdateClientSettingsRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .patch(self.endpoint(&format!("realms/{realm}/clients/{client_uuid}")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn assign_user_role(
        &self,
        realm: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!(
                "realms/{realm}/users/{user_id}/roles/{role_id}"
            )))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn remove_user_role(
        &self,
        realm: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .delete(self.endpoint(&format!(
                "realms/{realm}/users/{user_id}/roles/{role_id}"
            )))
            .bearer_auth(&self.token)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    pub fn list_user_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> Result<Vec<CreatedRole>, FerriskeyClientError> {
        self.get_list(&self.endpoint(&format!("realms/{realm}/users/{user_id}/roles")))
    }

    pub fn set_user_password(
        &self,
        realm: &str,
        user_id: &str,
        request: &SetPasswordRequest,
    ) -> Result<(), FerriskeyClientError> {
        let response = self
            .http
            .put(self.endpoint(&format!("realms/{realm}/users/{user_id}/reset-password")))
            .bearer_auth(&self.token)
            .json(request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(())
    }

    /// RFC 8628 §3.1 — start a device authorization flow.
    pub fn device_authorization(
        &self,
        realm: &str,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse, FerriskeyClientError> {
        let mut form: Vec<(&str, &str)> = vec![("client_id", client_id)];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }

        let response = self
            .http
            .post(self.endpoint(&format!(
                "realms/{realm}/protocol/openid-connect/auth/device"
            )))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<DeviceAuthorizationResponse>()?)
    }

    /// RFC 8628 §3.4 — poll the token endpoint with the device_code.
    /// Errors are translated to `DeviceTokenError` so the caller can apply
    /// the polling/backoff rules without re-parsing.
    pub fn exchange_device_code(
        &self,
        realm: &str,
        client_id: &str,
        device_code: &str,
        client_secret: Option<&str>,
    ) -> Result<JwtToken, DeviceTokenError> {
        let mut form: Vec<(&str, &str)> = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code",
            ),
            ("device_code", device_code),
            ("client_id", client_id),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }

        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/protocol/openid-connect/token")))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .map_err(|err| DeviceTokenError::Transient(FerriskeyClientError::Http(err)))?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<JwtToken>()
                .map_err(|err| DeviceTokenError::Transient(FerriskeyClientError::Http(err)));
        }

        if status == StatusCode::BAD_REQUEST {
            let body = response.text().unwrap_or_default();
            return Err(parse_oauth_error(&body));
        }

        let body = response.text().unwrap_or_default();
        Err(DeviceTokenError::Transient(FerriskeyClientError::Api {
            status,
            body,
        }))
    }

    /// Exchange a refresh token for a fresh access token (OAuth2 `refresh_token`
    /// grant). `client_secret` is sent only for confidential clients.
    pub fn exchange_refresh_token(
        &self,
        realm: &str,
        client_id: &str,
        refresh_token: &str,
        client_secret: Option<&str>,
    ) -> Result<JwtToken, FerriskeyClientError> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }

        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/protocol/openid-connect/token")))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<JwtToken>()?)
    }

    pub fn exchange_client_credentials(
        &self,
        realm: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<JwtToken, FerriskeyClientError> {
        let response = self
            .http
            .post(self.endpoint(&format!("realms/{realm}/protocol/openid-connect/token")))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<JwtToken>()?)
    }

    fn endpoint(&self, resource_path: &str) -> String {
        let resource_path = resource_path.trim_start_matches('/');
        if self.api_prefix.is_empty() {
            format!("{}/{}", self.base_url, resource_path)
        } else {
            format!("{}/{}/{}", self.base_url, self.api_prefix, resource_path)
        }
    }

    fn extract_envelope<T: DeserializeOwned>(
        &self,
        response: reqwest::blocking::Response,
    ) -> Result<T, FerriskeyClientError> {
        let envelope: DataEnvelope<T> = response.json()?;
        Ok(envelope.data)
    }

    fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, FerriskeyClientError> {
        let response = self.http.get(url).bearer_auth(&self.token).send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(FerriskeyClientError::Api { status, body });
        }

        Ok(response.json::<T>()?)
    }

    fn get_list<T: DeserializeOwned>(&self, url: &str) -> Result<Vec<T>, FerriskeyClientError> {
        let payload: ListPayload<T> = self.get_json(url)?;
        Ok(match payload {
            ListPayload::Raw(items) => items,
            ListPayload::Envelope { data } => data,
        })
    }
}

fn parse_oauth_error(body: &str) -> DeviceTokenError {
    match serde_json::from_str::<OAuthErrorPayload>(body) {
        Ok(payload) => match payload.error.as_str() {
            "authorization_pending" => DeviceTokenError::AuthorizationPending,
            "slow_down" => DeviceTokenError::SlowDown,
            "access_denied" => DeviceTokenError::AccessDenied,
            "expired_token" => DeviceTokenError::ExpiredToken,
            "invalid_grant" => DeviceTokenError::InvalidGrant,
            "invalid_client" => DeviceTokenError::InvalidClient,
            _ => DeviceTokenError::Other {
                code: payload.error,
                description: payload.error_description,
            },
        },
        Err(_) => DeviceTokenError::Transient(FerriskeyClientError::Api {
            status: StatusCode::BAD_REQUEST,
            body: body.to_owned(),
        }),
    }
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ListPayload<T> {
    Raw(Vec<T>),
    Envelope { data: Vec<T> },
}

#[derive(Debug, Deserialize)]
struct DataEnvelope<T> {
    data: T,
}
