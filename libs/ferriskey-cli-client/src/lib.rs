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
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedClient {
    pub id: String,
    pub client_id: String,
    pub name: String,
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

    pub fn get_client(
        &self,
        realm: &str,
        client_id: &str,
    ) -> Result<Option<ClientRepresentation>, FerriskeyClientError> {
        let url = format!(
            "{}?clientId={}",
            self.endpoint(&format!("realms/{realm}/clients")),
            client_id
        );
        let mut results: Vec<ClientRepresentation> = self.get_list(&url)?;
        Ok(results.drain(..).next())
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
