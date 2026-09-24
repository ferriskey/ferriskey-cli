//! Realm import: pull a realm description from an external source (a FerrisKey
//! config file, a live Keycloak instance, or a live Zitadel instance) into a
//! source-agnostic [`RealmBlueprint`], then replay it against the FerrisKey API.
//!
//! The FerrisKey API has no bulk-import endpoint, so [`apply::apply_blueprint`]
//! orchestrates the individual create calls in dependency order.

pub mod apply;
pub mod sources;

use ferriskey_cli_client::{
    FerriskeyClientError, ImportPasswordCredentialRequest, UpdateClientSettingsRequest,
    UpdateRealmSettingsRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A source-agnostic description of a realm and its contents.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmBlueprint {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<RealmSettingsBlueprint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleBlueprint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<ClientBlueprint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserBlueprint>,
}

/// Realm-level settings. Mirrors the backend `UpdateRealmSettingValidator`
/// (every field optional). Only the fields that are set are sent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmSettingsBlueprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_signing_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_registration_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgot_password_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember_me_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_link_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_link_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compass_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verification_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verification_ttl_hours: Option<i64>,
}

impl RealmSettingsBlueprint {
    pub fn to_request(&self) -> UpdateRealmSettingsRequest {
        UpdateRealmSettingsRequest {
            default_signing_algorithm: self.default_signing_algorithm.clone(),
            user_registration_enabled: self.user_registration_enabled,
            forgot_password_enabled: self.forgot_password_enabled,
            remember_me_enabled: self.remember_me_enabled,
            magic_link_enabled: self.magic_link_enabled,
            magic_link_ttl: self.magic_link_ttl,
            passkey_enabled: self.passkey_enabled,
            compass_enabled: self.compass_enabled,
            access_token_lifetime: self.access_token_lifetime,
            refresh_token_lifetime: self.refresh_token_lifetime,
            id_token_lifetime: self.id_token_lifetime,
            temporary_token_lifetime: self.temporary_token_lifetime,
            email_verification_enabled: self.email_verification_enabled,
            email_verification_ttl_hours: self.email_verification_ttl_hours,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoleBlueprint {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientBlueprint {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// One of `public`, `confidential`, `system` (matches the backend `ClientType`).
    #[serde(default = "default_client_type")]
    pub client_type: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub public_client: bool,
    #[serde(default)]
    pub service_account_enabled: bool,
    #[serde(default)]
    pub direct_access_grants_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web_origins: Vec<String>,
    #[serde(default)]
    pub device_authorization_grant_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_token_lifetime: Option<i64>,
    /// Client-scoped roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleBlueprint>,
}

impl ClientBlueprint {
    pub fn to_settings_request(&self) -> UpdateClientSettingsRequest {
        UpdateClientSettingsRequest {
            require_pkce: self.require_pkce,
            access_token_lifetime: self.access_token_lifetime,
            refresh_token_lifetime: self.refresh_token_lifetime,
            id_token_lifetime: self.id_token_lifetime,
            temporary_token_lifetime: self.temporary_token_lifetime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserBlueprint {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firstname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Roles to assign to this user: a plain name for a realm role, or
    /// `client_id:role_name` for a role scoped to that client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<PasswordCredentialBlueprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordCredentialBlueprint {
    pub algorithm: String,
    pub secret_data: String,
    pub hash_iterations: u32,
}

impl PasswordCredentialBlueprint {
    pub fn to_request(&self) -> ImportPasswordCredentialRequest {
        ImportPasswordCredentialRequest {
            algorithm: self.algorithm.clone(),
            secret_data: self.secret_data.clone(),
            hash_iterations: self.hash_iterations,
            salt: None,
            temporary: false,
        }
    }

    pub fn redacted(&self) -> Self {
        Self {
            secret_data: REDACTED_SECRET.to_owned(),
            ..self.clone()
        }
    }
}

const REDACTED_SECRET: &str = "<redacted>";

fn default_client_type() -> String {
    "public".to_owned()
}

fn default_protocol() -> String {
    "openid-connect".to_owned()
}

fn default_true() -> bool {
    true
}

/// A pluggable provider of one or more [`RealmBlueprint`]s. Most sources yield a
/// single realm; a Zitadel instance without a pinned organization yields one
/// realm per organization.
pub trait RealmSource {
    fn fetch(&self) -> Result<Vec<RealmBlueprint>, ImportError>;
}

/// Summary of what an import did (or, in dry-run mode, would do).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub realm: String,
    pub dry_run: bool,
    pub realm_created: bool,
    pub settings_applied: bool,
    pub roles_created: usize,
    pub clients_created: usize,
    pub redirects_created: usize,
    pub post_logout_redirects_created: usize,
    pub web_origins_created: usize,
    pub client_settings_applied: usize,
    pub client_roles_created: usize,
    pub users_created: usize,
    pub role_assignments: usize,
    pub passwords_imported: usize,
    /// Entities skipped because they already existed — distinguishes a
    /// converging replay from a run that did nothing.
    pub already_present: usize,
    /// Secret of every confidential client the import touched, so the
    /// import is self-sufficient — the caller doesn't need a separate
    /// `client secret` call per client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub client_secrets: Vec<ClientSecretEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientSecretEntry {
    pub client_id: String,
    pub secret: String,
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error("unknown source '{0}' (see `ferris-ctl source list`)")]
    UnknownSourceRef(String),
    #[error(
        "client role '{client_id}:{role}' referenced by user '{username}' was not found — \
         define it under that client's `roles` in the blueprint"
    )]
    UnresolvedClientRole {
        client_id: String,
        role: String,
        username: String,
    },
    #[error("provide either --from <kind> or --source-ref <name>")]
    NoSourceSpecified,
    #[error(
        "listing Zitadel organizations requires instance-level (IAM) permissions; \
         pin a single organization with --source-org / org-id, or grant the token an IAM manager role"
    )]
    ZitadelOrgListingForbidden,
    #[error(
        "Supabase role '{role}' on user '{username}' contains ':', which a realm blueprint \
         reserves for client-scoped roles ('client_id:role_name'); Supabase defines no clients, \
         so rename the role in app_metadata before importing"
    )]
    SupabaseNamespacedRole { role: String, username: String },
    #[error(
        "--source-passwords only applies to '--from supabase'; the '{0}' source carries no password export"
    )]
    PasswordsUnsupportedBySource(&'static str),
    #[error("failed to read the Supabase password export '{path}'")]
    PasswordCsv {
        path: String,
        #[source]
        source: csv::Error,
    },
    #[error(
        "the Supabase password export '{path}' has no '{column}' column — export it with \
         `select id, encrypted_password from auth.users`"
    )]
    PasswordCsvColumnMissing { path: String, column: &'static str },
    #[error("stored source '{name}' has kind '{kind}', which is not a valid import kind")]
    InvalidStoredKind { name: String, kind: String },
    #[error("failed to read source file '{path}'")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse YAML config")]
    Yaml(#[from] serde_yaml::Error),
    #[error("failed to parse TOML config")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported config file extension '{0}' (expected .yaml, .yml or .toml)")]
    UnsupportedConfigFormat(String),
    #[error("missing required argument for this source: {0}")]
    MissingArg(&'static str),
    #[error("request to source failed")]
    Http(#[from] reqwest::Error),
    #[error("source '{provider}' returned status {status}: {body}")]
    Source {
        provider: &'static str,
        status: reqwest::StatusCode,
        body: String,
    },
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const BCRYPT_HASH: &str = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    fn credential() -> PasswordCredentialBlueprint {
        PasswordCredentialBlueprint {
            algorithm: "bcrypt".to_owned(),
            secret_data: BCRYPT_HASH.to_owned(),
            hash_iterations: 10,
        }
    }

    #[test]
    fn credential_request_sends_no_salt_and_is_never_temporary() {
        let request = credential().to_request();
        assert_eq!(request.algorithm, "bcrypt");
        assert_eq!(request.secret_data, BCRYPT_HASH);
        assert_eq!(request.hash_iterations, 10);
        assert!(
            request.salt.is_none(),
            "bcrypt and argon2 embed their salt in secret_data"
        );
        assert!(
            !request.temporary,
            "an imported password must stay usable, not force a reset"
        );
    }

    #[test]
    fn credential_request_omits_the_salt_from_the_wire() {
        let json = serde_json::to_value(credential().to_request()).expect("serialize");
        assert!(json.get("salt").is_none());
        assert_eq!(json["hash_iterations"], 10);
    }

    #[test]
    fn redacting_a_credential_drops_the_hash_and_keeps_its_shape() {
        let redacted = credential().redacted();
        assert_eq!(redacted.algorithm, "bcrypt");
        assert_eq!(redacted.hash_iterations, 10);
        assert_ne!(redacted.secret_data, BCRYPT_HASH);
        assert!(!redacted.secret_data.contains("$2a$"));
    }

    #[test]
    fn a_user_without_credential_serializes_without_the_field() {
        let user = UserBlueprint {
            username: "alice".to_owned(),
            email: None,
            firstname: None,
            lastname: None,
            email_verified: None,
            roles: Vec::new(),
            credential: None,
        };
        let yaml = serde_yaml::to_string(&user).expect("serialize");
        assert!(!yaml.contains("credential"));
    }

    #[test]
    fn blueprint_yaml_round_trip() {
        let bp = RealmBlueprint {
            name: "acme".to_owned(),
            settings: Some(RealmSettingsBlueprint {
                access_token_lifetime: Some(300),
                user_registration_enabled: Some(true),
                ..Default::default()
            }),
            roles: vec![RoleBlueprint {
                name: "admin".to_owned(),
                description: Some("Administrators".to_owned()),
                permissions: vec!["realm:manage".to_owned()],
            }],
            clients: vec![ClientBlueprint {
                client_id: "web".to_owned(),
                name: Some("Web App".to_owned()),
                client_type: "public".to_owned(),
                protocol: "openid-connect".to_owned(),
                enabled: true,
                public_client: true,
                service_account_enabled: false,
                direct_access_grants_enabled: false,
                redirect_uris: vec!["https://app.acme.test/*".to_owned()],
                post_logout_redirect_uris: vec!["https://app.acme.test/bye".to_owned()],
                web_origins: vec!["https://app.acme.test".to_owned()],
                device_authorization_grant_enabled: true,
                require_pkce: Some(true),
                access_token_lifetime: Some(300),
                refresh_token_lifetime: None,
                id_token_lifetime: None,
                temporary_token_lifetime: None,
                roles: vec![],
            }],
            users: vec![UserBlueprint {
                username: "alice".to_owned(),
                email: Some("alice@acme.test".to_owned()),
                firstname: Some("Alice".to_owned()),
                lastname: None,
                email_verified: Some(true),
                roles: vec!["admin".to_owned()],
                credential: Some(PasswordCredentialBlueprint {
                    algorithm: "bcrypt".to_owned(),
                    secret_data: BCRYPT_HASH.to_owned(),
                    hash_iterations: 10,
                }),
            }],
        };

        let yaml = serde_yaml::to_string(&bp).expect("serialize");
        let parsed: RealmBlueprint = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(bp, parsed);
    }

    #[test]
    fn client_defaults_apply_when_omitted() {
        let yaml = "client_id: minimal\n";
        let client: ClientBlueprint = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(client.client_type, "public");
        assert_eq!(client.protocol, "openid-connect");
        assert!(client.enabled);
        assert!(!client.public_client);
        assert!(client.redirect_uris.is_empty());
    }

    #[test]
    fn settings_to_request_only_sets_present_fields() {
        let settings = RealmSettingsBlueprint {
            access_token_lifetime: Some(120),
            ..Default::default()
        };
        let request = settings.to_request();
        assert_eq!(request.access_token_lifetime, Some(120));
        assert!(request.refresh_token_lifetime.is_none());
    }
}
