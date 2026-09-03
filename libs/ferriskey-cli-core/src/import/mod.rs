//! Realm import: pull a realm description from an external source (a FerrisKey
//! config file, a live Keycloak instance, or a live Zitadel instance) into a
//! source-agnostic [`RealmBlueprint`], then replay it against the FerrisKey API.
//!
//! The FerrisKey API has no bulk-import endpoint, so [`apply::apply_blueprint`]
//! orchestrates the individual create calls in dependency order.

pub mod apply;
pub mod sources;

use ferriskey_cli_client::{FerriskeyClientError, UpdateRealmSettingsRequest};
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
    /// Client-scoped roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleBlueprint>,
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
    /// Realm role names to assign to this user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

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
    pub client_roles_created: usize,
    pub users_created: usize,
    pub role_assignments: usize,
    /// Entities skipped because they already existed — distinguishes a
    /// converging replay from a run that did nothing.
    pub already_present: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error("unknown source '{0}' (see `ferris-ctl source list`)")]
    UnknownSourceRef(String),
    #[error("provide either --from <kind> or --source-ref <name>")]
    NoSourceSpecified,
    #[error(
        "listing Zitadel organizations requires instance-level (IAM) permissions; \
         pin a single organization with --source-org / org-id, or grant the token an IAM manager role"
    )]
    ZitadelOrgListingForbidden,
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
                roles: vec![],
            }],
            users: vec![UserBlueprint {
                username: "alice".to_owned(),
                email: Some("alice@acme.test".to_owned()),
                firstname: Some("Alice".to_owned()),
                lastname: None,
                email_verified: Some(true),
                roles: vec!["admin".to_owned()],
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
