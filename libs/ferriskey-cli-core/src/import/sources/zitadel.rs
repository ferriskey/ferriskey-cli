//! Reads a Zitadel instance through its Management API (v1) and maps it onto a
//! [`RealmBlueprint`].
//!
//! Zitadel's model does not map one-to-one onto FerrisKey: there is no "realm"
//! concept (the whole instance/org is treated as one realm), OIDC applications
//! become clients, and project roles become realm roles. This mapping is
//! best-effort. Authentication uses a bearer token / personal access token
//! passed with `--source-token`. Endpoint shapes can vary across Zitadel
//! versions; adjust the structs below if your instance differs.

use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;

use crate::import::{
    ClientBlueprint, ImportError, RealmBlueprint, RealmSource, RoleBlueprint, UserBlueprint,
};

const SOURCE: &str = "zitadel";

pub struct ZitadelSource {
    base_url: String,
    token: String,
    /// When set, only this organization is imported (single realm). When unset,
    /// every organization of the instance is imported as its own realm.
    org_id: Option<String>,
    /// Realm name to use when a single organization is pinned via `org_id`.
    realm_name: Option<String>,
    http: Client,
}

impl ZitadelSource {
    /// Builds the source from resolved option values (inline flags already merged
    /// over any stored source).
    pub fn build(
        base_url: Option<String>,
        token: Option<String>,
        org_id: Option<String>,
        realm_name: Option<String>,
    ) -> Result<Self, ImportError> {
        let base_url = base_url
            .ok_or(ImportError::MissingArg("--source-url"))?
            .trim_end_matches('/')
            .to_owned();
        let token = token.ok_or(ImportError::MissingArg("--source-token"))?;

        Ok(Self {
            base_url,
            token,
            org_id,
            realm_name,
            http: Client::new(),
        })
    }

    /// POSTs an empty search body, optionally scoped to an organization.
    fn search<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        org_id: Option<&str>,
    ) -> Result<T, ImportError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.http.post(url).bearer_auth(&self.token).json(&json!({}));
        if let Some(org_id) = org_id {
            request = request.header("x-zitadel-orgid", org_id);
        }
        let response = request.send()?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ImportError::Source {
                provider: SOURCE,
                status,
                body,
            });
        }
        Ok(response.json::<T>()?)
    }

    /// Reads projects/roles/apps/users for one organization into a blueprint.
    fn fetch_org(&self, org_id: Option<&str>, name: String) -> Result<RealmBlueprint, ImportError> {
        let projects: ProjectList = self.search("/management/v1/projects/_search", org_id)?;

        let mut roles: Vec<RoleBlueprint> = Vec::new();
        let mut clients: Vec<ClientBlueprint> = Vec::new();

        for project in projects.result.unwrap_or_default() {
            let project_roles: RoleList = self.search(
                &format!("/management/v1/projects/{}/roles/_search", project.id),
                org_id,
            )?;
            for role in project_roles.result.unwrap_or_default() {
                roles.push(RoleBlueprint {
                    name: role.key,
                    description: role.display_name,
                    permissions: Vec::new(),
                });
            }

            let apps: AppList = self.search(
                &format!("/management/v1/projects/{}/apps/_search", project.id),
                org_id,
            )?;
            for app in apps.result.unwrap_or_default() {
                clients.push(map_app(app));
            }
        }

        // The users endpoint returns both human users and machine users
        // (service accounts). Humans become realm users; service accounts become
        // service-account clients.
        let raw_users: UserList = self.search("/management/v1/users/_search", org_id)?;
        let mut users = Vec::new();
        for user in raw_users.result.unwrap_or_default() {
            if let Some(human) = user.human {
                users.push(map_human(user.user_name, human));
            } else if let Some(machine) = user.machine {
                clients.push(map_service_account(user.user_name, machine));
            }
            // Users of unknown type are skipped.
        }

        Ok(RealmBlueprint {
            name,
            settings: None,
            roles,
            clients,
            users,
        })
    }
}

impl RealmSource for ZitadelSource {
    fn fetch(&self) -> Result<Vec<RealmBlueprint>, ImportError> {
        if let Some(org_id) = &self.org_id {
            let name = self
                .realm_name
                .clone()
                .unwrap_or_else(|| "zitadel".to_owned());
            return Ok(vec![self.fetch_org(Some(org_id), name)?]);
        }

        // No organization pinned: import every org of the instance as its own
        // realm. Listing orgs is an instance-level (Admin API) call; a token
        // scoped to a single org gets a 401/403 here — surface a clear hint.
        let orgs: OrgList = self
            .search("/admin/v1/orgs/_search", None)
            .map_err(|error| match error {
                ImportError::Source { status, .. }
                    if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED =>
                {
                    ImportError::ZitadelOrgListingForbidden
                }
                other => other,
            })?;
        let mut blueprints = Vec::new();
        for org in orgs.result.unwrap_or_default() {
            let name = sanitize_realm_name(&org.name);
            blueprints.push(self.fetch_org(Some(&org.id), name)?);
        }
        Ok(blueprints)
    }
}

/// Maps an organization name to a realm name FerrisKey will accept: lowercased,
/// with runs of non-alphanumeric characters collapsed to a single '-'.
fn sanitize_realm_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        "org".to_owned()
    } else {
        trimmed
    }
}

fn map_app(app: ZitadelApp) -> ClientBlueprint {
    let oidc = app.oidc_config.unwrap_or_default();
    ClientBlueprint {
        client_id: oidc.client_id.unwrap_or_else(|| app.id.clone()),
        name: Some(app.name),
        client_type: "confidential".to_owned(),
        protocol: "openid-connect".to_owned(),
        enabled: true,
        public_client: false,
        service_account_enabled: false,
        direct_access_grants_enabled: false,
        redirect_uris: oidc.redirect_uris.unwrap_or_default(),
        roles: Vec::new(),
    }
}

fn map_human(user_name: String, human: Human) -> UserBlueprint {
    let profile = human.profile.unwrap_or_default();
    let email = human.email.unwrap_or_default();
    UserBlueprint {
        username: user_name,
        email: email.email,
        firstname: profile.first_name,
        lastname: profile.last_name,
        email_verified: email.is_email_verified,
        roles: Vec::new(),
    }
}

/// A Zitadel service account (machine user) maps to a FerrisKey confidential
/// client with service accounts enabled. No secret/JWT is carried over.
fn map_service_account(user_name: String, machine: Machine) -> ClientBlueprint {
    ClientBlueprint {
        client_id: user_name.clone(),
        name: machine.name.or(Some(user_name)),
        client_type: "confidential".to_owned(),
        protocol: "openid-connect".to_owned(),
        enabled: true,
        public_client: false,
        service_account_enabled: true,
        direct_access_grants_enabled: false,
        redirect_uris: Vec::new(),
        roles: Vec::new(),
    }
}

#[derive(Debug, Deserialize)]
struct OrgList {
    result: Option<Vec<Org>>,
}

#[derive(Debug, Deserialize)]
struct Org {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ProjectList {
    result: Option<Vec<Project>>,
}

#[derive(Debug, Deserialize)]
struct Project {
    id: String,
}

#[derive(Debug, Deserialize)]
struct RoleList {
    result: Option<Vec<ZitadelRole>>,
}

#[derive(Debug, Deserialize)]
struct ZitadelRole {
    key: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppList {
    result: Option<Vec<ZitadelApp>>,
}

#[derive(Debug, Deserialize)]
struct ZitadelApp {
    id: String,
    name: String,
    #[serde(rename = "oidcConfig")]
    oidc_config: Option<OidcConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct OidcConfig {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "redirectUris")]
    redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UserList {
    result: Option<Vec<ZitadelUser>>,
}

#[derive(Debug, Deserialize)]
struct ZitadelUser {
    #[serde(rename = "userName")]
    user_name: String,
    human: Option<Human>,
    machine: Option<Machine>,
}

#[derive(Debug, Default, Deserialize)]
struct Machine {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Human {
    profile: Option<Profile>,
    email: Option<Email>,
}

#[derive(Debug, Default, Deserialize)]
struct Profile {
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Email {
    email: Option<String>,
    #[serde(rename = "isEmailVerified")]
    is_email_verified: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_zitadel_app_to_client() {
        let app = ZitadelApp {
            id: "app-1".to_owned(),
            name: "Web".to_owned(),
            oidc_config: Some(OidcConfig {
                client_id: Some("web@project".to_owned()),
                redirect_uris: Some(vec!["https://a/*".to_owned()]),
            }),
        };
        let bp = map_app(app);
        assert_eq!(bp.client_id, "web@project");
        assert_eq!(bp.name.as_deref(), Some("Web"));
        assert_eq!(bp.redirect_uris, vec!["https://a/*".to_owned()]);
    }

    #[test]
    fn maps_human_user_to_blueprint() {
        let human = Human {
            profile: Some(Profile {
                first_name: Some("Alice".to_owned()),
                last_name: Some("Doe".to_owned()),
            }),
            email: Some(Email {
                email: Some("alice@acme.test".to_owned()),
                is_email_verified: Some(true),
            }),
        };
        let bp = map_human("alice".to_owned(), human);
        assert_eq!(bp.username, "alice");
        assert_eq!(bp.email.as_deref(), Some("alice@acme.test"));
        assert_eq!(bp.firstname.as_deref(), Some("Alice"));
        assert_eq!(bp.email_verified, Some(true));
    }

    #[test]
    fn maps_service_account_to_client() {
        let machine = Machine {
            name: Some("CI Runner".to_owned()),
        };
        let client = map_service_account("ci-runner".to_owned(), machine);
        assert_eq!(client.client_id, "ci-runner");
        assert_eq!(client.name.as_deref(), Some("CI Runner"));
        assert_eq!(client.client_type, "confidential");
        assert!(client.service_account_enabled);
        assert!(!client.public_client);
    }

    #[test]
    fn deserializes_machine_user_without_human() {
        let json = r#"{"userName":"svc","machine":{"name":"Service"}}"#;
        let user: ZitadelUser = serde_json::from_str(json).expect("parse");
        assert!(user.human.is_none());
        assert_eq!(user.machine.expect("machine").name.as_deref(), Some("Service"));
    }

    #[test]
    fn sanitizes_org_names_into_realm_names() {
        assert_eq!(sanitize_realm_name("ACME Corp"), "acme-corp");
        assert_eq!(sanitize_realm_name("  Hello  World  "), "hello-world");
        assert_eq!(sanitize_realm_name("chebli.eu1"), "chebli-eu1");
        assert_eq!(sanitize_realm_name("***"), "org");
    }
}
