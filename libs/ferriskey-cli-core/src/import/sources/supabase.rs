//! Reads a Supabase project through its Auth (GoTrue) Admin API and maps the
//! users onto a [`RealmBlueprint`].
//!
//! Supabase has no realm, no OIDC client and no role catalogue of its own, so
//! an import carries users and nothing else. The realm name comes from
//! `--target-realm` (or `--source-realm`) and defaults to `supabase`.
//!
//! Passwords are never carried over. Supabase keeps bcrypt hashes in
//! `auth.users.encrypted_password` and does not serve them over the Admin API,
//! and the FerrisKey API accepts only a plaintext password on its
//! `reset-password` endpoint — neither side exposes a hash. Imported users
//! therefore arrive without credentials and have to go through a reset.
//!
//! Authentication uses the project's `service_role` key, passed with
//! `--source-token`; it is sent both as the `apikey` header Supabase's gateway
//! expects and as the bearer token GoTrue itself checks.

use std::collections::HashSet;

use reqwest::blocking::Client;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::import::{ImportError, RealmBlueprint, RealmSource, UserBlueprint};

const SOURCE: &str = "supabase";
const USER_PAGE_SIZE: usize = 100;
const DEFAULT_REALM_NAME: &str = "supabase";

const FIRST_NAME_KEYS: [&str; 3] = ["first_name", "firstName", "given_name"];
const LAST_NAME_KEYS: [&str; 3] = ["last_name", "lastName", "family_name"];
const FULL_NAME_KEYS: [&str; 2] = ["full_name", "name"];

/// Which Supabase accounts an import carries over.
///
/// The user table holds rows a migration usually should not replay: accounts an
/// operator soft-deleted, anonymous sign-in sessions, and addresses nobody ever
/// confirmed. Each is dropped by default; `Default` is therefore the strictest
/// setting, and every flag only ever widens what is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserFilters {
    pub include_deleted: bool,
    pub include_anonymous: bool,
    pub include_unconfirmed: bool,
}

impl UserFilters {
    /// Whether `user` survives the filters.
    ///
    /// The confirmation filter only judges accounts that have something to
    /// confirm. An anonymous account has neither address nor phone, so it is
    /// governed by `include_anonymous` alone — were it also subject to the
    /// confirmation filter, asking to keep anonymous users would still drop
    /// every one of them.
    fn keeps(&self, user: &SupabaseUser) -> bool {
        if user.deleted_at.is_some() && !self.include_deleted {
            return false;
        }
        if user.is_anonymous {
            return self.include_anonymous;
        }
        self.include_unconfirmed || user.is_confirmed()
    }
}

pub struct SupabaseSource {
    base_url: String,
    service_role_key: String,
    realm_name: Option<String>,
    filters: UserFilters,
    http: Client,
}

impl SupabaseSource {
    /// Builds the source from resolved option values (inline flags already
    /// merged over any stored source).
    pub fn build(
        base_url: Option<String>,
        service_role_key: Option<String>,
        realm_name: Option<String>,
        filters: UserFilters,
    ) -> Result<Self, ImportError> {
        let base_url =
            normalize_base_url(&base_url.ok_or(ImportError::MissingArg("--source-url"))?);
        let service_role_key = service_role_key.ok_or(ImportError::MissingArg("--source-token"))?;

        Ok(Self {
            base_url,
            service_role_key,
            realm_name,
            filters,
            http: Client::new(),
        })
    }

    /// Reads one page of the admin user list. Pages are 1-indexed.
    fn page(&self, page: usize) -> Result<Vec<SupabaseUser>, ImportError> {
        let url = format!(
            "{}/auth/v1/admin/users?page={page}&per_page={USER_PAGE_SIZE}",
            self.base_url
        );
        let response = self
            .http
            .get(url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ImportError::Source {
                provider: SOURCE,
                status,
                body,
            });
        }

        Ok(response.json::<UserList>()?.users)
    }

    /// Walks every page of the admin user list, keeping what the filters allow.
    ///
    /// Termination is on "this page brought no id we had not already seen", not
    /// on the usual "this page was shorter than the size we asked for". GoTrue
    /// caps `per_page` server-side, so a short page is the ordinary case rather
    /// than the last one, and the short-page test would stop after the first
    /// batch and silently drop the rest of the directory. Tracking ids also
    /// bounds the walk against a deployment that ignores `page` and keeps
    /// serving the first one.
    fn all_users(&self) -> Result<Vec<UserBlueprint>, ImportError> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut users = Vec::new();
        let mut page = 1;

        loop {
            let batch = self.page(page)?;
            let known = seen.len();
            for user in batch {
                if !seen.insert(user.id.clone()) {
                    continue;
                }
                if self.filters.keeps(&user) {
                    users.push(map_user(user));
                }
            }
            if seen.len() == known {
                return Ok(users);
            }
            page += 1;
        }
    }
}

impl RealmSource for SupabaseSource {
    fn fetch(&self) -> Result<Vec<RealmBlueprint>, ImportError> {
        let name = self
            .realm_name
            .clone()
            .unwrap_or_else(|| DEFAULT_REALM_NAME.to_owned());

        Ok(vec![RealmBlueprint {
            name,
            settings: None,
            roles: Vec::new(),
            clients: Vec::new(),
            users: self.all_users()?,
        }])
    }
}

/// Accepts both the project URL and one already pointing at the Auth API, so
/// `https://abc.supabase.co` and `https://abc.supabase.co/auth/v1` both reach
/// the same endpoint instead of one of them 404ing on a doubled path.
fn normalize_base_url(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_end_matches("/auth/v1")
        .trim_end_matches('/')
        .to_owned()
}

fn map_user(user: SupabaseUser) -> UserBlueprint {
    let (firstname, lastname) = names_from_metadata(&user.user_metadata);
    let email_verified = user
        .email
        .as_ref()
        .map(|_| user.email_confirmed_at.is_some());
    let username = user
        .email
        .clone()
        .or_else(|| user.phone.clone())
        .unwrap_or(user.id);

    UserBlueprint {
        username,
        email: user.email,
        firstname,
        lastname,
        email_verified,
        roles: Vec::new(),
    }
}

/// Pulls a first and last name out of Supabase's free-form `user_metadata`.
///
/// There is no profile schema behind that field: an email signup stores
/// whatever the application wrote into it, while an OAuth provider stores the
/// OIDC claims it received. The explicit keys are tried first, then a single
/// display name is split on its first run of whitespace.
fn names_from_metadata(metadata: &Map<String, Value>) -> (Option<String>, Option<String>) {
    let first = first_string(metadata, &FIRST_NAME_KEYS);
    let last = first_string(metadata, &LAST_NAME_KEYS);
    if first.is_some() || last.is_some() {
        return (first, last);
    }

    match first_string(metadata, &FULL_NAME_KEYS) {
        Some(full) => split_full_name(&full),
        None => (None, None),
    }
}

fn first_string(metadata: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        metadata
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn split_full_name(full: &str) -> (Option<String>, Option<String>) {
    match full.split_once(char::is_whitespace) {
        Some((first, rest)) => {
            let rest = rest.trim();
            (
                Some(first.to_owned()),
                (!rest.is_empty()).then(|| rest.to_owned()),
            )
        }
        None => (Some(full.to_owned()), None),
    }
}

/// Supabase serialises an absent email or phone as `""` rather than `null`, so
/// a plain `Option<String>` would carry an empty string into the blueprint and
/// create users with a blank address.
fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.filter(|value| !value.trim().is_empty()))
}

#[derive(Debug, Deserialize)]
struct UserList {
    #[serde(default)]
    users: Vec<SupabaseUser>,
}

#[derive(Debug, Deserialize)]
struct SupabaseUser {
    id: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    email: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    phone: Option<String>,
    #[serde(default)]
    email_confirmed_at: Option<String>,
    #[serde(default)]
    phone_confirmed_at: Option<String>,
    #[serde(default)]
    confirmed_at: Option<String>,
    #[serde(default)]
    deleted_at: Option<String>,
    #[serde(default)]
    is_anonymous: bool,
    #[serde(default)]
    user_metadata: Map<String, Value>,
}

impl SupabaseUser {
    fn is_confirmed(&self) -> bool {
        self.email_confirmed_at.is_some()
            || self.phone_confirmed_at.is_some()
            || self.confirmed_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str) -> SupabaseUser {
        SupabaseUser {
            id: id.to_owned(),
            email: None,
            phone: None,
            email_confirmed_at: None,
            phone_confirmed_at: None,
            confirmed_at: None,
            deleted_at: None,
            is_anonymous: false,
            user_metadata: Map::new(),
        }
    }

    fn confirmed_email_user(id: &str, email: &str) -> SupabaseUser {
        SupabaseUser {
            email: Some(email.to_owned()),
            email_confirmed_at: Some("2024-01-01T00:00:00Z".to_owned()),
            ..user(id)
        }
    }

    fn metadata(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
            .collect()
    }

    #[test]
    fn uses_the_full_email_as_username() {
        let blueprint = map_user(confirmed_email_user("id-1", "alice@acme.test"));
        assert_eq!(blueprint.username, "alice@acme.test");
        assert_eq!(blueprint.email.as_deref(), Some("alice@acme.test"));
        assert_eq!(blueprint.email_verified, Some(true));
    }

    #[test]
    fn falls_back_to_phone_when_there_is_no_email() {
        let blueprint = map_user(SupabaseUser {
            phone: Some("+33612345678".to_owned()),
            ..user("id-2")
        });
        assert_eq!(blueprint.username, "+33612345678");
        assert_eq!(blueprint.email, None);
    }

    #[test]
    fn falls_back_to_the_supabase_id_when_there_is_neither() {
        let blueprint = map_user(user("8f14e45f-ceea-467a-9ba3-6a1e8a1f0c11"));
        assert_eq!(blueprint.username, "8f14e45f-ceea-467a-9ba3-6a1e8a1f0c11");
    }

    #[test]
    fn reports_an_unverified_email_as_unverified() {
        let blueprint = map_user(SupabaseUser {
            email: Some("bob@acme.test".to_owned()),
            ..user("id-3")
        });
        assert_eq!(blueprint.email_verified, Some(false));
    }

    #[test]
    fn leaves_verification_unset_when_there_is_no_email() {
        let blueprint = map_user(SupabaseUser {
            phone: Some("+33612345678".to_owned()),
            ..user("id-4")
        });
        assert_eq!(blueprint.email_verified, None);
    }

    #[test]
    fn reads_an_empty_email_as_absent() {
        let json = r#"{"id":"id-5","email":"","phone":"  "}"#;
        let parsed: SupabaseUser = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.email, None);
        assert_eq!(parsed.phone, None);
    }

    #[test]
    fn deserializes_a_user_list_page() {
        let json = r#"{"aud":"authenticated","users":[{"id":"id-6","email":"a@b.test"}]}"#;
        let list: UserList = serde_json::from_str(json).expect("parse");
        assert_eq!(list.users.len(), 1);
        assert_eq!(list.users[0].email.as_deref(), Some("a@b.test"));
    }

    #[test]
    fn drops_soft_deleted_users_by_default() {
        let deleted = SupabaseUser {
            deleted_at: Some("2024-02-01T00:00:00Z".to_owned()),
            ..confirmed_email_user("id-7", "gone@acme.test")
        };
        assert!(!UserFilters::default().keeps(&deleted));
        assert!(
            UserFilters {
                include_deleted: true,
                ..UserFilters::default()
            }
            .keeps(&deleted)
        );
    }

    #[test]
    fn drops_anonymous_users_by_default() {
        let anonymous = SupabaseUser {
            is_anonymous: true,
            ..user("id-8")
        };
        assert!(!UserFilters::default().keeps(&anonymous));
    }

    #[test]
    fn keeps_anonymous_users_when_asked_even_though_they_are_unconfirmed() {
        let anonymous = SupabaseUser {
            is_anonymous: true,
            ..user("id-9")
        };
        assert!(
            UserFilters {
                include_anonymous: true,
                ..UserFilters::default()
            }
            .keeps(&anonymous),
            "include_anonymous must not be undone by the confirmation filter"
        );
    }

    #[test]
    fn drops_unconfirmed_users_by_default() {
        let unconfirmed = SupabaseUser {
            email: Some("never@acme.test".to_owned()),
            ..user("id-10")
        };
        assert!(!UserFilters::default().keeps(&unconfirmed));
        assert!(
            UserFilters {
                include_unconfirmed: true,
                ..UserFilters::default()
            }
            .keeps(&unconfirmed)
        );
    }

    #[test]
    fn treats_a_phone_confirmation_as_a_confirmation() {
        let phone_only = SupabaseUser {
            phone: Some("+33612345678".to_owned()),
            phone_confirmed_at: Some("2024-01-01T00:00:00Z".to_owned()),
            ..user("id-11")
        };
        assert!(UserFilters::default().keeps(&phone_only));
    }

    #[test]
    fn keeps_a_plain_confirmed_user_under_the_default_filters() {
        assert!(UserFilters::default().keeps(&confirmed_email_user("id-12", "ok@acme.test")));
    }

    #[test]
    fn reads_snake_case_names_from_metadata() {
        let (first, last) =
            names_from_metadata(&metadata(&[("first_name", "Alice"), ("last_name", "Doe")]));
        assert_eq!(first.as_deref(), Some("Alice"));
        assert_eq!(last.as_deref(), Some("Doe"));
    }

    #[test]
    fn reads_oidc_claim_names_from_metadata() {
        let (first, last) = names_from_metadata(&metadata(&[
            ("given_name", "Alice"),
            ("family_name", "Doe"),
        ]));
        assert_eq!(first.as_deref(), Some("Alice"));
        assert_eq!(last.as_deref(), Some("Doe"));
    }

    #[test]
    fn skips_a_blank_key_and_takes_the_next_one() {
        let (first, _) =
            names_from_metadata(&metadata(&[("first_name", "   "), ("given_name", "Alice")]));
        assert_eq!(first.as_deref(), Some("Alice"));
    }

    #[test]
    fn splits_a_full_name_when_no_explicit_part_is_present() {
        let (first, last) = names_from_metadata(&metadata(&[("full_name", "Alice Van Doe")]));
        assert_eq!(first.as_deref(), Some("Alice"));
        assert_eq!(last.as_deref(), Some("Van Doe"));
    }

    #[test]
    fn keeps_a_single_word_display_name_as_the_first_name() {
        assert_eq!(split_full_name("Alice"), (Some("Alice".to_owned()), None));
    }

    #[test]
    fn ignores_metadata_values_that_are_not_strings() {
        let mut raw = Map::new();
        raw.insert("first_name".to_owned(), Value::Bool(true));
        assert_eq!(names_from_metadata(&raw), (None, None));
    }

    #[test]
    fn maps_metadata_names_onto_the_blueprint() {
        let blueprint = map_user(SupabaseUser {
            user_metadata: metadata(&[("full_name", "Alice Doe")]),
            ..confirmed_email_user("id-13", "alice@acme.test")
        });
        assert_eq!(blueprint.firstname.as_deref(), Some("Alice"));
        assert_eq!(blueprint.lastname.as_deref(), Some("Doe"));
    }

    #[test]
    fn imports_no_roles() {
        let blueprint = map_user(confirmed_email_user("id-14", "alice@acme.test"));
        assert!(blueprint.roles.is_empty());
    }

    #[test]
    fn accepts_a_project_url_with_or_without_the_auth_path() {
        assert_eq!(
            normalize_base_url("https://abc.supabase.co"),
            "https://abc.supabase.co"
        );
        assert_eq!(
            normalize_base_url("https://abc.supabase.co/"),
            "https://abc.supabase.co"
        );
        assert_eq!(
            normalize_base_url("https://abc.supabase.co/auth/v1"),
            "https://abc.supabase.co"
        );
        assert_eq!(
            normalize_base_url("https://abc.supabase.co/auth/v1/"),
            "https://abc.supabase.co"
        );
    }

    #[test]
    fn requires_a_url_and_a_key() {
        let missing_url =
            SupabaseSource::build(None, Some("key".to_owned()), None, UserFilters::default());
        assert!(matches!(
            missing_url,
            Err(ImportError::MissingArg("--source-url"))
        ));

        let missing_key = SupabaseSource::build(
            Some("https://abc.supabase.co".to_owned()),
            None,
            None,
            UserFilters::default(),
        );
        assert!(matches!(
            missing_key,
            Err(ImportError::MissingArg("--source-token"))
        ));
    }
}
