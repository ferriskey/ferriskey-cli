use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use reqwest::blocking::Client;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::import::sources::supabase_passwords::PasswordCatalogue;
use crate::import::{ImportError, RealmBlueprint, RealmSource, RoleBlueprint, UserBlueprint};

const SOURCE: &str = "supabase";
const USER_PAGE_SIZE: usize = 100;
const DEFAULT_REALM_NAME: &str = "supabase";

const CLIENT_SCOPE_SEPARATOR: char = ':';

const ROLE_LIST_KEY: &str = "roles";
const ROLE_SINGLE_KEY: &str = "role";

const FIRST_NAME_KEYS: [&str; 3] = ["first_name", "firstName", "given_name"];
const LAST_NAME_KEYS: [&str; 3] = ["last_name", "lastName", "family_name"];
const FULL_NAME_KEYS: [&str; 2] = ["full_name", "name"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserFilters {
    pub include_deleted: bool,
    pub include_anonymous: bool,
    pub include_unconfirmed: bool,
}

impl UserFilters {
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
    passwords: PasswordCatalogue,
    preserve_ids: bool,
    http: Client,
}

impl SupabaseSource {
    pub fn build(
        base_url: Option<String>,
        service_role_key: Option<String>,
        realm_name: Option<String>,
        filters: UserFilters,
        passwords_export: Option<PathBuf>,
        preserve_ids: bool,
    ) -> Result<Self, ImportError> {
        let base_url =
            normalize_base_url(&base_url.ok_or(ImportError::MissingArg("--source-url"))?);
        let service_role_key = service_role_key.ok_or(ImportError::MissingArg("--source-token"))?;
        let passwords = match passwords_export {
            Some(path) => PasswordCatalogue::from_csv(&path)?,
            None => PasswordCatalogue::default(),
        };

        Ok(Self {
            base_url,
            service_role_key,
            realm_name,
            filters,
            passwords,
            preserve_ids,
            http: Client::new(),
        })
    }

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

    fn all_users(&self) -> Result<Vec<UserBlueprint>, ImportError> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut users = Vec::new();
        let mut page = 1;

        loop {
            let batch = self.page(page)?;
            let seen_before = seen.len();
            for user in batch {
                if !seen.insert(user.id.clone()) {
                    continue;
                }
                if self.filters.keeps(&user) {
                    users.push(map_user(user, &self.passwords, self.preserve_ids)?);
                }
            }

            let page_brought_nothing_new = seen.len() == seen_before;
            if page_brought_nothing_new {
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
        let users = self.all_users()?;

        for warning in self.passwords.warnings() {
            eprintln!("note: {warning}");
        }
        if self.passwords.without_password() > 0 {
            eprintln!(
                "note: {} supabase accounts carry no password hash (federated sign-in) and arrive without credentials",
                self.passwords.without_password()
            );
        }

        Ok(vec![RealmBlueprint {
            name,
            settings: None,
            roles: role_catalogue(&users),
            clients: Vec::new(),
            users,
        }])
    }
}

fn normalize_base_url(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_end_matches("/auth/v1")
        .trim_end_matches('/')
        .to_owned()
}

fn map_user(
    user: SupabaseUser,
    passwords: &PasswordCatalogue,
    preserve_ids: bool,
) -> Result<UserBlueprint, ImportError> {
    let (firstname, lastname) = names_from_metadata(&user.user_metadata);
    let email_verified = user
        .email
        .as_ref()
        .map(|_| user.email_confirmed_at.is_some());
    let username = user
        .email
        .clone()
        .or_else(|| user.phone.clone())
        .unwrap_or_else(|| user.id.clone());
    let roles = roles_from_metadata(&user.app_metadata, &username)?;
    let credential = passwords.get(&user.id);
    let id = preserve_ids.then(|| user.id.clone());

    Ok(UserBlueprint {
        username,
        id,
        email: user.email,
        firstname,
        lastname,
        email_verified,
        roles,
        credential,
    })
}

fn role_catalogue(users: &[UserBlueprint]) -> Vec<RoleBlueprint> {
    users
        .iter()
        .flat_map(|user| &user.roles)
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|name| RoleBlueprint {
            name: name.to_owned(),
            description: None,
            permissions: Vec::new(),
        })
        .collect()
}

fn roles_from_metadata(
    metadata: &Map<String, Value>,
    username: &str,
) -> Result<Vec<String>, ImportError> {
    let listed = metadata
        .get(ROLE_LIST_KEY)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str);
    let single = metadata.get(ROLE_SINGLE_KEY).and_then(Value::as_str);

    let mut roles: Vec<String> = Vec::new();
    for name in listed.chain(single) {
        let name = name.trim();
        if name.is_empty() || roles.iter().any(|kept| kept == name) {
            continue;
        }
        if name.contains(CLIENT_SCOPE_SEPARATOR) {
            return Err(ImportError::SupabaseNamespacedRole {
                role: name.to_owned(),
                username: username.to_owned(),
            });
        }
        roles.push(name.to_owned());
    }

    Ok(roles)
}

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
    #[serde(default)]
    app_metadata: Map<String, Value>,
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
            app_metadata: Map::new(),
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

    fn json_metadata(raw: &str) -> Map<String, Value> {
        serde_json::from_str(raw).expect("metadata fixture")
    }

    fn user_with_roles(email: &str, roles: &[&str]) -> UserBlueprint {
        UserBlueprint {
            username: email.to_owned(),
            id: None,
            email: Some(email.to_owned()),
            firstname: None,
            lastname: None,
            email_verified: Some(true),
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            credential: None,
        }
    }

    fn mapped(user: SupabaseUser) -> Result<UserBlueprint, ImportError> {
        map_user(user, &PasswordCatalogue::default(), false)
    }

    fn mapped_preserving(user: SupabaseUser) -> Result<UserBlueprint, ImportError> {
        map_user(user, &PasswordCatalogue::default(), true)
    }

    const BCRYPT_HASH: &str = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    fn catalogue_for(id: &str) -> PasswordCatalogue {
        PasswordCatalogue::from_reader(
            format!("id,encrypted_password\n{id},{BCRYPT_HASH}\n")
                .into_bytes()
                .as_slice(),
            "users.csv",
        )
        .expect("load")
    }

    #[test]
    fn carries_no_id_unless_asked() {
        let blueprint = mapped(confirmed_email_user(
            "2b6f0cc9-04a4-4d4f-9e58-1f6a4e3d0a11",
            "alice@acme.test",
        ))
        .expect("map");
        assert!(blueprint.id.is_none());
    }

    #[test]
    fn preserves_the_supabase_id_when_asked() {
        let blueprint = mapped_preserving(confirmed_email_user(
            "2b6f0cc9-04a4-4d4f-9e58-1f6a4e3d0a11",
            "alice@acme.test",
        ))
        .expect("map");
        assert_eq!(
            blueprint.id.as_deref(),
            Some("2b6f0cc9-04a4-4d4f-9e58-1f6a4e3d0a11")
        );
    }

    #[test]
    fn preserving_ids_leaves_the_username_derived_from_the_email() {
        let blueprint = mapped_preserving(confirmed_email_user(
            "2b6f0cc9-04a4-4d4f-9e58-1f6a4e3d0a11",
            "alice@acme.test",
        ))
        .expect("map");
        assert_eq!(blueprint.username, "alice@acme.test");
    }

    #[test]
    fn joins_a_password_onto_the_user_by_supabase_id() {
        let blueprint = map_user(
            confirmed_email_user("id-20", "alice@acme.test"),
            &catalogue_for("id-20"),
            false,
        )
        .expect("map");
        let credential = blueprint.credential.expect("credential");
        assert_eq!(credential.algorithm, "bcrypt");
        assert_eq!(credential.secret_data, BCRYPT_HASH);
        assert_eq!(credential.hash_iterations, 10);
    }

    #[test]
    fn joins_on_the_id_rather_than_the_email() {
        let blueprint = map_user(
            confirmed_email_user("id-21", "alice@acme.test"),
            &catalogue_for("alice@acme.test"),
            false,
        )
        .expect("map");
        assert!(
            blueprint.credential.is_none(),
            "the export is keyed by auth.users.id; an email is not a join key"
        );
    }

    #[test]
    fn leaves_a_user_without_credential_when_the_export_has_no_row_for_it() {
        let blueprint = map_user(
            confirmed_email_user("id-22", "bob@acme.test"),
            &catalogue_for("id-20"),
            false,
        )
        .expect("map");
        assert!(blueprint.credential.is_none());
    }

    #[test]
    fn carries_no_credential_when_no_export_was_given() {
        let blueprint = mapped(confirmed_email_user("id-23", "alice@acme.test")).expect("map");
        assert!(blueprint.credential.is_none());
    }

    #[test]
    fn uses_the_full_email_as_username() {
        let blueprint = mapped(confirmed_email_user("id-1", "alice@acme.test")).expect("map");
        assert_eq!(blueprint.username, "alice@acme.test");
        assert_eq!(blueprint.email.as_deref(), Some("alice@acme.test"));
        assert_eq!(blueprint.email_verified, Some(true));
    }

    #[test]
    fn falls_back_to_phone_when_there_is_no_email() {
        let blueprint = mapped(SupabaseUser {
            phone: Some("+33612345678".to_owned()),
            ..user("id-2")
        })
        .expect("map");
        assert_eq!(blueprint.username, "+33612345678");
        assert_eq!(blueprint.email, None);
    }

    #[test]
    fn falls_back_to_the_supabase_id_when_there_is_neither() {
        let blueprint = mapped(user("8f14e45f-ceea-467a-9ba3-6a1e8a1f0c11")).expect("map");
        assert_eq!(blueprint.username, "8f14e45f-ceea-467a-9ba3-6a1e8a1f0c11");
    }

    #[test]
    fn reports_an_unverified_email_as_unverified() {
        let blueprint = mapped(SupabaseUser {
            email: Some("bob@acme.test".to_owned()),
            ..user("id-3")
        })
        .expect("map");
        assert_eq!(blueprint.email_verified, Some(false));
    }

    #[test]
    fn leaves_verification_unset_when_there_is_no_email() {
        let blueprint = mapped(SupabaseUser {
            phone: Some("+33612345678".to_owned()),
            ..user("id-4")
        })
        .expect("map");
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
        let (first, last) =
            names_from_metadata(&metadata(&[("given_name", "Alice"), ("family_name", "Doe")]));
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
        let blueprint = mapped(SupabaseUser {
            user_metadata: metadata(&[("full_name", "Alice Doe")]),
            ..confirmed_email_user("id-13", "alice@acme.test")
        })
        .expect("map");
        assert_eq!(blueprint.firstname.as_deref(), Some("Alice"));
        assert_eq!(blueprint.lastname.as_deref(), Some("Doe"));
    }

    #[test]
    fn reads_a_roles_array_from_app_metadata() {
        let roles = roles_from_metadata(
            &json_metadata(r#"{"roles":["admin","billing"]}"#),
            "alice@acme.test",
        )
        .expect("roles");
        assert_eq!(roles, vec!["admin".to_owned(), "billing".to_owned()]);
    }

    #[test]
    fn reads_a_single_role_string_from_app_metadata() {
        let roles = roles_from_metadata(&json_metadata(r#"{"role":"admin"}"#), "alice@acme.test")
            .expect("roles");
        assert_eq!(roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn merges_both_role_conventions_without_duplicating() {
        let roles = roles_from_metadata(
            &json_metadata(r#"{"roles":["admin","billing"],"role":"admin"}"#),
            "alice@acme.test",
        )
        .expect("roles");
        assert_eq!(roles, vec!["admin".to_owned(), "billing".to_owned()]);
    }

    #[test]
    fn never_reads_supabase_own_app_metadata_keys_as_roles() {
        let roles = roles_from_metadata(
            &json_metadata(r#"{"provider":"email","providers":["email","google"]}"#),
            "alice@acme.test",
        )
        .expect("roles");
        assert!(roles.is_empty());
    }

    #[test]
    fn ignores_role_entries_that_are_not_strings() {
        let roles = roles_from_metadata(
            &json_metadata(r#"{"roles":["admin",42,null,{"a":1}]}"#),
            "alice@acme.test",
        )
        .expect("roles");
        assert_eq!(roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn skips_blank_role_names() {
        let roles = roles_from_metadata(
            &json_metadata(r#"{"roles":["  ","admin",""]}"#),
            "alice@acme.test",
        )
        .expect("roles");
        assert_eq!(roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn rejects_a_role_name_that_collides_with_the_client_scope_syntax() {
        let rejected = roles_from_metadata(
            &json_metadata(r#"{"roles":["billing:read"]}"#),
            "alice@acme.test",
        );
        assert!(matches!(
            rejected,
            Err(ImportError::SupabaseNamespacedRole { role, username })
                if role == "billing:read" && username == "alice@acme.test"
        ));
    }

    #[test]
    fn carries_roles_onto_the_user_blueprint() {
        let blueprint = mapped(SupabaseUser {
            app_metadata: json_metadata(r#"{"provider":"email","roles":["admin"]}"#),
            ..confirmed_email_user("id-15", "alice@acme.test")
        })
        .expect("map");
        assert_eq!(blueprint.roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn imports_no_roles_when_app_metadata_names_none() {
        let blueprint = mapped(confirmed_email_user("id-14", "alice@acme.test")).expect("map");
        assert!(blueprint.roles.is_empty());
    }

    #[test]
    fn builds_a_sorted_deduplicated_catalogue_from_the_users() {
        let catalogue = role_catalogue(&[
            user_with_roles("alice@acme.test", &["billing", "admin"]),
            user_with_roles("bob@acme.test", &["admin", "support"]),
        ]);
        let names: Vec<&str> = catalogue.iter().map(|role| role.name.as_str()).collect();
        assert_eq!(names, vec!["admin", "billing", "support"]);
    }

    #[test]
    fn catalogue_carries_no_description_or_permission() {
        let catalogue = role_catalogue(&[user_with_roles("alice@acme.test", &["admin"])]);
        assert_eq!(catalogue.len(), 1);
        assert_eq!(catalogue[0].description, None);
        assert!(catalogue[0].permissions.is_empty());
    }

    #[test]
    fn catalogue_is_empty_when_no_user_names_a_role() {
        let catalogue = role_catalogue(&[user_with_roles("alice@acme.test", &[])]);
        assert!(catalogue.is_empty());
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
        let missing_url = SupabaseSource::build(
            None,
            Some("key".to_owned()),
            None,
            UserFilters::default(),
            None,
            false,
        );
        assert!(matches!(
            missing_url,
            Err(ImportError::MissingArg("--source-url"))
        ));

        let missing_key = SupabaseSource::build(
            Some("https://abc.supabase.co".to_owned()),
            None,
            None,
            UserFilters::default(),
            None,
            false,
        );
        assert!(matches!(
            missing_key,
            Err(ImportError::MissingArg("--source-token"))
        ));
    }
}
