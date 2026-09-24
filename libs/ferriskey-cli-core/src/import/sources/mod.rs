//! Source adapters: each turns an external system into one or more
//! [`RealmBlueprint`]s.

pub mod config;
pub mod keycloak;
pub mod supabase;
pub mod supabase_passwords;
pub mod zitadel;

use ferriskey_cli_commands::{ImportSource, RealmImportArgs};

use crate::config::{FileContextRepository, StoredSource};

use super::{ImportError, RealmSource};
use config::ConfigSource;
use keycloak::KeycloakSource;
use supabase::{SupabaseSource, UserFilters};
use zitadel::ZitadelSource;

/// Builds the appropriate [`RealmSource`] from the parsed CLI arguments.
///
/// Resolution order: a `--source-ref` names a stored source (whose `kind`
/// selects the adapter and whose fields are defaults); otherwise `--from`
/// selects the adapter from inline flags only. Inline `--source-*` flags always
/// override the stored values.
pub fn source_from_args(args: &RealmImportArgs) -> Result<Box<dyn RealmSource>, ImportError> {
    if let Some(name) = &args.source_ref {
        let store = FileContextRepository::new()?.load()?;
        let stored = store
            .sources
            .get(name)
            .ok_or_else(|| ImportError::UnknownSourceRef(name.clone()))?;
        build_from_stored(name, stored, args)
    } else if let Some(kind) = &args.source {
        build_from_inline(kind, args)
    } else {
        Err(ImportError::NoSourceSpecified)
    }
}

fn build_from_inline(
    kind: &ImportSource,
    args: &RealmImportArgs,
) -> Result<Box<dyn RealmSource>, ImportError> {
    match kind {
        ImportSource::Config => {
            reject_passwords(args, "config")?;
            let path = args.file.clone().ok_or(ImportError::MissingArg("--file"))?;
            Ok(Box::new(ConfigSource::new(path)))
        }
        ImportSource::Keycloak => {
            reject_passwords(args, "keycloak")?;
            Ok(Box::new(KeycloakSource::build(
                args.source_url.clone(),
                args.source_realm.clone(),
                args.source_client_id.clone(),
                args.source_client_secret.clone(),
                args.source_token.clone(),
            )?))
        }
        ImportSource::Zitadel => {
            reject_passwords(args, "zitadel")?;
            Ok(Box::new(ZitadelSource::build(
                args.source_url.clone(),
                args.source_token.clone(),
                args.source_org.clone(),
                args.target_realm
                    .clone()
                    .or_else(|| args.source_realm.clone()),
            )?))
        }
        ImportSource::Supabase => Ok(Box::new(SupabaseSource::build(
            args.source_url.clone(),
            args.source_token.clone(),
            args.target_realm
                .clone()
                .or_else(|| args.source_realm.clone()),
            user_filters(args),
            args.source_passwords.clone(),
        )?)),
    }
}

fn reject_passwords(args: &RealmImportArgs, kind: &'static str) -> Result<(), ImportError> {
    match args.source_passwords {
        Some(_) => Err(ImportError::PasswordsUnsupportedBySource(kind)),
        None => Ok(()),
    }
}

fn user_filters(args: &RealmImportArgs) -> UserFilters {
    UserFilters {
        include_deleted: args.source_include_deleted,
        include_anonymous: args.source_include_anonymous,
        include_unconfirmed: args.source_include_unconfirmed,
    }
}

fn build_from_stored(
    name: &str,
    stored: &StoredSource,
    args: &RealmImportArgs,
) -> Result<Box<dyn RealmSource>, ImportError> {
    match stored.kind.as_str() {
        "keycloak" => {
            reject_passwords(args, "keycloak")?;
            Ok(Box::new(KeycloakSource::build(
                args.source_url.clone().or_else(|| Some(stored.url.clone())),
                args.source_realm.clone().or_else(|| stored.realm.clone()),
                args.source_client_id
                    .clone()
                    .or_else(|| stored.client_id.clone()),
                args.source_client_secret
                    .clone()
                    .or_else(|| stored.client_secret.clone()),
                args.source_token.clone().or_else(|| stored.token.clone()),
            )?))
        }
        "zitadel" => {
            reject_passwords(args, "zitadel")?;
            Ok(Box::new(ZitadelSource::build(
                args.source_url.clone().or_else(|| Some(stored.url.clone())),
                args.source_token.clone().or_else(|| stored.token.clone()),
                args.source_org.clone().or_else(|| stored.org_id.clone()),
                args.target_realm
                    .clone()
                    .or_else(|| args.source_realm.clone())
                    .or_else(|| stored.realm.clone()),
            )?))
        }
        "supabase" => Ok(Box::new(SupabaseSource::build(
            args.source_url.clone().or_else(|| Some(stored.url.clone())),
            args.source_token.clone().or_else(|| stored.token.clone()),
            args.target_realm
                .clone()
                .or_else(|| args.source_realm.clone())
                .or_else(|| stored.realm.clone()),
            user_filters(args),
            args.source_passwords.clone(),
        )?)),
        other => Err(ImportError::InvalidStoredKind {
            name: name.to_owned(),
            kind: other.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args_with_passwords() -> RealmImportArgs {
        RealmImportArgs {
            source_passwords: Some(PathBuf::from("auth_users.csv")),
            source_url: Some("https://example.test".to_owned()),
            source_token: Some("token".to_owned()),
            file: Some(PathBuf::from("realm.yaml")),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_a_password_export_on_a_source_that_has_none() {
        for (kind, name) in [
            (ImportSource::Config, "config"),
            (ImportSource::Keycloak, "keycloak"),
            (ImportSource::Zitadel, "zitadel"),
        ] {
            let built = build_from_inline(&kind, &args_with_passwords());
            assert!(
                matches!(built, Err(ImportError::PasswordsUnsupportedBySource(got)) if got == name),
                "--source-passwords must not be silently ignored by '{name}'"
            );
        }
    }

    #[test]
    fn rejects_a_password_export_on_a_stored_source_that_has_none() {
        for kind in ["keycloak", "zitadel"] {
            let stored = StoredSource {
                kind: kind.to_owned(),
                url: "https://example.test".to_owned(),
                realm: None,
                client_id: None,
                client_secret: None,
                token: Some("token".to_owned()),
                org_id: None,
            };
            let built = build_from_stored("stored", &stored, &args_with_passwords());
            assert!(matches!(
                built,
                Err(ImportError::PasswordsUnsupportedBySource(_))
            ));
        }
    }

    #[test]
    fn a_missing_password_export_is_reported_against_its_path() {
        let built = build_from_inline(&ImportSource::Supabase, &args_with_passwords());
        assert!(matches!(
            built,
            Err(ImportError::Io { ref path, .. }) if path == "auth_users.csv"
        ));
    }
}
