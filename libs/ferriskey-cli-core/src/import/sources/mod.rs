//! Source adapters: each turns an external system into one or more
//! [`RealmBlueprint`]s.

pub mod config;
pub mod keycloak;
pub mod zitadel;

use ferriskey_cli_commands::{ImportSource, RealmImportArgs};

use crate::config::{FileContextRepository, StoredSource};

use super::{ImportError, RealmSource};
use config::ConfigSource;
use keycloak::KeycloakSource;
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
            let path = args.file.clone().ok_or(ImportError::MissingArg("--file"))?;
            Ok(Box::new(ConfigSource::new(path)))
        }
        ImportSource::Keycloak => Ok(Box::new(KeycloakSource::build(
            args.source_url.clone(),
            args.source_realm.clone(),
            args.source_client_id.clone(),
            args.source_client_secret.clone(),
            args.source_token.clone(),
        )?)),
        ImportSource::Zitadel => Ok(Box::new(ZitadelSource::build(
            args.source_url.clone(),
            args.source_token.clone(),
            args.source_org.clone(),
            args.target_realm.clone().or_else(|| args.source_realm.clone()),
        )?)),
    }
}

fn build_from_stored(
    name: &str,
    stored: &StoredSource,
    args: &RealmImportArgs,
) -> Result<Box<dyn RealmSource>, ImportError> {
    match stored.kind.as_str() {
        "keycloak" => Ok(Box::new(KeycloakSource::build(
            args.source_url.clone().or_else(|| Some(stored.url.clone())),
            args.source_realm.clone().or_else(|| stored.realm.clone()),
            args.source_client_id.clone().or_else(|| stored.client_id.clone()),
            args.source_client_secret
                .clone()
                .or_else(|| stored.client_secret.clone()),
            args.source_token.clone().or_else(|| stored.token.clone()),
        )?)),
        "zitadel" => Ok(Box::new(ZitadelSource::build(
            args.source_url.clone().or_else(|| Some(stored.url.clone())),
            args.source_token.clone().or_else(|| stored.token.clone()),
            args.source_org.clone().or_else(|| stored.org_id.clone()),
            args.target_realm
                .clone()
                .or_else(|| args.source_realm.clone())
                .or_else(|| stored.realm.clone()),
        )?)),
        other => Err(ImportError::InvalidStoredKind {
            name: name.to_owned(),
            kind: other.to_owned(),
        }),
    }
}
