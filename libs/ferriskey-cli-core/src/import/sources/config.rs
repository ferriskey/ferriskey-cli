//! Reads a [`RealmBlueprint`] from a FerrisKey-native YAML or TOML file.

use std::fs;
use std::path::{Path, PathBuf};

use crate::import::{ImportError, RealmBlueprint, RealmSource};

pub struct ConfigSource {
    path: PathBuf,
}

impl ConfigSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl RealmSource for ConfigSource {
    fn fetch(&self) -> Result<Vec<RealmBlueprint>, ImportError> {
        let content = fs::read_to_string(&self.path).map_err(|source| ImportError::Io {
            path: self.path.display().to_string(),
            source,
        })?;
        Ok(vec![parse_blueprint(&self.path, &content)?])
    }
}

fn parse_blueprint(path: &Path, content: &str) -> Result<RealmBlueprint, ImportError> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_lowercase)
        .as_deref()
    {
        Some("yaml") | Some("yml") => Ok(serde_yaml::from_str(content)?),
        Some("toml") => Ok(toml::from_str(content)?),
        other => Err(ImportError::UnsupportedConfigFormat(
            other.unwrap_or_default().to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml() {
        let yaml = r#"
name: acme
settings:
  access_token_lifetime: 300
roles:
  - name: admin
clients:
  - client_id: web
    redirect_uris:
      - https://app.acme.test/*
users:
  - username: alice
    roles:
      - admin
"#;
        let bp = parse_blueprint(Path::new("realm.yaml"), yaml).expect("parse");
        assert_eq!(bp.name, "acme");
        assert_eq!(bp.roles.len(), 1);
        assert_eq!(bp.clients[0].client_id, "web");
        assert_eq!(bp.clients[0].redirect_uris.len(), 1);
        assert_eq!(bp.users[0].roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn parses_toml() {
        let toml = r#"
name = "acme"

[[roles]]
name = "admin"

[[clients]]
client_id = "web"
"#;
        let bp = parse_blueprint(Path::new("realm.toml"), toml).expect("parse");
        assert_eq!(bp.name, "acme");
        assert_eq!(bp.clients[0].client_id, "web");
    }

    #[test]
    fn rejects_unknown_extension() {
        let err = parse_blueprint(Path::new("realm.txt"), "name: acme")
            .expect_err("unknown extension");
        assert!(matches!(err, ImportError::UnsupportedConfigFormat(ext) if ext == "txt"));
    }
}
