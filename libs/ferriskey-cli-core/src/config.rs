use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct StoredContext {
    pub(crate) url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) realm: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContextStore {
    pub(crate) current_context: Option<String>,
    pub(crate) contexts: BTreeMap<String, StoredContext>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unable to determine a configuration directory")]
    MissingConfigDirectory,
    #[error("failed to create config directory '{path}'")]
    CreateConfigDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read '{path}'")]
    ReadConfigFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse '{path}'")]
    ParseConfigFile {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize configuration")]
    SerializeConfig {
        #[source]
        source: toml::ser::Error,
    },
    #[error("failed to write '{path}'")]
    WriteConfigFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to move '{from}' into '{to}'")]
    PersistConfigFile {
        from: String,
        to: String,
        #[source]
        source: std::io::Error,
    },
}

pub(crate) struct FileContextRepository {
    file_path: PathBuf,
}

impl FileContextRepository {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            file_path: default_context_file_path()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_path(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    pub(crate) fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub(crate) fn load(&self) -> Result<ContextStore> {
        match fs::read_to_string(&self.file_path) {
            Ok(contents) => {
                toml::from_str(&contents).map_err(|source| ConfigError::ParseConfigFile {
                    path: self.file_path.display().to_string(),
                    source,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ContextStore::default())
            }
            Err(source) => Err(ConfigError::ReadConfigFile {
                path: self.file_path.display().to_string(),
                source,
            }),
        }
    }

    pub(crate) fn save(&self, store: &ContextStore) -> Result<()> {
        self.ensure_parent_dir()?;

        let serialized = toml::to_string_pretty(store)
            .map_err(|source| ConfigError::SerializeConfig { source })?;
        let temp_path = temporary_file_path(&self.file_path);
        fs::write(&temp_path, serialized).map_err(|source| ConfigError::WriteConfigFile {
            path: temp_path.display().to_string(),
            source,
        })?;
        fs::rename(&temp_path, &self.file_path).map_err(|source| {
            ConfigError::PersistConfigFile {
                from: temp_path.display().to_string(),
                to: self.file_path.display().to_string(),
                source,
            }
        })?;

        Ok(())
    }

    fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::CreateConfigDirectory {
                path: parent.display().to_string(),
                source,
            })?;
        }

        Ok(())
    }
}

fn default_context_file_path() -> Result<PathBuf> {
    let config_root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .or_else(|| env::var_os("APPDATA").map(PathBuf::from))
        .ok_or(ConfigError::MissingConfigDirectory)?;

    Ok(config_root.join("ferriskey").join("config.toml"))
}

fn temporary_file_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "config.toml".into());
    file_name.push(".tmp");
    path.with_file_name(file_name)
}
