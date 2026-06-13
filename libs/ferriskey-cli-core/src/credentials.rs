use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ferriskey_cli_client::JwtToken;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CredentialsError>;

/// Persisted tokens for a single (server, realm, client_id) triple. Only one
/// session is kept; logging in again replaces the previous credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCredentials {
    pub server_url: String,
    pub realm: String,
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Unix timestamp at which the tokens were obtained.
    pub obtained_at: i64,
}

impl StoredCredentials {
    pub fn from_token(
        server_url: String,
        realm: String,
        client_id: String,
        token: JwtToken,
        obtained_at: i64,
    ) -> Self {
        Self {
            server_url,
            realm,
            client_id,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            token_type: token.token_type,
            expires_in: token.expires_in as i64,
            refresh_expires_in: token.refresh_expires_in,
            scope: token.scope,
            obtained_at,
        }
    }
}

#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("unable to determine a configuration directory")]
    MissingConfigDirectory,
    #[error("failed to create credentials directory '{path}'")]
    CreateDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read '{path}'")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse '{path}'")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize credentials")]
    Serialize {
        #[source]
        source: toml::ser::Error,
    },
    #[error("failed to write '{path}'")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to move '{from}' into '{to}'")]
    Persist {
        from: String,
        to: String,
        #[source]
        source: std::io::Error,
    },
}

pub struct CredentialsRepository {
    file_path: PathBuf,
}

impl CredentialsRepository {
    pub fn new() -> Result<Self> {
        Ok(Self {
            file_path: default_credentials_path()?,
        })
    }

    #[cfg(test)]
    pub fn from_path(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    /// Returns `None` if the credentials file does not exist yet (i.e. the
    /// user has never run `login`). Surfaces parse errors as `Err`.
    pub fn load(&self) -> Result<Option<StoredCredentials>> {
        match fs::read_to_string(&self.file_path) {
            Ok(contents) => {
                let creds = toml::from_str::<StoredCredentials>(&contents).map_err(|source| {
                    CredentialsError::Parse {
                        path: self.file_path.display().to_string(),
                        source,
                    }
                })?;
                Ok(Some(creds))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(CredentialsError::Read {
                path: self.file_path.display().to_string(),
                source,
            }),
        }
    }

    pub fn save(&self, creds: &StoredCredentials) -> Result<()> {
        self.ensure_parent_dir()?;

        let serialized =
            toml::to_string_pretty(creds).map_err(|source| CredentialsError::Serialize { source })?;
        let temp_path = temporary_file_path(&self.file_path);
        write_with_restricted_permissions(&temp_path, serialized.as_bytes())?;
        fs::rename(&temp_path, &self.file_path).map_err(|source| CredentialsError::Persist {
            from: temp_path.display().to_string(),
            to: self.file_path.display().to_string(),
            source,
        })?;
        Ok(())
    }

    /// Remove the stored credentials file. Returns `Ok(false)` when there was
    /// nothing to remove (no active session), `Ok(true)` when a file was deleted.
    pub fn delete(&self) -> Result<bool> {
        match fs::remove_file(&self.file_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(CredentialsError::Write {
                path: self.file_path.display().to_string(),
                source,
            }),
        }
    }

    fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).map_err(|source| CredentialsError::CreateDirectory {
                path: parent.display().to_string(),
                source,
            })?;
        }
        Ok(())
    }
}

fn default_credentials_path() -> Result<PathBuf> {
    let config_root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .or_else(|| env::var_os("APPDATA").map(PathBuf::from))
        .ok_or(CredentialsError::MissingConfigDirectory)?;

    Ok(config_root.join("ferriskey").join("credentials.toml"))
}

fn temporary_file_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "credentials.toml".into());
    file_name.push(".tmp");
    path.with_file_name(file_name)
}

#[cfg(unix)]
fn write_with_restricted_permissions(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| CredentialsError::Write {
            path: path.display().to_string(),
            source,
        })?;
    file.write_all(data)
        .map_err(|source| CredentialsError::Write {
            path: path.display().to_string(),
            source,
        })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_with_restricted_permissions(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).map_err(|source| CredentialsError::Write {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_credentials() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("credentials.toml");
        let repo = CredentialsRepository::from_path(path.clone());

        let creds = StoredCredentials {
            server_url: "https://auth.example.com".to_owned(),
            realm: "master".to_owned(),
            client_id: "ferris-ctl".to_owned(),
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            id_token: Some("id".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_in: 300,
            refresh_expires_in: Some(1800),
            scope: Some("openid".to_owned()),
            obtained_at: 1_700_000_000,
        };

        repo.save(&creds).expect("save");
        let contents = fs::read_to_string(&path).expect("read");
        let parsed: StoredCredentials = toml::from_str(&contents).expect("parse");
        assert_eq!(parsed, creds);
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("credentials.toml");
        let repo = CredentialsRepository::from_path(path.clone());

        let creds = StoredCredentials {
            server_url: "https://auth.example.com".to_owned(),
            realm: "master".to_owned(),
            client_id: "ferris-ctl".to_owned(),
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            id_token: None,
            token_type: "Bearer".to_owned(),
            expires_in: 300,
            refresh_expires_in: None,
            scope: None,
            obtained_at: 0,
        };

        repo.save(&creds).expect("save");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
