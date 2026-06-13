use std::time::{SystemTime, UNIX_EPOCH};

use ferriskey_cli_client::{FerriskeyClient, FerriskeyClientError};
use thiserror::Error;

use crate::config::StoredContext;
use crate::credentials::{CredentialsError, CredentialsRepository, StoredCredentials};

/// Tokens are refreshed this many seconds before their nominal expiry to absorb
/// clock skew and request latency.
const EXPIRY_LEEWAY_SECONDS: i64 = 30;

/// Authentication source used to obtain the bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    /// Reused the still-valid access token persisted by `ferris-ctl login`.
    StoredToken,
    /// Refreshed an expired access token using the stored refresh token.
    RefreshedToken,
    /// Exchanged the context's client_id/client_secret via the
    /// `client_credentials` OAuth grant.
    ClientCredentials,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
    #[error(
        "no credentials available: run 'ferris-ctl login' or add a context with --client-secret"
    )]
    NoCredentials,
    #[error("system time is before the unix epoch")]
    SystemTime,
}

/// Resolve a bearer token for the given context and target realm.
///
/// Resolution order:
/// 1. If `credentials.toml` matches the context+realm triple, reuse its
///    access_token while still valid, otherwise refresh it via the stored
///    refresh_token and persist the rotated tokens.
/// 2. Else, if the context carries a non-empty client_secret, perform the
///    `client_credentials` OAuth grant.
/// 3. Else, fail loudly with `NoCredentials` — the user needs to log in.
pub(crate) fn resolve_bearer_token(
    context: &StoredContext,
    realm: &str,
) -> Result<(String, AuthSource), SessionError> {
    let repository = CredentialsRepository::new()?;
    if let Some(creds) = repository.load()?
        && creds.server_url == context.url
        && creds.realm == realm
        && creds.client_id == context.client_id
    {
        if !is_expired(creds.obtained_at, creds.expires_in, unix_now()?) {
            return Ok((creds.access_token, AuthSource::StoredToken));
        }
        // Access token expired: try to refresh it silently. On failure we fall
        // through to the client_secret path or surface NoCredentials.
        if let Some(access_token) = try_refresh(context, realm, &creds, &repository)? {
            return Ok((access_token, AuthSource::RefreshedToken));
        }
    }

    if let Some(secret) = context.client_secret.as_deref().filter(|s| !s.is_empty()) {
        let auth = FerriskeyClient::new(context.url.clone(), "", "")?;
        let token = auth.exchange_client_credentials(realm, &context.client_id, secret)?;
        return Ok((token.access_token, AuthSource::ClientCredentials));
    }

    Err(SessionError::NoCredentials)
}

/// Returns true when a token obtained at `obtained_at` with lifetime
/// `expires_in` seconds is at or past its expiry (minus a leeway buffer).
fn is_expired(obtained_at: i64, expires_in: i64, now: i64) -> bool {
    obtained_at + expires_in - EXPIRY_LEEWAY_SECONDS <= now
}

/// Attempt to refresh the stored credentials. Returns the new access token on
/// success, or `Ok(None)` when refresh is not possible (refresh token expired)
/// or rejected by the server — letting the caller fall back gracefully.
fn try_refresh(
    context: &StoredContext,
    realm: &str,
    creds: &StoredCredentials,
    repository: &CredentialsRepository,
) -> Result<Option<String>, SessionError> {
    // If we know the refresh token's lifetime and it has lapsed, don't bother.
    if let Some(refresh_expires_in) = creds.refresh_expires_in
        && is_expired(creds.obtained_at, refresh_expires_in, unix_now()?)
    {
        return Ok(None);
    }

    let auth = FerriskeyClient::new(context.url.clone(), "", "")?;
    let secret = context.client_secret.as_deref().filter(|s| !s.is_empty());
    let token =
        match auth.exchange_refresh_token(realm, &context.client_id, &creds.refresh_token, secret) {
            Ok(token) => token,
            Err(_) => return Ok(None),
        };

    let updated = StoredCredentials::from_token(
        creds.server_url.clone(),
        creds.realm.clone(),
        creds.client_id.clone(),
        token,
        unix_now()?,
    );
    let access_token = updated.access_token.clone();
    repository.save(&updated)?;
    Ok(Some(access_token))
}

fn unix_now() -> Result<i64, SessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| SessionError::SystemTime)
}

/// Convenience wrapper that returns an authenticated `FerriskeyClient` ready
/// to make API calls.
pub(crate) fn authenticated_client(
    context: &StoredContext,
    realm: &str,
) -> Result<FerriskeyClient, SessionError> {
    let (token, _source) = resolve_bearer_token(context, realm)?;
    Ok(FerriskeyClient::new(context.url.clone(), "", token)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_token_is_not_expired() {
        // obtained at t=1000, lives 300s → valid well before t=1000+300-leeway.
        assert!(!is_expired(1000, 300, 1100));
    }

    #[test]
    fn token_past_lifetime_is_expired() {
        assert!(is_expired(1000, 300, 1400));
    }

    #[test]
    fn token_within_leeway_window_is_treated_as_expired() {
        // Expiry is 1300; with a 30s leeway anything from 1270 onward refreshes.
        assert!(is_expired(1000, 300, 1280));
        assert!(!is_expired(1000, 300, 1269));
    }
}
