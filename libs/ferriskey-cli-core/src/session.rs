use ferriskey_cli_client::{FerriskeyClient, FerriskeyClientError};
use thiserror::Error;

use crate::config::StoredContext;
use crate::credentials::{CredentialsError, CredentialsRepository};

/// Authentication source used to obtain the bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    /// Reused the access token persisted by `ferris-ctl login`.
    StoredToken,
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
}

/// Resolve a bearer token for the given context and target realm.
///
/// Resolution order:
/// 1. If `credentials.toml` exists and its (server_url, realm, client_id)
///    triple matches the context+realm, reuse its access_token.
/// 2. Else, if the context carries a non-empty client_secret, perform the
///    `client_credentials` OAuth grant.
/// 3. Else, fail loudly with `NoCredentials` — the user needs to log in.
pub(crate) fn resolve_bearer_token(
    context: &StoredContext,
    realm: &str,
) -> Result<(String, AuthSource), SessionError> {
    if let Some(creds) = CredentialsRepository::new()?.load()?
        && creds.server_url == context.url
        && creds.realm == realm
        && creds.client_id == context.client_id
    {
        return Ok((creds.access_token, AuthSource::StoredToken));
    }

    if let Some(secret) = context.client_secret.as_deref().filter(|s| !s.is_empty()) {
        let auth = FerriskeyClient::new(context.url.clone(), "", "")?;
        let token = auth.exchange_client_credentials(realm, &context.client_id, secret)?;
        return Ok((token.access_token, AuthSource::ClientCredentials));
    }

    Err(SessionError::NoCredentials)
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
