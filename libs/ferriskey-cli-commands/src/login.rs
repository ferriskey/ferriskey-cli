use clap::Args;

/// Authenticate against FerrisKey using the OAuth 2.0 Device Authorization
/// Grant (RFC 8628). Persists the issued tokens for use by other commands.
#[derive(Debug, Args)]
pub struct LoginCommand {
    /// OAuth scope to request (space-separated). Defaults to `openid profile email`.
    #[arg(long)]
    pub scope: Option<String>,

    /// Skip opening the verification URL in a browser.
    #[arg(long, default_value_t = false)]
    pub no_browser: bool,
}
