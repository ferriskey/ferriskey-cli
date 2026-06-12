use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferriskey_cli_client::{
    DeviceAuthorizationResponse, DeviceTokenError, FerriskeyClient, FerriskeyClientError, JwtToken,
};
use ferriskey_cli_commands::LoginCommand;
use thiserror::Error;

use crate::config::{ConfigError, ContextStore, FileContextRepository, StoredContext};
use crate::credentials::{CredentialsError, CredentialsRepository, StoredCredentials};

const DEFAULT_REALM: &str = "master";
const DEFAULT_SCOPE: &str = "openid profile email";
const TRANSIENT_BACKOFF_CAP_SECONDS: u64 = 30;

type Result<T> = std::result::Result<T, LoginCommandError>;

#[derive(Debug, Error)]
pub enum LoginCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    #[error(transparent)]
    Api(#[from] FerriskeyClientError),
    #[error("context '{0}' does not exist")]
    ContextNotFound(String),
    #[error("no active context is configured; pass --url/--client-id or run 'ferris-ctl context add'")]
    NoActiveContext,
    #[error("server URL is required: pass --url or configure a context")]
    MissingServerUrl,
    #[error("client id is required: pass --client-id or configure a context")]
    MissingClientId,
    #[error("authorization was denied by the user")]
    AccessDenied,
    #[error("the device authorization session expired; run 'ferris-ctl login' again")]
    ExpiredToken,
    #[error("the device code was rejected (invalid or already consumed)")]
    InvalidGrant,
    #[error("the configured client_id was rejected by the server")]
    InvalidClient,
    #[error("OAuth error: {code}{}", description.as_deref().map(|d| format!(" — {d}")).unwrap_or_default())]
    OAuthError {
        code: String,
        description: Option<String>,
    },
    #[error("login interrupted")]
    Interrupted,
    #[error("system time is before the unix epoch")]
    SystemTime,
}

impl LoginCommandError {
    /// Returns the process exit code for this error. Ctrl-C maps to 130, the
    /// conventional value for SIGINT.
    pub fn exit_code(&self) -> i32 {
        match self {
            LoginCommandError::Interrupted => 130,
            _ => 1,
        }
    }
}

/// Entry point dispatched from `core::run`.
pub fn run(
    context_override: Option<&str>,
    url_override: Option<&str>,
    client_id_override: Option<&str>,
    realm_override: Option<&str>,
    command: LoginCommand,
) -> Result<()> {
    let target = resolve_target(
        context_override,
        url_override,
        client_id_override,
        realm_override,
    )?;
    let scope = command.scope.as_deref().unwrap_or(DEFAULT_SCOPE);

    let interrupted = install_signal_handler();
    let sleeper = RealSleeper::new(interrupted.clone());

    let auth = FerriskeyClient::new(target.url.clone(), "", "")?;
    let device = auth.device_authorization(&target.realm, &target.client_id, Some(scope))?;

    print_user_instructions(&device);
    open_browser(device.verification_uri_complete.as_deref(), command.no_browser);

    eprintln!("Waiting for authorization…");

    let token = poll_for_token(
        device.interval.max(1),
        device.expires_in,
        &sleeper,
        || {
            auth.exchange_device_code(
                &target.realm,
                &target.client_id,
                &device.device_code,
                target.client_secret.as_deref(),
            )
        },
    )?;

    let obtained_at = unix_now()?;
    let credentials = StoredCredentials::from_token(
        target.url.clone(),
        target.realm.clone(),
        target.client_id.clone(),
        token.clone(),
        obtained_at,
    );
    CredentialsRepository::new()?.save(&credentials)?;

    let identity = token.id_token.as_deref().and_then(decode_id_token);
    let display_name = identity
        .as_ref()
        .and_then(|claims| {
            claims
                .preferred_username
                .clone()
                .or_else(|| claims.email.clone())
                .or_else(|| claims.name.clone())
        })
        .unwrap_or_else(|| target.client_id.clone());
    println!(
        "✓ Logged in as {} on realm {}.",
        display_name, target.realm
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct LoginTarget {
    url: String,
    realm: String,
    client_id: String,
    client_secret: Option<String>,
}

fn resolve_target(
    context_override: Option<&str>,
    url_override: Option<&str>,
    client_id_override: Option<&str>,
    realm_override: Option<&str>,
) -> Result<LoginTarget> {
    let context = load_context(context_override).transpose()?;

    let url = url_override
        .map(|s| s.to_owned())
        .or_else(|| context.as_ref().map(|c| c.url.clone()))
        .ok_or(LoginCommandError::MissingServerUrl)?;
    let client_id = client_id_override
        .map(|s| s.to_owned())
        .or_else(|| context.as_ref().map(|c| c.client_id.clone()))
        .ok_or(LoginCommandError::MissingClientId)?;
    let realm = realm_override
        .map(|s| s.to_owned())
        .or_else(|| context.as_ref().and_then(|c| c.realm.clone()))
        .unwrap_or_else(|| DEFAULT_REALM.to_owned());
    let client_secret = context
        .as_ref()
        .and_then(|c| c.client_secret.clone())
        .filter(|s| !s.is_empty());

    Ok(LoginTarget {
        url,
        realm,
        client_id,
        client_secret,
    })
}

/// Returns:
/// - `None` if no context file exists and no override is supplied;
/// - `Some(Ok(ctx))` if a context was found;
/// - `Some(Err(_))` if the override names a context that does not exist.
fn load_context(context_override: Option<&str>) -> Option<Result<StoredContext>> {
    let repository = match FileContextRepository::new() {
        Ok(repo) => repo,
        Err(err) => return Some(Err(LoginCommandError::Config(err))),
    };
    let store = match repository.load() {
        Ok(store) => store,
        Err(err) => return Some(Err(LoginCommandError::Config(err))),
    };
    select_context(&store, context_override)
}

fn select_context(
    store: &ContextStore,
    context_override: Option<&str>,
) -> Option<Result<StoredContext>> {
    match context_override {
        Some(name) => Some(
            store
                .contexts
                .get(name)
                .cloned()
                .ok_or_else(|| LoginCommandError::ContextNotFound(name.to_owned())),
        ),
        None => match &store.current_context {
            Some(active) => match store.contexts.get(active).cloned() {
                Some(ctx) => Some(Ok(ctx)),
                None => Some(Err(LoginCommandError::ContextNotFound(active.clone()))),
            },
            None => None,
        },
    }
}

fn print_user_instructions(device: &DeviceAuthorizationResponse) {
    println!();
    println!("To sign in, open the following URL in a browser:");
    println!();
    println!("    {}", device.verification_uri);
    println!();
    println!("and enter the code:");
    println!();
    println!("    {}", device.user_code);
    println!();
}

fn open_browser(url: Option<&str>, disabled: bool) {
    if disabled {
        return;
    }
    let Some(url) = url else { return };
    let opener = if cfg!(target_os = "macos") {
        Some(("open", vec![url]))
    } else if cfg!(target_os = "windows") {
        Some(("cmd", vec!["/C", "start", "", url]))
    } else if cfg!(target_os = "linux") {
        Some(("xdg-open", vec![url]))
    } else {
        None
    };
    if let Some((cmd, args)) = opener {
        let _ = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

fn unix_now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LoginCommandError::SystemTime)
        .map(|d| d.as_secs() as i64)
}

/// Install a Ctrl-C handler that flips an `AtomicBool`. Re-installing is a
/// no-op so this is safe to call from the command handler.
fn install_signal_handler() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = flag.clone();
    let _ = ctrlc::set_handler(move || {
        handler_flag.store(true, Ordering::SeqCst);
    });
    flag
}

/// Abstraction over `thread::sleep` so polling can be unit-tested with
/// controlled, instantaneous time.
pub(crate) trait Sleeper {
    /// Sleep for `duration` (or until interrupted). Returns `true` if the
    /// process should treat this as an interruption (Ctrl-C).
    fn sleep(&self, duration: Duration) -> bool;
}

struct RealSleeper {
    interrupted: Arc<AtomicBool>,
}

impl RealSleeper {
    fn new(interrupted: Arc<AtomicBool>) -> Self {
        Self { interrupted }
    }
}

impl Sleeper for RealSleeper {
    fn sleep(&self, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let tick = Duration::from_millis(100);
        loop {
            if self.interrupted.load(Ordering::SeqCst) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline.saturating_duration_since(now).min(tick);
            std::thread::sleep(remaining);
        }
    }
}

/// RFC 8628 §3.5 polling loop. Generic over a sleeper (for tests) and the
/// poll callback (so we can drive it from a mock without an HTTP round-trip).
pub(crate) fn poll_for_token<S, P>(
    initial_interval: u64,
    expires_in: u64,
    sleeper: &S,
    mut poll: P,
) -> Result<JwtToken>
where
    S: Sleeper,
    P: FnMut() -> std::result::Result<JwtToken, DeviceTokenError>,
{
    let mut interval = initial_interval.max(1);
    let mut elapsed: u64 = 0;
    let mut transient_backoff: u64 = 1;

    loop {
        if elapsed.saturating_add(interval) > expires_in {
            return Err(LoginCommandError::ExpiredToken);
        }
        if sleeper.sleep(Duration::from_secs(interval)) {
            return Err(LoginCommandError::Interrupted);
        }
        elapsed = elapsed.saturating_add(interval);

        match poll() {
            Ok(token) => return Ok(token),
            Err(DeviceTokenError::AuthorizationPending) => {
                transient_backoff = 1;
            }
            Err(DeviceTokenError::SlowDown) => {
                interval = interval.saturating_add(5);
                transient_backoff = 1;
            }
            Err(DeviceTokenError::AccessDenied) => return Err(LoginCommandError::AccessDenied),
            Err(DeviceTokenError::ExpiredToken) => return Err(LoginCommandError::ExpiredToken),
            Err(DeviceTokenError::InvalidGrant) => return Err(LoginCommandError::InvalidGrant),
            Err(DeviceTokenError::InvalidClient) => return Err(LoginCommandError::InvalidClient),
            Err(DeviceTokenError::Other { code, description }) => {
                return Err(LoginCommandError::OAuthError { code, description });
            }
            Err(DeviceTokenError::Transient(_)) => {
                if elapsed.saturating_add(transient_backoff) > expires_in {
                    return Err(LoginCommandError::ExpiredToken);
                }
                if sleeper.sleep(Duration::from_secs(transient_backoff)) {
                    return Err(LoginCommandError::Interrupted);
                }
                elapsed = elapsed.saturating_add(transient_backoff);
                transient_backoff =
                    transient_backoff.saturating_mul(2).min(TRANSIENT_BACKOFF_CAP_SECONDS);
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct IdTokenClaims {
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

fn decode_id_token(token: &str) -> Option<IdTokenClaims> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(IdTokenClaims {
        preferred_username: value
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        email: value.get("email").and_then(|v| v.as_str()).map(str::to_owned),
        name: value.get("name").and_then(|v| v.as_str()).map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn sample_token() -> JwtToken {
        JwtToken {
            access_token: "access".to_owned(),
            expires_in: 300,
            id_token: None,
            refresh_token: "refresh".to_owned(),
            token_type: "Bearer".to_owned(),
            refresh_expires_in: Some(1800),
            scope: Some("openid".to_owned()),
        }
    }

    /// Mock sleeper that records sleep durations without actually waiting.
    struct MockSleeper {
        slept: RefCell<Vec<u64>>,
    }

    impl MockSleeper {
        fn new() -> Self {
            Self {
                slept: RefCell::new(Vec::new()),
            }
        }

        fn durations(&self) -> Vec<u64> {
            self.slept.borrow().clone()
        }
    }

    impl Sleeper for MockSleeper {
        fn sleep(&self, duration: Duration) -> bool {
            self.slept.borrow_mut().push(duration.as_secs());
            false
        }
    }

    /// Sleeper that signals interruption on the Nth sleep call.
    struct InterruptingSleeper {
        sleeps: RefCell<u32>,
        interrupt_after: u32,
    }

    impl Sleeper for InterruptingSleeper {
        fn sleep(&self, _duration: Duration) -> bool {
            let mut count = self.sleeps.borrow_mut();
            *count += 1;
            *count > self.interrupt_after
        }
    }

    fn scripted_poll(
        steps: Vec<std::result::Result<JwtToken, DeviceTokenError>>,
    ) -> impl FnMut() -> std::result::Result<JwtToken, DeviceTokenError> {
        let mut iter = steps.into_iter();
        move || iter.next().expect("polled more times than scripted")
    }

    #[test]
    fn pending_then_slow_down_then_success_increments_interval() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![
            Err(DeviceTokenError::AuthorizationPending),
            Err(DeviceTokenError::SlowDown),
            Ok(sample_token()),
        ]);

        let result = poll_for_token(5, 600, &sleeper, poll).expect("login succeeded");

        assert_eq!(result.access_token, "access");
        // Sleeps: 5 (initial), 5 (still initial — slow_down bumps for NEXT poll),
        // then 10 (5 + 5 bump from slow_down).
        assert_eq!(sleeper.durations(), vec![5, 5, 10]);
    }

    #[test]
    fn slow_down_compounds_across_multiple_signals() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![
            Err(DeviceTokenError::SlowDown),
            Err(DeviceTokenError::SlowDown),
            Ok(sample_token()),
        ]);

        poll_for_token(5, 600, &sleeper, poll).expect("login succeeded");

        // 5 (initial), 10 (after first slow_down), 15 (after second slow_down).
        assert_eq!(sleeper.durations(), vec![5, 10, 15]);
    }

    #[test]
    fn access_denied_returns_terminal_error() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![Err(DeviceTokenError::AccessDenied)]);

        let err = poll_for_token(5, 600, &sleeper, poll).expect_err("should fail");

        assert!(matches!(err, LoginCommandError::AccessDenied));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn expired_token_returns_terminal_error() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![Err(DeviceTokenError::ExpiredToken)]);

        let err = poll_for_token(5, 600, &sleeper, poll).expect_err("should fail");

        assert!(matches!(err, LoginCommandError::ExpiredToken));
    }

    #[test]
    fn invalid_grant_returns_terminal_error() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![Err(DeviceTokenError::InvalidGrant)]);

        let err = poll_for_token(5, 600, &sleeper, poll).expect_err("should fail");

        assert!(matches!(err, LoginCommandError::InvalidGrant));
    }

    #[test]
    fn global_deadline_treats_session_as_expired() {
        // expires_in is shorter than the first interval — we should not even sleep.
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![]);

        let err = poll_for_token(10, 5, &sleeper, poll).expect_err("should expire");

        assert!(matches!(err, LoginCommandError::ExpiredToken));
        assert!(sleeper.durations().is_empty());
    }

    #[test]
    fn transient_errors_back_off_and_retry() {
        let sleeper = MockSleeper::new();
        let poll = scripted_poll(vec![
            Err(DeviceTokenError::Transient(FerriskeyClientError::Api {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                body: "boom".to_owned(),
            })),
            Err(DeviceTokenError::Transient(FerriskeyClientError::Api {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                body: "boom".to_owned(),
            })),
            Ok(sample_token()),
        ]);

        poll_for_token(5, 600, &sleeper, poll).expect("login succeeded");

        // 5 (poll), 1 (backoff), 5 (poll), 2 (backoff), 5 (poll → success).
        assert_eq!(sleeper.durations(), vec![5, 1, 5, 2, 5]);
    }

    #[test]
    fn interrupt_during_polling_returns_interrupted_with_exit_130() {
        let sleeper = InterruptingSleeper {
            sleeps: RefCell::new(0),
            interrupt_after: 0,
        };
        let poll = scripted_poll(vec![Ok(sample_token())]);

        let err = poll_for_token(5, 600, &sleeper, poll).expect_err("interrupted");

        assert!(matches!(err, LoginCommandError::Interrupted));
        assert_eq!(err.exit_code(), 130);
    }

    #[test]
    fn decode_id_token_extracts_preferred_username() {
        // {"preferred_username":"alice","email":"a@example.com","name":"Alice"}
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"preferred_username":"alice","email":"a@example.com","name":"Alice"}"#,
        );
        let jwt = format!("header.{payload}.signature");

        let claims = decode_id_token(&jwt).expect("decoded");

        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
        assert_eq!(claims.email.as_deref(), Some("a@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn decode_id_token_tolerates_garbage() {
        assert!(decode_id_token("not-a-jwt").is_none());
        assert!(decode_id_token("a.@@@.c").is_none());
    }
}
