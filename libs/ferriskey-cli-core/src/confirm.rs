use std::io::{self, IsTerminal, Write};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfirmError {
    #[error("aborted")]
    Aborted,
    #[error(
        "refusing to proceed without confirmation: re-run with --force to confirm in a non-interactive shell"
    )]
    NonInteractive,
    #[error("failed to read confirmation from stdin")]
    Io(#[source] io::Error),
}

/// Prompt for confirmation of a destructive action.
///
/// - When `force` is true, returns `Ok(())` immediately (no prompt).
/// - When stdin is not a TTY, returns `NonInteractive` so scripts must opt in
///   with `--force` rather than hanging or silently proceeding.
/// - Otherwise prompts on stderr and accepts `y`/`yes` (case-insensitive).
pub(crate) fn confirm(prompt: &str, force: bool) -> Result<(), ConfirmError> {
    if force {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(ConfirmError::NonInteractive);
    }

    eprint!("{prompt} [y/N]: ");
    let _ = io::stderr().flush();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(ConfirmError::Io)?;

    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err(ConfirmError::Aborted),
    }
}
