use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::{build_agent, unix_to_system_time, PollError};
use crate::app_settings;
use crate::diagnose;
use crate::models::{CodexCreditsState, CreditsSection, UsageData, UsageSection};

const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
pub(super) const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Deserialize)]
struct CodexAuthFile {
    tokens: Option<CodexTokenData>,
}

#[derive(Clone, Deserialize)]
struct CodexTokenData {
    access_token: String,
    account_id: Option<String>,
    /// Compared with the codex-multi-auth pool by the refresh scheduler; never
    /// logged. Optional so a null here cannot break the plain auth.json poll.
    #[serde(default)]
    refresh_token: Option<String>,
}

/// The account and refresh token auth.json holds, for the refresh scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CliAuth {
    pub account_id: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CliAuthState {
    /// No auth.json path, or the file does not exist.
    Missing,
    /// The file exists but could not be read or parsed.
    Unreadable,
    Present(CliAuth),
}

#[derive(Deserialize)]
pub(super) struct CodexUsageResponse {
    rate_limit: Option<Option<Box<CodexRateLimitDetails>>>,
    credits: Option<Option<Box<CodexCredits>>>,
}

#[derive(Deserialize)]
struct CodexCredits {
    #[serde(default)]
    has_credits: bool,
    #[serde(default)]
    unlimited: bool,
    #[serde(default)]
    overage_limit_reached: bool,
    /// Sent as a decimal string, in credits rather than currency.
    balance: Option<String>,
}

/// Codex bills credits at 25 to the dollar. Only the displayed amount depends
/// on this, never the gauge: a ratio of two credit figures is unit-free, so a
/// change to this rate cannot make the bar wrong.
const CODEX_CREDITS_PER_DOLLAR: f64 = 25.0;

#[derive(Deserialize)]
struct CodexRateLimitDetails {
    primary_window: Option<Option<Box<CodexRateLimitWindow>>>,
    secondary_window: Option<Option<Box<CodexRateLimitWindow>>>,
    /// True once any window is spent, whichever one it was. Better than
    /// reading a percentage back out of a window we mapped ourselves, and it
    /// keeps working if the five-hour window is switched on again.
    #[serde(default)]
    limit_reached: bool,
}

#[derive(Deserialize)]
pub(super) struct CodexRateLimitWindow {
    used_percent: f64,
    reset_at: i64,
    limit_window_seconds: Option<i64>,
}

/// A window at or above this length is a weekly allowance rather than a
/// session one. Codex currently sends 604800 for weekly and 18000 for the
/// five-hour window, so anything from a day up is unambiguously weekly.
const WEEKLY_WINDOW_THRESHOLD_SECONDS: i64 = 86_400;

pub(super) fn poll_codex() -> Result<UsageData, PollError> {
    let path = codex_auth_path().ok_or(PollError::NoCredentials)?;
    poll_account(&path)
}

pub(super) fn poll_account(path: &Path) -> Result<UsageData, PollError> {
    let creds = match read_codex_credentials_at(path) {
        Some(creds) => creds,
        None => {
            diagnose::log("Codex usage poll failed: no Codex credentials found");
            return Err(PollError::NoCredentials);
        }
    };

    match fetch_codex_usage_at(&creds.access_token, creds.account_id.as_deref(), Some(path)) {
        Ok(data) => Ok(data),
        Err(PollError::AuthRequired) => {
            if path.file_name().is_some_and(|name| name == "auth.json") {
                if let Some(directory) = path.parent() {
                    cli_refresh_codex_token(directory);
                }
            }
            let refreshed = read_codex_credentials_at(path).ok_or(PollError::TokenExpired)?;
            fetch_codex_usage_at(
                &refreshed.access_token,
                refreshed.account_id.as_deref(),
                Some(path),
            )
        }
        Err(error) => Err(error),
    }
}

/// Poll one account from the codex-multi-auth pool. Both credential files are
/// read-only here: the wrapper refreshes the pool and the Codex CLI refreshes
/// auth.json on its own, so when auth.json holds this same account it can
/// serve the poll while the pool copy is expired or rejected.
pub(super) fn poll_multi_auth_account(
    store: &Path,
    account_id: &str,
) -> Result<UsageData, PollError> {
    poll_multi_auth_account_with(
        store,
        account_id,
        codex_auth_path().as_deref(),
        now_ms(),
        |token| fetch_codex_usage_at(token, Some(account_id), Some(store)),
    )
}

fn poll_multi_auth_account_with(
    store: &Path,
    account_id: &str,
    auth_path: Option<&Path>,
    now_ms: i64,
    fetch: impl Fn(&str) -> Result<UsageData, PollError>,
) -> Result<UsageData, PollError> {
    let pool = crate::codex_multi_auth::read_store(store).ok_or(PollError::NoCredentials)?;
    let account = pool.find(account_id).ok_or(PollError::NoCredentials)?;
    let pool_token = Some(account.access_token.trim())
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    let cli_token = auth_path
        .and_then(|path| read_auth_file(path).ok().flatten())
        .filter(|tokens| tokens.account_id.as_deref() == Some(account_id))
        .map(|tokens| tokens.access_token.trim().to_owned())
        .filter(|token| !token.is_empty() && Some(token) != pool_token.as_ref());
    // Skip a request that is bound to fail when the pool says its copy expired.
    let pool_expired = account
        .expires_at_ms()
        .is_some_and(|expires_at| expires_at <= now_ms);
    let candidates = if pool_expired {
        [(cli_token, true), (pool_token, false)]
    } else {
        [(pool_token, false), (cli_token, true)]
    };
    let mut rejected = Vec::new();
    for (token, from_cli) in candidates {
        let Some(token) = token else {
            continue;
        };
        match fetch(&token) {
            Ok(data) => {
                if from_cli {
                    diagnose::log(format!(
                        "Codex usage poll: served pool account {} from auth.json",
                        crate::codex_multi_auth::profile_id(account_id)
                    ));
                }
                return Ok(data);
            }
            Err(PollError::AuthRequired) => rejected.push(token),
            Err(error) => return Err(error),
        }
    }
    if rejected.is_empty() {
        return Err(PollError::NoCredentials);
    }
    // The wrapper may have rotated the pool while the requests were in flight.
    match multi_auth_token(store, account_id) {
        Ok(refreshed) if !rejected.iter().any(|token| token == refreshed.trim()) => {
            match fetch(refreshed.trim()) {
                Err(PollError::AuthRequired) => Err(PollError::TokenExpired),
                result => result,
            }
        }
        _ => {
            diagnose::log(
                "Codex usage poll: codex-multi-auth token rejected; waiting for the wrapper to refresh it",
            );
            Err(PollError::TokenExpired)
        }
    }
}

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

enum AuthFileError {
    Missing,
    Unreadable,
}

/// auth.json without the error logging of `read_codex_credentials_at`: pool
/// users read it on every poll and a missing file is normal for them.
fn read_auth_file(path: &Path) -> Result<Option<CodexTokenData>, AuthFileError> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AuthFileError::Missing
        } else {
            AuthFileError::Unreadable
        }
    })?;
    serde_json::from_str::<CodexAuthFile>(&content)
        .map(|auth| auth.tokens)
        .map_err(|_| AuthFileError::Unreadable)
}

pub(super) fn read_cli_auth(path: Option<&Path>) -> CliAuthState {
    let Some(path) = path else {
        return CliAuthState::Missing;
    };
    match read_auth_file(path) {
        Err(AuthFileError::Missing) => CliAuthState::Missing,
        Err(AuthFileError::Unreadable) => CliAuthState::Unreadable,
        Ok(tokens) => CliAuthState::Present(
            tokens
                .map(|tokens| CliAuth {
                    account_id: tokens.account_id.unwrap_or_default(),
                    refresh_token: tokens.refresh_token.unwrap_or_default(),
                })
                .unwrap_or_default(),
        ),
    }
}

fn multi_auth_token(store: &Path, account_id: &str) -> Result<String, PollError> {
    let store = crate::codex_multi_auth::read_store(store).ok_or(PollError::NoCredentials)?;
    let account = store.find(account_id).ok_or(PollError::NoCredentials)?;
    if account.access_token.trim().is_empty() {
        return Err(PollError::NoCredentials);
    }
    Ok(account.access_token.clone())
}

fn fetch_codex_usage_at(
    token: &str,
    account_id: Option<&str>,
    path: Option<&Path>,
) -> Result<UsageData, PollError> {
    let account_id = account_id.filter(|value| !value.is_empty());
    let agent = build_agent()?;
    let mut request = agent
        .get(CODEX_USAGE_URL)
        .header("Authorization", &format!("Bearer {token}"))
        .header("User-Agent", "codex-cli");

    if let Some(account_id) = account_id {
        request = request.header("ChatGPT-Account-Id", account_id);
    }

    let mut resp = match request.call() {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(code)) if code == 401 || code == 403 => {
            diagnose::log(format!(
                "Codex usage endpoint returned auth error status {code}; refresh required"
            ));
            return Err(PollError::AuthRequired);
        }
        Err(error) => {
            diagnose::log_error("Codex usage endpoint request failed", error);
            return Err(PollError::RequestFailed);
        }
    };

    let response: CodexUsageResponse = match resp.body_mut().read_json() {
        Ok(response) => response,
        Err(error) => {
            diagnose::log_error("unable to parse Codex usage response", error);
            return Err(PollError::RequestFailed);
        }
    };

    codex_usage_from_response_at(response, account_id, path).ok_or(PollError::RequestFailed)
}

#[cfg(test)]
pub(super) fn codex_usage_from_response(
    response: CodexUsageResponse,
    account_id: Option<&str>,
) -> Option<UsageData> {
    codex_usage_from_response_at(response, account_id, None)
}

fn codex_usage_from_response_at(
    response: CodexUsageResponse,
    account_id: Option<&str>,
    path: Option<&Path>,
) -> Option<UsageData> {
    let credits = response.credits.flatten();
    let details = *response.rate_limit.flatten()?;
    let mut data = UsageData::default();

    // Assign by window length, not by slot. Codex has shipped the weekly
    // allowance in `primary_window` with `secondary_window` empty while the
    // five-hour window is switched off, so trusting the slot order puts a
    // weekly figure in the session bar.
    for (window, default_is_weekly) in [
        (details.primary_window.flatten(), false),
        (details.secondary_window.flatten(), true),
    ]
    .into_iter()
    .filter_map(|(window, default_is_weekly)| window.map(|window| (window, default_is_weekly)))
    {
        let section = codex_section_from_window(&window);
        if window_is_weekly(&window).unwrap_or(default_is_weekly) {
            data.weekly = section;
        } else {
            data.session = section;
        }
    }

    data.credits = credits.and_then(|credits| {
        let state_path = path.map(|path| {
            app_settings::app_data_directory().join(credit_state_file_name(path, account_id))
        });
        let previous = match &state_path {
            Some(path) => std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .or_else(|| {
                    app_settings::load_codex_credits().filter(|state| {
                        account_id.is_some() && state.account_id.as_deref() == account_id
                    })
                }),
            None => app_settings::load_codex_credits(),
        };
        let (state, section) = codex_credits(previous, &credits, details.limit_reached, account_id);
        let saved = match &state_path {
            Some(path) => app_settings::write_json_atomic(path, &state),
            None => app_settings::save_codex_credits(&state),
        };
        if let Err(error) = saved {
            diagnose::log(format!("unable to persist Codex credit baseline: {error}"));
        }
        section
    });

    Some(data)
}

fn credit_state_file_name(path: &Path, account_id: Option<&str>) -> String {
    format!(
        "codex-credits-{}.json",
        crate::accounts::fingerprint(&format!(
            "{}|{account_id:?}",
            crate::accounts::source_key(path)
        ))
    )
}

/// Tracks the balance across polls and turns it into a gauge.
///
/// The balance only ever falls as credits are spent, so any rise is a top-up
/// and re-baselines the gauge. Tracking continues whether or not the gauge is
/// shown, because a top-up that happens while the bar is hidden still has to
/// move the baseline.
fn codex_credits(
    previous: Option<CodexCreditsState>,
    credits: &CodexCredits,
    limit_reached: bool,
    account_id: Option<&str>,
) -> (CodexCreditsState, Option<CreditsSection>) {
    let balance = credits
        .balance
        .as_deref()
        .and_then(|balance| balance.parse::<f64>().ok())
        .filter(|balance| balance.is_finite() && *balance >= 0.0)
        .unwrap_or_default();

    let previous = previous.filter(|state| state.account_id.as_deref() == account_id);
    let baseline = match previous {
        // A rise can only come from a top-up. Seed from the first balance we
        // see, which reads as untouched until the next top-up corrects it.
        Some(previous) if balance <= previous.balance => previous.baseline.max(balance),
        _ => balance,
    };
    let state = CodexCreditsState {
        account_id: account_id.map(str::to_owned),
        balance,
        baseline,
    };

    // The bars stay on the ordinary windows until two things are true at once:
    // an allowance is spent, and credits have actually started going down
    // against the current top-up. The second half is an observation rather
    // than an assumption about when a provider decides to bill credits, and it
    // holds steady while idle, so the gauge does not flicker away on a poll
    // that happens to see no change.
    let in_use = balance < baseline;
    let applicable =
        credits.has_credits && !credits.unlimited && limit_reached && in_use && baseline > 0.0;
    if !applicable {
        return (state, None);
    }

    let percentage = if credits.overage_limit_reached {
        100.0
    } else {
        (((baseline - balance) / baseline) * 100.0).clamp(0.0, 100.0)
    };

    (
        state,
        Some(CreditsSection {
            percentage,
            remaining: balance / CODEX_CREDITS_PER_DOLLAR,
            total: baseline / CODEX_CREDITS_PER_DOLLAR,
        }),
    )
}

/// Returns no classification when the API omits the duration. The caller then
/// preserves the legacy slot mapping: primary is session, secondary is weekly.
fn window_is_weekly(window: &CodexRateLimitWindow) -> Option<bool> {
    window
        .limit_window_seconds
        .map(|seconds| seconds >= WEEKLY_WINDOW_THRESHOLD_SECONDS)
}

pub(super) fn codex_section_from_window(window: &CodexRateLimitWindow) -> UsageSection {
    UsageSection {
        available: true,
        percentage: window.used_percent,
        resets_at: unix_to_system_time(Some(window.reset_at)),
    }
}

pub(super) fn credential_watch_snapshot() -> Vec<String> {
    let Some(path) = codex_auth_path() else {
        return vec!["codex:auth-path-missing".into()];
    };
    let key = format!("codex:{}", path.display());
    let signature = match std::fs::metadata(path) {
        Ok(metadata) => {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            format!("{key}|present|{}|{modified}", metadata.len())
        }
        Err(_) => format!("{key}|missing"),
    };
    vec![signature]
}

/// Source signature of a Codex credential file. A pool account can also be
/// served from auth.json, so pool signatures cover both files.
pub(super) fn account_watch_signature(path: &Path) -> String {
    if path
        .file_name()
        .is_some_and(|name| name == crate::codex_multi_auth::STORE_FILE_NAME)
    {
        pool_watch_signature(path, codex_auth_path().as_deref())
    } else {
        crate::accounts::file_signature(path)
    }
}

fn pool_watch_signature(pool: &Path, auth: Option<&Path>) -> String {
    crate::accounts::fingerprint(&format!(
        "{}|{}",
        crate::accounts::file_signature(pool),
        auth.map(crate::accounts::file_signature)
            .unwrap_or_default()
    ))
}

pub(super) fn codex_auth_path() -> Option<PathBuf> {
    if std::env::var_os("CODEX_HOME").is_some_and(|value| !value.is_empty()) {
        let codex_home =
            crate::accounts::environment_directory(crate::providers::ProviderId::Codex)?;
        return Some(codex_home.join("auth.json"));
    }
    Some(dirs::home_dir()?.join(".codex").join("auth.json"))
}

fn read_codex_credentials_at(auth_path: &Path) -> Option<CodexTokenData> {
    let content = match std::fs::read_to_string(auth_path) {
        Ok(content) => content,
        Err(error) => {
            diagnose::log_error(
                &format!(
                    "unable to read Codex credentials at {}",
                    auth_path.display()
                ),
                error,
            );
            return None;
        }
    };
    let auth: CodexAuthFile = serde_json::from_str(&content).ok()?;
    auth.tokens
        .filter(|tokens| !tokens.access_token.trim().is_empty())
}

fn cli_refresh_codex_token(directory: &Path) {
    let codex_path = resolve_windows_codex_path();
    let is_cmd = codex_path.to_lowercase().ends_with(".cmd");
    let is_ps1 = codex_path.to_lowercase().ends_with(".ps1");
    diagnose::log(format!(
        "attempting Windows Codex token refresh via {codex_path}"
    ));

    let args: &[&str] = &["exec", "."];
    let mut command = if is_cmd {
        let mut command = Command::new("cmd.exe");
        command.arg("/c").arg(&codex_path).args(args);
        command
    } else if is_ps1 {
        let mut command = Command::new("powershell.exe");
        command
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&codex_path)
            .args(args);
        command
    } else {
        let mut command = Command::new(&codex_path);
        command.args(args);
        command
    };
    command
        .env("CODEX_HOME", directory)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            diagnose::log_error("unable to spawn Windows Codex token refresh", error);
            return;
        }
    };
    wait_for_refresh(&mut child);
}

fn resolve_windows_codex_path() -> String {
    for name in ["codex.cmd", "codex.ps1", "codex.exe", "codex"] {
        if Command::new(name)
            .arg("--version")
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return name.to_string();
        }
    }

    for name in ["codex.cmd", "codex.ps1", "codex.exe", "codex"] {
        if let Ok(output) = Command::new("where.exe")
            .arg(name)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(path) = stdout
                    .lines()
                    .next()
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                {
                    return path.to_string();
                }
            }
        }
    }
    "codex.cmd".to_string()
}

fn wait_for_refresh(child: &mut std::process::Child) {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > Duration::from_secs(30) => {
                let _ = child.kill();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(500)),
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "usage-codex-{tag}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const NOW: i64 = 1_000_000_000_000;

    fn write_pool(path: &Path, expires_at: i64) {
        std::fs::write(
            path,
            format!(
                r#"{{"accounts":[{{"accountId":"org-a","accessToken":"pool","expiresAt":{expires_at}}}]}}"#
            ),
        )
        .unwrap();
    }

    fn write_auth(path: &Path, account_id: &str, access_token: &str) {
        std::fs::write(
            path,
            format!(
                r#"{{"tokens":{{"access_token":"{access_token}","account_id":"{account_id}","refresh_token":"r"}}}}"#
            ),
        )
        .unwrap();
    }

    /// Polls `account_id` with a fake endpoint that accepts only `accepts`
    /// (or fails every call with `failure` when given) and records the tokens
    /// it was sent.
    fn poll_with(
        store: &Path,
        auth: &Path,
        account_id: &str,
        accepts: &[&str],
        failure: Option<PollError>,
    ) -> (Result<UsageData, PollError>, Vec<String>) {
        let calls = RefCell::new(Vec::new());
        let result = poll_multi_auth_account_with(store, account_id, Some(auth), NOW, |token| {
            calls.borrow_mut().push(token.to_string());
            match failure {
                Some(error) => Err(error),
                None if accepts.contains(&token) => Ok(UsageData::default()),
                None => Err(PollError::AuthRequired),
            }
        });
        (result, calls.into_inner())
    }

    #[test]
    fn pool_accounts_fall_back_to_auth_json_for_the_same_account() {
        let dir = TempDir::new("fallback");
        let store = dir.0.join(crate::codex_multi_auth::STORE_FILE_NAME);
        let auth = dir.0.join("auth.json");
        write_pool(&store, NOW + 3_600_000);
        write_auth(&auth, "org-a", "cli");

        let (result, calls) = poll_with(&store, &auth, "org-a", &["pool"], None);
        assert!(result.is_ok());
        assert_eq!(calls, ["pool"]);

        let (result, calls) = poll_with(&store, &auth, "org-a", &["cli"], None);
        assert!(result.is_ok());
        assert_eq!(calls, ["pool", "cli"]);

        let (result, calls) =
            poll_with(&store, &auth, "org-a", &[], Some(PollError::RequestFailed));
        assert_eq!(result.unwrap_err(), PollError::RequestFailed);
        assert_eq!(calls, ["pool"], "a non-auth failure is not retried");

        let (result, calls) = poll_with(&store, &auth, "org-z", &["pool", "cli"], None);
        assert_eq!(result.unwrap_err(), PollError::NoCredentials);
        assert!(calls.is_empty());

        write_pool(&store, NOW - 1);
        let (result, calls) = poll_with(&store, &auth, "org-a", &["cli"], None);
        assert!(result.is_ok());
        assert_eq!(calls, ["cli"], "an expired pool token is not tried first");

        write_pool(&store, NOW + 3_600_000);
        write_auth(&auth, "org-b", "cli");
        let (result, calls) = poll_with(&store, &auth, "org-a", &["cli"], None);
        assert_eq!(result.unwrap_err(), PollError::TokenExpired);
        assert_eq!(calls, ["pool"], "another account's token is never sent");

        write_auth(&auth, "org-a", "pool");
        let (result, calls) = poll_with(&store, &auth, "org-a", &[], None);
        assert_eq!(result.unwrap_err(), PollError::TokenExpired);
        assert_eq!(calls, ["pool"], "the same token is sent once");
    }

    #[test]
    fn read_cli_auth_reads_account_and_refresh_token() {
        let dir = TempDir::new("cli-auth");
        let auth = dir.0.join("auth.json");
        assert_eq!(read_cli_auth(None), CliAuthState::Missing);
        assert_eq!(read_cli_auth(Some(&auth)), CliAuthState::Missing);
        write_auth(&auth, "org-a", "access");
        assert_eq!(
            read_cli_auth(Some(&auth)),
            CliAuthState::Present(CliAuth {
                account_id: "org-a".into(),
                refresh_token: "r".into(),
            })
        );
        std::fs::write(&auth, r#"{"tokens":{"access_token":"access"}}"#).unwrap();
        assert_eq!(
            read_cli_auth(Some(&auth)),
            CliAuthState::Present(CliAuth::default())
        );
        std::fs::write(
            &auth,
            r#"{"tokens":{"access_token":"access","account_id":"org-a","refresh_token":null}}"#,
        )
        .unwrap();
        assert_eq!(
            read_cli_auth(Some(&auth)),
            CliAuthState::Present(CliAuth {
                account_id: "org-a".into(),
                refresh_token: String::new(),
            })
        );
        std::fs::write(&auth, "{}").unwrap();
        assert_eq!(
            read_cli_auth(Some(&auth)),
            CliAuthState::Present(CliAuth::default())
        );
        std::fs::write(&auth, "not json").unwrap();
        assert_eq!(read_cli_auth(Some(&auth)), CliAuthState::Unreadable);
    }

    #[test]
    fn pool_signatures_follow_auth_json() {
        let dir = TempDir::new("signature");
        let store = dir.0.join(crate::codex_multi_auth::STORE_FILE_NAME);
        let auth = dir.0.join("auth.json");
        write_pool(&store, NOW);
        write_auth(&auth, "org-a", "first");
        let before = pool_watch_signature(&store, Some(&auth));
        assert_eq!(before, pool_watch_signature(&store, Some(&auth)));
        write_auth(&auth, "org-a", "refreshed by the Codex CLI");
        let after_cli = pool_watch_signature(&store, Some(&auth));
        assert_ne!(before, after_cli);
        write_pool(&store, NOW + 3_600_000);
        assert_ne!(after_cli, pool_watch_signature(&store, Some(&auth)));
        assert_eq!(
            pool_watch_signature(&store, None),
            pool_watch_signature(&store, None)
        );
    }

    #[test]
    fn credit_history_is_scoped_to_source_and_account() {
        let first = Path::new("C:\\account-tests\\work\\auth.json");
        let second = Path::new("C:\\account-tests\\personal\\auth.json");
        assert_ne!(
            credit_state_file_name(first, Some("work")),
            credit_state_file_name(second, Some("work"))
        );
        assert_ne!(
            credit_state_file_name(first, Some("work")),
            credit_state_file_name(first, Some("personal"))
        );
        assert_ne!(
            credit_state_file_name(first, None),
            credit_state_file_name(second, None)
        );
    }

    fn usage_from_json(json: &str) -> UsageData {
        let response: CodexUsageResponse =
            serde_json::from_str(json).expect("the fixture should deserialize");
        codex_usage_from_response(response, None).expect("the fixture should carry rate limits")
    }

    fn credits(balance: &str, has_credits: bool) -> CodexCredits {
        CodexCredits {
            has_credits,
            unlimited: false,
            overage_limit_reached: false,
            balance: Some(balance.into()),
        }
    }

    #[test]
    fn the_first_balance_seeds_the_baseline_and_reads_untouched() {
        let (state, section) = codex_credits(None, &credits("1026.112935", true), true, None);

        assert_eq!(state.baseline, 1026.112935);
        // Nothing has been drawn against the seeded baseline yet, so the bars
        // stay on the ordinary windows until a later poll sees it fall.
        assert!(section.is_none());

        // That later poll, with 25 credits to the dollar.
        let previous = state;
        let (_, section) = codex_credits(Some(previous), &credits("1016.190898", true), true, None);
        let section = section.expect("a falling balance should expose the gauge");
        assert!(
            (section.remaining - 40.64763592).abs() < 1e-6,
            "{section:?}"
        );
    }

    #[test]
    fn spending_against_a_baseline_fills_the_gauge() {
        let previous = CodexCreditsState {
            account_id: None,
            balance: 2500.0,
            baseline: 2500.0,
        };
        let (state, section) = codex_credits(Some(previous), &credits("1250.0", true), true, None);

        assert_eq!(state.baseline, 2500.0);
        let section = section.expect("gauge");
        assert_eq!(section.percentage, 50.0);
        assert_eq!(section.remaining, 50.0);
        assert_eq!(section.total, 100.0);
    }

    #[test]
    fn a_rise_in_the_balance_is_a_reload_and_rebaselines() {
        let previous = CodexCreditsState {
            account_id: None,
            balance: 100.0,
            baseline: 2500.0,
        };
        let (state, section) = codex_credits(Some(previous), &credits("2600.0", true), true, None);

        assert_eq!(state.baseline, 2600.0);
        // A fresh top-up has nothing spent against it, so the gauge stands
        // down until credits start being drawn on again.
        assert!(section.is_none());
    }

    #[test]
    fn changing_accounts_reseeds_the_credit_baseline() {
        let previous = CodexCreditsState {
            account_id: Some("old-account".into()),
            balance: 100.0,
            baseline: 2500.0,
        };
        let (state, section) = codex_credits(
            Some(previous),
            &credits("50.0", true),
            true,
            Some("new-account"),
        );

        assert_eq!(state.account_id.as_deref(), Some("new-account"));
        assert_eq!(state.baseline, 50.0);
        assert!(
            section.is_none(),
            "a different account's lower balance is not prior spending"
        );
    }

    #[test]
    fn the_gauge_hides_while_an_allowance_remains() {
        let previous = CodexCreditsState {
            account_id: None,
            balance: 2000.0,
            baseline: 2500.0,
        };
        let (state, section) = codex_credits(Some(previous), &credits("1000.0", true), false, None);

        // Tracking continues while hidden so a reload still moves the baseline.
        assert_eq!(state.balance, 1000.0);
        assert_eq!(state.baseline, 2500.0);
        assert!(section.is_none());
    }

    #[test]
    fn accounts_without_credits_get_no_gauge() {
        let (_, section) = codex_credits(None, &credits("0", false), true, None);
        assert!(section.is_none());

        let unlimited = CodexCredits {
            unlimited: true,
            ..credits("1000.0", true)
        };
        let (_, section) = codex_credits(None, &unlimited, true, None);
        assert!(section.is_none());
    }

    #[test]
    fn a_reached_overage_limit_pins_the_gauge_full() {
        let previous = CodexCreditsState {
            account_id: None,
            balance: 500.0,
            baseline: 1000.0,
        };
        let reached = CodexCredits {
            overage_limit_reached: true,
            ..credits("500.0", true)
        };
        let (_, section) = codex_credits(Some(previous), &reached, true, None);

        assert_eq!(section.expect("gauge").percentage, 100.0);
    }

    #[test]
    fn a_lone_weekly_window_lands_in_the_weekly_bar() {
        // Codex ships this shape while the five-hour window is switched off:
        // the weekly allowance arrives in `primary_window`.
        let data = usage_from_json(
            r#"{
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 100,
                        "limit_window_seconds": 604800,
                        "reset_at": 1787198224
                    },
                    "secondary_window": null
                }
            }"#,
        );

        assert_eq!(data.weekly.percentage, 100.0);
        assert_eq!(data.session.percentage, 0.0);
        assert!(data.weekly.resets_at.is_some());
        assert!(data.session.resets_at.is_none());
        assert!(data.weekly.available);
        assert!(!data.session.available);
    }

    #[test]
    fn a_reported_zero_usage_window_is_available_without_a_usable_reset() {
        let data = usage_from_json(
            r#"{
            "rate_limit": {
                "primary_window": {"used_percent":0,"limit_window_seconds":18000,"reset_at":-1},
                "secondary_window": null
            }
        }"#,
        );
        assert!(data.session.available);
        assert_eq!(data.session.percentage, 0.0);
        assert!(data.session.resets_at.is_none());
        assert!(!data.weekly.available);
    }

    #[test]
    fn windows_are_assigned_by_length_regardless_of_slot_order() {
        let data = usage_from_json(
            r#"{
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 80,
                        "limit_window_seconds": 604800,
                        "reset_at": 1787198224
                    },
                    "secondary_window": {
                        "used_percent": 20,
                        "limit_window_seconds": 18000,
                        "reset_at": 1787100000
                    }
                }
            }"#,
        );

        assert_eq!(data.weekly.percentage, 80.0);
        assert_eq!(data.session.percentage, 20.0);
    }

    #[test]
    fn an_unlabelled_window_stays_in_the_session_bar() {
        let data = usage_from_json(
            r#"{
                "rate_limit": {
                    "primary_window": {"used_percent": 42, "reset_at": 1787100000},
                    "secondary_window": null
                }
            }"#,
        );

        assert_eq!(data.session.percentage, 42.0);
        assert_eq!(data.weekly.percentage, 0.0);
    }

    #[test]
    fn two_unlabelled_windows_keep_the_legacy_slot_mapping() {
        let data = usage_from_json(
            r#"{
                "rate_limit": {
                    "primary_window": {"used_percent": 20, "reset_at": 1787100000},
                    "secondary_window": {"used_percent": 80, "reset_at": 1787198224}
                }
            }"#,
        );

        assert_eq!(data.session.percentage, 20.0);
        assert_eq!(data.weekly.percentage, 80.0);
    }
}
