//! Keeps codex-multi-auth pool tokens fresh without becoming a token writer.
//!
//! Pool access tokens expire after about ten days, and the wrapper refreshes
//! an account only when it uses it. Shortly before a shown account expires,
//! this module runs the wrapper's own `codex-multi-auth check`, which
//! refreshes through the wrapper's cross-process lease and saves the pool.
//! OpenAI refresh tokens are single-use, so the run is shaped to never leave
//! auth.json holding a spent one: CLI sync is on only when the wrapper's active
//! account is refreshed, and the run is skipped whenever auth.json does not
//! match what the wrapper is about to do.
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, Mutex, MutexGuard, Once, OnceLock};
use std::time::{Duration, Instant};

use super::codex::{self, CliAuthState, CREATE_NO_WINDOW};
use crate::accounts::ProviderAccounts;
use crate::codex_multi_auth::{Store, StoreAccount};
use crate::diagnose;

/// codex-multi-auth refreshes an account once it has this little time left
/// (`ACCESS_TOKEN_FRESH_WINDOW_MS`, 2.15), so running it earlier changes nothing.
const REFRESH_WINDOW_MS: i64 = 5 * 60 * 1000;
/// Look-ahead for predicting what a run refreshes: an account may cross the
/// wrapper's line between this decision and the wrapper's own evaluation.
const SYNC_MARGIN_MS: i64 = 2 * 60 * 1000;
/// A run that left an account's expiry unchanged is retried after this long.
const RETRY_AFTER_MS: i64 = 60 * 60 * 1000;
/// Longest single sleep; every poll also wakes the thread.
const MAX_WAIT_MS: i64 = 60 * 60 * 1000;
const MIN_WAIT_MS: i64 = 1_000;
/// The wrapper runs its install setup (app binding, launcher routing, config
/// edits) before any command until its marker reaches this version
/// (`FIRST_RUN_MARKER_VERSION`, 2.15), so a background run waits for it.
const WRAPPER_SETUP_VERSION: f64 = 2.0;
const WRAPPER_SETUP_MARKER: &str = "first-run-setup.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockReason {
    /// The wrapper has not finished its own first-run setup.
    WrapperSetupPending,
    /// `check` re-enables every account it finds healthy.
    DisabledAccountInPool,
    AuthUnreadable,
    AuthMissing,
    NoActiveAccount,
    AuthHoldsAnotherAccount,
    RefreshTokenDiffers,
    /// The run would spend the refresh token auth.json holds without
    /// writing the new one back.
    AuthTokenWouldBeSpent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Due {
    account_id: String,
    expires_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Decision {
    Idle,
    WaitUntil(i64),
    Trigger { due: Vec<Due>, sync_cli: bool },
    Blocked(BlockReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attempt {
    expires_at: Option<i64>,
    at_ms: i64,
}

/// Earliest time the wrapper would refresh this account; mirrors
/// `!hasUsableAccessToken` in codex-multi-auth 2.15.
fn refresh_due_at(account: &StoreAccount) -> i64 {
    match account.expires_at_ms() {
        Some(expires_at) if !account.access_token.is_empty() => {
            expires_at.saturating_sub(REFRESH_WINDOW_MS)
        }
        _ => i64::MIN,
    }
}

fn decide(
    pool: Option<&Store>,
    cli: &CliAuthState,
    wrapper_ready: bool,
    monitored: &[String],
    attempts: &HashMap<String, Attempt>,
    now_ms: i64,
) -> Decision {
    let Some(pool) = pool else {
        return Decision::Idle;
    };
    let mut due = Vec::new();
    let mut next: Option<i64> = None;
    for account_id in monitored {
        let Some(account) = pool.find(account_id) else {
            continue;
        };
        let expires_at = account.expires_at_ms();
        let natural = refresh_due_at(account);
        let due_at = match attempts.get(account_id) {
            Some(attempt) if attempt.expires_at == expires_at => {
                natural.max(attempt.at_ms.saturating_add(RETRY_AFTER_MS))
            }
            _ => natural,
        };
        if now_ms >= due_at {
            due.push(Due {
                account_id: account_id.clone(),
                expires_at,
            });
        } else {
            next = Some(next.map_or(due_at, |next| next.min(due_at)));
        }
    }
    if due.is_empty() {
        return next.map_or(Decision::Idle, Decision::WaitUntil);
    }
    if !wrapper_ready {
        return Decision::Blocked(BlockReason::WrapperSetupPending);
    }
    if pool
        .accounts
        .iter()
        .any(|account| account.enabled == Some(false))
    {
        return Decision::Blocked(BlockReason::DisabledAccountInPool);
    }
    let cli = match cli {
        CliAuthState::Unreadable => return Decision::Blocked(BlockReason::AuthUnreadable),
        CliAuthState::Missing => None,
        CliAuthState::Present(cli) => Some(cli),
    };
    // What the wrapper will refresh: every pool account, shown or not.
    let horizon = now_ms.saturating_add(SYNC_MARGIN_MS);
    let refreshable: Vec<&StoreAccount> = pool
        .accounts
        .iter()
        .filter(|account| horizon >= refresh_due_at(account))
        .collect();
    let Some(active) = pool.codex_active() else {
        return Decision::Blocked(BlockReason::NoActiveAccount);
    };
    let sync_cli = refreshable
        .iter()
        .any(|account| std::ptr::eq(*account, active));
    if sync_cli {
        // The wrapper writes the active account into auth.json afterwards,
        // so auth.json must hold exactly what the pool holds for it.
        let Some(cli) = cli else {
            return Decision::Blocked(BlockReason::AuthMissing);
        };
        if cli.account_id != active.account_id {
            return Decision::Blocked(BlockReason::AuthHoldsAnotherAccount);
        }
        if cli.refresh_token.is_empty() || cli.refresh_token != active.refresh_token {
            return Decision::Blocked(BlockReason::RefreshTokenDiffers);
        }
    } else if let Some(cli) = cli {
        if !cli.refresh_token.is_empty()
            && refreshable
                .iter()
                .any(|account| account.refresh_token == cli.refresh_token)
        {
            return Decision::Blocked(BlockReason::AuthTokenWouldBeSpent);
        }
    }
    Decision::Trigger { due, sync_cli }
}

#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Sleep this many milliseconds unless woken.
    Sleep(i64),
    /// Run the wrapper against this pool; the attempt is already recorded.
    Spawn {
        store: PathBuf,
        sync_cli: bool,
        due_count: usize,
    },
}

impl Step {
    fn sleep(ms: i64) -> Self {
        Self::Sleep(ms.clamp(MIN_WAIT_MS, MAX_WAIT_MS))
    }
}

/// All scheduling state and decisions, free of threads and I/O.
#[derive(Default)]
struct RefreshScheduler {
    monitored: Vec<String>,
    store: Option<PathBuf>,
    attempts: HashMap<String, Attempt>,
    in_flight: bool,
    last_block: Option<BlockReason>,
    /// Bumped by every change from outside the thread, so the thread can tell
    /// that state moved while it was reading files without the lock.
    generation: u64,
}

impl RefreshScheduler {
    fn set_monitored(&mut self, monitored: Vec<String>, store: Option<PathBuf>) {
        self.monitored = monitored;
        self.store = store;
        self.generation = self.generation.wrapping_add(1);
    }

    fn step(
        &mut self,
        pool: Option<&Store>,
        cli: &CliAuthState,
        wrapper_ready: bool,
        now_ms: i64,
    ) -> Step {
        if self.in_flight {
            return Step::sleep(MAX_WAIT_MS);
        }
        match decide(
            pool,
            cli,
            wrapper_ready,
            &self.monitored,
            &self.attempts,
            now_ms,
        ) {
            Decision::Idle => Step::sleep(MAX_WAIT_MS),
            Decision::WaitUntil(at) => Step::sleep(at.saturating_sub(now_ms)),
            Decision::Blocked(reason) => {
                if self.last_block != Some(reason) {
                    diagnose::log(format!("codex-multi-auth refresh skipped ({reason:?})"));
                }
                self.last_block = Some(reason);
                Step::sleep(MAX_WAIT_MS)
            }
            Decision::Trigger { due, sync_cli } => {
                let Some(store) = self.store.clone() else {
                    return Step::sleep(MAX_WAIT_MS);
                };
                self.last_block = None;
                for due in &due {
                    self.attempts.insert(
                        due.account_id.clone(),
                        Attempt {
                            expires_at: due.expires_at,
                            at_ms: now_ms,
                        },
                    );
                }
                self.in_flight = true;
                Step::Spawn {
                    store,
                    sync_cli,
                    due_count: due.len(),
                }
            }
        }
    }

    /// The recorded attempts keep the retry backoff.
    fn spawn_failed(&mut self) {
        self.in_flight = false;
        self.generation = self.generation.wrapping_add(1);
    }

    fn child_exited(&mut self) {
        self.in_flight = false;
        self.generation = self.generation.wrapping_add(1);
    }
}

fn monitored_accounts(codex_enabled: bool, accounts: &ProviderAccounts) -> Vec<String> {
    if !codex_enabled {
        return Vec::new();
    }
    accounts
        .profiles
        .iter()
        .filter(|profile| profile.enabled && profile.is_multi_auth())
        .map(|profile| profile.multi_auth_account.clone())
        .collect()
}

#[derive(Default)]
struct Shared {
    scheduler: Mutex<RefreshScheduler>,
    wake: Condvar,
}

static SHARED: OnceLock<Shared> = OnceLock::new();
static STARTED: Once = Once::new();

fn lock(shared: &Shared) -> MutexGuard<'_, RefreshScheduler> {
    shared
        .scheduler
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Called on every poll with the accounts the widget shows.
pub(super) fn schedule(codex_enabled: bool, accounts: &ProviderAccounts) {
    if cfg!(test) {
        return;
    }
    let monitored = monitored_accounts(codex_enabled, accounts);
    let store = crate::codex_multi_auth::store_path();
    let shared = SHARED.get_or_init(Shared::default);
    lock(shared).set_monitored(monitored, store);
    STARTED.call_once(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("codex-multi-auth-refresh".into())
            .spawn(move || run(shared))
        {
            diagnose::log_error("codex-multi-auth refresh thread could not start", error);
        }
    });
    shared.wake.notify_one();
}

fn run(shared: &'static Shared) {
    let mut guard = lock(shared);
    loop {
        let seen = guard.generation;
        let store = guard.store.clone();
        drop(guard);
        // Read every time, even while a run is in flight: a snapshot taken
        // before it finishes must never be decided on.
        let pool = store
            .as_deref()
            .and_then(crate::codex_multi_auth::read_store);
        let auth_path = codex::codex_auth_path();
        let cli = codex::read_cli_auth(auth_path.as_deref());
        let wrapper_ready = store.as_deref().is_some_and(wrapper_setup_done);
        guard = lock(shared);
        if guard.generation != seen {
            continue;
        }
        // The lock is held from the check above into the wait, so a
        // notification cannot slip in between deciding and sleeping.
        match guard.step(pool.as_ref(), &cli, wrapper_ready, codex::now_ms()) {
            Step::Sleep(ms) => {
                guard = shared
                    .wake
                    .wait_timeout(guard, Duration::from_millis(ms.unsigned_abs()))
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
            Step::Spawn {
                store,
                sync_cli,
                due_count,
            } => {
                drop(guard);
                match spawn_check(&store, auth_path.as_deref(), sync_cli) {
                    Ok(child) => {
                        diagnose::log(format!(
                            "codex-multi-auth refresh: running check for {due_count} account(s) due, cli sync {}",
                            if sync_cli { "on" } else { "off" }
                        ));
                        wait_for(child);
                        lock(shared).child_exited();
                    }
                    Err(error) => {
                        diagnose::log_error("codex-multi-auth refresh could not start", error);
                        lock(shared).spawn_failed();
                    }
                }
                guard = lock(shared);
            }
        }
    }
}

/// Waits without a timeout and never kills the run: a kill between OpenAI
/// rotating a refresh token and the wrapper saving it loses the token. The
/// scheduler has nothing else to do while a run is in flight, so it waits here.
fn wait_for(mut child: Child) {
    let started = Instant::now();
    let code = child.wait().ok().and_then(|status| status.code());
    diagnose::log(format!(
        "codex-multi-auth refresh: check finished exit={code:?} after {} ms",
        started.elapsed().as_millis()
    ));
}

/// True once the wrapper's first-run marker beside the pool is current, so
/// `check` goes straight to the command instead of installing things first.
fn wrapper_setup_done(store: &Path) -> bool {
    std::fs::read(store.with_file_name(WRAPPER_SETUP_MARKER))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|marker| marker.get("version").and_then(serde_json::Value::as_f64))
        .is_some_and(|version| version >= WRAPPER_SETUP_VERSION)
}

fn spawn_check(store: &Path, auth_path: Option<&Path>, sync_cli: bool) -> std::io::Result<Child> {
    let wrapper = resolve_wrapper().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "codex-multi-auth.cmd is not on PATH",
        )
    })?;
    let directory = store.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the pool path has no directory",
        )
    })?;
    // Bind the run to the files this module validated, whatever the monitor
    // inherited: the pool, auth.json, sync on or off, and no config edits.
    let mut command = Command::new(wrapper);
    command
        .arg("check")
        .env("CODEX_MULTI_AUTH_DIR", directory)
        .env(
            "CODEX_MULTI_AUTH_SYNC_CODEX_CLI",
            if sync_cli { "1" } else { "0" },
        )
        .env("CODEX_MULTI_AUTH_ENFORCE_CLI_FILE_AUTH_STORE", "0");
    if let Some(auth_path) = auth_path {
        command.env("CODEX_CLI_AUTH_PATH", auth_path).env(
            "CODEX_CLI_ACCOUNTS_PATH",
            auth_path.with_file_name("accounts.json"),
        );
    }
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn resolve_wrapper() -> Option<PathBuf> {
    let output = Command::new("where.exe")
        .arg("codex-multi-auth.cmd")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountProfile;
    use crate::poller::codex::CliAuth;
    use serde_json::json;

    const NOW: i64 = 1_000_000_000_000;
    const HOUR: i64 = 3_600_000;
    const MINUTE: i64 = 60_000;

    fn account(id: &str, expires_at: Option<i64>) -> serde_json::Value {
        let mut account = json!({
            "accountId": id,
            "accessToken": format!("access-{id}"),
            "refreshToken": format!("refresh-{id}"),
        });
        if let Some(expires_at) = expires_at {
            account["expiresAt"] = json!(expires_at);
        }
        account
    }

    fn pool(accounts: Vec<serde_json::Value>) -> Store {
        pool_with(accounts, json!({}))
    }

    fn pool_with(accounts: Vec<serde_json::Value>, extra: serde_json::Value) -> Store {
        let mut value = json!({ "accounts": accounts, "activeIndex": 0 });
        if let serde_json::Value::Object(extra) = extra {
            for (key, entry) in extra {
                value[key] = entry;
            }
        }
        serde_json::from_value(value).unwrap()
    }

    fn cli(account_id: &str, refresh_token: &str) -> CliAuthState {
        CliAuthState::Present(CliAuth {
            account_id: account_id.into(),
            refresh_token: refresh_token.into(),
        })
    }

    fn mirror() -> CliAuthState {
        cli("org-a", "refresh-org-a")
    }

    fn monitored(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn decide_now(store: &Store, cli: &CliAuthState, ids: &[&str]) -> Decision {
        decide(
            Some(store),
            cli,
            true,
            &monitored(ids),
            &HashMap::new(),
            NOW,
        )
    }

    fn trigger(ids: &[(&str, Option<i64>)], sync_cli: bool) -> Decision {
        Decision::Trigger {
            due: ids
                .iter()
                .map(|(id, expires_at)| Due {
                    account_id: id.to_string(),
                    expires_at: *expires_at,
                })
                .collect(),
            sync_cli,
        }
    }

    #[test]
    fn nothing_due_waits_for_the_refresh_window() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + 2 * HOUR)),
        ]);
        assert_eq!(
            decide_now(&store, &mirror(), &["org-a", "org-b"]),
            Decision::WaitUntil(NOW + HOUR - REFRESH_WINDOW_MS)
        );
    }

    #[test]
    fn a_due_inactive_account_triggers_without_cli_sync() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        let expected = trigger(&[("org-b", Some(NOW + MINUTE))], false);
        for cli_state in [
            mirror(),
            CliAuthState::Missing,
            cli("org-a", "newer-than-the-pool"),
        ] {
            assert_eq!(
                decide_now(&store, &cli_state, &["org-a", "org-b"]),
                expected,
                "{cli_state:?}"
            );
        }
    }

    #[test]
    fn a_sync_off_run_never_spends_the_token_auth_json_holds() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        assert_eq!(
            decide_now(&store, &cli("org-b", "refresh-org-b"), &["org-b"]),
            Decision::Blocked(BlockReason::AuthTokenWouldBeSpent)
        );
        let with_unmonitored = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
            account("org-c", Some(NOW - MINUTE)),
        ]);
        assert_eq!(
            decide_now(
                &with_unmonitored,
                &cli("org-c", "refresh-org-c"),
                &["org-b"]
            ),
            Decision::Blocked(BlockReason::AuthTokenWouldBeSpent)
        );
    }

    #[test]
    fn a_due_active_account_needs_the_mirror() {
        let store = pool(vec![
            account("org-a", Some(NOW + MINUTE)),
            account("org-b", Some(NOW + HOUR)),
        ]);
        assert_eq!(
            decide_now(&store, &mirror(), &["org-a"]),
            trigger(&[("org-a", Some(NOW + MINUTE))], true)
        );
        for (cli_state, reason) in [
            (CliAuthState::Missing, BlockReason::AuthMissing),
            (
                cli("org-b", "refresh-org-a"),
                BlockReason::AuthHoldsAnotherAccount,
            ),
            (cli("org-a", "other"), BlockReason::RefreshTokenDiffers),
            (cli("org-a", ""), BlockReason::RefreshTokenDiffers),
        ] {
            assert_eq!(
                decide_now(&store, &cli_state, &["org-a"]),
                Decision::Blocked(reason)
            );
        }
        let mut no_token = account("org-a", Some(NOW + MINUTE));
        no_token["refreshToken"] = json!("");
        let empty = pool(vec![no_token]);
        assert_eq!(
            decide_now(&empty, &cli("org-a", ""), &["org-a"]),
            Decision::Blocked(BlockReason::RefreshTokenDiffers)
        );
    }

    #[test]
    fn the_wrapper_predicate_decides_sync() {
        let sync_for = |active: serde_json::Value| {
            let store = pool(vec![active, account("org-b", Some(NOW + MINUTE))]);
            match decide_now(&store, &mirror(), &["org-b"]) {
                Decision::Trigger { sync_cli, .. } => sync_cli,
                other => panic!("expected a trigger, got {other:?}"),
            }
        };
        assert!(sync_for(account("org-a", Some(NOW + 6 * MINUTE))));
        assert!(!sync_for(account("org-a", Some(NOW + 8 * MINUTE))));
        assert!(sync_for(account("org-a", None)));
        let mut no_access = account("org-a", Some(NOW + HOUR));
        no_access["accessToken"] = json!("");
        assert!(sync_for(no_access));
    }

    #[test]
    fn missing_expiry_or_access_token_is_due() {
        let mut no_access = account("org-b", Some(NOW + HOUR));
        no_access["accessToken"] = json!("");
        for inactive in [account("org-b", None), no_access] {
            let expires_at = inactive["expiresAt"].as_i64();
            let store = pool(vec![account("org-a", Some(NOW + HOUR)), inactive]);
            assert_eq!(
                decide_now(&store, &mirror(), &["org-b"]),
                trigger(&[("org-b", expires_at)], false)
            );
        }
    }

    #[test]
    fn only_monitored_accounts_count() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        assert_eq!(
            decide_now(&store, &mirror(), &["org-a"]),
            Decision::WaitUntil(NOW + HOUR - REFRESH_WINDOW_MS)
        );
    }

    #[test]
    fn an_attempt_backs_off_for_an_hour_per_expiry() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        let attempted = |expires_at: i64, at_ms: i64| {
            let attempts = HashMap::from([(
                "org-b".to_string(),
                Attempt {
                    expires_at: Some(expires_at),
                    at_ms,
                },
            )]);
            decide(
                Some(&store),
                &mirror(),
                true,
                &monitored(&["org-b"]),
                &attempts,
                NOW,
            )
        };
        assert_eq!(
            attempted(NOW + MINUTE, NOW - 10 * MINUTE),
            Decision::WaitUntil(NOW + 50 * MINUTE)
        );
        assert_eq!(
            attempted(NOW + MINUTE, NOW - 61 * MINUTE),
            trigger(&[("org-b", Some(NOW + MINUTE))], false)
        );
        assert_eq!(
            attempted(NOW - HOUR, NOW - MINUTE),
            trigger(&[("org-b", Some(NOW + MINUTE))], false)
        );
    }

    #[test]
    fn a_pending_wrapper_setup_blocks() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        assert_eq!(
            decide(
                Some(&store),
                &mirror(),
                false,
                &monitored(&["org-b"]),
                &HashMap::new(),
                NOW
            ),
            Decision::Blocked(BlockReason::WrapperSetupPending)
        );
    }

    #[test]
    fn the_wrapper_setup_marker_must_be_current() {
        let directory = std::env::temp_dir().join(format!(
            "usage-multi-auth-marker-{}-{}",
            std::process::id(),
            codex::now_ms()
        ));
        std::fs::create_dir(&directory).unwrap();
        let store = directory.join(crate::codex_multi_auth::STORE_FILE_NAME);
        let marker = directory.join(WRAPPER_SETUP_MARKER);
        assert!(!wrapper_setup_done(&store), "no marker yet");
        for (content, done) in [
            (r#"{"version":1}"#, false),
            (r#"{"version":"2"}"#, false),
            ("not json", false),
            (r#"{"version":2,"appBind":"completed"}"#, true),
            (r#"{"version":3}"#, true),
        ] {
            std::fs::write(&marker, content).unwrap();
            assert_eq!(wrapper_setup_done(&store), done, "{content}");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_disabled_pool_account_blocks() {
        let mut disabled = account("org-c", Some(NOW + HOUR));
        disabled["enabled"] = json!(false);
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
            disabled,
        ]);
        assert_eq!(
            decide_now(&store, &mirror(), &["org-b"]),
            Decision::Blocked(BlockReason::DisabledAccountInPool)
        );
    }

    #[test]
    fn an_unreadable_auth_json_blocks() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        assert_eq!(
            decide_now(&store, &CliAuthState::Unreadable, &["org-b"]),
            Decision::Blocked(BlockReason::AuthUnreadable)
        );
    }

    #[test]
    fn the_guard_follows_the_codex_family_index() {
        let store = pool_with(
            vec![
                account("org-a", Some(NOW + HOUR)),
                account("org-b", Some(NOW + MINUTE)),
            ],
            json!({ "activeIndexByFamily": { "codex": 1 } }),
        );
        assert_eq!(
            decide_now(&store, &cli("org-b", "refresh-org-b"), &["org-b"]),
            trigger(&[("org-b", Some(NOW + MINUTE))], true)
        );
        assert_eq!(
            decide_now(&store, &mirror(), &["org-b"]),
            Decision::Blocked(BlockReason::AuthHoldsAnotherAccount)
        );
    }

    #[test]
    fn no_pool_or_no_monitored_accounts_is_idle() {
        let store = pool(vec![account("org-a", Some(NOW - MINUTE))]);
        assert_eq!(
            decide(
                None,
                &mirror(),
                true,
                &monitored(&["org-a"]),
                &HashMap::new(),
                NOW
            ),
            Decision::Idle
        );
        assert_eq!(decide_now(&store, &mirror(), &[]), Decision::Idle);
        assert_eq!(decide_now(&store, &mirror(), &["org-z"]), Decision::Idle);
    }

    fn scheduler(ids: &[&str]) -> RefreshScheduler {
        let mut scheduler = RefreshScheduler::default();
        scheduler.set_monitored(
            monitored(ids),
            Some(PathBuf::from("C:\\pool\\accounts.json")),
        );
        scheduler
    }

    #[test]
    fn a_future_expiry_sleeps_until_the_window_then_spawns() {
        let store = pool(vec![account("org-a", Some(NOW + 20 * MINUTE))]);
        let mut scheduler = scheduler(&["org-a"]);
        assert_eq!(
            scheduler.step(Some(&store), &mirror(), true, NOW),
            Step::Sleep(15 * MINUTE)
        );
        let far = pool(vec![account("org-a", Some(NOW + 10 * HOUR))]);
        assert_eq!(
            scheduler.step(Some(&far), &mirror(), true, NOW),
            Step::Sleep(MAX_WAIT_MS)
        );
        assert_eq!(
            scheduler.step(Some(&store), &mirror(), true, NOW + 15 * MINUTE),
            Step::Spawn {
                store: PathBuf::from("C:\\pool\\accounts.json"),
                sync_cli: true,
                due_count: 1,
            }
        );
    }

    #[test]
    fn no_second_spawn_while_in_flight() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        let mut scheduler = scheduler(&["org-b"]);
        assert!(matches!(
            scheduler.step(Some(&store), &mirror(), true, NOW),
            Step::Spawn { .. }
        ));
        for later in [NOW, NOW + MINUTE, NOW + HOUR] {
            assert_eq!(
                scheduler.step(Some(&store), &mirror(), true, later),
                Step::Sleep(MAX_WAIT_MS)
            );
        }
        scheduler.child_exited();
        assert_eq!(
            scheduler.step(Some(&store), &mirror(), true, NOW + MINUTE),
            Step::Sleep(HOUR - MINUTE),
            "an unchanged expiry waits for the retry backoff"
        );
        let refreshed = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + 20 * MINUTE)),
        ]);
        assert_eq!(
            scheduler.step(Some(&refreshed), &mirror(), true, NOW + MINUTE),
            Step::Sleep(14 * MINUTE),
            "a new expiry is scheduled from its own window"
        );
    }

    #[test]
    fn spawn_failure_backs_off() {
        let store = pool(vec![
            account("org-a", Some(NOW + 2 * HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        let mut scheduler = scheduler(&["org-b"]);
        assert!(matches!(
            scheduler.step(Some(&store), &mirror(), true, NOW),
            Step::Spawn { .. }
        ));
        scheduler.spawn_failed();
        assert_eq!(
            scheduler.step(Some(&store), &mirror(), true, NOW + 1_000),
            Step::Sleep(HOUR - 1_000)
        );
    }

    #[test]
    fn external_changes_bump_the_generation() {
        let mut scheduler = RefreshScheduler::default();
        let mut last = scheduler.generation;
        let mut bumped = |scheduler: &RefreshScheduler| {
            let moved = scheduler.generation != last;
            last = scheduler.generation;
            moved
        };
        scheduler.set_monitored(Vec::new(), None);
        assert!(bumped(&scheduler));
        scheduler.spawn_failed();
        assert!(bumped(&scheduler));
        scheduler.child_exited();
        assert!(bumped(&scheduler));
        scheduler.step(None, &mirror(), true, NOW);
        assert!(!bumped(&scheduler), "the thread's own step does not count");
    }

    #[test]
    fn disabling_codex_stops_triggers() {
        let profiles = ["org-a", "org-b", "org-c"]
            .into_iter()
            .map(|id| AccountProfile {
                id: crate::codex_multi_auth::profile_id(id),
                multi_auth_account: id.into(),
                enabled: id != "org-c",
                ..Default::default()
            })
            .chain([AccountProfile::default()])
            .collect();
        let accounts = ProviderAccounts {
            profiles,
            ..Default::default()
        };
        assert_eq!(
            monitored_accounts(true, &accounts),
            monitored(&["org-a", "org-b"])
        );
        assert!(monitored_accounts(false, &accounts).is_empty());

        let store = pool(vec![account("org-a", Some(NOW - MINUTE))]);
        let mut scheduler = scheduler(&["org-a"]);
        scheduler.set_monitored(monitored_accounts(false, &accounts), None);
        assert_eq!(
            scheduler.step(Some(&store), &mirror(), true, NOW),
            Step::Sleep(MAX_WAIT_MS)
        );
    }

    #[test]
    fn blocked_logs_once_per_reason() {
        let store = pool(vec![
            account("org-a", Some(NOW + HOUR)),
            account("org-b", Some(NOW + MINUTE)),
        ]);
        let mut scheduler = scheduler(&["org-b"]);
        for _ in 0..2 {
            assert_eq!(
                scheduler.step(Some(&store), &CliAuthState::Unreadable, true, NOW),
                Step::Sleep(MAX_WAIT_MS)
            );
            assert_eq!(scheduler.last_block, Some(BlockReason::AuthUnreadable));
        }
        assert!(matches!(
            scheduler.step(Some(&store), &mirror(), true, NOW),
            Step::Spawn { .. }
        ));
        assert_eq!(scheduler.last_block, None);
    }
}
