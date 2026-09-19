//! Accounts saved by the `codex-multi-auth` CLI wrapper.
//!
//! The wrapper keeps every logged-in ChatGPT account, tokens included, in one
//! pool file under the Codex home directory and copies whichever one is active
//! into `auth.json`. The monitor treats that pool as a read-only credential
//! source: settings carry account ids and display names only, and the poller
//! reads a token straight from the pool at request time. Token refresh stays
//! with the wrapper, which rotates refresh tokens; a second writer would
//! invalidate its copy.
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::accounts::{fingerprint, AccountProfile, ProviderAccounts};
use crate::providers::ProviderId;

pub const STORE_FILE_NAME: &str = "openai-codex-accounts.json";
/// Menu action value meaning "show whichever account the Codex CLI is using".
pub const FOLLOW_ACTIVE: &str = "*";
const PROFILE_ID_PREFIX: &str = "codex_ma_";

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Store {
    pub accounts: Vec<StoreAccount>,
    pub active_index: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StoreAccount {
    pub account_id: String,
    pub email: String,
    pub account_label: String,
    /// Read by the poller only; never copied into settings or logs.
    pub access_token: String,
    pub enabled: Option<bool>,
}

impl StoreAccount {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn display_name(&self) -> String {
        [&self.email, &self.account_label, &self.account_id]
            .into_iter()
            .map(|value| value.trim())
            .find(|value| !value.is_empty())
            .unwrap_or("Codex account")
            .to_string()
    }
}

impl Store {
    pub fn active(&self) -> Option<&StoreAccount> {
        self.active_index.and_then(|index| self.accounts.get(index))
    }

    pub fn find(&self, account_id: &str) -> Option<&StoreAccount> {
        self.accounts
            .iter()
            .find(|account| account.account_id == account_id)
    }
}

pub fn store_path() -> Option<PathBuf> {
    let home = crate::accounts::environment_directory(ProviderId::Codex)
        .or_else(|| dirs::home_dir().map(|home| home.join(".codex")))?;
    Some(home.join("multi-auth").join(STORE_FILE_NAME))
}

/// The pool, or None when the wrapper is not installed or the file is unreadable.
pub fn load_store() -> Option<Store> {
    read_store(&store_path()?)
}

pub fn read_store(path: &Path) -> Option<Store> {
    let content = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&content) {
        Ok(store) => Some(store),
        Err(error) => {
            crate::diagnose::log(format!(
                "unable to parse codex-multi-auth accounts at {}: {error}",
                path.display()
            ));
            None
        }
    }
}

/// Stable profile id for a pool account. It carries a hash rather than the
/// organisation id itself, so theme bindings stay free of identifiers.
pub fn profile_id(account_id: &str) -> String {
    format!("{PROFILE_ID_PREFIX}{}", &fingerprint(account_id)[..8])
}

pub fn has_pool_profiles(accounts: &ProviderAccounts) -> bool {
    accounts.profiles.iter().any(AccountProfile::is_multi_auth)
}

/// Mirror the pool into the Codex account profiles: one profile per pool
/// account, removed again when the wrapper forgets the account. Returns true
/// when the settings changed and should be saved.
///
/// The first time a pool is seen, the default profile is switched off (it
/// reads `auth.json`, which the wrapper keeps equal to the active account, so
/// it would only duplicate a pool entry) and the widget starts following the
/// wrapper's active account. Both are ordinary settings afterwards.
pub fn sync_profiles(accounts: &mut ProviderAccounts, store: Option<&Store>) -> bool {
    let Some(store) = store else {
        return false;
    };
    let pool: Vec<&StoreAccount> = store
        .accounts
        .iter()
        .filter(|account| !account.account_id.trim().is_empty())
        .collect();
    let mut changed = false;
    let before = accounts.profiles.len();
    accounts.profiles.retain(|profile| {
        !profile.is_multi_auth()
            || pool
                .iter()
                .any(|account| account.account_id == profile.multi_auth_account)
    });
    changed |= accounts.profiles.len() != before;
    let first_discovery = !has_pool_profiles(accounts) && !pool.is_empty();
    for account in &pool {
        if accounts
            .profiles
            .iter()
            .any(|profile| profile.multi_auth_account == account.account_id)
        {
            continue;
        }
        let id = profile_id(&account.account_id);
        accounts.used_ids.insert(id.clone());
        accounts.profiles.push(AccountProfile {
            id,
            name: account.display_name(),
            multi_auth_account: account.account_id.clone(),
            enabled: account.is_enabled(),
            ..Default::default()
        });
        changed = true;
    }
    if first_discovery {
        for profile in &mut accounts.profiles {
            if profile.id == "default"
                && profile.config_dir.trim().is_empty()
                && profile.credentials_path.trim().is_empty()
            {
                profile.enabled = false;
            }
        }
        accounts.follow_multi_auth = true;
        changed = true;
    }
    if accounts.follow_multi_auth {
        if let Some(active) = store.active() {
            let id = profile_id(&active.account_id);
            if accounts.selected != id
                && accounts
                    .profiles
                    .iter()
                    .any(|profile| profile.id == id && profile.enabled)
            {
                accounts.selected = id;
                changed = true;
            }
        }
    }
    if changed {
        accounts.normalize();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(json: &str) -> Store {
        serde_json::from_str(json).expect("fixture should parse")
    }

    const TWO_ACCOUNTS: &str = r#"{
        "version": 3,
        "accounts": [
            {"accountId": "org-first", "email": "first@example.com", "accessToken": "t1", "enabled": true, "workspaces": []},
            {"accountId": "org-second", "email": "second@example.com", "accessToken": "t2", "enabled": true}
        ],
        "activeIndex": 1,
        "activeIndexByFamily": {"codex": 1}
    }"#;

    #[test]
    fn the_pool_parses_with_unknown_fields_and_missing_flags() {
        let pool = store(TWO_ACCOUNTS);
        assert_eq!(pool.accounts.len(), 2);
        assert_eq!(pool.active().unwrap().email, "second@example.com");
        assert!(pool.find("org-first").unwrap().is_enabled());
        let bare = store(r#"{"accounts":[{"accountId":"org-x"}]}"#);
        assert!(bare.accounts[0].is_enabled());
        assert_eq!(bare.accounts[0].display_name(), "org-x");
        assert!(bare.active().is_none());
    }

    #[test]
    fn first_discovery_mirrors_the_pool_and_follows_the_active_account() {
        let mut accounts = ProviderAccounts::default();
        assert!(sync_profiles(&mut accounts, Some(&store(TWO_ACCOUNTS))));
        assert_eq!(accounts.profiles.len(), 3);
        assert!(
            !accounts.profiles[0].enabled,
            "default duplicates the active account"
        );
        assert_eq!(accounts.profiles[1].name, "first@example.com");
        assert_eq!(accounts.profiles[1].multi_auth_account, "org-first");
        assert!(accounts.follow_multi_auth);
        assert_eq!(accounts.selected, profile_id("org-second"));
        assert_eq!(accounts.selected().unwrap().name, "second@example.com");
        // Ids are safe for theme bindings and never repeat the organisation id.
        assert!(accounts
            .selected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        assert!(!accounts.selected.contains("org-second"));
        // A second pass with the same pool is a no-op.
        let snapshot = accounts.clone();
        assert!(!sync_profiles(&mut accounts, Some(&store(TWO_ACCOUNTS))));
        assert_eq!(accounts, snapshot);
        // Without a pool nothing is touched.
        assert!(!sync_profiles(&mut accounts, None));
    }

    #[test]
    fn a_pinned_account_ignores_cli_switches_until_follow_is_turned_back_on() {
        let mut accounts = ProviderAccounts::default();
        sync_profiles(&mut accounts, Some(&store(TWO_ACCOUNTS)));
        accounts.follow_multi_auth = false;
        accounts.selected = profile_id("org-first");
        let switched = store(&TWO_ACCOUNTS.replace("\"activeIndex\": 1", "\"activeIndex\": 0"));
        assert!(!sync_profiles(&mut accounts, Some(&switched)));
        assert_eq!(accounts.selected, profile_id("org-first"));
        accounts.follow_multi_auth = true;
        assert!(!sync_profiles(&mut accounts, Some(&switched)));
        let back = store(TWO_ACCOUNTS);
        assert!(sync_profiles(&mut accounts, Some(&back)));
        assert_eq!(accounts.selected, profile_id("org-second"));
    }

    #[test]
    fn accounts_removed_from_the_pool_drop_their_profiles() {
        let mut accounts = ProviderAccounts::default();
        sync_profiles(&mut accounts, Some(&store(TWO_ACCOUNTS)));
        let only_first = store(
            r#"{"accounts":[{"accountId":"org-first","email":"first@example.com","accessToken":"t1"}],"activeIndex":0}"#,
        );
        assert!(sync_profiles(&mut accounts, Some(&only_first)));
        assert_eq!(accounts.profiles.len(), 2);
        assert_eq!(accounts.selected, profile_id("org-first"));
        // The retired id stays reserved so a theme binding never jumps accounts.
        assert!(accounts.used_ids.contains(&profile_id("org-second")));
    }
}
