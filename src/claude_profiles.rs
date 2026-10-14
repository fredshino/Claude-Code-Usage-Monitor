//! Claude Code profiles found in the home folder (`~/.claude-<name>`, each its own
//! `CLAUDE_CONFIG_DIR`). Settings carry the folder and a display name only; the poller reads
//! `<folder>/.credentials.json` like any profile with a config directory.
//!
//! Discovery is read-only. Nothing here writes into a profile folder, and an expired token is
//! refreshed by Claude Code itself (`claude -p .` under that `CLAUDE_CONFIG_DIR`), so Claude
//! Code stays the only token writer. The email that names a profile comes from the folder's
//! `.claude.json`; it is shown in the menu and the dashboard and never reaches a log.
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::accounts::{fingerprint, source_key, AccountProfile, ProviderAccounts};
use crate::providers::ProviderId;

pub const PROFILE_ID_PREFIX: &str = "claude_cd_";
const DIR_PREFIX: &str = ".claude-";
const CREDENTIALS_FILE_NAME: &str = ".credentials.json";
const CONFIG_FILE_NAME: &str = ".claude.json";

/// A `~/.claude-<name>` folder that holds a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundProfile {
    pub dir_name: String,
    pub dir: PathBuf,
    pub credentials: PathBuf,
}

/// None when the scan could not run (no home directory, or read_dir on it failed): the
/// caller must then skip the sync, so a transient failure never drops a profile.
pub fn discover() -> Option<Vec<FoundProfile>> {
    discover_in(&dirs::home_dir()?)
}

/// Every `.claude-<name>` directory directly under `home` that contains a regular
/// `.credentials.json`, sorted by lower-cased folder name. Entries that cannot be read are
/// skipped; only a failure to list `home` itself returns None.
pub fn discover_in(home: &Path) -> Option<Vec<FoundProfile>> {
    let entries = std::fs::read_dir(home).ok()?;
    let mut found: Vec<FoundProfile> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let dir_name = entry.file_name().to_str()?.to_string();
            let named = dir_name
                .to_lowercase()
                .strip_prefix(DIR_PREFIX)
                .is_some_and(|rest| !rest.is_empty());
            if !named {
                return None;
            }
            let dir = home.join(&dir_name);
            // `metadata` follows links, so a junctioned profile folder counts too.
            if !std::fs::metadata(&dir).is_ok_and(|metadata| metadata.is_dir()) {
                return None;
            }
            let credentials = dir.join(CREDENTIALS_FILE_NAME);
            if !std::fs::metadata(&credentials).is_ok_and(|metadata| metadata.is_file()) {
                return None;
            }
            Some(FoundProfile {
                dir_name,
                dir,
                credentials,
            })
        })
        .collect();
    found.sort_by_cached_key(|profile| profile.dir_name.to_lowercase());
    Some(found)
}

/// Stable profile id for a profile folder. It carries a hash rather than the folder name,
/// so theme bindings stay free of identifiers.
pub fn profile_id(dir_name: &str) -> String {
    format!(
        "{PROFILE_ID_PREFIX}{}",
        &fingerprint(&dir_name.to_lowercase())[..8]
    )
}

/// `oauthAccount.emailAddress` from a Claude Code `.claude.json`, trimmed; None when the file
/// is missing, unreadable, not JSON, or carries no email.
pub fn email_in(config_json: &Path) -> Option<String> {
    let content = std::fs::read_to_string(config_json).ok()?;
    let value: Value = serde_json::from_str(&content).ok()?;
    let email = value
        .get("oauthAccount")?
        .get("emailAddress")?
        .as_str()?
        .trim();
    (!email.is_empty()).then(|| email.to_string())
}

/// The `.claude.json` that belongs to the default profile: inside `CLAUDE_CONFIG_DIR` when it
/// is set (Claude Code then keeps its global config there), else `~/.claude.json`.
pub fn default_config_json() -> Option<PathBuf> {
    crate::accounts::environment_directory(ProviderId::Claude)
        .map(|directory| directory.join(CONFIG_FILE_NAME))
        .or_else(|| dirs::home_dir().map(|home| home.join(CONFIG_FILE_NAME)))
}

/// What the default profile reads, passed in so `sync_profiles` stays free of environment
/// and home-folder lookups.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultSource<'a> {
    /// The credentials file the default profile resolves to.
    pub credentials: Option<&'a Path>,
    /// The `.claude.json` that names the default profile's account.
    pub config_json: Option<&'a Path>,
}

fn is_unnamed_default(profile: &AccountProfile) -> bool {
    profile.id == "default"
        && profile.config_dir.trim().is_empty()
        && profile.credentials_path.trim().is_empty()
        && profile.name == "Default"
}

/// True while the default profile would take its email at the next sync: some profile was
/// discovered and the default still carries its built-in name. Callers can use it to avoid
/// re-reading a `.claude.json` that held no email.
pub fn default_awaits_email(accounts: &ProviderAccounts) -> bool {
    accounts
        .profiles
        .iter()
        .any(|profile| profile.auto_discovered)
        && accounts.profiles.iter().any(is_unnamed_default)
}

/// Mirror the discovered folders into the Claude account profiles: one profile per folder
/// that no existing profile already reads, removed again when the folder loses its login.
/// Returns true when the settings changed and should be saved.
///
/// Once a second account is listed, the default profile takes its email as its name, but
/// only while it is still called `Default`. The selection never moves, except when the
/// selected profile itself is removed.
pub fn sync_profiles(
    accounts: &mut ProviderAccounts,
    found: &[FoundProfile],
    default: &DefaultSource,
) -> bool {
    let mut changed = false;
    let before = accounts.profiles.len();
    accounts.profiles.retain(|profile| {
        !profile.auto_discovered
            || found.iter().any(|found| {
                found.dir.to_string_lossy().to_lowercase() == profile.config_dir.to_lowercase()
            })
    });
    changed |= accounts.profiles.len() != before;
    for found in found {
        let key = source_key(&found.credentials);
        let represented = accounts.profiles.iter().any(|profile| {
            match profile.credential_path(ProviderId::Claude) {
                Ok(Some(path)) => source_key(&path) == key,
                // Only an unconfigured default profile resolves to no path of its own.
                Ok(None) => default
                    .credentials
                    .is_some_and(|path| source_key(path) == key),
                Err(_) => false,
            }
        });
        if represented {
            continue;
        }
        let id = profile_id(&found.dir_name);
        accounts.used_ids.insert(id.clone());
        let name = email_in(&found.dir.join(CONFIG_FILE_NAME)).unwrap_or_else(|| {
            found
                .dir_name
                .strip_prefix('.')
                .unwrap_or(&found.dir_name)
                .to_string()
        });
        accounts.profiles.push(AccountProfile {
            id,
            name,
            config_dir: found.dir.to_string_lossy().into_owned(),
            auto_discovered: true,
            enabled: true,
            ..Default::default()
        });
        changed = true;
    }
    // Checked before reading the file, so the large `~/.claude.json` is parsed only while a
    // rename is still pending.
    if default_awaits_email(accounts) {
        if let Some(email) = default.config_json.and_then(email_in) {
            if let Some(profile) = accounts.profiles.iter_mut().find(|p| is_unnamed_default(p)) {
                profile.name = email;
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
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A scratch home folder under the system temp directory, removed on drop.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "claude-profiles-test-{tag}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// A profile folder, optionally logged in and optionally carrying an email.
        fn profile(&self, name: &str, logged_in: bool, email: Option<&str>) -> PathBuf {
            let dir = self.0.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if logged_in {
                std::fs::write(dir.join(CREDENTIALS_FILE_NAME), "{}").unwrap();
            }
            if let Some(email) = email {
                write_config(&dir.join(CONFIG_FILE_NAME), email);
            }
            dir
        }

        fn found(&self) -> Vec<FoundProfile> {
            discover_in(&self.0).expect("the temp home lists")
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_config(path: &Path, email: &str) {
        let json = serde_json::json!({
            "numStartups": 3,
            "oauthAccount": {"emailAddress": email, "accountUuid": "x"},
        });
        std::fs::write(path, json.to_string()).unwrap();
    }

    fn names(found: &[FoundProfile]) -> Vec<&str> {
        found
            .iter()
            .map(|profile| profile.dir_name.as_str())
            .collect()
    }

    #[test]
    fn discovery_needs_a_logged_in_claude_dash_directory() {
        let home = TempHome::new("discover");
        home.profile(".claude-work", true, None);
        home.profile(".Claude-Alt", true, None);
        home.profile(".claude-empty", false, None);
        home.profile(".claude", true, None);
        home.profile(".claude-", true, None);
        home.profile("claude-nodot", true, None);
        std::fs::write(home.0.join(".claude-file"), "{}").unwrap();
        let odd = home.profile(".claude-odd", false, None);
        std::fs::create_dir_all(odd.join(CREDENTIALS_FILE_NAME)).unwrap();
        let found = home.found();
        assert_eq!(names(&found), vec![".Claude-Alt", ".claude-work"]);
        assert_eq!(found[1].dir, home.0.join(".claude-work"));
        assert_eq!(
            found[1].credentials,
            home.0.join(".claude-work").join(CREDENTIALS_FILE_NAME)
        );
    }

    #[test]
    fn a_scan_that_cannot_run_returns_none() {
        let home = TempHome::new("missing");
        assert!(discover_in(&home.0.join("absent")).is_none());
        let file = home.0.join("plain-file");
        std::fs::write(&file, "x").unwrap();
        assert!(discover_in(&file).is_none());
        assert_eq!(discover_in(&home.0), Some(Vec::new()));
    }

    #[test]
    fn ids_are_stable_hashes_of_the_folder_name() {
        let id = profile_id(".claude-hotmail");
        assert!(id.starts_with(PROFILE_ID_PREFIX));
        let hash = &id[PROFILE_ID_PREFIX.len()..];
        assert_eq!(hash.len(), 8);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, profile_id(".Claude-Hotmail"));
        assert_ne!(id, profile_id(".claude-work"));
        assert!(!id.contains("hotmail"));
    }

    #[test]
    fn profiles_are_added_once_and_named_by_email() {
        let home = TempHome::new("add");
        let hotmail = home.profile(".claude-hotmail", true, Some(" second@example.com "));
        let broken = home.profile(".claude-broken", true, None);
        std::fs::write(broken.join(CONFIG_FILE_NAME), "{not json").unwrap();
        home.profile(".claude-bare", true, None);
        let mut accounts = ProviderAccounts::default();
        let found = home.found();
        assert!(sync_profiles(
            &mut accounts,
            &found,
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 4);
        assert_eq!(accounts.selected, "default");
        let added = |dir_name: &str| {
            accounts
                .profiles
                .iter()
                .find(|profile| profile.id == profile_id(dir_name))
                .unwrap_or_else(|| panic!("{dir_name} was added"))
                .clone()
        };
        let profile = added(".claude-hotmail");
        assert_eq!(profile.name, "second@example.com");
        assert_eq!(profile.config_dir, hotmail.to_string_lossy());
        assert!(Path::new(&profile.config_dir).is_absolute());
        assert!(profile.auto_discovered && profile.enabled);
        assert!(profile.credentials_path.is_empty());
        assert_eq!(
            profile.credential_path(ProviderId::Claude).unwrap(),
            Some(hotmail.join(CREDENTIALS_FILE_NAME))
        );
        assert_eq!(added(".claude-broken").name, "claude-broken");
        assert_eq!(added(".claude-bare").name, "claude-bare");
        for dir_name in [".claude-hotmail", ".claude-broken", ".claude-bare"] {
            assert!(accounts.used_ids.contains(&profile_id(dir_name)));
        }
        // A second pass is a no-op, and a profile switched off stays off.
        accounts
            .profiles
            .iter_mut()
            .find(|profile| profile.id == profile_id(".claude-bare"))
            .unwrap()
            .enabled = false;
        accounts.normalize();
        let snapshot = accounts.clone();
        assert!(!sync_profiles(
            &mut accounts,
            &found,
            &DefaultSource::default()
        ));
        assert_eq!(accounts, snapshot);
    }

    #[test]
    fn the_default_takes_its_email_only_while_it_is_called_default() {
        let home = TempHome::new("rename");
        home.profile(".claude-hotmail", true, Some("second@example.com"));
        let primary = home.0.join(CONFIG_FILE_NAME);
        write_config(&primary, "first@example.com");
        let source = DefaultSource {
            credentials: None,
            config_json: Some(&primary),
        };
        // Nothing discovered: the default keeps its name.
        let mut accounts = ProviderAccounts::default();
        assert!(!sync_profiles(&mut accounts, &[], &source));
        assert_eq!(accounts.profiles[0].name, "Default");
        // A second account appears: the default takes the primary's email.
        let found = home.found();
        assert!(sync_profiles(&mut accounts, &found, &source));
        assert_eq!(accounts.profiles[0].name, "first@example.com");
        assert_eq!(accounts.selected, "default");
        assert!(!default_awaits_email(&accounts));
        assert!(!sync_profiles(&mut accounts, &found, &source));
        // A name the owner chose is never replaced.
        let mut accounts = ProviderAccounts::default();
        accounts.profiles[0].name = "Gmail".into();
        assert!(sync_profiles(&mut accounts, &found, &source));
        assert_eq!(accounts.profiles[0].name, "Gmail");
        // Without a readable email the default stays `Default`.
        let mut accounts = ProviderAccounts::default();
        assert!(sync_profiles(
            &mut accounts,
            &found,
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles[0].name, "Default");
        assert!(default_awaits_email(&accounts));
    }

    #[test]
    fn a_folder_another_profile_already_reads_is_not_added_again() {
        let home = TempHome::new("dedup");
        let dir = home.profile(".claude-hotmail", true, Some("second@example.com"));
        let found = home.found();
        // A profile made by hand for the same folder, spelled in another case.
        let mut accounts = ProviderAccounts::default();
        accounts.profiles.push(AccountProfile {
            id: "account_1".into(),
            name: "Hotmail".into(),
            config_dir: dir.to_string_lossy().to_uppercase(),
            ..Default::default()
        });
        accounts.normalize();
        assert!(!sync_profiles(
            &mut accounts,
            &found,
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 2);
        // A hand-made profile pointing at the credentials file itself.
        let mut accounts = ProviderAccounts::default();
        accounts.profiles.push(AccountProfile {
            id: "account_1".into(),
            credentials_path: found[0].credentials.to_string_lossy().into_owned(),
            ..Default::default()
        });
        assert!(!sync_profiles(
            &mut accounts,
            &found,
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 2);
        // The monitor runs with CLAUDE_CONFIG_DIR at that folder.
        let mut accounts = ProviderAccounts::default();
        let source = DefaultSource {
            credentials: Some(&found[0].credentials),
            config_json: None,
        };
        assert!(!sync_profiles(&mut accounts, &found, &source));
        assert_eq!(accounts.profiles.len(), 1);
        // A default profile given an explicit config directory reads that folder, whatever
        // the default credentials resolve to.
        let mut accounts = ProviderAccounts::default();
        accounts.profiles[0].config_dir = dir.to_string_lossy().into_owned();
        let elsewhere = home.0.join(".claude").join(CREDENTIALS_FILE_NAME);
        let source = DefaultSource {
            credentials: Some(&elsewhere),
            config_json: None,
        };
        assert!(!sync_profiles(&mut accounts, &found, &source));
        assert_eq!(accounts.profiles.len(), 1);
    }

    #[test]
    fn a_folder_that_loses_its_login_drops_its_profile_and_keeps_the_id() {
        let home = TempHome::new("remove");
        let hotmail = home.profile(".claude-hotmail", true, Some("second@example.com"));
        let work = home.profile(".claude-work", true, Some("third@example.com"));
        let mut accounts = ProviderAccounts::default();
        assert!(sync_profiles(
            &mut accounts,
            &home.found(),
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 3);
        accounts.selected = profile_id(".claude-hotmail");
        // Logging out removes the credentials file.
        std::fs::remove_file(hotmail.join(CREDENTIALS_FILE_NAME)).unwrap();
        assert!(sync_profiles(
            &mut accounts,
            &home.found(),
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 2);
        assert!(accounts.used_ids.contains(&profile_id(".claude-hotmail")));
        assert_eq!(accounts.selected, "default");
        // Deleting the folder removes the other one.
        std::fs::remove_dir_all(&work).unwrap();
        assert!(sync_profiles(
            &mut accounts,
            &home.found(),
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 1);
        assert!(accounts.used_ids.contains(&profile_id(".claude-work")));
        // A login that comes back reuses the reserved id, so theme bindings follow it.
        std::fs::write(hotmail.join(CREDENTIALS_FILE_NAME), "{}").unwrap();
        assert!(sync_profiles(
            &mut accounts,
            &home.found(),
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles[1].id, profile_id(".claude-hotmail"));
        // Hand-made profiles are never removed by a sync.
        let mut accounts = ProviderAccounts::default();
        accounts.add();
        assert!(!sync_profiles(
            &mut accounts,
            &[],
            &DefaultSource::default()
        ));
        assert_eq!(accounts.profiles.len(), 2);
    }
}
