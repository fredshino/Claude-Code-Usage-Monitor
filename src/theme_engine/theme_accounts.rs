//! Account bindings. Every monitored account is reachable by its profile id
//! (`accounts.<provider>.<id>.*`) and, for an enabled provider, by its 1-based
//! position in the account settings (`accounts.<provider>.<n>.*`), next to
//! `accounts.<provider>.count`. Positions let a built-in theme lay out several
//! accounts without knowing their ids; `ProviderAccounts::normalize` never
//! keeps an all-digit profile id, so the two names cannot collide.
use super::*;
use crate::models::AccountUsage;

const ACCOUNT_PROVIDERS: [ProviderId; 2] = [ProviderId::Claude, ProviderId::Codex];

impl DataContext {
    pub(super) fn insert_accounts(&mut self, data: Option<&AppUsageData>, runtime: ThemeRuntime) {
        for provider in ACCOUNT_PROVIDERS {
            let key = provider.descriptor().key;
            let accounts: Vec<&AccountUsage> = data
                .map(|data| {
                    data.accounts
                        .iter()
                        .filter(|account| account.provider == provider)
                        .collect()
                })
                .unwrap_or_default();
            let names: Vec<&str> = accounts
                .iter()
                .map(|account| account.profile.name.as_str())
                .collect();
            let labels = short_labels(&names);
            for (account, label) in accounts.iter().zip(&labels) {
                self.insert_account(
                    &format!("accounts.{key}.{}", account.profile.id),
                    account,
                    label,
                    runtime.countdown,
                );
            }
            let shown = if runtime.provider_enabled(provider) {
                accounts.len()
            } else {
                0
            };
            self.insert(&format!("accounts.{key}.count"), shown as f64);
            for (index, (account, label)) in accounts.iter().zip(&labels).take(shown).enumerate() {
                self.insert_account(
                    &format!("accounts.{key}.{}", index + 1),
                    account,
                    label,
                    runtime.countdown,
                );
            }
        }
    }

    fn insert_account(&mut self, key: &str, account: &AccountUsage, label: &str, countdown: bool) {
        self.insert_string(&format!("{key}.name"), &account.profile.name);
        self.insert_string(&format!("{key}.label"), label);
        self.insert(&format!("{key}.selected"), account.selected as u8 as f64);
        self.insert(
            &format!("{key}.has_error"),
            account.error.is_some() as u8 as f64,
        );
        self.insert_provider(
            key,
            account.usage.as_ref(),
            account.provider == ProviderId::Codex,
            countdown,
        );
    }
}

/// Short names that tell one provider's accounts apart at a glance, in the
/// order given. A name that is not an email address was chosen by the user and
/// is kept as it is. Email addresses become the first label of their domain
/// ("gmail") when that alone tells them apart, else the part before the @,
/// else the whole address.
pub(super) fn short_labels(names: &[&str]) -> Vec<String> {
    let emails: Vec<Option<[&str; 2]>> = names.iter().map(|name| email_parts(name)).collect();
    let distinct = |part: usize| {
        let mut seen = std::collections::HashSet::new();
        emails
            .iter()
            .flatten()
            .all(|email| seen.insert(email[part].to_lowercase()))
    };
    // Part 1 is the first domain label, part 0 what comes before the @.
    let Some(part) = [1, 0].into_iter().find(|&part| distinct(part)) else {
        return names.iter().map(|name| name.trim().to_string()).collect();
    };
    names
        .iter()
        .zip(&emails)
        .map(|(name, email)| email.map_or(name.trim(), |email| email[part]).to_string())
        .collect()
}

/// `[local part, first domain label]` of a plain email address.
fn email_parts(name: &str) -> Option<[&str; 2]> {
    let (local, domain) = name.trim().split_once('@')?;
    let head = domain.split('.').next()?;
    let plain = |part: &str| !part.is_empty() && !part.contains(char::is_whitespace);
    (plain(local) && plain(head) && !domain.contains('@')).then_some([local, head])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountProfile, AccountSettings, ProviderAccounts};
    use crate::models::{UsageData, UsageLimit, UsageSection};

    fn section(percentage: f64) -> UsageSection {
        UsageSection {
            available: true,
            percentage,
            resets_at: None,
        }
    }

    fn usage(session: f64, weekly: f64, fable: Option<f64>) -> UsageData {
        UsageData {
            session: section(session),
            weekly: section(weekly),
            limits: fable
                .map(|percentage| UsageLimit {
                    key: "weekly_scoped_fable".into(),
                    kind: "weekly_scoped".into(),
                    label: "Fable".into(),
                    model: Some("Fable".into()),
                    is_active: true,
                    usage: section(percentage),
                    ..Default::default()
                })
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    fn profile(id: &str, name: &str) -> AccountProfile {
        AccountProfile {
            id: id.into(),
            name: name.into(),
            ..Default::default()
        }
    }

    /// Claude accounts as `(id, name, usage)` in settings order, the first one
    /// selected, plus the default Codex account. No usage means a login error.
    fn data(claude: &[(&str, &str, Option<UsageData>)]) -> AppUsageData {
        let mut data = AppUsageData::default();
        for (provider, profile, usage) in claude
            .iter()
            .map(|(id, name, usage)| (ProviderId::Claude, profile(id, name), usage.clone()))
            .chain([(
                ProviderId::Codex,
                AccountProfile::default(),
                Some(usage(22.0, 18.0, None)),
            )])
        {
            data.accounts.push(AccountUsage {
                provider,
                profile,
                source_signature: String::new(),
                source_path: None,
                error: usage
                    .is_none()
                    .then_some(crate::poller::PollError::TokenExpired),
                usage,
                selected: false,
            });
        }
        data.select_accounts(&AccountSettings {
            claude: ProviderAccounts {
                profiles: claude
                    .iter()
                    .map(|(id, name, _)| profile(id, name))
                    .collect(),
                selected: claude[0].0.into(),
                ..Default::default()
            },
            ..Default::default()
        });
        data
    }

    fn two_accounts() -> AppUsageData {
        data(&[
            (
                "default",
                "fred@gmail.com",
                Some(usage(11.0, 33.0, Some(50.0))),
            ),
            (
                "claude_cd_a",
                "fred@hotmail.com",
                Some(usage(64.0, 87.0, Some(8.0))),
            ),
        ])
    }

    fn context(data: Option<&AppUsageData>, runtime: ThemeRuntime) -> DataContext {
        DataContext::from_usage_with_runtime(data, &Canvas::default(), runtime)
    }

    #[test]
    fn positions_follow_settings_and_count_only_an_enabled_provider() {
        let data = two_accounts();
        let enabled = context(Some(&data), ThemeRuntime::new(true, true, false));
        assert_eq!(enabled.get("accounts.claude.count"), Some(2.0));
        assert_eq!(enabled.get("accounts.codex.count"), Some(1.0));
        assert_eq!(enabled.get_string("accounts.claude.1.label"), Some("gmail"));
        assert_eq!(
            enabled.get_string("accounts.claude.2.label"),
            Some("hotmail")
        );
        assert_eq!(
            enabled.get_string("accounts.claude.claude_cd_a.label"),
            Some("hotmail")
        );
        assert_eq!(enabled.get("accounts.claude.1.selected"), Some(1.0));
        assert_eq!(
            enabled.get("accounts.claude.2.session.percentage"),
            Some(64.0)
        );
        assert_eq!(
            enabled.get("accounts.claude.2.model.fable.percentage"),
            Some(8.0)
        );

        let disabled = context(Some(&data), ThemeRuntime::new(false, true, false));
        assert_eq!(disabled.get("accounts.claude.count"), Some(0.0));
        // Positions fall back to typed defaults; ids stay bound.
        assert_eq!(
            disabled.get("accounts.claude.2.session.percentage"),
            Some(0.0)
        );
        assert_eq!(disabled.get_string("accounts.claude.2.label"), Some(""));
        assert_eq!(
            disabled.get("accounts.claude.claude_cd_a.session.percentage"),
            Some(64.0)
        );

        let empty = context(None, ThemeRuntime::new(true, true, false));
        assert_eq!(empty.get("accounts.claude.count"), Some(0.0));
        assert_eq!(empty.get_string("accounts.claude.1.label"), Some(""));
    }

    #[test]
    fn classic_gives_each_claude_account_its_own_labelled_card() {
        let theme = ThemeDocument::starter();
        let surface = &theme.surfaces[0];
        let runtime = ThemeRuntime::new(true, true, false);
        let index = |id: &str| {
            surface
                .children
                .iter()
                .position(|object| object.id == id)
                .unwrap()
        };
        let bounds = |data: &AppUsageData, id: &str| {
            resolve_object_bounds_with_runtime(&theme, 0, index(id), Some(data), runtime)
        };

        let single = data(&[(
            "default",
            "fred@gmail.com",
            Some(usage(11.0, 33.0, Some(50.0))),
        )]);
        assert_eq!(
            resolve_surface_size(&theme, 0, Some(&single), runtime),
            (378, 46)
        );
        assert!(bounds(&single, "claude-account-1").is_none());
        assert!(bounds(&single, "claude-provider").is_some());
        assert!(bounds(&single, "fable-provider").is_some());

        let two = two_accounts();
        let (width, height) = resolve_surface_size(&theme, 0, Some(&two), runtime);
        assert_eq!((width, height), (756, 46));
        assert!(bounds(&two, "claude-provider").is_none());
        assert!(bounds(&two, "fable-provider").is_none());
        assert!(bounds(&two, "claude-account-3").is_none());
        let codex = bounds(&two, "codex-provider").unwrap();
        let canvas = Canvas {
            width,
            height,
            ..Default::default()
        };
        let mut context = DataContext::from_usage_with_runtime(Some(&two), &canvas, runtime);
        let mut previous_right = 0.0;
        for (n, label, session, fable) in [
            (1, "gmail", "11%", "Fable 50%"),
            (2, "hotmail", "64%", "Fable 8%"),
        ] {
            let group = format!("claude-account-{n}");
            let card = bounds(&two, &group).unwrap();
            assert!(
                card.0 >= previous_right && card.0 + card.2 <= codex.0,
                "{group}"
            );
            previous_right = card.0 + card.2;
            for dark in [false, true] {
                context.insert("system.dark", dark as u8 as f64);
                let mut texts = Vec::new();
                for (object_index, object) in surface.children.iter().enumerate() {
                    if object.parent.as_deref() != Some(group.as_str())
                        || evaluate(&object.render.0, &context).unwrap() == 0.0
                    {
                        continue;
                    }
                    if let SceneContent::Text { template, .. } = &object.content {
                        texts.push(format_template(template, &context));
                    }
                    // Bounds follow the system mode, which only one twin matches;
                    // dark and light twins share their geometry.
                    if let Some((x, y, w, h)) = resolve_object_bounds_with_runtime(
                        &theme,
                        0,
                        object_index,
                        Some(&two),
                        runtime,
                    ) {
                        assert!(
                            x >= card.0 && x + w <= card.0 + card.2 && y >= 0.0 && y + h <= 46.0,
                            "{}",
                            object.id
                        );
                    }
                }
                assert_eq!(texts.first().map(String::as_str), Some(label));
                assert!(texts.iter().any(|text| text == session), "{texts:?}");
                assert!(texts.iter().any(|text| text == fable), "{texts:?}");
            }
        }
        let rendered = render_theme_surface_with_runtime(&theme, 0, Some(&two), runtime);
        assert!(rendered.warnings.is_empty(), "{:?}", rendered.warnings);

        // A third account gets a third card. An account in error keeps its card
        // and drops the Fable column it can no longer report.
        let three = data(&[
            (
                "default",
                "fred@gmail.com",
                Some(usage(11.0, 33.0, Some(50.0))),
            ),
            ("claude_cd_a", "fred@hotmail.com", None),
            ("claude_cd_b", "Work", Some(usage(1.0, 2.0, None))),
        ]);
        assert_eq!(
            resolve_surface_size(&theme, 0, Some(&three), runtime).0,
            867
        );
        assert!(bounds(&three, "claude-account-3").is_some());
        assert!(bounds(&three, "claude-account-2-fable-value-dark").is_none());
        let three_context = DataContext::from_usage_with_runtime(Some(&three), &canvas, runtime);
        assert_eq!(
            format_template(
                "{accounts.claude.2.session.display:usage_line}",
                &three_context
            ),
            "!"
        );
        assert_eq!(
            three_context.get_string("accounts.claude.3.label"),
            Some("Work")
        );

        // Turning Claude off leaves the Codex-only widget as it was.
        let codex_only = ThemeRuntime::new(false, true, false);
        assert_eq!(
            resolve_surface_size(&theme, 0, Some(&two), codex_only),
            resolve_surface_size(&theme, 0, None, codex_only)
        );
    }

    #[test]
    fn email_names_shorten_to_the_part_that_tells_them_apart() {
        assert_eq!(
            short_labels(&["fred@gmail.com", "fred@hotmail.com"]),
            ["gmail", "hotmail"]
        );
        assert_eq!(
            short_labels(&["fred@example.com", "alex@Example.org"]),
            ["fred", "alex"]
        );
        assert_eq!(
            short_labels(&["fred@example.com", "fred@example.org"]),
            ["fred@example.com", "fred@example.org"]
        );
        assert_eq!(short_labels(&["fred@gmail.com"]), ["gmail"]);
    }

    #[test]
    fn chosen_names_are_kept_and_do_not_affect_email_labels() {
        assert_eq!(
            short_labels(&[" Work ", "fred@gmail.com", "Default"]),
            ["Work", "gmail", "Default"]
        );
        assert_eq!(
            short_labels(&["not an@email", "@gmail.com", "a@b@c"]),
            ["not an@email", "@gmail.com", "a@b@c"]
        );
        assert!(short_labels(&[]).is_empty());
    }
}
