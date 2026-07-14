use std::time::SystemTime;

#[derive(Clone, Debug, Default)]
pub struct UsageSection {
    pub percentage: f64,
    pub resets_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Default)]
pub struct UsageData {
    pub session: UsageSection,
    pub weekly: UsageSection,
    /// Weekly, model-scoped usage for Fable (Claude Code only). Present only
    /// when the usage endpoint reports a Fable-scoped weekly limit.
    pub fable: Option<UsageSection>,
    /// True when this data came from a source that reports Fable-scoped
    /// limits (the usage endpoint). When false, `fable == None` means
    /// "unknown" — the Messages API fallback cannot see Fable — rather than
    /// "the account has no Fable limit", so consumers should keep their
    /// previous Fable state.
    pub fable_authoritative: bool,
}

#[derive(Clone, Debug, Default)]
pub struct AppUsageData {
    pub claude_code: Option<UsageData>,
    pub codex: Option<UsageData>,
    pub antigravity: Option<UsageData>,
}
