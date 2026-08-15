use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub watch: WatchConfig,

    #[serde(default)]
    pub allowlist: AllowlistConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub concurrency: ConcurrencyConfig,

    #[serde(default)]
    pub endpoint_alert: EndpointAlertConfig,

    #[serde(default)]
    pub notifications: NotificationsConfig,

    #[serde(default)]
    pub siem: SiemConfig,

    #[serde(default)]
    pub trust_api: TrustApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_quiet")]
    pub quiet: bool,

    #[serde(default = "default_jsonl")]
    pub jsonl: bool,

    #[serde(default = "default_suppress_ms")]
    pub suppress_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedRule {
    pub substring: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchConfig {
    #[serde(default)]
    pub protected: Vec<ProtectedRule>,

    #[serde(default)]
    pub protected_substrings: Vec<String>,

    #[serde(default)]
    pub exact_paths: Vec<ProtectedRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub signer_subject_allow: Vec<String>,

    #[serde(default)]
    pub process_name_allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    #[default]
    None,
    Chain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_require_signature")]
    pub require_signature: bool,

    #[serde(default = "default_require_signer_allowlist")]
    pub require_signer_allowlist: bool,

    #[serde(default)]
    pub allow_legacy_process_name_fallback: bool,

    #[serde(default)]
    pub revocation_mode: RevocationMode,

    #[serde(default)]
    pub denylisted_cert_thumbprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustApiMode {
    WintrustOnly,
    ApiOnly,
    PreferApi,
    PreferWintrust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustApiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_trust_api_endpoint")]
    pub endpoint: String,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_trust_api_timeout_ms")]
    pub timeout_ms: u64,

    #[serde(default = "default_trust_api_mode")]
    pub mode: TrustApiMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    #[serde(default = "default_alert_channel_capacity")]
    pub alert_channel_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTransport {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAlertConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub endpoint: String,

    #[serde(default)]
    pub transport: EndpointTransport,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    #[serde(default = "default_endpoint_retries")]
    pub retries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub providers: Vec<NotificationProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationFormat {
    #[default]
    Json,
    Cef,
    SigmaJson,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationFilterConfig {
    #[serde(default)]
    pub kinds: Vec<String>,

    #[serde(default)]
    pub rules: Vec<String>,

    #[serde(default)]
    pub min_severity: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationProviderConfig {
    Webhook {
        name: String,

        #[serde(default = "default_provider_enabled")]
        enabled: bool,

        url: String,

        #[serde(default)]
        format: NotificationFormat,

        #[serde(default = "default_notification_timeout_ms")]
        timeout_ms: u64,

        #[serde(default = "default_notification_max_attempts")]
        max_attempts: usize,

        #[serde(default = "default_notification_backoff_ms")]
        backoff_ms: u64,

        #[serde(default)]
        headers: BTreeMap<String, String>,

        #[serde(default)]
        bearer_token_env: Option<String>,

        #[serde(flatten)]
        filter: NotificationFilterConfig,
    },
    Socket {
        name: String,

        #[serde(default = "default_provider_enabled")]
        enabled: bool,

        endpoint: String,

        #[serde(default)]
        transport: EndpointTransport,

        #[serde(default)]
        format: NotificationFormat,

        #[serde(default = "default_notification_timeout_ms")]
        timeout_ms: u64,

        #[serde(default = "default_notification_max_attempts")]
        max_attempts: usize,

        #[serde(default = "default_notification_backoff_ms")]
        backoff_ms: u64,

        #[serde(flatten)]
        filter: NotificationFilterConfig,
    },
}

impl NotificationProviderConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Webhook { name, .. } | Self::Socket { name, .. } => name,
        }
    }

    pub fn is_enabled(&self) -> bool {
        match self {
            Self::Webhook { enabled, .. } | Self::Socket { enabled, .. } => *enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    #[serde(default = "default_siem_enabled")]
    pub enabled: bool,

    #[serde(default = "default_siem_formats")]
    pub formats: Vec<String>,

    #[serde(default = "default_generate_sigma_rules")]
    pub generate_sigma_rules: bool,

    #[serde(default = "default_sigma_rules_file")]
    pub sigma_rules_file: String,
}

fn default_quiet() -> bool {
    true
}
fn default_jsonl() -> bool {
    true
}
fn default_suppress_ms() -> u64 {
    1500
}
fn default_require_signature() -> bool {
    true
}
fn default_require_signer_allowlist() -> bool {
    true
}
fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().max(2))
        .unwrap_or(4)
}
fn default_alert_channel_capacity() -> usize {
    4096
}
fn default_connect_timeout_ms() -> u64 {
    1500
}
fn default_endpoint_retries() -> usize {
    1
}
fn default_provider_enabled() -> bool {
    true
}
fn default_notification_timeout_ms() -> u64 {
    3000
}
fn default_notification_max_attempts() -> usize {
    3
}
fn default_notification_backoff_ms() -> u64 {
    250
}
fn default_trust_api_timeout_ms() -> u64 {
    2500
}
fn default_siem_enabled() -> bool {
    true
}
fn default_siem_formats() -> Vec<String> {
    vec![
        "jsonl".to_string(),
        "cef".to_string(),
        "sigma_json".to_string(),
    ]
}
fn default_generate_sigma_rules() -> bool {
    true
}
fn default_sigma_rules_file() -> String {
    "sigma_rules.yml".to_string()
}
fn default_trust_api_mode() -> TrustApiMode {
    TrustApiMode::WintrustOnly
}
fn default_trust_api_endpoint() -> String {
    String::new()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            quiet: default_quiet(),
            jsonl: default_jsonl(),
            suppress_ms: default_suppress_ms(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_signature: default_require_signature(),
            require_signer_allowlist: default_require_signer_allowlist(),
            allow_legacy_process_name_fallback: false,
            revocation_mode: RevocationMode::None,
            denylisted_cert_thumbprints: Vec::new(),
        }
    }
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            worker_threads: default_worker_threads(),
            alert_channel_capacity: default_alert_channel_capacity(),
        }
    }
}

impl Default for EndpointAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            transport: EndpointTransport::Udp,
            connect_timeout_ms: default_connect_timeout_ms(),
            retries: default_endpoint_retries(),
        }
    }
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: default_siem_enabled(),
            formats: default_siem_formats(),
            generate_sigma_rules: default_generate_sigma_rules(),
            sigma_rules_file: default_sigma_rules_file(),
        }
    }
}

impl Default for TrustApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_trust_api_endpoint(),
            api_key: None,
            timeout_ms: default_trust_api_timeout_ms(),
            mode: default_trust_api_mode(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let mut cfg: Config = toml::from_str(&text).context("failed to parse config.toml")?;

        for rule in &mut cfg.watch.protected {
            rule.substring = rule.substring.to_lowercase();
        }
        for rule in &mut cfg.watch.exact_paths {
            rule.substring = rule.substring.to_lowercase();
        }

        cfg.watch.protected_substrings = cfg
            .watch
            .protected_substrings
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        cfg.allowlist.signer_subject_allow = cfg
            .allowlist
            .signer_subject_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        cfg.allowlist.process_name_allow = cfg
            .allowlist
            .process_name_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        cfg.security.denylisted_cert_thumbprints = cfg
            .security
            .denylisted_cert_thumbprints
            .into_iter()
            .map(normalize_thumbprint)
            .filter(|s| !s.is_empty())
            .collect();

        if cfg.watch.protected.is_empty() && !cfg.watch.protected_substrings.is_empty() {
            cfg.watch.protected = cfg
                .watch
                .protected_substrings
                .iter()
                .map(|s| ProtectedRule {
                    substring: s.clone(),
                    name: s.clone(),
                })
                .collect();
        }

        if cfg.concurrency.worker_threads == 0 {
            cfg.concurrency.worker_threads = default_worker_threads();
        }
        if cfg.concurrency.alert_channel_capacity == 0 {
            cfg.concurrency.alert_channel_capacity = default_alert_channel_capacity();
        }

        if cfg.endpoint_alert.enabled && cfg.endpoint_alert.endpoint.trim().is_empty() {
            anyhow::bail!("endpoint_alert.enabled=true but endpoint_alert.endpoint is empty");
        }

        normalize_notification_providers(&mut cfg.notifications)?;

        if cfg.trust_api.enabled && cfg.trust_api.endpoint.trim().is_empty() {
            anyhow::bail!("trust_api.enabled=true but trust_api.endpoint is empty");
        }

        cfg.siem.formats = cfg
            .siem
            .formats
            .into_iter()
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if cfg.siem.formats.is_empty() {
            cfg.siem.formats = default_siem_formats();
        }
        validate_siem_formats(&cfg.siem.formats)?;

        Ok(cfg)
    }
}

fn normalize_notification_providers(cfg: &mut NotificationsConfig) -> Result<()> {
    let mut names = HashSet::new();
    for provider in &mut cfg.providers {
        let (
            name,
            enabled,
            target,
            target_label,
            timeout_ms,
            max_attempts,
            bearer_token_env,
            filter,
        ) = match provider {
            NotificationProviderConfig::Webhook {
                name,
                enabled,
                url,
                timeout_ms,
                max_attempts,
                bearer_token_env,
                filter,
                ..
            } => (
                name,
                *enabled,
                url,
                "url",
                *timeout_ms,
                *max_attempts,
                Some(bearer_token_env),
                filter,
            ),
            NotificationProviderConfig::Socket {
                name,
                enabled,
                endpoint,
                timeout_ms,
                max_attempts,
                filter,
                ..
            } => (
                name,
                *enabled,
                endpoint,
                "endpoint",
                *timeout_ms,
                *max_attempts,
                None,
                filter,
            ),
        };

        *name = name.trim().to_string();
        if name.is_empty() {
            anyhow::bail!("notification provider name cannot be empty");
        }
        if !names.insert(name.to_lowercase()) {
            anyhow::bail!("duplicate notification provider name '{name}'");
        }

        *target = target.trim().to_string();
        if enabled && target.is_empty() {
            anyhow::bail!("notification provider '{name}' has an empty {target_label}");
        }
        if timeout_ms == 0 {
            anyhow::bail!("notification provider '{name}' timeout_ms must be greater than zero");
        }
        if max_attempts == 0 {
            anyhow::bail!("notification provider '{name}' max_attempts must be greater than zero");
        }

        if let Some(value) = bearer_token_env {
            *value = value
                .as_deref()
                .map(str::trim)
                .filter(|env_name| !env_name.is_empty())
                .map(str::to_string);
        }

        normalize_filter(name, filter)?;
    }
    Ok(())
}

fn normalize_filter(name: &str, filter: &mut NotificationFilterConfig) -> Result<()> {
    filter.kinds = filter
        .kinds
        .drain(..)
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    filter.rules = filter
        .rules
        .drain(..)
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
        .collect();

    if filter.min_severity.is_some_and(|value| value > 10) {
        anyhow::bail!("notification provider '{name}' min_severity must be between 0 and 10");
    }
    Ok(())
}

fn normalize_thumbprint(value: String) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase()
}

fn validate_siem_formats(formats: &[String]) -> Result<()> {
    let allowed: HashSet<&str> = ["jsonl", "text", "cef", "sigma_json"].into_iter().collect();
    for fmt in formats {
        if !allowed.contains(fmt.as_str()) {
            anyhow::bail!(
                "unknown siem format '{}' (allowed: jsonl, text, cef, sigma_json)",
                fmt
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn write_temp_config(content: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ryftenius-vigil-config-{ts}.toml"));
        fs::write(&path, content).expect("failed to write temp config");
        path
    }

    #[test]
    fn normalize_thumbprint_strips_non_hex_and_uppercases() {
        let got = normalize_thumbprint("aa:bb cc-dd_11".to_string());
        assert_eq!(got, "AABBCCDD11");
    }

    #[test]
    fn config_load_rejects_unknown_siem_format() {
        let path = write_temp_config(
            r#"
[siem]
formats = ["jsonl", "bogus"]
"#,
        );

        let err = Config::load(&path).expect_err("config should fail");
        let _ = fs::remove_file(&path);
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown siem format"));
    }

    #[test]
    fn config_load_validates_endpoint_when_enabled() {
        let path = write_temp_config(
            r#"
[endpoint_alert]
enabled = true
endpoint = ""
"#,
        );

        let err = Config::load(&path).expect_err("config should fail");
        let _ = fs::remove_file(&path);
        let msg = format!("{err:#}");
        assert!(msg.contains("endpoint_alert.enabled=true"));
    }

    #[test]
    fn config_load_normalizes_allowlist_and_rules() {
        let path = write_temp_config(
            r#"
[allowlist]
signer_subject_allow = ["Microsoft Corporation"]
process_name_allow = ["Chrome.exe"]

[security]
denylisted_cert_thumbprints = ["aa:bb:11"]

[watch]
protected_substrings = ["\\Users\\Damon\\Cookies"]
"#,
        );

        let cfg = Config::load(&path).expect("config should load");
        let _ = fs::remove_file(&path);

        assert_eq!(
            cfg.allowlist.signer_subject_allow[0],
            "microsoft corporation"
        );
        assert_eq!(cfg.allowlist.process_name_allow[0], "chrome.exe");
        assert_eq!(cfg.security.denylisted_cert_thumbprints[0], "AABB11");
        assert_eq!(cfg.watch.protected[0].substring, "\\users\\damon\\cookies");
    }

    #[test]
    fn config_loads_and_normalizes_notification_providers() {
        let path = write_temp_config(
            r#"
[notifications]
enabled = true

[[notifications.providers]]
type = "webhook"
name = " Primary SOAR "
url = " https://soar.example.test/hooks/vigil "
format = "json"
timeout_ms = 4000
max_attempts = 4
backoff_ms = 500
headers = { "X-Tenant" = "blue-team" }
bearer_token_env = " VIGIL_SOAR_TOKEN "
kinds = [" Protected_Resource_Access "]
rules = [" Cookie Store "]
min_severity = 8

[[notifications.providers]]
type = "socket"
name = "CEF collector"
endpoint = "127.0.0.1:5514"
transport = "tcp"
format = "cef"
"#,
        );

        let cfg = Config::load(&path).expect("config should load");
        let _ = fs::remove_file(&path);

        assert!(cfg.notifications.enabled);
        assert_eq!(cfg.notifications.providers.len(), 2);
        let NotificationProviderConfig::Webhook {
            name,
            url,
            bearer_token_env,
            filter,
            ..
        } = &cfg.notifications.providers[0]
        else {
            panic!("expected webhook provider");
        };
        assert_eq!(name, "Primary SOAR");
        assert_eq!(url, "https://soar.example.test/hooks/vigil");
        assert_eq!(bearer_token_env.as_deref(), Some("VIGIL_SOAR_TOKEN"));
        assert_eq!(filter.kinds, ["protected_resource_access"]);
        assert_eq!(filter.rules, ["cookie store"]);
        assert_eq!(filter.min_severity, Some(8));
    }

    #[test]
    fn config_rejects_duplicate_notification_provider_names() {
        let path = write_temp_config(
            r#"
[notifications]
enabled = true

[[notifications.providers]]
type = "webhook"
name = "SOAR"
url = "https://soar.example.test/one"

[[notifications.providers]]
type = "socket"
name = "soar"
endpoint = "127.0.0.1:9000"
"#,
        );

        let error = Config::load(&path).expect_err("duplicate provider names should fail");
        let _ = fs::remove_file(&path);
        assert!(
            error
                .to_string()
                .contains("duplicate notification provider name")
        );
    }

    #[test]
    fn checked_in_config_loads() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        let cfg = Config::load(&path).expect("checked-in config should load");

        assert_eq!(cfg.notifications.providers.len(), 2);
        assert_eq!(cfg.notifications.providers[0].name(), "primary-soar");
        assert_eq!(cfg.notifications.providers[1].name(), "cef-collector");
    }
}
