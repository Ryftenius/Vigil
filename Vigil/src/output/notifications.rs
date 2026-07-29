use crate::{
    output::alerts::Alert,
    support::config::{Config, NotificationProviderConfig},
};
use anyhow::{Result, bail};
use std::sync::Arc;

#[cfg(feature = "remote_endpoint")]
use crate::support::config::{EndpointAlertConfig, EndpointTransport};
#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
use crate::support::config::{NotificationFilterConfig, NotificationFormat};
#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications"))]
use anyhow::Context;
#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications"))]
use anyhow::anyhow;
#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
use serde::Serialize;
#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications"))]
use std::{thread, time::Duration};

#[cfg(feature = "remote_endpoint")]
use std::{
    io::Write,
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

#[cfg(feature = "webhook_notifications")]
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
};

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
const ENVELOPE_SCHEMA: &str = "titan.vigil.alert.v1";

trait NotificationProvider: Send + Sync {
    fn name(&self) -> &str;
    fn matches(&self, alert: &Alert) -> bool;
    fn send(&self, alert: &Alert) -> Result<()>;
}

#[derive(Debug)]
pub struct DeliveryFailure {
    pub provider: String,
    pub error: anyhow::Error,
}

#[derive(Default)]
pub struct NotificationPipeline {
    providers: Vec<Arc<dyn NotificationProvider>>,
}

impl NotificationPipeline {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let mut pipeline = Self::default();

        if cfg.notifications.enabled {
            for provider in &cfg.notifications.providers {
                if !provider.is_enabled() {
                    continue;
                }
                pipeline.add_configured_provider(provider)?;
            }
        }

        if cfg.endpoint_alert.enabled {
            #[cfg(feature = "remote_endpoint")]
            pipeline
                .providers
                .push(Arc::new(SocketProvider::from_legacy(&cfg.endpoint_alert)));
        }

        Ok(pipeline)
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub fn send(&self, alert: &Alert) -> Vec<DeliveryFailure> {
        let mut failures = Vec::new();
        for provider in &self.providers {
            if !provider.matches(alert) {
                continue;
            }
            if let Err(error) = provider.send(alert) {
                failures.push(DeliveryFailure {
                    provider: provider.name().to_string(),
                    error,
                });
            }
        }
        failures
    }

    fn add_configured_provider(&mut self, provider: &NotificationProviderConfig) -> Result<()> {
        match provider {
            NotificationProviderConfig::Webhook { .. } => self.add_webhook_provider(provider),
            NotificationProviderConfig::Socket { .. } => self.add_socket_provider(provider),
        }
    }

    fn add_webhook_provider(&mut self, provider: &NotificationProviderConfig) -> Result<()> {
        #[cfg(feature = "webhook_notifications")]
        {
            self.providers.push(Arc::new(
                WebhookProvider::from_config(provider).with_context(|| {
                    format!(
                        "failed to initialize webhook provider '{}'",
                        provider.name()
                    )
                })?,
            ));
            Ok(())
        }

        #[cfg(not(feature = "webhook_notifications"))]
        bail!(
            "notification provider '{}' requires the webhook_notifications feature",
            provider.name()
        );
    }

    fn add_socket_provider(&mut self, provider: &NotificationProviderConfig) -> Result<()> {
        #[cfg(feature = "remote_endpoint")]
        {
            self.providers.push(Arc::new(
                SocketProvider::from_config(provider).with_context(|| {
                    format!("failed to initialize socket provider '{}'", provider.name())
                })?,
            ));
            Ok(())
        }

        #[cfg(not(feature = "remote_endpoint"))]
        bail!(
            "notification provider '{}' requires the remote_endpoint feature",
            provider.name()
        );
    }
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications"))]
#[derive(Clone)]
struct ProviderPolicy {
    name: String,
    format: NotificationFormat,
    filter: AlertFilter,
    max_attempts: usize,
    backoff: Duration,
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications"))]
impl ProviderPolicy {
    fn retry(&self, mut operation: impl FnMut() -> Result<()>) -> Result<()> {
        let mut last_error = None;
        for attempt in 1..=self.max_attempts {
            match operation() {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }

            if attempt < self.max_attempts && !self.backoff.is_zero() {
                let multiplier = u32::try_from(attempt).unwrap_or(u32::MAX);
                thread::sleep(self.backoff.saturating_mul(multiplier));
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("notification delivery did not run")))
            .with_context(|| {
                format!(
                    "provider '{}' failed after {} attempt(s)",
                    self.name, self.max_attempts
                )
            })
    }
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
#[derive(Clone)]
struct AlertFilter(NotificationFilterConfig);

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
impl AlertFilter {
    fn matches(&self, alert: &Alert) -> bool {
        if self
            .0
            .min_severity
            .is_some_and(|minimum| alert.severity() < minimum)
        {
            return false;
        }
        if !self.0.kinds.is_empty()
            && !self
                .0
                .kinds
                .iter()
                .any(|kind| kind.eq_ignore_ascii_case(&alert.kind))
        {
            return false;
        }
        if !self.0.rules.is_empty()
            && !self
                .0
                .rules
                .iter()
                .any(|rule| rule.eq_ignore_ascii_case(&alert.data_name))
        {
            return false;
        }
        true
    }
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
#[derive(Serialize)]
struct NotificationEnvelope<'a> {
    schema: &'static str,
    source: &'static str,
    severity: u8,
    alert: &'a Alert,
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
struct EncodedPayload {
    body: Vec<u8>,
}

#[cfg(any(feature = "remote_endpoint", feature = "webhook_notifications", test))]
fn encode_payload(
    alert: &Alert,
    format: &NotificationFormat,
    legacy_raw_json: bool,
) -> Result<EncodedPayload> {
    match format {
        NotificationFormat::Json if legacy_raw_json => Ok(EncodedPayload {
            body: serde_json::to_vec(alert)?,
        }),
        NotificationFormat::Json => Ok(EncodedPayload {
            body: serde_json::to_vec(&NotificationEnvelope {
                schema: ENVELOPE_SCHEMA,
                source: "TITAN Vigil",
                severity: alert.severity(),
                alert,
            })?,
        }),
        NotificationFormat::Cef => Ok(EncodedPayload {
            body: alert.cef_line().into_bytes(),
        }),
        NotificationFormat::SigmaJson => Ok(EncodedPayload {
            body: serde_json::to_vec(&alert.sigma_json())?,
        }),
    }
}

#[cfg(feature = "webhook_notifications")]
fn content_type(format: &NotificationFormat) -> &'static str {
    match format {
        NotificationFormat::Cef => "text/plain; charset=utf-8",
        NotificationFormat::Json | NotificationFormat::SigmaJson => "application/json",
    }
}

#[cfg(feature = "webhook_notifications")]
struct WebhookProvider {
    policy: ProviderPolicy,
    url: String,
    client: Client,
}

#[cfg(feature = "webhook_notifications")]
impl WebhookProvider {
    fn from_config(config: &NotificationProviderConfig) -> Result<Self> {
        let NotificationProviderConfig::Webhook {
            name,
            url,
            format,
            timeout_ms,
            max_attempts,
            backoff_ms,
            headers,
            bearer_token_env,
            filter,
            ..
        } = config
        else {
            bail!("webhook provider received non-webhook configuration");
        };

        let mut default_headers = HeaderMap::new();
        for (key, value) in headers {
            let name = HeaderName::from_bytes(key.as_bytes())
                .with_context(|| format!("provider '{name}' has invalid header name '{key}'"))?;
            let value = HeaderValue::from_str(value)
                .with_context(|| format!("provider '{name}' has an invalid value for '{key}'"))?;
            default_headers.insert(name, value);
        }

        if let Some(env_name) = bearer_token_env {
            let token = std::env::var(env_name).with_context(|| {
                format!("provider '{name}' requires environment variable {env_name}")
            })?;
            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .with_context(|| format!("provider '{name}' bearer token is not a valid header"))?;
            default_headers.insert(AUTHORIZATION, value);
        }

        let timeout = Duration::from_millis(*timeout_ms);
        let client = Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .default_headers(default_headers)
            .build()
            .with_context(|| format!("failed to build webhook client for provider '{name}'"))?;

        Ok(Self {
            policy: ProviderPolicy {
                name: name.clone(),
                format: format.clone(),
                filter: AlertFilter(filter.clone()),
                max_attempts: *max_attempts,
                backoff: Duration::from_millis(*backoff_ms),
            },
            url: url.clone(),
            client,
        })
    }

    fn send_once(&self, payload: &EncodedPayload) -> Result<()> {
        self.client
            .post(&self.url)
            .header("content-type", content_type(&self.policy.format))
            .body(payload.body.clone())
            .send()
            .with_context(|| format!("POST {} failed", self.url))?
            .error_for_status()
            .with_context(|| format!("POST {} returned an error status", self.url))?;
        Ok(())
    }
}

#[cfg(feature = "webhook_notifications")]
impl NotificationProvider for WebhookProvider {
    fn name(&self) -> &str {
        &self.policy.name
    }

    fn matches(&self, alert: &Alert) -> bool {
        self.policy.filter.matches(alert)
    }

    fn send(&self, alert: &Alert) -> Result<()> {
        let payload = encode_payload(alert, &self.policy.format, false)?;
        self.policy.retry(|| self.send_once(&payload))
    }
}

#[cfg(feature = "remote_endpoint")]
struct SocketProvider {
    policy: ProviderPolicy,
    target: String,
    transport: EndpointTransport,
    timeout: Duration,
    legacy_raw_json: bool,
}

#[cfg(feature = "remote_endpoint")]
impl SocketProvider {
    fn from_config(config: &NotificationProviderConfig) -> Result<Self> {
        let NotificationProviderConfig::Socket {
            name,
            endpoint,
            transport,
            format,
            timeout_ms,
            max_attempts,
            backoff_ms,
            filter,
            ..
        } = config
        else {
            bail!("socket provider received non-socket configuration");
        };

        Ok(Self {
            policy: ProviderPolicy {
                name: name.clone(),
                format: format.clone(),
                filter: AlertFilter(filter.clone()),
                max_attempts: *max_attempts,
                backoff: Duration::from_millis(*backoff_ms),
            },
            target: endpoint.clone(),
            transport: transport.clone(),
            timeout: Duration::from_millis(*timeout_ms),
            legacy_raw_json: false,
        })
    }

    fn from_legacy(config: &EndpointAlertConfig) -> Self {
        Self {
            policy: ProviderPolicy {
                name: "legacy-endpoint".to_string(),
                format: NotificationFormat::Json,
                filter: AlertFilter(NotificationFilterConfig::default()),
                max_attempts: config.retries.max(1),
                backoff: Duration::ZERO,
            },
            target: config.endpoint.trim().to_string(),
            transport: config.transport.clone(),
            timeout: Duration::from_millis(config.connect_timeout_ms.max(100)),
            legacy_raw_json: true,
        }
    }

    fn send_once(&self, payload: &EncodedPayload) -> Result<()> {
        match self.transport {
            EndpointTransport::Udp => self.send_udp(&payload.body),
            EndpointTransport::Tcp => self.send_tcp(&payload.body),
        }
    }

    fn send_udp(&self, body: &[u8]) -> Result<()> {
        let addr = self.resolve_first_addr()?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.send_to(body, addr)?;
        Ok(())
    }

    fn send_tcp(&self, body: &[u8]) -> Result<()> {
        let addr = self.resolve_first_addr()?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(body)?;
        stream.write_all(b"\n")?;
        Ok(())
    }

    fn resolve_first_addr(&self) -> Result<std::net::SocketAddr> {
        self.target
            .to_socket_addrs()
            .with_context(|| format!("invalid endpoint address '{}'", self.target))?
            .next()
            .context("endpoint resolved to no addresses")
    }
}

#[cfg(feature = "remote_endpoint")]
impl NotificationProvider for SocketProvider {
    fn name(&self) -> &str {
        &self.policy.name
    }

    fn matches(&self, alert: &Alert) -> bool {
        self.policy.filter.matches(alert)
    }

    fn send(&self, alert: &Alert) -> Result<()> {
        let payload = encode_payload(alert, &self.policy.format, self.legacy_raw_json)?;
        self.policy.retry(|| self.send_once(&payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "webhook_notifications"))]
    use crate::support::config::{
        AllowlistConfig, ConcurrencyConfig, GeneralConfig, NotificationsConfig, SecurityConfig,
        SiemConfig, TrustApiConfig, WatchConfig,
    };

    fn test_alert() -> Alert {
        Alert::new(
            42,
            "C:\\test\\proc.exe".to_string(),
            "C:\\secret\\cookies.db".to_string(),
            "Cookie Store".to_string(),
            12,
            "protected_resource_access",
            "unit-test",
        )
    }

    #[cfg(not(feature = "webhook_notifications"))]
    fn base_config() -> Config {
        Config {
            general: GeneralConfig::default(),
            watch: WatchConfig::default(),
            allowlist: AllowlistConfig::default(),
            security: SecurityConfig::default(),
            concurrency: ConcurrencyConfig::default(),
            endpoint_alert: crate::support::config::EndpointAlertConfig::default(),
            notifications: NotificationsConfig {
                enabled: true,
                providers: Vec::new(),
            },
            siem: SiemConfig::default(),
            trust_api: TrustApiConfig::default(),
        }
    }

    #[test]
    fn json_payload_uses_versioned_envelope() {
        let alert = test_alert();
        let payload =
            encode_payload(&alert, &NotificationFormat::Json, false).expect("encode payload");
        let value: serde_json::Value =
            serde_json::from_slice(&payload.body).expect("decode envelope");
        assert_eq!(value["schema"], ENVELOPE_SCHEMA);
        assert_eq!(value["source"], "TITAN Vigil");
        assert_eq!(value["severity"], 8);
        assert_eq!(value["alert"]["pid"], 42);
    }

    #[test]
    fn policy_filters_by_kind_rule_and_severity() {
        let alert = test_alert();
        let filter = AlertFilter(NotificationFilterConfig {
            kinds: vec!["protected_resource_access".to_string()],
            rules: vec!["cookie store".to_string()],
            min_severity: Some(8),
        });
        assert!(filter.matches(&alert));

        let mut rejected = filter.clone();
        rejected.0.min_severity = Some(9);
        assert!(!rejected.matches(&alert));
    }

    #[cfg(not(feature = "webhook_notifications"))]
    #[test]
    fn configured_webhook_requires_feature() {
        let mut cfg = base_config();
        cfg.notifications
            .providers
            .push(NotificationProviderConfig::Webhook {
                name: "soar".to_string(),
                enabled: true,
                url: "https://soar.example.test/hooks/vigil".to_string(),
                format: NotificationFormat::Json,
                timeout_ms: 1000,
                max_attempts: 1,
                backoff_ms: 0,
                headers: Default::default(),
                bearer_token_env: None,
                filter: NotificationFilterConfig::default(),
            });

        let error = NotificationPipeline::from_config(&cfg)
            .err()
            .expect("missing feature should fail");
        assert!(error.to_string().contains("webhook_notifications"));
    }

    #[cfg(feature = "webhook_notifications")]
    #[test]
    fn webhook_posts_envelope_and_retries_server_error() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::mpsc,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            for status in ["500 Internal Server Error", "200 OK"] {
                let (mut stream, _) = listener.accept().expect("accept HTTP request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let mut buffer = [0u8; 8192];
                let size = stream.read(&mut buffer).expect("read HTTP request");
                request_tx
                    .send(String::from_utf8_lossy(&buffer[..size]).into_owned())
                    .expect("send captured request");
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write HTTP response");
            }
        });

        let provider_config = NotificationProviderConfig::Webhook {
            name: "soar".to_string(),
            enabled: true,
            url: format!("http://{address}/hooks/vigil"),
            format: NotificationFormat::Json,
            timeout_ms: 2000,
            max_attempts: 2,
            backoff_ms: 1,
            headers: [("x-vigil-tenant".to_string(), "blue-team".to_string())]
                .into_iter()
                .collect(),
            bearer_token_env: None,
            filter: NotificationFilterConfig::default(),
        };
        let provider = WebhookProvider::from_config(&provider_config).expect("webhook provider");
        provider.send(&test_alert()).expect("webhook delivery");
        server.join().expect("join HTTP server");

        let requests: Vec<_> = request_rx.try_iter().collect();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1]
                .to_lowercase()
                .contains("x-vigil-tenant: blue-team")
        );
        assert!(requests[1].contains(ENVELOPE_SCHEMA));
    }

    #[cfg(feature = "remote_endpoint")]
    #[test]
    fn socket_provider_delivers_json_envelope() {
        use std::net::UdpSocket;

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind UDP receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let address = receiver.local_addr().expect("receiver address");

        let provider_config = NotificationProviderConfig::Socket {
            name: "socket".to_string(),
            enabled: true,
            endpoint: address.to_string(),
            transport: EndpointTransport::Udp,
            format: NotificationFormat::Json,
            timeout_ms: 1000,
            max_attempts: 1,
            backoff_ms: 0,
            filter: NotificationFilterConfig::default(),
        };
        let provider = SocketProvider::from_config(&provider_config).expect("socket provider");
        provider.send(&test_alert()).expect("socket delivery");

        let mut buffer = [0u8; 4096];
        let (size, _) = receiver
            .recv_from(&mut buffer)
            .expect("receive UDP payload");
        let value: serde_json::Value =
            serde_json::from_slice(&buffer[..size]).expect("decode envelope");
        assert_eq!(value["schema"], ENVELOPE_SCHEMA);
        assert_eq!(value["alert"]["pid"], 42);
    }
}
