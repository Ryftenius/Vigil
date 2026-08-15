<h1 align="center">RYFTENIUS Vigil</h1>
<p align="center"><b>Kernel ETW Blue-Team Telemetry Engine</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Telemetry-Kernel%20ETW-5C2D91?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-SIEM%20Ready-2E8B57?style=for-the-badge" />
</p>

<p align="center">
Detects untrusted processes accessing protected filesystem resources using low-latency Kernel ETW instrumentation and deterministic policy evaluation.
</p>

## Project Documentation

- `README.md`: Runtime overview, configuration, and operations
- `CONTRIBUTING.md`: Development and PR workflow

---

## Repository Layout

- `Vigil/src/main.rs`: entrypoint wiring config, logging, worker pool, ETW session lifecycle
- `Vigil/src/runtime/`: detection engine state and alert orchestration
- `Vigil/src/telemetry/`: Kernel ETW session management and trusted-handle discovery
- `Vigil/src/trust/`: signer verification and process metadata helpers
- `Vigil/src/output/`: alert schema, log sinks, notification providers, and toast UX
- `Vigil/src/support/`: config/CLI parsing and startup diagnostics
- `tests/data_access_test/`: synthetic filesystem access generator used for validation

---

## What It Detects

The engine monitors kernel-level file I/O events and raises alerts when:

* An **untrusted or unsigned process**
* Attempts to **access a configured protected path**
* Including access via **handle duplication from trusted processes**

Typical protected targets include (configurable):

* Browser profile data (cookies, login databases)
* Application secrets stored on disk
* Token stores (e.g. LevelDB-based apps)
* Any sensitive filesystem location you define

---

## How It Works

* Starts a **Kernel ETW user trace** (process + file providers)
* Tracks process start events and caches process metadata
* Tracks file name mappings via ETW file events
* Matches accessed paths against protected rules using deterministic indexed lookups
* Evaluates process trust using:

  * Authenticode signature verification
  * Optional certificate revocation checks (`security.revocation_mode = "chain"`)
  * Explicit denylist of known compromised signer certificate thumbprints
  * Optional signer allowlist
  * Optional legacy process-name allowlist fallback
* Detects suspicious access patterns including:

  * Direct access by untrusted processes
  * Access via file objects originally opened by trusted processes
* Emits alerts through:

  * JSONL / text / CEF / Sigma-JSON log sinks
  * Optional console output
  * Windows toast notifications (rate-limited)
  * Named HTTP webhook providers for SOAR and notification pipelines
  * Named UDP/TCP providers for SIEM and collector endpoints
* Uses bounded crossbeam channels and worker threads for sink processing/backpressure

---

## Requirements

* Windows
* Administrative privileges (required for Kernel ETW sessions)
* Rust toolchain (for building)

---

## Configuration

Configuration is provided via a TOML file.

Key concepts:

* **Protected rules**
  Substring-based path matching for sensitive resources.

* **Allowlists**

  * Certificate signer subject fragments
  * Legacy process name suffixes

* **Security policy**

  * Signature requirement toggle
  * Revocation mode
  * Compromised cert thumbprint denylist
  * Legacy fallback policy
  * Optional operator trust API (mode: wintrust-only, api-only, prefer-api, prefer-wintrust)

* **Concurrency policy**

  * Worker thread count
  * Channel capacity for burst control

* **Notification providers**

  * Multiple named webhook and socket destinations
  * JSON envelope, CEF, or Sigma JSON payloads
  * Per-provider kind, rule, and minimum-severity filters
  * Timeouts, retry attempts, and progressive retry backoff
  * Static headers and environment-backed bearer tokens

* **SIEM and Sigma**

  * Multi-format outputs (`jsonl`, `text`, `cef`, `sigma_json`)
  * Optional Sigma rule artifact generation on startup

* **General settings**

  * Alert suppression window
  * Quiet mode
  * JSONL vs text logging

Example (simplified):

```toml
[general]
quiet = false
suppress_ms = 1500

[security]
require_signature = true
require_signer_allowlist = true
allow_legacy_process_name_fallback = false
revocation_mode = "chain"
denylisted_cert_thumbprints = []

[concurrency]
worker_threads = 4
alert_channel_capacity = 8192

[notifications]
enabled = true

[[notifications.providers]]
type = "webhook"
name = "primary-soar"
enabled = true
url = "https://soar.example.com/api/v1/hooks/vigil"
format = "json"
timeout_ms = 3000
max_attempts = 3
backoff_ms = 250
bearer_token_env = "VIGIL_SOAR_TOKEN"
headers = { "X-Tenant-ID" = "blue-team" }
kinds = ["protected_resource_access"]
rules = []
min_severity = 8

[[notifications.providers]]
type = "socket"
name = "cef-collector"
enabled = false
endpoint = "127.0.0.1:5514"
transport = "tcp"
format = "cef"
timeout_ms = 1500
max_attempts = 2
backoff_ms = 100

[siem]
enabled = true
formats = ["jsonl", "cef", "sigma_json"]
generate_sigma_rules = true
sigma_rules_file = "sigma_rules.yml"

[watch]
protected = [
  { name = "Browser Cookies", substring = "cookies" },
  { name = "Token Store", substring = "leveldb" }
]

[allowlist]
signer_subject_allow = ["microsoft", "google"]
process_name_allow = ["chrome.exe", "msedge.exe"]

[trust_api]
enabled = false
endpoint = "https://trust.example.com/verify"
api_key = "Bearer token-here"
timeout_ms = 2500
# modes: wintrust_only | api_only | prefer_api | prefer_wintrust
mode = "prefer_api"
```

---

## SOAR and Notification Pipelines

Set `notifications.enabled = true`, then add one or more named providers. Each
provider can be enabled or disabled independently. Vigil evaluates the routing
filters for every alert and delivers matching alerts to all matching providers.

Webhook providers send HTTP `POST` requests with a stable, versioned JSON
envelope:

```json
{
  "schema": "ryftenius.vigil.alert.v1",
  "source": "RYFTENIUS Vigil",
  "severity": 8,
  "alert": {
    "ts_unix": 1785225600,
    "pid": 4242,
    "process": "C:\\Tools\\collector.exe",
    "target": "C:\\Users\\analyst\\AppData\\...\\Cookies",
    "data_name": "Browser Cookies",
    "event_id": 12,
    "kind": "protected_resource_access",
    "note": "untrusted process accessed protected data"
  }
}
```

Webhook delivery treats any HTTP success status as accepted. Connection
failures and non-success responses are retried up to `max_attempts`, using
progressive `backoff_ms` delays. Providers run independently, so one failed
destination does not stop delivery to the remaining destinations.

### Provider reference

| Setting | Applies to | Description |
| --- | --- | --- |
| `name` | All | Unique provider name used in delivery diagnostics |
| `enabled` | All | Enables this provider; defaults to `true` |
| `format` | All | `json`, `cef`, or `sigma_json` |
| `timeout_ms` | All | Per-attempt connection and delivery timeout |
| `max_attempts` | All | Total delivery attempts, including the first |
| `backoff_ms` | All | Base delay used for progressive retry backoff |
| `kinds` | All | Alert kinds to accept; an empty list accepts all |
| `rules` | All | Protected rule names to accept; an empty list accepts all |
| `min_severity` | All | Minimum severity from `0` through `10` |
| `url` | Webhook | HTTP or HTTPS destination |
| `headers` | Webhook | Static request headers for routing or tenancy |
| `bearer_token_env` | Webhook | Environment variable containing the bearer token |
| `endpoint` | Socket | Collector address in `host:port` form |
| `transport` | Socket | `udp` or `tcp` |

When multiple filters are configured, an alert must satisfy all of them.
`format = "cef"` emits one CEF record, while `format = "sigma_json"` emits the
existing Sigma-compatible event object.

Use `bearer_token_env` for credentials instead of storing tokens in TOML:

```powershell
$env:VIGIL_SOAR_TOKEN = (Get-Content C:\ProgramData\Vigil\soar.token -Raw).Trim()
Set-Location Vigil
cargo run --release --features webhook_notifications -- --config config.toml
```

Build with `webhook_notifications` for webhook providers and `remote_endpoint`
for socket providers. Enable both features when a deployment uses both provider
types.

The original `[endpoint_alert]` block remains supported and is routed through
the socket provider internally.

---

## Running

```bash
cd Vigil
cargo run --release -- --config config.toml
```

Verbose output:

```bash
cargo run --release -- --config config.toml --verbose
```

Logs are written to:

```
%LOCALAPPDATA%\RYFTENIUS-Vigil-CE\logs
```

When `siem.generate_sigma_rules = true`, a Sigma rules artifact is also generated in the same log directory (or the configured absolute path).

### Feature flags

- `remote_endpoint` (opt-in): build with UDP/TCP remote alert forwarding enabled. Example:
  `cargo run --release --features remote_endpoint -- --config config.toml`
- `webhook_notifications` (opt-in): deliver alerts to HTTP webhook providers. Example:
  `cargo run --release --features webhook_notifications -- --config config.toml`
- `trust_api` (opt-in): call an operator HTTP trust API to decide signer trust, optionally replacing WinTrust. Example:
  `cargo run --release --features trust_api -- --config config.toml`

Enable both notification transports with:

```bash
cargo run --release --features "webhook_notifications,remote_endpoint" -- --config config.toml
```

### Testing

- Core suite: `cargo test`
- Notification suite: `cargo test --all-features -- output::notifications`
- Trust API suite (opt-in): `cargo test --features trust_api -- trust::api`

---

## Alert Semantics

Each alert includes:

* Timestamp
* PID
* Process image path
* Target file path
* Protected rule name
* ETW event ID
* Alert kind (reason)
* Human-readable note

Alerts are **deduplicated and rate-limited** to avoid storms.

---

## Threat Model Fit

This tool is suited for:

* Host-based detection
* Suspicious process discovery
* Post-exploitation visibility
* Blue-team telemetry enrichment
