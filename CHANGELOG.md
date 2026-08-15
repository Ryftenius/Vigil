# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning after 1.0.

## [Unreleased]

### Added

- Configuration-driven notification pipeline with multiple named providers
- HTTP webhook provider for SOAR, case-management, and notification systems
- UDP/TCP socket providers with JSON, CEF, and Sigma JSON payload selection
- Per-provider alert routing by kind, protected rule, and minimum severity
- Provider-specific timeout, retry, backoff, headers, and environment-backed bearer tokens
- Versioned `ryftenius.vigil.alert.v1` webhook envelope
- Enterprise-oriented config sections (`security`, `concurrency`, `endpoint_alert`, `siem`)
- SIEM output formats (JSONL, CEF, Sigma JSON)
- Sigma rule artifact generation
- ETW startup preflight diagnostics and fallback session naming
- Logger sink fallback for access-denied file paths
- Security and contribution documentation (`SECURITY.md`, `CONTRIBUTING.md`)
- Windows CI workflow with fmt/clippy/build/test
- Unit tests for config validation and alert formatting/logger behavior
