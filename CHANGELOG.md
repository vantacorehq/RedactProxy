# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-10-10

### Added
- Proxy for LLM APIs (OpenAI-compatible, Anthropic) that masks PII and secrets in requests and restores original values in responses (JSON, `text/*`, SSE streams).
- 18 built-in detectors, including checksum-validated types (credit card, IBAN, INN, SNILS).
- Policy file: per-type actions (`mask`, `redact`, `block`, `allow`), disabled detectors, allowlist, custom detectors.
- Service endpoints: `/_health`, `/_metrics`, `/_redact`.
- CLI: `serve` and `scan` commands in `redactproxy.py`; `list` and `check` in `tools.py`.
- Dockerfile and unit tests.
