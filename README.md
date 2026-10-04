# RedactProxy

A proxy gateway that masks personally identifiable information (PII) and secrets on the fly in requests to LLM APIs (OpenAI-compatible, Anthropic). It forwards the masked request to the provider and puts the original values back into the response (JSON and SSE stream).

- Python 3.10+, standard library only, zero dependencies.
- PII and secret values never reach logs, metrics, or exceptions: only types and counters are recorded.
- Fail-closed: an invalid body or an unsupported content type means the request is never sent to the provider.

## How it works

1. The client sends its request to RedactProxy instead of the provider.
2. Detectors find PII and secrets in the string values of the JSON (dictionary keys and the `model`, `role`, `type`, `id` fields are left untouched).
3. Actions by type:
   - `mask`: the value is replaced with a token like `[EMAIL_1]`; one value always maps to one token; the token is reversible;
   - `redact`: the value is replaced with `[REDACTED:TYPE]` and is never stored (keys, tokens, passwords, PEM blocks);
   - `block`: the request is rejected (422) and nothing is sent to the provider;
   - `allow`: the value is passed through.
4. The provider's response (JSON, `text/*`, SSE) goes through reverse substitution of tokens. In a stream, split tokens (`[EM` + `AIL_1]`) are stitched back together.

## Quick start

```bash
export UPSTREAM_URL=https://api.openai.com
export PROXY_TOKEN=choose-a-long-token
python redactproxy.py serve --port 8080 --policy policy.example.json
```

Point your client at `http://127.0.0.1:8080`. The provider key is passed as usual (the `Authorization` header is forwarded upstream), and you add the `X-Redact-Proxy-Token` header for the proxy itself:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "X-Redact-Proxy-Token: $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Write an email to ivan@corp.ru"}]}'
```

For Anthropic, set `UPSTREAM_URL=https://api.anthropic.com`.

## Configuration

Command-line flags take priority over environment variables.

| Variable | Flag | Default | Purpose |
|---|---|---|---|
| `UPSTREAM_URL` | `--upstream` | `https://api.openai.com` | provider address |
| `LISTEN_HOST` | `--host` | `127.0.0.1` | listen address |
| `LISTEN_PORT` | `--port` | `8080` | listen port |
| `UPSTREAM_TIMEOUT` | n/a | `120` | upstream timeout, seconds |
| `MAX_BODY_MB` | n/a | `10` | maximum request body size |
| `POLICY_FILE` | `--policy` | n/a | path to policy.json |
| `PROXY_TOKEN` | `--token` | n/a | access token for the proxy |
| `LOG_LEVEL` | n/a | `INFO` | logging level |

If the proxy listens on a non-loopback address without a token, a warning is logged at startup.

## Service endpoints

- `GET /_health`: returns `{"status":"ok"}`, no authentication required.
- `GET /_metrics`: counters in Prometheus format (`redactproxy_requests_total`, `redactproxy_findings_total{type="EMAIL"}`, and others).
- `POST /_redact`: dry run: `{"text":"..."}` returns `{"text":"[EMAIL_1]","findings":{"EMAIL":1}}`; returns 422 on `block`.

All other paths are forwarded upstream. Proxy status codes: 401 invalid token, 411 chunked request, 413 body over the limit, 415 unsupported body type, 422 blocked by policy, 400 invalid body, 502 upstream unavailable.

## Detectors

18 built in: `PRIVATE_KEY`, `AWS_KEY`, `GITHUB_TOKEN`, `API_KEY`, `SLACK_TOKEN`, `JWT`, `BEARER_TOKEN`, `URL_CREDENTIALS`, `SECRET` (all `redact`), `CREDIT_CARD` (Luhn), `IBAN` (mod-97), `INN`, `SNILS` (checksums), `PASSPORT_RU`, `SSN`, `EMAIL`, `PHONE`, `IP_ADDRESS` (all `mask`). List with priorities: `python tools.py list`.

When matches overlap, the detector with the lower priority number wins, then the longer match.

## Policy

See `policy.example.json`: `actions` (action per type), `disabled` (turned-off detectors), `allowlist` (exact values to skip), `custom` (your own detectors: `name`, `pattern`, `ignore_case`, `group`, `priority`, `action`), `unmask_responses`, `passthrough_binary`. Extra keys (such as `_comment`) are ignored. Validate a file with `python tools.py check policy.json`.

## Extending

Pass your own detector via `Redactor(extra_detectors=[...])`, or subclass `Redactor` and override `find()` (for example, to add name detection with NER). See `NameRedactor` in `test_redactproxy.py`.

## CLI

```bash
echo "write to ivan@corp.ru" | python redactproxy.py scan --policy policy.example.json
# stdout: write to [EMAIL_1]
# stderr: {"findings": ["EMAIL"]}
```

## Docker

```bash
docker build -t redactproxy .
docker run --rm -p 8080:8080 \
  -e PROXY_TOKEN=... -e UPSTREAM_URL=https://api.openai.com redactproxy
```

## Tests

```bash
python -m unittest -v test_redactproxy
```

## Limitations

- Only string values in JSON and `text/*` bodies are masked; binary bodies are rejected (415) unless `passthrough_binary` is enabled.
- Reverse substitution in streams works for `choices[].delta.content` (OpenAI) and `content_block_delta.delta.text` (Anthropic); function-call arguments and other fields are not restored.
- Detectors rely on regular expressions and checksums; this lowers the risk of leaks but does not guarantee that all sensitive data is found.
- Requests with `Transfer-Encoding: chunked` are not supported; response compression is disabled (`Accept-Encoding: identity`).
- The proxy does not encrypt traffic itself: in production, run it behind a TLS terminator or inside a trusted network.
