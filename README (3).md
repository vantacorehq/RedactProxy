# RedactProxy

Прокси-шлюз, который на лету маскирует персональные данные (PII) и секреты в запросах
к LLM API (OpenAI-совместимые, Anthropic), пересылает провайдеру уже замаскированный
запрос, а в ответе (JSON и SSE-стрим) подставляет исходные значения обратно.

- Python 3.10+, только стандартная библиотека, ноль зависимостей.
- Значения PII и секретов не попадают в логи, метрики и исключения: пишутся только типы и счётчики.
- Fail-closed: невалидное тело или неподдерживаемый тип — запрос не уходит провайдеру.

## Как это работает

1. Клиент отправляет запрос в RedactProxy вместо провайдера.
2. Детекторы находят PII и секреты в строковых значениях JSON (ключи и поля `model`, `role`, `type`, `id` не трогаются).
3. Действия по типам:
   - `mask` — значение заменяется токеном `[EMAIL_1]`; одно значение даёт один токен; токен обратим;
   - `redact` — значение заменяется на `[REDACTED:TYPE]` и нигде не сохраняется (ключи, токены, пароли, PEM);
   - `block` — запрос отклоняется (422), провайдеру ничего не уходит;
   - `allow` — значение пропускается.
4. Ответ провайдера (JSON, `text/*`, SSE) проходит обратную подстановку токенов. В стриме «разорванные» токены (`[EM` + `AIL_1]`) склеиваются.

## Быстрый старт

```bash
export UPSTREAM_URL=https://api.openai.com
export PROXY_TOKEN=придумайте-длинный-токен
python redactproxy.py serve --port 8080 --policy policy.example.json
```

Клиент направляйте на `http://127.0.0.1:8080`, ключ провайдера передаётся как обычно (заголовок `Authorization` пересылается апстриму), а к прокси добавьте заголовок `X-Redact-Proxy-Token`:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "X-Redact-Proxy-Token: $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Напиши письмо на ivan@corp.ru"}]}'
```

Для Anthropic укажите `UPSTREAM_URL=https://api.anthropic.com`.

## Настройка

Флаги командной строки приоритетнее переменных окружения.

| Переменная | Флаг | По умолчанию | Назначение |
|---|---|---|---|
| `UPSTREAM_URL` | `--upstream` | `https://api.openai.com` | адрес провайдера |
| `LISTEN_HOST` | `--host` | `127.0.0.1` | адрес прослушивания |
| `LISTEN_PORT` | `--port` | `8080` | порт |
| `UPSTREAM_TIMEOUT` | — | `120` | таймаут апстрима, секунды |
| `MAX_BODY_MB` | — | `10` | максимальный размер тела запроса |
| `POLICY_FILE` | `--policy` | — | путь к policy.json |
| `PROXY_TOKEN` | `--token` | — | токен доступа к прокси |
| `LOG_LEVEL` | — | `INFO` | уровень логирования |

Если прокси слушает не loopback-адрес и токен не задан, при старте будет предупреждение.

## Служебные эндпоинты

- `GET /_health` — `{"status":"ok"}`, без авторизации.
- `GET /_metrics` — счётчики в формате Prometheus (`redactproxy_requests_total`, `redactproxy_findings_total{type="EMAIL"}` и др.).
- `POST /_redact` — dry-run: `{"text":"..."}` → `{"text":"[EMAIL_1]","findings":{"EMAIL":1}}`; при `block` — 422.

Остальные пути пересылаются апстриму. Коды ответов прокси: 401 — неверный токен, 411 — chunked-запрос, 413 — тело больше лимита, 415 — неподдерживаемый тип тела, 422 — заблокировано политикой, 400 — невалидное тело, 502 — апстрим недоступен.

## Детекторы

18 встроенных: `PRIVATE_KEY`, `AWS_KEY`, `GITHUB_TOKEN`, `API_KEY`, `SLACK_TOKEN`, `JWT`, `BEARER_TOKEN`, `URL_CREDENTIALS`, `SECRET` (все — `redact`), `CREDIT_CARD` (Luhn), `IBAN` (mod-97), `INN`, `SNILS` (контрольные суммы), `PASSPORT_RU`, `SSN`, `EMAIL`, `PHONE`, `IP_ADDRESS` (все — `mask`). Список с приоритетами: `python tools.py list`.

При пересечении побеждает детектор с меньшим приоритетом, затем более длинное совпадение.

## Политика

См. `policy.example.json`: `actions` (действие по типу), `disabled` (отключённые детекторы), `allowlist` (точные значения-исключения), `custom` (свои детекторы: `name`, `pattern`, `ignore_case`, `group`, `priority`, `action`), `unmask_responses`, `passthrough_binary`. Лишние ключи (например `_comment`) игнорируются. Проверка файла: `python tools.py check policy.json`.

## Расширение

Свой детектор можно передать в `Redactor(extra_detectors=[...])`, либо унаследоваться от `Redactor` и переопределить `find()` (например, чтобы добавить поиск имён через NER). Пример — `NameRedactor` в `test_redactproxy.py`.

## CLI

```bash
echo "пишите ivan@corp.ru" | python redactproxy.py scan --policy policy.example.json
# stdout: пишите [EMAIL_1]
# stderr: {"findings": ["EMAIL"]}
```

## Docker

```bash
docker build -t redactproxy .
docker run --rm -p 8080:8080 \
  -e PROXY_TOKEN=... -e UPSTREAM_URL=https://api.openai.com redactproxy
```

## Тесты

```bash
python -m unittest -v test_redactproxy
```

## Ограничения

- Маскируются только строковые значения JSON и `text/*`; бинарные тела отклоняются (415), если не включён `passthrough_binary`.
- Обратная подстановка в стриме работает для `choices[].delta.content` (OpenAI) и `content_block_delta.delta.text` (Anthropic); аргументы вызова функций и другие поля не восстанавливаются.
- Детекторы основаны на регулярных выражениях и контрольных суммах; это снижает риск утечки, но не гарантирует обнаружение всех данных.
- Запросы с `Transfer-Encoding: chunked` не поддерживаются; сжатие ответов отключено (`Accept-Encoding: identity`).
- Сам прокси не шифрует трафик: в продакшене запускайте его за TLS-терминатором или в доверенной сети.
