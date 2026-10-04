#!/usr/bin/env python3
"""RedactProxy — прокси-шлюз, маскирующий PII и секреты в запросах к LLM API.

Запрос клиента маскируется, уходит провайдеру, а в ответе (JSON и SSE-стрим)
обратимые токены заменяются исходными значениями. Секреты («redact») необратимы.
Значения PII и секретов никогда не попадают в логи, метрики и исключения.

Разделы модуля: 1) детекторы, 2) ядро, 3) HTTP-прокси, 4) CLI.
"""
from __future__ import annotations

import argparse
import copy
import hmac
import json
import logging
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

__version__ = "0.1.0"

log = logging.getLogger("redactproxy")

# =====================================================================
# РАЗДЕЛ 1. ДЕТЕКТОРЫ
# =====================================================================


@dataclass(frozen=True)
class Detector:
    """Описание одного детектора чувствительных данных."""

    name: str
    pattern: "re.Pattern[str]"
    validator: Optional[Callable[[str], bool]] = None
    group: int = 0
    priority: int = 50
    default_action: str = "mask"  # mask | redact | block | allow


def _digits(value: str) -> str:
    """Оставляет в строке только цифры."""
    return re.sub(r"\D", "", value)


def luhn(value: str) -> bool:
    """Проверка номера карты по алгоритму Луна (13-19 цифр, не все одинаковые)."""
    d = _digits(value)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban(value: str) -> bool:
    """Проверка IBAN: длина 15-34 и контрольная сумма mod-97."""
    s = re.sub(r"\s", "", value).upper()
    if not 15 <= len(s) <= 34 or not s.isalnum():
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


_INN10 = [2, 4, 10, 3, 5, 9, 4, 6, 8]
_INN12_1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
_INN12_2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]


def inn(value: str) -> bool:
    """Проверка ИНН (10 и 12 цифр) по контрольным суммам ФНС."""
    d = [int(c) for c in _digits(value)]

    def ctrl(coefs: List[int], digs: List[int]) -> int:
        return sum(c * x for c, x in zip(coefs, digs)) % 11 % 10

    if len(d) == 10:
        return ctrl(_INN10, d[:9]) == d[9]
    if len(d) == 12:
        return ctrl(_INN12_1, d[:10]) == d[10] and ctrl(_INN12_2, d[:11]) == d[11]
    return False


def snils(value: str) -> bool:
    """Проверка СНИЛС: контрольное число из последних двух цифр."""
    d = _digits(value)
    if len(d) != 11:
        return False
    total = sum(int(d[i]) * (9 - i) for i in range(9))
    if total < 100:
        ctrl = total
    elif total in (100, 101):
        ctrl = 0
    else:
        ctrl = total % 101
        if ctrl in (100, 101):
            ctrl = 0
    return ctrl == int(d[9:])


def phone(value: str) -> bool:
    """Телефон: от 10 до 15 цифр."""
    return 10 <= len(_digits(value)) <= 15


def ipv4(value: str) -> bool:
    """IPv4: исключаем «пустой» и loopback-адреса."""
    return value not in ("0.0.0.0", "127.0.0.1")


_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

DEFAULT_DETECTORS: List[Detector] = [
    Detector("PRIVATE_KEY",
             re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
             priority=1, default_action="redact"),
    Detector("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
             priority=5, default_action="redact"),
    Detector("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
             priority=5, default_action="redact"),
    Detector("API_KEY", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"),
             priority=5, default_action="redact"),
    Detector("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
             priority=5, default_action="redact"),
    Detector("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
             priority=6, default_action="redact"),
    Detector("BEARER_TOKEN", re.compile(r"\bbearer\s+([A-Za-z0-9._~+/=-]{16,})", re.I),
             group=1, priority=7, default_action="redact"),
    Detector("URL_CREDENTIALS",
             re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@", re.I),
             group=1, priority=8, default_action="redact"),
    Detector("SECRET",
             re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token|пароль)"
                        r"\b\s*[:=]\s*[\"']?([^\s\"',;]{4,})", re.I),
             group=1, priority=9, default_action="redact"),
    Detector("CREDIT_CARD", re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])"),
             validator=luhn, priority=20),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
             validator=iban, priority=21),
    Detector("INN", re.compile(r"\bинн\b\D{0,3}(\d{12}|\d{10})\b", re.I),
             validator=inn, group=1, priority=30),
    Detector("SNILS", re.compile(r"\b\d{3}-\d{3}-\d{3}[ -]\d{2}\b"),
             validator=snils, priority=30),
    Detector("PASSPORT_RU", re.compile(r"паспорт\D{0,15}(\d{2}\s?\d{2}\s?\d{6})", re.I),
             group=1, priority=30),
    Detector("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
             priority=31),
    Detector("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
             priority=40),
    Detector("PHONE",
             re.compile(r"(?<![\w+])(?:\+\d{1,3}|8)[\s\-(]*\d{2,4}[\s\-)]*\d{2,4}[\s\-]*\d{2,4}"
                        r"(?:[\s\-]*\d{2,4})?(?!\w)"),
             validator=phone, priority=50),
    Detector("IP_ADDRESS", re.compile(r"\b(?:" + _OCTET + r"\.){3}" + _OCTET + r"\b"),
             validator=ipv4, priority=60),
]


def build_custom(spec: dict) -> Detector:
    """Строит детектор из описания в политике (поле custom)."""
    flags = re.I if spec.get("ignore_case") else 0
    return Detector(
        name=str(spec["name"]).upper(),
        pattern=re.compile(spec["pattern"], flags),
        group=int(spec.get("group", 0)),
        priority=int(spec.get("priority", 45)),
        default_action=str(spec.get("action", "mask")).lower(),
    )


# =====================================================================
# РАЗДЕЛ 2. ЯДРО
# =====================================================================

TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")
PARTIAL_RE = re.compile(r"\[[A-Z0-9_]{0,40}$")
SKIP_KEYS = {"model", "role", "type", "id", "object", "stop_reason", "finish_reason"}


class BlockedError(Exception):
    """Запрос заблокирован политикой. Хранит только типы, не значения."""

    def __init__(self, kinds) -> None:
        self.kinds: List[str] = sorted(set(kinds))
        super().__init__("request blocked by policy: " + ", ".join(self.kinds))


class UnsupportedBody(Exception):
    """Тип тела запроса не поддерживается (fail-closed)."""


@dataclass
class Finding:
    """Одна находка: тип, границы в тексте и применённое действие."""

    kind: str
    start: int
    end: int
    action: str


class Vault:
    """Хранилище соответствий токен ↔ значение на время одного запроса."""

    def __init__(self) -> None:
        self._by_token: Dict[str, str] = {}
        self._by_value: Dict[tuple, str] = {}
        self._counts: Counter = Counter()

    def token_for(self, kind: str, value: str) -> str:
        """Возвращает токен вида [KIND_N]; одно значение — один токен."""
        key = (kind, value)
        token = self._by_value.get(key)
        if token is None:
            self._counts[kind] += 1
            token = "[%s_%d]" % (kind, self._counts[kind])
            self._by_value[key] = token
            self._by_token[token] = value
        return token

    def restore(self, text: str) -> str:
        """Подставляет оригиналы вместо известных токенов, неизвестные не трогает."""
        if not self._by_token or not text:
            return text
        return TOKEN_RE.sub(lambda m: self._by_token.get(m.group(0), m.group(0)), text)

    def __len__(self) -> int:
        """Число токенов в хранилище."""
        return len(self._by_token)


class StreamUnmasker:
    """Восстанавливает токены в потоке кусков, удерживая «оборванный» хвост."""

    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self._buf = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        m = PARTIAL_RE.search(self._buf)
        if m:
            ready, self._buf = self._buf[: m.start()], self._buf[m.start():]
        else:
            ready, self._buf = self._buf, ""
        return self.vault.restore(ready)

    def flush(self) -> str:
        out = self.vault.restore(self._buf)
        self._buf = ""
        return out


@dataclass
class Policy:
    """Политика: действия по типам, отключённые детекторы, allowlist, свои детекторы."""

    actions: dict = field(default_factory=dict)
    disabled: set = field(default_factory=set)
    allowlist: set = field(default_factory=set)
    custom: list = field(default_factory=list)
    unmask_responses: bool = True
    passthrough_binary: bool = False

    @classmethod
    def from_file(cls, path) -> "Policy":
        """Читает политику из JSON; лишние ключи (например _comment) игнорируются."""
        if not path:
            return cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("policy root must be an object")
        return cls(
            actions={str(k).upper(): str(v).lower() for k, v in dict(data.get("actions", {})).items()},
            disabled={str(x).upper() for x in data.get("disabled", [])},
            allowlist={str(x) for x in data.get("allowlist", [])},
            custom=list(data.get("custom", [])),
            unmask_responses=bool(data.get("unmask_responses", True)),
            passthrough_binary=bool(data.get("passthrough_binary", False)),
        )


class Redactor:
    """Поиск и маскирование чувствительных данных в тексте и JSON."""

    def __init__(self, policy: Optional[Policy] = None, extra_detectors=None) -> None:
        self.policy = policy or Policy()
        disabled = {d.upper() for d in self.policy.disabled}
        detectors = [d for d in DEFAULT_DETECTORS if d.name not in disabled]
        detectors += [build_custom(spec) for spec in self.policy.custom]
        detectors += list(extra_detectors or [])
        self.detectors: List[Detector] = detectors

    def _action(self, det: Detector) -> str:
        return self.policy.actions.get(det.name, det.default_action)

    def find(self, text: str) -> List[Finding]:
        """Находит непересекающиеся совпадения; побеждает меньший priority, затем длиннее."""
        cands = []
        for det in self.detectors:
            for m in det.pattern.finditer(text):
                s, e = m.span(det.group)
                if s < 0:
                    continue
                if det.validator is not None and det.group == 0:
                    while e > s and text[e - 1] in " -":  # хвостовой пробел/дефис не часть значения
                        e -= 1
                value = text[s:e]
                if value in self.policy.allowlist:
                    continue
                if det.validator is not None and not det.validator(value):
                    continue
                cands.append((det.priority, -(e - s), s, e, det))
        cands.sort(key=lambda c: (c[0], c[1], c[2]))
        busy = bytearray(len(text))
        found: List[Finding] = []
        for _prio, _neg, s, e, det in cands:
            if e <= s or any(busy[s:e]):
                continue
            busy[s:e] = b"\x01" * (e - s)
            found.append(Finding(det.name, s, e, self._action(det)))
        found.sort(key=lambda f: f.start)
        return found

    def redact_text(self, text: str, vault: Vault, findings: Optional[List[Finding]] = None) -> str:
        """Маскирует текст. При действии block выбрасывает BlockedError, ничего не возвращая."""
        if not text:
            return text
        blocked = set()
        parts: List[str] = []
        recorded: List[Finding] = []
        pos = 0
        for f in self.find(text):
            if f.action == "allow":
                continue
            if f.action == "block":
                blocked.add(f.kind)
                continue
            if f.action == "redact":
                repl = "[REDACTED:%s]" % f.kind  # секрет в Vault не попадает
            else:
                repl = vault.token_for(f.kind, text[f.start:f.end])
            parts.append(text[pos:f.start])
            parts.append(repl)
            pos = f.end
            recorded.append(f)
        if blocked:
            raise BlockedError(blocked)
        parts.append(text[pos:])
        if findings is not None:
            findings.extend(recorded)
        return "".join(parts)

    def redact_json(self, obj, vault: Vault, findings: Optional[List[Finding]] = None):
        """Рекурсивно маскирует строки; ключи не трогает, значения SKIP_KEYS пропускает."""
        if isinstance(obj, str):
            return self.redact_text(obj, vault, findings)
        if isinstance(obj, list):
            return [self.redact_json(x, vault, findings) for x in obj]
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in SKIP_KEYS and isinstance(v, str):
                    out[k] = v
                else:
                    out[k] = self.redact_json(v, vault, findings)
            return out
        return obj

    def redact_body(self, body: bytes, content_type: str, vault: Vault):
        """Маскирует тело запроса. Возвращает (новое_тело, находки). Fail-closed."""
        findings: List[Finding] = []
        if not body:
            return body, findings
        ctype = (content_type or "").split(";")[0].strip().lower()
        if ctype.endswith("json"):
            try:
                obj = json.loads(body.decode("utf-8"))
            except ValueError:
                raise ValueError("invalid JSON body") from None  # без текста исходной ошибки
            obj = self.redact_json(obj, vault, findings)
            return json.dumps(obj, ensure_ascii=False).encode("utf-8"), findings
        if ctype.startswith("text/"):
            try:
                text = body.decode("utf-8")
            except ValueError:
                raise ValueError("invalid text body") from None
            return self.redact_text(text, vault, findings).encode("utf-8"), findings
        if self.policy.passthrough_binary:
            return body, findings
        raise UnsupportedBody(ctype or "unknown")

    @staticmethod
    def restore_json(obj, vault: Vault):
        """Рекурсивно подставляет оригиналы вместо токенов во всех строках."""
        if isinstance(obj, str):
            return vault.restore(obj)
        if isinstance(obj, list):
            return [Redactor.restore_json(x, vault) for x in obj]
        if isinstance(obj, dict):
            return {k: Redactor.restore_json(v, vault) for k, v in obj.items()}
        return obj


# =====================================================================
# РАЗДЕЛ 3. HTTP-ПРОКСИ
# =====================================================================

AUTH_HEADER = "X-Redact-Proxy-Token"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
       "trailers", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding"}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

DEFAULT_UPSTREAM = "https://api.openai.com"


@dataclass
class Config:
    """Настройки прокси."""

    upstream: str = DEFAULT_UPSTREAM
    host: str = "127.0.0.1"
    port: int = 8080
    timeout: float = 120.0
    max_body: int = 10 * 1024 * 1024
    policy_file: Optional[str] = None
    auth_token: Optional[str] = None

    @classmethod
    def from_env(cls, env=None) -> "Config":
        e = os.environ if env is None else env
        return cls(
            upstream=e.get("UPSTREAM_URL", DEFAULT_UPSTREAM),
            host=e.get("LISTEN_HOST", "127.0.0.1"),
            port=int(e.get("LISTEN_PORT", "8080")),
            timeout=float(e.get("UPSTREAM_TIMEOUT", "120")),
            max_body=int(float(e.get("MAX_BODY_MB", "10")) * 1024 * 1024),
            policy_file=e.get("POLICY_FILE") or None,
            auth_token=e.get("PROXY_TOKEN") or None,
        )


def _slots(obj) -> list:
    """Находит текстовые дельты в событии: список (слот, контейнер, ключ).

    OpenAI: choices[i].delta.content -> слот ("c", index);
    Anthropic: content_block_delta -> delta.text -> слот ("a", index).
    """
    out = []
    if not isinstance(obj, dict):
        return out
    if obj.get("type") == "content_block_delta":
        delta = obj.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            out.append((("a", obj.get("index", 0)), delta, "text"))
    choices = obj.get("choices")
    if isinstance(choices, list):
        for i, ch in enumerate(choices):
            if not isinstance(ch, dict):
                continue
            delta = ch.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                out.append((("c", ch.get("index", i)), delta, "content"))
    return out


def _sse_line(obj) -> bytes:
    return b"data: " + json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"


def sse_unmask(resp, vault: Vault) -> Iterator[bytes]:
    """Построчно читает SSE-ответ апстрима и отдаёт байты с восстановленными токенами."""
    unmaskers: Dict[tuple, StreamUnmasker] = {}
    last: Dict[tuple, dict] = {}

    def tails(only=None) -> List[bytes]:
        """Сбрасывает удержанные хвосты отдельными событиями."""
        out = []
        for slot, um in unmaskers.items():
            if only is not None and slot not in only:
                continue
            tail = um.flush()
            if not tail:
                continue
            ev = copy.deepcopy(last[slot])
            for s, cont, key in _slots(ev):
                cont[key] = tail if s == slot else ""
            prefix = b"event: content_block_delta\n" if slot[0] == "a" else b""
            out.append(prefix + _sse_line(ev) + b"\n")
        return out

    held: List[bytes] = []  # строки event:/id:/retry:, ожидающие своего data:
    for line in iter(resp.readline, b""):
        if line.startswith((b"event:", b"id:", b"retry:")):
            held.append(line)
            continue
        if not line.startswith(b"data:"):
            yield from held
            held = []
            yield line
            continue
        payload = line[5:].strip()
        if payload == b"[DONE]":
            yield from tails()
            yield from held
            held = []
            yield line
            continue
        try:
            ev = json.loads(payload.decode("utf-8"))
        except ValueError:
            yield from held
            held = []
            yield line
            continue
        etype = ev.get("type") if isinstance(ev, dict) else None
        if etype == "message_stop":
            yield from tails()
        elif etype == "content_block_stop":
            yield from tails({("a", ev.get("index", 0))})
        yield from held
        held = []
        slots = _slots(ev)
        if not slots:
            yield line
            continue
        snapshot = copy.deepcopy(ev)
        for slot, cont, key in slots:
            um = unmaskers.get(slot)
            if um is None:
                um = unmaskers[slot] = StreamUnmasker(vault)
            last[slot] = snapshot
            cont[key] = um.feed(cont[key])
        yield _sse_line(ev)
    yield from tails()
    yield from held


class Metrics:
    """Потокобезопасные счётчики в формате Prometheus. Только типы и числа."""

    COUNTERS = ("requests_total", "blocked_total", "rejected_total",
                "unauthorized_total", "upstream_errors_total")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter = Counter()
        self._findings: Counter = Counter()

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counters[name] += n

    def add_findings(self, counts: Dict[str, int]) -> None:
        with self._lock:
            for kind, n in counts.items():
                self._findings[kind] += n

    def render(self) -> str:
        with self._lock:
            lines = []
            for name in self.COUNTERS:
                lines.append("# TYPE redactproxy_%s counter" % name)
                lines.append("redactproxy_%s %d" % (name, self._counters[name]))
            lines.append("# TYPE redactproxy_findings_total counter")
            for kind in sorted(self._findings):
                lines.append('redactproxy_findings_total{type="%s"} %d' % (kind, self._findings[kind]))
        return "\n".join(lines) + "\n"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # без chunked: стрим идёт «как есть» до закрытия соединения
    server_version = "RedactProxy/" + __version__

    def log_message(self, fmt, *args) -> None:  # штатный access-лог отключён
        pass

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = lambda self: self._handle()

    # --- вспомогательные ответы ---
    def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _relay_head(self, status: int, headers, length: Optional[int]) -> None:
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() in HOP or k.lower() in ("server", "date"):
                continue
            self.send_header(k, v)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.end_headers()

    # --- основной обработчик ---
    def _handle(self) -> None:
        srv: "ProxyServer" = self.server  # type: ignore[assignment]
        cfg, metrics, redactor = srv.cfg, srv.metrics, srv.redactor
        method = self.command
        route = self.path.split("?", 1)[0]

        # 1) health без авторизации
        if method == "GET" and route == "/_health":
            return self._json(200, {"status": "ok"})

        # 2) авторизация
        if cfg.auth_token:
            got = self.headers.get(AUTH_HEADER, "")
            if not hmac.compare_digest(got.encode("utf-8"), cfg.auth_token.encode("utf-8")):
                metrics.inc("unauthorized_total")
                return self._json(401, {"error": "unauthorized"})

        # 3) метрики
        if method == "GET" and route == "/_metrics":
            return self._send(200, metrics.render().encode("utf-8"), "text/plain; version=0.0.4")

        # 4) чтение тела
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            return self._json(411, {"error": "chunked request bodies are not supported"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if length < 0:
            return self._json(400, {"error": "bad Content-Length"})
        if length > cfg.max_body:
            return self._json(413, {"error": "request body too large"})
        body = self.rfile.read(length) if length else b""

        # 5) dry-run
        if method == "POST" and route == "/_redact":
            try:
                data = json.loads(body.decode("utf-8"))
                text = data["text"]
                if not isinstance(text, str):
                    raise ValueError("text must be a string")
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "expected JSON {\"text\": \"...\"}"})
            findings: List[Finding] = []
            try:
                masked = redactor.redact_text(text, Vault(), findings)
            except BlockedError as exc:
                return self._json(422, {"blocked": exc.kinds})
            counts = Counter(f.kind for f in findings)
            return self._json(200, {"text": masked, "findings": dict(sorted(counts.items()))})

        # 6) маскирование запроса
        metrics.inc("requests_total")
        vault = Vault()
        try:
            new_body, findings = redactor.redact_body(body, self.headers.get("Content-Type", ""), vault)
        except BlockedError as exc:
            metrics.inc("blocked_total")
            log.warning("BLOCKED %s %s kinds=%s", method, route, exc.kinds)
            return self._json(422, {"error": {"type": "redaction_blocked", "message": str(exc),
                                              "kinds": exc.kinds}})
        except UnsupportedBody:
            metrics.inc("rejected_total")
            return self._json(415, {"error": "unsupported content type"})
        except ValueError:
            metrics.inc("rejected_total")
            return self._json(400, {"error": "invalid body (fail-closed)"})

        # 7) метрики и лог: только типы и счётчики
        counts = Counter(f.kind for f in findings)
        metrics.add_findings(counts)
        log.info("%s %s redacted=%s", method, route, dict(sorted(counts.items())))

        # 8) пересылка апстриму
        url = cfg.upstream.rstrip("/") + self.path
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP and k.lower() != AUTH_HEADER.lower()}
        headers["Accept-Encoding"] = "identity"
        data_out = new_body if (new_body or method in ("POST", "PUT", "PATCH")) else None
        req = urllib.request.Request(url, data=data_out, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=cfg.timeout)
        except urllib.error.HTTPError as err:
            resp = err  # ответ апстрима с кодом ошибки отдаём клиенту как есть
        except Exception as exc:  # noqa: BLE001 — логируем только тип ошибки
            metrics.inc("upstream_errors_total")
            log.error("upstream error %s %s: %s", method, route, type(exc).__name__)
            return self._json(502, {"error": "upstream unavailable"})

        # 9) ответ клиенту
        try:
            status = resp.getcode()
            rheaders = resp.headers
            base = (rheaders.get("Content-Type", "") or "").split(";")[0].strip().lower()
            can_unmask = redactor.policy.unmask_responses and len(vault) > 0

            if base == "text/event-stream":
                self._relay_head(status, rheaders, None)
                chunks = sse_unmask(resp, vault) if can_unmask else iter(resp.readline, b"")
                try:
                    for chunk in chunks:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except OSError:
                    log.info("client disconnected during stream")
                return

            data = resp.read()
            if can_unmask:
                if base.endswith("json"):
                    try:
                        obj = json.loads(data.decode("utf-8"))
                        data = json.dumps(Redactor.restore_json(obj, vault),
                                          ensure_ascii=False).encode("utf-8")
                    except ValueError:
                        pass  # не JSON — отдаём как есть
                elif base.startswith("text/"):
                    try:
                        data = vault.restore(data.decode("utf-8")).encode("utf-8")
                    except UnicodeDecodeError:
                        pass
            self._relay_head(status, rheaders, len(data))
            self.wfile.write(data)
        finally:
            resp.close()


class ProxyServer(ThreadingHTTPServer):
    """HTTP-сервер прокси: хранит конфиг, Redactor и метрики."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, cfg: Config, redactor: Optional[Redactor] = None,
                 metrics: Optional[Metrics] = None) -> None:
        super().__init__(server_address, _Handler)
        self.cfg = cfg
        self.redactor = redactor or Redactor(Policy.from_file(cfg.policy_file))
        self.metrics = metrics or Metrics()

    def handle_error(self, request, client_address) -> None:
        # Не печатаем трейсбэк с возможными данными — только тип ошибки.
        exc_type = sys.exc_info()[0]
        log.error("handler error: %s", exc_type.__name__ if exc_type else "unknown")


def serve(cfg: Config) -> None:
    """Запускает прокси и работает до Ctrl+C."""
    redactor = Redactor(Policy.from_file(cfg.policy_file))
    if not cfg.auth_token and cfg.host not in LOOPBACK:
        log.warning("прокси слушает %s без PROXY_TOKEN — любой в сети сможет им пользоваться", cfg.host)
    server = ProxyServer((cfg.host, cfg.port), cfg, redactor)
    log.info("listening on http://%s:%d -> %s", cfg.host, server.server_address[1], cfg.upstream)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("stopping")
    finally:
        server.server_close()


# =====================================================================
# РАЗДЕЛ 4. CLI
# =====================================================================


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="redactproxy", description="Прокси-маскировщик PII и секретов для LLM API")
    parser.add_argument("--version", action="version", version="redactproxy " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="запустить прокси")
    p_serve.add_argument("--upstream", help="URL апстрима (env UPSTREAM_URL)")
    p_serve.add_argument("--host", help="адрес прослушивания (env LISTEN_HOST)")
    p_serve.add_argument("--port", type=int, help="порт (env LISTEN_PORT)")
    p_serve.add_argument("--policy", help="путь к policy.json (env POLICY_FILE)")
    p_serve.add_argument("--token", help="токен доступа к прокси (env PROXY_TOKEN)")

    p_scan = sub.add_parser("scan", help="замаскировать stdin; находки — в stderr")
    p_scan.add_argument("--policy", help="путь к policy.json")

    args = parser.parse_args(argv)
    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        if args.command == "serve":
            cfg = Config.from_env()
            if args.upstream:
                cfg.upstream = args.upstream
            if args.host:
                cfg.host = args.host
            if args.port is not None:
                cfg.port = args.port
            if args.policy:
                cfg.policy_file = args.policy
            if args.token:
                cfg.auth_token = args.token
            serve(cfg)
            return 0

        redactor = Redactor(Policy.from_file(args.policy))
        vault = Vault()
        findings: List[Finding] = []
        try:
            out = redactor.redact_text(sys.stdin.read(), vault, findings)
        except BlockedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        sys.stdout.write(out)
        sys.stdout.flush()
        print(json.dumps({"findings": sorted({f.kind for f in findings})}), file=sys.stderr)
        return 0
    except (OSError, ValueError, KeyError, TypeError, re.error) as exc:
        print("ошибка: %s" % type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
