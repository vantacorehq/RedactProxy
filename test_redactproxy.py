"""Тесты RedactProxy (unittest, без зависимостей). Запуск: python -m unittest -v"""
import os

os.environ["no_proxy"] = "127.0.0.1,localhost"  # локальные запросы мимо системного прокси

import json
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from redactproxy import (BlockedError, Config, Detector, Finding, Policy, ProxyServer,
                         Redactor, StreamUnmasker, Vault)

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
       "-----END RSA PRIVATE KEY-----")


def mask(text, redactor=None):
    """Маскирует текст, возвращает (результат, vault)."""
    vault = Vault()
    out = (redactor or Redactor()).redact_text(text, vault, [])
    return out, vault


class RedactorTests(unittest.TestCase):
    def test_email_phone_roundtrip(self):
        text = "Позвоните +7 (495) 123-45-67 или пишите a@b.com"
        out, vault = mask(text)
        self.assertIn("[PHONE_1]", out)
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)
        self.assertEqual(vault.restore(out), text)

    def test_same_value_same_token(self):
        out, _ = mask("a@b.com, again a@b.com, and c@d.com")
        self.assertEqual(out, "[EMAIL_1], again [EMAIL_1], and [EMAIL_2]")

    def test_credit_card_luhn(self):
        out, _ = mask("Карта 4111 1111 1111 1111.")
        self.assertIn("[CREDIT_CARD_1]", out)
        bad = "Карта 1234 5678 9012 3456."
        self.assertEqual(mask(bad)[0], bad)  # не проходит Luhn

    def test_inn_and_snils(self):
        self.assertEqual(mask("ИНН 7707083893")[0], "ИНН [INN_1]")
        self.assertEqual(mask("ИНН 7707083894")[0], "ИНН 7707083894")
        self.assertEqual(mask("СНИЛС 112-233-445 95")[0], "СНИЛС [SNILS_1]")

    def test_iban(self):
        self.assertEqual(mask("IBAN GB82WEST12345698765432")[0], "IBAN [IBAN_1]")

    def test_secrets_are_irreversible(self):
        out, vault = mask("key AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(out, "key [REDACTED:AWS_KEY]")
        out2, vault2 = mask("password: hunter2hunter")
        self.assertEqual(out2, "password: [REDACTED:SECRET]")
        self.assertNotIn("hunter2hunter", vault2.restore(out2))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", vault.restore(out))
        self.assertEqual(len(vault) + len(vault2), 0)

    def test_pem_and_url_credentials(self):
        out, _ = mask("Ключ:\n" + PEM + "\nконец")
        self.assertEqual(out, "Ключ:\n[REDACTED:PRIVATE_KEY]\nконец")
        out, _ = mask("postgres://admin:s3cretPass@db:5432/x")
        self.assertEqual(out, "postgres://admin:[REDACTED:URL_CREDENTIALS]@db:5432/x")

    def test_block_raises(self):
        redactor = Redactor(Policy(actions={"EMAIL": "block"}))
        with self.assertRaises(BlockedError) as ctx:
            redactor.redact_text("write to a@b.com", Vault())
        self.assertEqual(ctx.exception.kinds, ["EMAIL"])
        self.assertEqual(str(ctx.exception), "request blocked by policy: EMAIL")

    def test_allowlist_disabled_custom(self):
        text = "support@corp.com"
        self.assertEqual(mask(text, Redactor(Policy(allowlist={"support@corp.com"})))[0], text)
        self.assertEqual(mask("a@b.com", Redactor(Policy(disabled={"EMAIL"})))[0], "a@b.com")
        custom = Policy(custom=[{"name": "emp_id", "pattern": r"\bEMP-\d{5}\b"}])
        self.assertEqual(mask("id EMP-12345", Redactor(custom))[0], "id [EMP_ID_1]")

    def test_redact_json_skips_model_and_role(self):
        obj = {"model": "m@x.io", "role": "r@x.io", "content": "c@x.io"}
        out = Redactor().redact_json(obj, Vault(), [])
        self.assertEqual(out, {"model": "m@x.io", "role": "r@x.io", "content": "[EMAIL_1]"})

    def test_stream_unmasker(self):
        vault = Vault()
        vault.token_for("EMAIL", "a@b.com")
        um = StreamUnmasker(vault)
        out = "".join(um.feed(c) for c in ["Hi [EM", "AIL_", "1] bye [x"]) + um.flush()
        self.assertEqual(out, "Hi a@b.com bye [x")


class NameRedactor(Redactor):
    """Пример расширения: добавляет собственный детектор имени поверх встроенных."""

    NAME = "Иван Петров"

    def find(self, text):
        found = super().find(text)
        i = text.find(self.NAME)
        if i >= 0:
            s, e = i, i + len(self.NAME)
            if all(f.end <= s or f.start >= e for f in found):
                found.append(Finding("PERSON", s, e, "mask"))
                found.sort(key=lambda f: f.start)
        return found


class ExtensionTests(unittest.TestCase):
    def test_extra_detectors(self):
        det = Detector("TICKET", re.compile(r"\bJIRA-\d+\b"))
        out, _ = mask("see JIRA-42", Redactor(extra_detectors=[det]))
        self.assertEqual(out, "see [TICKET_1]")

    def test_subclass_overrides_find(self):
        text = "Клиент Иван Петров, ivan@corp.ru"
        out, vault = mask(text, NameRedactor())
        self.assertEqual(out, "Клиент [PERSON_1], [EMAIL_1]")
        self.assertEqual(vault.restore(out), text)


# ---------------------------------------------------------------- прокси ---

class _UpstreamHandler(BaseHTTPRequestHandler):
    """Поддельный апстрим: эхо (JSON) или SSE кусками по 4 символа."""

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.received.append(raw.decode("utf-8"))
        data = json.loads(raw)
        content = data["messages"][0]["content"]
        if data.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(0, len(content), 4):
                ev = {"choices": [{"index": 0, "delta": {"content": content[i:i + 4]}}]}
                self.wfile.write(("data: " + json.dumps(ev) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
        else:
            body = json.dumps({"id": "1", "model": data["model"], "choices": [
                {"message": {"role": "assistant", "content": "Echo: " + content}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _call(base, path, payload=None, raw=None, method=None, headers=None):
    data = raw if raw is not None else (json.dumps(payload).encode("utf-8") if payload is not None else None)
    hdrs = {"Content-Type": "application/json"} if data is not None else {}
    hdrs.update(headers or {})
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as err:
        try:
            return err.code, err.read()
        finally:
            err.close()


class ProxyHarness:
    """Поднимает поддельный апстрим и прокси на свободных портах."""

    token = None

    def setUp(self):
        self.up = HTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        self.up.received = []
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        cfg = Config(upstream="http://127.0.0.1:%d" % self.up.server_address[1],
                     host="127.0.0.1", port=0, timeout=10, auth_token=self.token)
        self.proxy = ProxyServer(("127.0.0.1", 0), cfg)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.proxy.server_address[1]

    def tearDown(self):
        for srv in (self.proxy, self.up):
            srv.shutdown()
            srv.server_close()


def _chat(content, stream=False):
    payload = {"model": "gpt-test", "messages": [{"role": "user", "content": content}]}
    if stream:
        payload["stream"] = True
    return payload


class ProxyTests(ProxyHarness, unittest.TestCase):
    def test_json_roundtrip(self):
        status, body = _call(self.base, "/v1/chat/completions",
                             _chat("Mail a@b.com key AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(status, 200)
        sent = self.up.received[0]
        self.assertIn("[EMAIL_1]", sent)
        self.assertNotIn("a@b.com", sent)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sent)  # секрет не уходит вообще
        reply = json.loads(body)["choices"][0]["message"]["content"]
        self.assertIn("a@b.com", reply)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", body.decode("utf-8"))

    def test_sse_roundtrip(self):
        status, body = _call(self.base, "/v1/chat/completions", _chat("Write to a@b.com please", True))
        self.assertEqual(status, 200)
        parts = []
        for line in body.decode("utf-8").splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                parts.append(json.loads(line[6:])["choices"][0]["delta"].get("content", ""))
        text = "".join(parts)
        self.assertEqual(text, "Write to a@b.com please")
        self.assertNotIn("[EMAIL_1]", text)

    def test_dry_run_and_health(self):
        status, body = _call(self.base, "/_redact", {"text": "a@b.com"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"text": "[EMAIL_1]", "findings": {"EMAIL": 1}})
        status, body = _call(self.base, "/_health", method="GET")
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))

    def test_invalid_json_is_rejected(self):
        status, _ = _call(self.base, "/v1/chat/completions", raw=b"{bad json")
        self.assertEqual(status, 400)
        self.assertEqual(self.up.received, [])  # апстрим ничего не получил


class AuthAndMetricsTests(ProxyHarness, unittest.TestCase):
    token = "s3cret-proxy-token"

    def test_requires_token(self):
        status, _ = _call(self.base, "/v1/chat/completions", _chat("hi"))
        self.assertEqual(status, 401)
        status, _ = _call(self.base, "/v1/chat/completions", _chat("hi"),
                          headers={"X-Redact-Proxy-Token": "wrong"})
        self.assertEqual(status, 401)
        self.assertEqual(self.up.received, [])

    def test_token_allows_and_metrics_count(self):
        auth = {"X-Redact-Proxy-Token": self.token}
        status, _ = _call(self.base, "/v1/chat/completions", _chat("Mail a@b.com"), headers=auth)
        self.assertEqual(status, 200)
        status, body = _call(self.base, "/_metrics", method="GET", headers=auth)
        text = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("redactproxy_requests_total 1", text)
        self.assertIn('redactproxy_findings_total{type="EMAIL"} 1', text)
        self.assertNotIn("a@b.com", text)


if __name__ == "__main__":
    unittest.main()
