#!/usr/bin/env python3
"""Служебные утилиты RedactProxy (только стандартная библиотека).

Команды:
  python tools.py list              — таблица детекторов (имя, приоритет, действие)
  python tools.py check policy.json — проверка файла политики
  python tools.py bench [-n 2000]   — грубый замер скорости маскирования
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

from redactproxy import DEFAULT_DETECTORS, Redactor, Vault

VALID_ACTIONS = ("mask", "redact", "block", "allow")


def check_policy(path) -> list:
    """Возвращает список ошибок политики (пустой список — всё в порядке)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        return ["не удалось прочитать файл: %s" % (exc.strerror or "ошибка ввода-вывода")]
    except ValueError:
        return ["файл не является корректным JSON"]
    if not isinstance(data, dict):
        return ["корень политики должен быть объектом"]

    errors = []
    known = {d.name for d in DEFAULT_DETECTORS}

    custom = data.get("custom", [])
    if not isinstance(custom, list):
        errors.append("custom: ожидается список")
        custom = []
    for i, spec in enumerate(custom):
        where = "custom[%d]" % i
        if not isinstance(spec, dict):
            errors.append(where + ": ожидается объект")
            continue
        name, pattern = spec.get("name"), spec.get("pattern")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            errors.append(where + ": name должно быть латинским идентификатором")
        else:
            known.add(name.upper())
        compiled = None
        if not isinstance(pattern, str):
            errors.append(where + ": pattern должен быть строкой")
        else:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                errors.append("%s: некорректный pattern (%s)" % (where, exc.msg))
        group = spec.get("group", 0)
        if not isinstance(group, int) or group < 0:
            errors.append(where + ": group должен быть целым числом >= 0")
        elif compiled is not None and group > compiled.groups:
            errors.append(where + ": group больше числа групп в pattern")
        if not isinstance(spec.get("priority", 45), int):
            errors.append(where + ": priority должен быть целым числом")
        if str(spec.get("action", "mask")).lower() not in VALID_ACTIONS:
            errors.append(where + ": action должен быть одним из " + "/".join(VALID_ACTIONS))

    actions = data.get("actions", {})
    if not isinstance(actions, dict):
        errors.append("actions: ожидается объект")
    else:
        for kind, action in actions.items():
            if str(kind).upper() not in known:
                errors.append("actions: неизвестный тип %s" % kind)
            if str(action).lower() not in VALID_ACTIONS:
                errors.append("actions.%s: допустимы %s" % (kind, "/".join(VALID_ACTIONS)))

    disabled = data.get("disabled", [])
    if not isinstance(disabled, list):
        errors.append("disabled: ожидается список")
    else:
        for kind in disabled:
            if str(kind).upper() not in known:
                errors.append("disabled: неизвестный тип %s" % kind)

    allowlist = data.get("allowlist", [])
    if not isinstance(allowlist, list) or not all(isinstance(x, str) for x in allowlist):
        errors.append("allowlist: ожидается список строк")

    for key in ("unmask_responses", "passthrough_binary"):
        if key in data and not isinstance(data[key], bool):
            errors.append("%s: ожидается true/false" % key)
    return errors


def cmd_list(_args) -> int:
    print("%-16s %-9s %s" % ("ТИП", "ПРИОРИТЕТ", "ДЕЙСТВИЕ"))
    for det in sorted(DEFAULT_DETECTORS, key=lambda d: (d.priority, d.name)):
        print("%-16s %-9d %s" % (det.name, det.priority, det.default_action))
    return 0


def cmd_check(args) -> int:
    errors = check_policy(args.policy)
    if errors:
        for err in errors:
            print("ОШИБКА:", err, file=sys.stderr)
        return 1
    print("Политика корректна.")
    return 0


def cmd_bench(args) -> int:
    sample = ("Клиент ivan@corp.ru, тел. +7 (495) 123-45-67, карта 4111 1111 1111 1111, "
              "ключ AKIAIOSFODNN7EXAMPLE, хост 10.20.30.40. Обычный текст без данных. " * 3)
    redactor = Redactor()
    start = time.perf_counter()
    for _ in range(args.n):
        redactor.redact_text(sample, Vault(), [])
    elapsed = max(time.perf_counter() - start, 1e-9)
    kb = len(sample.encode("utf-8")) * args.n / 1024
    print("итераций: %d, время: %.2f с, скорость: %.0f КБ/с, %.0f запросов/с"
          % (args.n, elapsed, kb / elapsed, args.n / elapsed))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="tools.py", description="Утилиты RedactProxy")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="показать встроенные детекторы").set_defaults(func=cmd_list)
    p_check = sub.add_parser("check", help="проверить policy.json")
    p_check.add_argument("policy")
    p_check.set_defaults(func=cmd_check)
    p_bench = sub.add_parser("bench", help="замер скорости")
    p_bench.add_argument("-n", type=int, default=2000, help="число итераций")
    p_bench.set_defaults(func=cmd_bench)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
