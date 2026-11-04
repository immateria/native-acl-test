"""Build and parse the standalone Windows SDK ACL mapping probe."""
from __future__ import annotations

import collections
import json
import pathlib
from typing import Iterable


def compile_command(compiler: str, source: pathlib.Path, executable: pathlib.Path,
                    object_file: pathlib.Path) -> list[str]:
    """Return the strict MSVC/clang-cl command used by the native mapper."""
    return [
        compiler,
        "/nologo",
        "/std:c11",
        "/W4",
        "/WX",
        str(source),
        "/Fe:" + str(executable),
        "/Fo:" + str(object_file),
        "/link",
        "advapi32.lib",
        "kernel32.lib",
    ]


def load_jsonl(path: pathlib.Path) -> list[dict]:
    """Load and validate line-delimited mapping records."""
    records: list[dict] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid mapper JSON at line {line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"mapper record at line {line_number} is not an object")
        kind = value.get("kind")
        if not isinstance(kind, str) or not kind:
            raise ValueError(f"mapper record at line {line_number} lacks a nonempty kind")
        records.append(value)
    if not records:
        raise ValueError("mapper produced no records")
    return records


def summarize(records: Iterable[dict]) -> dict:
    """Summarize record kinds and nonzero native outcomes without judging them."""
    values = list(records)
    kinds = collections.Counter(value["kind"] for value in values)
    nonzero = 0
    for value in values:
        for key in ("fixture_code", "open_code", "source_code", "api_code", "cleanup_code", "privilege_code"):
            code = value.get(key)
            if isinstance(code, int) and code != 0:
                nonzero += 1
                break
    return {
        "records": len(values),
        "kinds": dict(sorted(kinds.items())),
        "nonzero_outcomes": nonzero,
    }
