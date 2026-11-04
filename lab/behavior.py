"""Versioned append-only JSONL evidence for native behavior mapping."""
import hashlib
import json
import pathlib

SCHEMA = 1
STATUSES = frozenset(("ok", "observe", "skip", "error"))


def catalog_digest(expected):
    return hashlib.sha256(("\n".join(expected) + "\n").encode("utf-8")).hexdigest()


def load_jsonl(path):
    rows = []
    path = pathlib.Path(path)
    if not path.exists():
        return rows
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise ValueError(f"{path}:{number}: empty JSONL row")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{number}: row is not an object")
        rows.append(row)
    return rows


class RowWriter:
    """Write one durable line per semantic key and a final summary."""

    def __init__(self, path, platform, domain, expected):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.platform = platform
        self.domain = domain
        self.expected = tuple(expected)
        if len(self.expected) != len(set(self.expected)):
            raise ValueError("behavior catalog contains duplicate keys")
        self.expected_set = set(self.expected)
        self.seen = set()
        self.counts = {status: 0 for status in STATUSES}
        self.finished = False

    def _append(self, row):
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n")
            stream.flush()

    def emit(self, key, status, details):
        if self.finished:
            raise ValueError("behavior writer already finished")
        if key not in self.expected_set:
            raise ValueError(f"unexpected behavior key: {key}")
        if key in self.seen:
            raise ValueError(f"duplicate behavior key: {key}")
        if status not in STATUSES:
            raise ValueError(f"invalid behavior status: {status}")
        if not isinstance(details, dict):
            raise TypeError("behavior details must be an object")
        self.seen.add(key)
        self.counts[status] += 1
        self._append(dict(schema=SCHEMA, platform=self.platform, domain=self.domain,
                          key=key, status=status, details=details))

    def finish(self, worker=None):
        if self.finished:
            raise ValueError("behavior writer already finished")
        self.finished = True
        summary = dict(schema=SCHEMA, platform=self.platform, domain=self.domain,
                       key="summary", status="ok" if self.seen == self.expected_set and self.counts["error"] == 0 else "error",
                       details=dict(expected=len(self.expected), completed=len(self.seen),
                                    missing=sorted(self.expected_set - self.seen), counts=self.counts,
                                    catalog_sha256=catalog_digest(self.expected), worker=worker or {}))
        self._append(summary)
        return summary


def validate_jsonl(path, platform, domain, expected):
    expected = tuple(expected)
    rows = load_jsonl(path)
    if not rows:
        raise ValueError("behavior output is empty")
    summaries = [row for row in rows if row.get("key") == "summary"]
    if len(summaries) != 1 or rows[-1] is not summaries[0]:
        raise ValueError("behavior summary must exist exactly once and be final")
    body = rows[:-1]
    keys = []
    counts = {status: 0 for status in STATUSES}
    for number, row in enumerate(rows, 1):
        if row.get("schema") != SCHEMA or row.get("platform") != platform or row.get("domain") != domain:
            raise ValueError(f"behavior identity mismatch at row {number}")
        if not isinstance(row.get("details"), dict):
            raise ValueError(f"behavior details missing at row {number}")
        if row is summaries[0]:
            continue
        if row.get("status") not in STATUSES or not isinstance(row.get("key"), str):
            raise ValueError(f"invalid behavior row at {number}")
        keys.append(row["key"])
        counts[row["status"]] += 1
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate behavior keys")
    if set(keys) != set(expected):
        missing = sorted(set(expected) - set(keys))
        unexpected = sorted(set(keys) - set(expected))
        raise ValueError(f"behavior catalog mismatch: missing={missing[:8]} unexpected={unexpected[:8]}")
    summary = summaries[0]
    details = summary["details"]
    if (summary.get("status") != "ok" or details.get("expected") != len(expected)
            or details.get("completed") != len(expected) or details.get("missing") != []
            or details.get("catalog_sha256") != catalog_digest(expected)
            or details.get("counts") != counts):
        raise ValueError("behavior summary contradicts rows")
    return details
