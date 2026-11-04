"""Compare extracted lane artifacts by stable qualification and behavior keys."""
import argparse
import json
import re
from pathlib import Path


VOLATILE_DETAIL_KEYS = frozenset({
    "elapsed", "elapsed_ms", "elapsed_seconds", "started_at", "finished_at",
    "timestamp", "time_ns", "mtime", "mtime_ns", "ctime", "ctime_ns",
    "worker", "python",
})
LOCAL_SID_RE = re.compile(r"^S-1-5-21-(?:[0-9]+-){3}[0-9]+$", re.I)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
GENERATED_ACCOUNT_RE = re.compile(r"^acl[A-Za-z]*_[0-9a-f]{8,}$", re.I)
HEX_VALUE_RE = re.compile(r"^(?:[0-9a-f]{2})+$", re.I)
BINARY_DETAIL_KEYS = frozenset({
    "raw", "hex", "requested_hex", "candidate_ace_hex", "candidate_acl_hex",
    "descriptor_hex", "descriptor", "bytes_hex", "filesec_identity_bytes",
})


def index(path, key, value):
    result = {}
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        ident = key(row)
        if ident is None:
            continue
        if ident in result:
            raise ValueError(f"duplicate key {ident} in {path}")
        result[ident] = value(row)
    return result


def changes(a, b):
    return [
        {"key": key, "before": a.get(key), "after": b.get(key)}
        for key in sorted(a.keys() | b.keys())
        if a.get(key) != b.get(key)
    ]


def _normalize_string(value):
    normalized = value.replace("\\", "/")
    marker = "/native-acl-ci/"
    lower = normalized.lower()
    at = lower.find(marker)
    if at >= 0:
        normalized = "<native-acl-ci>" + normalized[at + len("/native-acl-ci"):]
    normalized = re.sub(r"acl-map-[0-9a-f]{8,}", "acl-map-<id>", normalized, flags=re.I)
    normalized = re.sub(
        r"(?:darwin|windows)-[a-z0-9-]+-[0-9a-f]{16}-[A-Za-z0-9_-]+",
        "<behavior-fixture>", normalized, flags=re.I,
    )
    return normalized


def _identity_placeholder(state, category, value):
    mapping = state.setdefault(category, {})
    if value not in mapping:
        mapping[value] = f"<{category}-{len(mapping) + 1}>"
    return mapping[value]


def normalize_behavior(value, parent_key=None, state=None):
    """Remove host identity/layout noise while retaining parsed ACL semantics.

    Raw descriptors remain available in the artifacts. The semantic projection
    intentionally reduces binary fields to byte lengths because embedded local
    SIDs and Darwin UUIDs differ on every hosted runner; parsed descriptor/ACL
    fields remain in the comparison.
    """
    if state is None:
        state = {}
    if isinstance(value, dict):
        output = {}
        for key in sorted(value):
            if key in VOLATILE_DETAIL_KEYS or key.endswith(("_elapsed", "_duration")):
                continue
            output[key] = normalize_behavior(value[key], key, state)
        return output
    if isinstance(value, list):
        return [normalize_behavior(item, parent_key, state) for item in value]
    if isinstance(value, str):
        normalized = _normalize_string(value)
        if parent_key in BINARY_DETAIL_KEYS or (parent_key and parent_key.endswith("_hex")):
            if HEX_VALUE_RE.fullmatch(value):
                return {"encoding": "hex", "length": len(value) // 2}
        if LOCAL_SID_RE.fullmatch(value):
            return _identity_placeholder(state, "local-sid", value)
        if UUID_RE.fullmatch(value) and parent_key in {
            "principal", "user_uuid", "group_uuid", "owner_uuid", "current_uuid",
        }:
            return _identity_placeholder(state, "principal-uuid", value.lower())
        if GENERATED_ACCOUNT_RE.fullmatch(value):
            return _identity_placeholder(state, "generated-account", value)
        return normalized
    return value


def behavior_index(root):
    result = {}
    behavior_root = root / "behavior"
    if not behavior_root.is_dir():
        return result
    for path in sorted(behavior_root.glob("*.jsonl")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                raise ValueError(f"{path}:{number}: empty behavior row")
            row = json.loads(line)
            if row.get("key") == "summary":
                continue
            domain = row.get("domain")
            key = row.get("key")
            if not isinstance(domain, str) or not isinstance(key, str):
                raise ValueError(f"{path}:{number}: behavior identity missing")
            ident = (domain, key)
            if ident in result:
                raise ValueError(f"duplicate behavior key {ident} in {path}")
            result[ident] = {
                "status": row.get("status"),
                "details": normalize_behavior(row.get("details", {})),
            }
    return result


def _behavior_diff(before, after):
    before_keys = set(before)
    after_keys = set(after)
    coverage = [
        {"key": key, "before": key in before_keys, "after": key in after_keys}
        for key in sorted(before_keys ^ after_keys)
    ]
    semantic = [
        {"key": key, "before": before[key], "after": after[key]}
        for key in sorted(before_keys & after_keys)
        if before[key] != after[key]
    ]
    summary = {}
    for change in semantic:
        domain = change["key"][0]
        summary[domain] = summary.get(domain, 0) + 1
    return semantic, coverage, dict(sorted(summary.items()))


def compare(old, new):
    def get(root):
        if not (root / "run.json").is_file():
            raise ValueError(f"{root}: select an extracted lane artifact, not the parent directory")

        def selector_key(row):
            if row["kind"] == "selector":
                return (row["object"], row["operation"], row["selector"], row["variant"])
            return None

        columns = (
            "sdk_access", "access", "fixture_code", "open_code", "source_code",
            "api_code", "cleanup_code", "granted_access", "ntstatus",
        )

        def darwin(row):
            # UUIDs and filesec identity fields vary across runner hosts.
            if "native_error" in row:
                return {"native_error": row["native_error"]}
            return {
                key: (row[key]["presence"], row[key]["flags"], len(row[key]["entries"] or []))
                for key in ("path", "fd")
            } | {"libc_ok": row["libc"]["ok"], "libc_errno": row["libc"].get("errno")}

        meta = json.loads((root / "run.json").read_text(encoding="utf-8"))
        gate = (json.loads((root / "gate.json").read_text(encoding="utf-8"))
                if (root / "gate.json").exists()
                else {"ok": False, "problems": ["missing gate"]})
        return (
            {"lane": meta["lane"], "sha": meta["context"].get("GITHUB_SHA"),
             "args": meta["args"], "gate": gate},
            index(root / "results.jsonl", lambda row: row["id"], lambda row: row["status"]),
            index(root / "windows-selectors.jsonl", selector_key,
                  lambda row: {key: row.get(key) for key in columns}),
            index(root / "darwin-presence.jsonl", lambda row: row["case"], darwin),
            index(root / "windows-selectors-privileged.jsonl", selector_key,
                  lambda row: {key: row.get(key) for key in columns}),
            behavior_index(root),
        )

    before = get(old)
    after = get(new)
    behavior_changes, coverage_changes, behavior_summary = _behavior_diff(before[5], after[5])
    return {
        "before": before[0],
        "after": after[0],
        "case_changes": changes(before[1], after[1]),
        "selector_changes": changes(before[2], after[2]),
        "darwin_changes": changes(before[3], after[3]),
        "privileged_selector_changes": changes(before[4], after[4]),
        "behavior_changes": behavior_changes,
        "behavior_coverage_changes": coverage_changes,
        "behavior_change_summary": behavior_summary,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(compare(arguments.old, arguments.new), indent=2))
