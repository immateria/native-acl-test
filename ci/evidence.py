"""Validate a native handback independently of the collector's process exit."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import zipfile
from lab import behavior, behavior_catalog, core

BAD = {'FAIL', 'ERROR', 'BLOCKED', 'TIMEOUT'}
STATUSES = BAD | {'PASS', 'OBSERVE', 'SKIP'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]




def _behavior_manifest(platform, depth, lane):
    manifest = behavior_catalog.manifest(platform, depth)
    if platform == "windows" and lane != "windows-lab":
        manifest = {name: values for name, values in manifest.items()
                    if name != "multiuser-map"}
    return manifest


def validate_behavior(root, platform, lane):
    """Independently revalidate every behavior row and its aggregate summary."""
    root = Path(root)
    errors = []
    result = {"rows": 0, "depth": None, "domains": {}}
    summary_path = root / "summary.json"
    if not summary_path.is_file():
        return result, ["behavior summary is missing"]
    try:
        summary = read(summary_path)
        depth = summary.get("depth")
        result["depth"] = depth
        if depth not in behavior_catalog.DEPTHS:
            return result, [f"behavior depth is invalid: {depth!r}"]
        manifest = _behavior_manifest(platform, depth, lane)
        if summary.get("platform") != platform:
            errors.append("behavior summary reports the wrong platform")
        if summary.get("failures"):
            errors.append(f"behavior workers reported failures: {summary.get('failures')}")
        if set(summary.get("domains", {})) != set(manifest):
            errors.append("behavior summary domains do not match the lane manifest")
        expected_rows = sum(len(values) for values in manifest.values())
        if summary.get("expected_rows") != expected_rows:
            errors.append("behavior summary expected-row count is inconsistent")
        actual_files = {path.stem for path in root.glob("*.jsonl")}
        unexpected = sorted(actual_files - set(manifest))
        if unexpected:
            errors.append(f"unexpected behavior domains: {unexpected}")
        for domain, expected in manifest.items():
            path = root / f"{domain}.jsonl"
            try:
                details = behavior.validate_jsonl(path, platform, domain, expected)
                result["domains"][domain] = {
                    "rows": len(expected),
                    "counts": details["counts"],
                    "catalog_sha256": details["catalog_sha256"],
                }
                result["rows"] += len(expected)
                row_errors = details["counts"]["error"]
                if row_errors:
                    errors.append(f"{domain}: {row_errors} behavior row(s) reported error")
                if domain == "authz" and not details["counts"]["ok"]:
                    errors.append("authz: no evaluated access checks")
                if summary.get("domains", {}).get(domain) != details:
                    errors.append(f"{domain}: aggregate summary differs from JSONL")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                errors.append(f"{domain}: {exc}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"behavior summary: {exc}")
    return result, errors


def write_hash_manifest(root):
    """Hash every regular evidence file recursively, excluding the manifest itself."""
    root = Path(root)
    files = sorted(
        path for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS"
    )
    lines = [
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(root).as_posix() + "\n"
        for path in files
    ]
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    return len(files)


def validate(meta, manifest, records, summary):
    """Missing, duplicate, out-of-contract, and unexecuted cases must not go green."""
    errors = []
    expected = meta['expected']
    named = [r['id'] for r in records]
    planned = [r['id'] for r in manifest]
    counts = Counter(r['status'] for r in records)
    if not expected or len(expected)!=len(set(expected)) or planned!=expected or named!=expected:
        errors.append('case IDs do not match the ordered plan exactly')
    if set(counts)-STATUSES or dict(counts)!=summary['counts']:
        errors.append('invalid statuses or inconsistent status totals')
    if summary['completed']!=len(named) or summary['selected']!=len(expected): errors.append('incomplete run')
    if summary['errors'] or summary['exit_code']!=0 or BAD.intersection(counts): errors.append('native collector reported failures')
    if not counts['PASS'] and not counts['OBSERVE']: errors.append('no assertion or observation executed')
    osname = 'darwin' if meta['lane'].startswith('macos-') else 'windows'
    if summary['platform']!=osname: errors.append('collector reported the wrong OS')
    stages={s['name']:s['status'] for s in summary['stages']}
    required={'crystal-version','format','bridge-build','sdk-abi-build','sdk-abi-run','final-cleanup'}
    if osname=='windows': required.update(['windows-native-map-build','windows-native-map-run','windows-native-map-parse'])
    if meta['lane']=='windows-lab': required.update(['local-account-provision','local-account-cleanup','account-bridge-prepare'])
    args=meta['args']
    if '--skip-specs' not in args:
        seed=int(args[args.index('--seed')+1]);required.update([f'checkpoint-specs-{seed}',f'checkpoint-specs-{seed+1}','checkpoint-release-specs'])
    for stage in sorted(required):
        if stages.get(stage)!='PASS': errors.append(f'required stage {stage}: {stages.get(stage,"MISSING")}')
    if 'FAIL' in stages.values(): errors.append('a recorded stage failed')
    return errors


def finish(work, out):
    """Keep available diagnostics even when compilation, collection or validation fails."""
    out.mkdir(exist_ok=True)
    problems = []
    records = []
    counts = {}
    lane = os.getenv("ACL_LANE", "unknown")
    meta = None
    behavior_summary = {"rows": 0, "depth": None, "domains": {}}
    try:
        meta = read(out / "run.json")
        lane = meta["lane"]
        from ci.lane import check_identity
        for stage in ("explore", "collect"):
            try:
                check_identity(lane, read(out / f"identity-{stage}.json"))
            except (ValueError, KeyError, OSError) as exc:
                problems.append(f"{stage} identity: {exc}")
        directories = [path for path in (work / "raw").glob("acl-results-*")
                       if path.is_dir() and not path.is_symlink()]
        if len(directories) != 1:
            raise ValueError(f"expected one native result directory; found {len(directories)}")
        root = directories[0]
        for name in ("summary.json", "case-manifest.json", "environment.json", "results.jsonl", "REPORT.md"):
            if (root / name).is_file():
                shutil.copyfile(root / name, out / name)
        archive = root.with_suffix(".zip")
        if not archive.is_file():
            problems.append("collector did not finalize the ZIP; salvaging partial evidence")
            archive = core.archive(root)
        with zipfile.ZipFile(archive) as bundle:
            if bundle.testzip() is not None:
                raise ValueError("collector archive CRC failure")
        shutil.copyfile(archive, out / "handback.zip")
        records = rows(out / "results.jsonl")
        counts = dict(Counter(record["status"] for record in records))
        problems += validate(meta, read(out / "case-manifest.json"), records, read(out / "summary.json"))
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        problems.append(str(exc))

    if meta is not None:
        platform = "darwin" if lane.startswith("macos-") else "windows"
        behavior_summary, behavior_errors = validate_behavior(out / "behavior", platform, lane)
        problems.extend(behavior_errors)

    for step in ("setup", "explore", "collect"):
        outcome = os.getenv("ACL_" + step.upper() + "_OUTCOME")
        if outcome and outcome != "success":
            problems.append(f"Actions step {step}: {outcome}")
    behavior_profile = (meta or {}).get("behavior_profile")
    if behavior_profile == "map":
        for step in ("filesystem_setup", "filesystem_cleanup"):
            outcome = os.getenv("ACL_" + step.upper() + "_OUTCOME")
            if outcome and outcome != "success":
                problems.append(f"Actions step {step}: {outcome}")

    core.write_json(out / "gate.json", {
        "lane": lane,
        "counts": counts,
        "behavior": behavior_summary,
        "problems": problems,
        "ok": not problems,
    })
    lines = [
        f"## Native ACL: {lane}",
        "",
        f"Case outcomes: `{json.dumps(counts, sort_keys=True)}`",
        f"Behavior rows: `{behavior_summary.get('rows', 0)}` across "
        f"`{len(behavior_summary.get('domains', {}))}` domains",
        "",
        "Evidence gate: " + ("FAIL" if problems else "PASS"),
    ]
    lines += ["- " + str(problem).replace("\n", " ")[:500] for problem in problems]
    bad = [record for record in records if record["status"] in BAD]
    if bad:
        lines += ["", "First failing case IDs:"] + [
            f"- `{record['id']}`: {record['status']}" for record in bad[:30]
        ]
    lines += ["", "See `handback.zip` for individual requests, native responses and compiler diagnostics."]
    markdown = "\n".join(lines) + "\n"
    (out / "LANE.md").write_text(markdown, encoding="utf-8")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(markdown)
    write_hash_manifest(out)
    print(markdown)
    return int(bool(problems))
