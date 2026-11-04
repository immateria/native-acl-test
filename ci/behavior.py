"""Launch and validate isolated native behavior-map workers."""
import json
import pathlib
import sys

from lab import behavior, behavior_catalog, core


def depth_for_profile(profile):
    if profile in ("smoke", "full", "map"):
        return profile
    if profile == "stress":
        return "smoke"
    raise ValueError("unknown profile")


def run_all(platform, profile, work, out, privileged=False, timeout=900,
            domains=None, local_accounts=False):
    depth = depth_for_profile(profile)
    manifest = behavior_catalog.manifest(platform, depth)
    if domains is not None:
        requested = tuple(domains)
        unknown = sorted(set(requested) - set(manifest))
        if unknown:
            raise ValueError(f"unknown behavior domains: {unknown}")
        manifest = {name: manifest[name] for name in requested}
    behavior_root = pathlib.Path(out) / "behavior"
    behavior_root.mkdir(parents=True, exist_ok=True)
    summaries = {}
    failures = []
    for domain, expected in manifest.items():
        destination = behavior_root / f"{domain}.jsonl"
        prefix = behavior_root / f"{domain}-worker"
        argv = [sys.executable, "-m", "lab.behavior_worker", "--platform", platform,
                "--domain", domain, "--depth", depth, "--workspace", str(pathlib.Path(work) / "scratch"),
                "--output", str(destination)]
        if privileged:
            argv.append("--privileged")
        if local_accounts:
            argv.append("--local-accounts")
        result = core.command(argv, prefix, timeout, cwd=pathlib.Path(__file__).resolve().parents[1])
        try:
            if result.get("returncode") != 0 or result.get("timed_out"):
                raise ValueError(f"worker failed: returncode={result.get('returncode')} timed_out={result.get('timed_out')}")
            summaries[domain] = behavior.validate_jsonl(destination, platform, domain, expected)
            errors = summaries[domain]["counts"]["error"]
            if errors:
                failures.append(f"{domain}: {errors} behavior row(s) reported error")
            if domain == "authz" and not summaries[domain]["counts"]["ok"]:
                failures.append("authz: no evaluated access checks")
        except (OSError, ValueError, KeyError) as exc:
            failures.append(f"{domain}: {exc}")
    core.write_json(behavior_root / "summary.json", dict(platform=platform, depth=depth,
                    domains=summaries, failures=failures,
                    expected_rows=sum(len(values) for values in manifest.values())))
    if failures:
        raise ValueError("; ".join(failures))
    return summaries
