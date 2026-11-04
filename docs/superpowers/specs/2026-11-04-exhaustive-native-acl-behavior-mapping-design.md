# Exhaustive Native ACL Behavior Mapping Design

## Intent

Turn `native-acl-test` from a broad shard qualification suite into a repeatable operating-system behavior laboratory. The suite must distinguish three questions instead of conflating them:

1. Can the Crystal model preserve the bytes?
2. Does the native API accept, normalize, or reject the requested descriptor/ACL?
3. What authorization, inheritance, lifecycle, path, privilege, and filesystem behavior does the kernel actually enforce?

The goal is evidence, not a false claim that Windows and Darwin share one ACL model or that every undocumented outcome is a test failure.

## Goals

- Add a manual `map` profile that performs large deterministic native matrices while running only smoke qualification cases.
- Record every matrix row as versioned JSONL with stable semantic keys suitable for cross-run comparison.
- Cover Darwin ACL storage, inheritance, mode/access interaction, lifecycle, and API boundary behavior.
- Cover Windows descriptor storage, selector combinations, access evaluation, inheritance events, object/path lifecycle, token/privilege state, and optional real-account behavior.
- Keep each mapping domain in a separate process with its own timeout and salvageable output.
- Validate exact matrix completeness before a mapping stage can be green.
- Run mapping across more than one hosted OS generation/architecture where GitHub provides it.
- Preserve the current shard qualification suite and its pass/fail semantics.

## Non-goals

- Do not invent a cross-platform effective-access evaluator.
- Do not treat an observation that differs by OS build/filesystem as a shard defect.
- Do not claim domain/central-access-policy semantics without a domain lab.
- Do not change system-wide audit policy in ordinary hosted runs.
- Do not require external Python packages or network access from the harness.

## Anti-goals

- No hidden aggregate that only reports “500 checks passed”; every subcase needs a stable row key and raw evidence.
- No one-process monolith whose crash loses every domain.
- No guessed expectations for undocumented normalization.
- No privilege enabling except in explicitly privileged mapping domains.
- No browser, GitHub authentication, or repository mutation from the test harness.

## Architecture

### Qualification versus mapping

`smoke`, `full`, and `stress` retain assertion-oriented shard qualification. A new `map` profile runs the smoke case catalog plus exhaustive independent behavior domains. Mapping output is observational unless a contract is explicit and already verified by both native and shard paths.

### Domain workers

`ci.behavior` launches one subprocess per domain. Each worker owns a generated fixture directory and writes append-only JSONL. The parent validates row identity and completeness, writes a summary, and retains partial output on timeout/crash.

### Stable evidence schema

Every row contains:

```text
schema, platform, domain, case, variant, key, status, details
```

`key` is generated from semantic dimensions, never a loop counter or temporary path. A final summary row contains expected/completed/status counts and the catalog digest.

### Matrix tiers

- `smoke`: a small representative subset used on every push.
- `full`: all assertion-oriented qualification cases and bounded behavior maps.
- `map`: exhaustive pairwise/combinatorial maps, manual dispatch only.
- `stress`: resource/repetition qualification; behavior maps remain bounded.

### Darwin domains

1. **storage** — ACE kinds, principals, rights, ACE flags, ACL flags, counts, file/directory storage, native normalization.
2. **inheritance** — all inheritance flag combinations across child type and generation; create, move-in, copy-in, and hard-link events.
3. **mode-access** — POSIX mode × ACL policy × concrete filesystem operation, recording success/errno and resulting ACL/mode.
4. **lifecycle** — rename, replacement, hard link, clone/copy, open-descriptor identity, unlink, chmod/chown-group, and symlink operations.
5. **api** — path/fd/link API variants, `getattrlist` option/buffer behavior, empty/absent/present states, malformed and unsupported flags.

### Windows domains

1. **descriptor-storage** — ACE type/placement/revision/flags/object type, ACL/descriptor states, native validation and normalization.
2. **selector-combinations** — single, pairwise, key combined, and exhaustive `SECURITY_INFORMATION` query/set combinations with exact open/API outcomes.
3. **access-evaluation** — concrete/generic rights and `MAXIMUM_ALLOWED` across ordered DACL policies; compare `AccessCheck`, actual `CreateFileW`, and operation probes.
4. **inheritance-events** — every inheritance flag combination across files/directories, generations, existing-child propagation, move/copy/hard-link events, and control bits.
5. **lifecycle** — hard links, ADS, symlinks/junctions, rename/replace/delete-pending, long/DOS/device/volume paths, handle-versus-name identity, and case-sensitive directories.
6. **token-privilege** — privilege assigned/disabled/enabled outcomes, owner implicit rights, restricted/deny-only tokens, integrity, default owner/DACL, and backup/restore selectors.
7. **authz** — SDDL conditional/callback ACE preservation and, where the native Authz APIs are available, TRUE/FALSE/UNKNOWN condition outcomes with explicit client attributes.
8. **multiuser-map** — expanded real-user/group behavior in the existing opt-in local-account lane.

## CI topology

Push keeps the existing bounded lanes. Manual mapping supports:

- macOS 15 arm64;
- macOS 13 x64 where still offered by GitHub;
- Windows 2025 elevated and filtered;
- Windows 2022 elevated and filtered;
- Windows 2025 local-account lab.

Unsupported/deprecated runner labels must be removable in one place (`ci/lane.py`). Mapping artifacts are uploaded even when validation is red.

## Safety

All mutations occur below a newly created marker-owned scratch root. Mapping workers do not follow symlink/reparse targets during cleanup. Windows account creation remains manual-dispatch-only on a GitHub-hosted VM. Optional volume/share experiments must use generated mounts/shares and record cleanup failures.

## Approaches considered

1. **Add hundreds of ordinary isolated qualification cases.** Strong isolation but too slow and poor for exploratory outcomes.
2. **One giant native probe.** Fast, but a crash destroys coverage and makes iteration difficult.
3. **Domain-isolated mapping workers plus the existing qualification suite.** Chosen: it preserves assertion rigor while producing large, salvageable behavior maps with stable keys.
