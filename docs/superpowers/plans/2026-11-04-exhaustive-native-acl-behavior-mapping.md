# Exhaustive Native ACL Behavior Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a domain-isolated, exhaustive native ACL behavior-mapping layer for Darwin and Windows without weakening the existing shard qualification suite.

**Architecture:** A new `map` profile runs smoke qualification plus deterministic behavior workers. Each worker writes versioned JSONL with stable semantic keys; CI validates exact completeness and retains partial evidence. Platform modules use existing native oracles and generated fixtures, while mapping outcomes remain observational unless backed by an explicit native contract.

**Tech Stack:** Python 3.9+ standard library, ctypes/Win32/libSystem, Crystal 1.18+/1.21, GitHub Actions, JSONL evidence.

**Spec:** `docs/superpowers/specs/2026-11-04-exhaustive-native-acl-behavior-mapping-design.md`

## Global Constraints

- No third-party runtime dependencies.
- Native OS identity must never be spoofed.
- All mutations stay below a newly created owned scratch root.
- Every matrix subcase has a stable semantic key and one JSONL row.
- Partial output survives worker crashes and timeouts.
- Privileges/accounts are opt-in and never enabled implicitly by the shard.
- `map` is manual-dispatch-oriented; push lanes remain bounded.
- Crystal floor remains `>= 1.18.0, < 2.0.0`.

## Review Focus

- A worker that exits after writing a complete-looking prefix must still fail exact catalog validation.
- Duplicate semantic keys must be rejected even when row counts match.
- Native errors must retain operation, code, selector/path, and requested access rather than collapse to pass/fail.
- Cleanup failure must make the domain non-green while preserving evidence.
- Full and map catalogs must remain deterministic across Python hash seeds and host path differences.

---

### Task 1: Mapping profile, catalog, schema, and worker isolation

**Files:**
- Create: `lab/behavior.py`
- Create: `lab/behavior_catalog.py`
- Create: `lab/behavior_worker.py`
- Create: `ci/behavior.py`
- Modify: `run.py`
- Modify: `lab/catalog.py`
- Modify: `ci/lane.py`
- Modify: `.github/workflows/native-acl.yml`
- Test: `tests/test_behavior.py`

**Interfaces:**
- Produces `behavior_catalog.domains(platform, depth, local_accounts=False)` and `ci.behavior.run_all(...)`.
- Produces JSONL schema 1 rows and exact per-domain validators.

- [ ] Write failing tests for deterministic catalogs, map-profile selection, duplicate/missing row rejection, partial-output salvage, and per-domain subprocess isolation.
- [ ] Run `python3 -m unittest tests.test_behavior -v` and confirm the new tests fail for missing modules/profile.
- [ ] Implement the shared catalog/schema/writer/validator and worker subprocess orchestration.
- [ ] Add `map` to CLI/workflow planning; map qualification selects smoke cases while exploration uses exhaustive depth.
- [ ] Run focused and full Python tests.

### Task 2: Darwin behavior domains

**Files:**
- Create: `lab/darwin_behavior.py`
- Modify: `lab/darwin.py`
- Modify: `ci/explore.py`
- Test: `tests/test_behavior.py`

**Interfaces:**
- Consumes behavior rows/catalog from Task 1.
- Produces domains `storage`, `inheritance`, `mode-access`, `lifecycle`, and `api`.

- [ ] Write failing tests that pin Darwin semantic keys/counts for smoke/full/map depth and verify every catalog dimension is represented.
- [ ] Run focused tests and confirm catalog/dispatcher failures.
- [ ] Implement native storage, inheritance, mode/access, lifecycle, and API mapping with one generated fixture per mutating row.
- [ ] Ensure uncertain outcomes are `observe`, explicit harness failures are `error`, and raw ACL/errno evidence is retained.
- [ ] Run all Python tests and Linux model qualification.

### Task 3: Windows descriptor, selector, access, and inheritance domains

**Files:**
- Create: `lab/windows_behavior.py`
- Modify: `lab/windows.py`
- Modify: `ci/explore.py`
- Test: `tests/test_behavior.py`

**Interfaces:**
- Produces domains `descriptor-storage`, `selector-combinations`, `access-evaluation`, and `inheritance-events`.
- Reuses `wire`, `Windows`, and current generated-fixture cleanup primitives.

- [ ] Write failing tests for exact Windows semantic keys/counts, selector-combination depth, ACE placement/revision axes, rights/policy axes, and inheritance event axes.
- [ ] Run focused tests and confirm failures.
- [ ] Implement native validation/write/read normalization, selector query/set attempts, AccessCheck/CreateFile evidence, and inheritance event mapping.
- [ ] Record open failures separately from security API failures.
- [ ] Run full Python tests and cross-target bridge compilation.

### Task 4: Windows lifecycle, token/privilege, Authz, and local-account mapping

**Files:**
- Modify: `lab/windows_behavior.py`
- Modify: `lab/windows.py`
- Modify: `lab/windows_accounts.py`
- Modify: `probes/windows_acl_map.c`
- Modify: `probes/windows_acl_map_stub.h`
- Test: `tests/test_behavior.py`

**Interfaces:**
- Produces domains `lifecycle`, `token-privilege`, `authz`, and `multiuser-map`.

- [ ] Write failing tests for lifecycle/path cases, privilege state matrix, conditional TRUE/FALSE/UNKNOWN keys, and expanded account-map keys.
- [ ] Run focused tests and confirm failures.
- [ ] Implement lifecycle/object-identity observations and token/privilege snapshots.
- [ ] Add Authz/conditional probing where supported; unsupported APIs become explicit observations, not silent omissions.
- [ ] Expand local-account mapping without adding it to automatic push lanes.
- [ ] Run full Python tests and strict C syntax/object-generation checks.

### Task 5: Multi-runner and filesystem mapping

**Files:**
- Modify: `ci/lane.py`
- Modify: `.github/workflows/native-acl.yml`
- Create: `ci/macos-volumes.sh`
- Create: `ci/windows-filesystems.ps1`
- Test: `tests/test_ci.py`

**Interfaces:**
- Produces optional runner lanes and generated filesystem roots passed to mapping workers.

- [ ] Write failing tests for explicit runner labels, push/manual lane boundaries, and cleanup-required generated volume/share metadata.
- [ ] Run focused tests and confirm failures.
- [ ] Add manual map lanes for macOS x64/arm64 and Windows 2022/2025 elevated/filtered.
- [ ] Add best-effort generated APFS case-sensitive/HFS+ and Windows loopback-SMB/ReFS probes with exact skip reasons and cleanup evidence.
- [ ] Run all Python tests and workflow static checks.

### Task 6: Comparison, coverage documentation, version, and package

**Files:**
- Modify: `ci/compare.py`
- Modify: `ci/evidence.py`
- Modify: `docs/COVERAGE.md`
- Create: `docs/BEHAVIOR-MAPPING.md`
- Create: `docs/checkpoint-7.md`
- Modify: `README.md`
- Modify: `acl/shard.yml`
- Modify: `acl/src/acl/version.cr`
- Modify: `SOURCE-COMMIT`

**Interfaces:**
- Produces cross-run semantic diffs and the 0.0.7 source artifact.

- [ ] Write failing tests for behavior-row comparison by semantic key and gate handling of incomplete domains.
- [ ] Run focused tests and confirm failures.
- [ ] Implement behavior diffs and evidence summaries.
- [ ] Regenerate reviewed coverage locks and document exact qualification-case and behavior-row counts.
- [ ] Advance to 0.0.7, run setup, format, specs, model lanes, Python tests, cross-target objects, package-hash verification, and fresh-extract verification.
- [ ] Request whole-branch review and fix Critical/Important findings with red-green tests.
