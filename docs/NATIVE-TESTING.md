# Running the native suites — checkpoint 7

A self-contained verification kit for the **`acl` 0.0.6 source in this checkpoint**. It contains the source under test, a compiled-on-your-machine Crystal bridge, independent Python/ctypes native API oracles, C SDK probes, process-isolated cases, and automatic evidence collection. No additional ZIP from the earlier conversation is required.

**Default full matrix: 248 macOS cases + 357 Windows cases = 605 individually named cases.** The opt-in Windows local-account lab adds 36 cases, bringing an expanded Windows run to 393 and the combined catalog to 641. Each native platform also runs 1,000 generated valid binary round-trips and 3,000 deliberately malformed structural inputs inside its two model cases. The ordinary checkpoint specs run twice with different ordering seeds and once in release mode. These counts describe selected work, not a claim that every native case has passed.

## 1. Requirements

- Python **3.9 or later**, standard library only.
- A working **native Crystal 1.18+** installation. Prefer your usual current compiler for the first run. `--crystal` / `-Crystal` selects another executable.
- Shards is optional for the manifest-check stage; the shard has no shard dependencies and the kit never downloads any.
- macOS: Command Line Tools / a working `cc` and macOS SDK for the separate C ABI probe.
- Windows: an SDK/MSVC **Developer PowerShell** with Crystal on PATH; `cl.exe` or `clang-cl.exe` is needed for the C ABI probe. The Python oracle itself does not require a C compiler.

The launchers do not install software, elevate, or change system audit policy. The normal launchers do not create accounts unless `-LocalAccounts` is explicitly selected. That opt-in mode requires an already elevated shell, creates three disposable local users and two disposable local groups, and removes them in final cleanup. A missing compiler is recorded; Python must already be usable to start the collector.

## 2. First runs

Run from the `native-acl-test` repository root. For hosted runs, start with the root README.

### macOS — ordinary user first

```sh
bash ./run-macos.sh --profile full
```

Do **not** start the first run with `sudo`: the explicit deny/enforcement cases need an ordinary-user baseline. A root run is identified and those enforcement cases are reported as skipped rather than treated as passing.

### Windows — non-elevated developer shell first

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-windows.ps1 -Profile full
```

`-ExecutionPolicy Bypass` applies to this PowerShell process, not a permanent machine/user setting. In a shell that already permits the script, `./run-windows.ps1 -Profile full` is sufficient. A Developer Command Prompt can instead run:

```bat
py -3 run.py --profile full
```

### Windows — elevated developer shell second

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-windows.ps1 -Profile full -Privileged
```

The `-Privileged` flag **does not elevate**. Open the shell as administrator yourself. The seven opt-in SACL cases attempt to enable `SeSecurityPrivilege` in their individual worker processes. The backup case additionally attempts to enable assigned backup/restore privileges in its disposable worker. Missing privileges or unsupported configurations are recorded separately from successes. Current-token integrity and privilege metadata are recorded so ordinary/elevated differences can be interpreted. No audit policy is enabled and no audit log is cleared.

### Windows — disposable local users/groups

Run the focused 36-case authorization matrix from an **elevated Developer PowerShell**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-windows-multiuser.ps1
```

Run the entire Windows matrix, including privileged SACL cases and the local-account cases, with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-windows.ps1 -Profile full -Privileged -LocalAccounts
```

The collector creates Alice/Bob/Carol roles plus allow/deny groups with run-specific names, writes credentials only below the protected scratch tree, and includes only non-secret names/SIDs in `local-accounts.json`. Normal cleanup removes all five principals even when individual cases fail. After an abrupt process or machine interruption, use the emitted public metadata:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\cleanup-local-accounts.ps1 `
  -MetadataPath 'C:\path\to\acl-results-...\local-accounts.json' -Confirm:$false
```

Review `-WhatIf` first when desired. The cleanup script refuses names outside the exact generated lab-name grammar.

For a smaller elevated follow-up after a full ordinary run:

```powershell
.\run-windows.ps1 -Profile full -Privileged -Only 'windows.sacl.*','windows.path.*' -SkipSpecs -SkipSdk
```

## 3. What to upload

Every completed collection prints:

```text
COUNTS { ... }
RESULT_DIRECTORY .../acl-results-<platform>-<UTC>-<unique-id>
UPLOAD .../acl-results-<platform>-<UTC>-<unique-id>.zip
```

**Upload the `acl-results-*.zip` files, including runs with failures.** The ordinary macOS run, ordinary Windows run, and elevated Windows run are the most useful initial set. Do not fix or delete failed tests before returning the evidence.

By default, results are under this kit's `results/` folder. They contain `summary.json`, a complete case manifest, `results.jsonl`, per-case results and tracebacks, native ACL/descriptor bytes, exact bridge requests/responses, compiler/spec/SDK output, source hashes, and `manifest.sha256`. Fixture file contents and compiled executables are not included.

A normal compiler failure, case failure, timeout, or handled Ctrl-C still reaches result packaging. Abrupt termination of the whole runner, power loss, or storage failure cannot guarantee a completed archive. After stopping an interrupted run, package whatever evidence exists without touching its fixtures:

```sh
python3 pack-results.py /path/to/acl-results-...
```

On Windows use `py -3 pack-results.py 'C:\path\to\acl-results-...'`.

## 4. Interpretation

| Status | Meaning |
|---|---|
| `PASS` | This case's actual assertions passed. |
| `FAIL` | An assertion or differential comparison failed. |
| `ERROR` | An unexpected exception, crash, or cleanup problem occurred. |
| `TIMEOUT` | The case exceeded its deadline. |
| `BLOCKED` | A required build/dependency was unavailable. |
| `SKIP` | A named capability, privilege, or explicit run option prevented the case. |
| `OBSERVE` | Useful native behavior was recorded, but not assigned a guessed success contract. |

A matched native rejection, an unsupported SDDL form, or an undersized attribute-buffer experiment can be an observation. It is never counted as a successful round-trip. A zero process exit status means no hard failure was recorded; it does **not** convert skips/observations into passes or certify the shard.

The collector keeps going after individual failures. Each case has a fresh process, fresh directory, deterministic parameters, and a timeout. Timeout/crash records retain the command, inputs, and captured output. Cleanup is also bounded. Operating systems can have uninterruptible kernel I/O, especially on remote filesystems; a timeout is not a promise that a kernel operation can always be cancelled immediately. Start with a local filesystem.

## 5. Scope and safety

All ACL mutations target newly created synthetic fixtures beneath a **new, randomly named private directory**. The collector does not apply test ACLs to the supplied parent directory, project source, home directory, or existing user files. It clears inherited ACLs/protects the ACL on its new workspace before creating fixtures. Symlinks and hard links used by the suite point only within the generated test area; cleanup does not follow them.

Null/empty Windows DACL and Darwin self-deny experiments retain appropriate handles/descriptors for restoration. Other deny-entry matrices use a non-applicable Darwin well-known `Nobody` principal, or a synthetic Windows SID with a current-user recovery grant. The Windows parent workspace remains restricted. Fixture cleanup attempts restoration before deletion and records any leftover path rather than hiding the problem.

**Returned reports contain local paths and your current UID/GID, SID/UUID, integrity level and privilege metadata where relevant.** They do not collect passwords, credentials, full environment dumps, process memory dumps, or existing user-file contents. In local-account mode, passwords exist only in a protected scratch-tree file and process memory; result archives contain only public principal metadata. Inspect the archive before sharing outside this conversation.

## 6. Coverage

See `docs/COVERAGE.md` and the reviewed `ci/coverage.json` inventory; `python run.py --list --platform windows --profile full` prints complete parameters.

**macOS:** every defined fine-grained/generic right, allow/deny kinds, all 32 combinations of five ACE inheritance-related flags, ACL-level flags, present empty/omitted/removed state, 0–128 entries and 129 rejection, entry ordering, UUID principal classes, libc-vs-getattrlist comparisons, undersized attribute buffers, inheritance through multiple generations, chmod interaction, actual deny enforcement, Unicode/long/relative paths, symlink follow/no-follow and dangling/intermediate links, hard links, rename with a held descriptor, FIFO no-follow, borrowed/invalid descriptors, error codes, and repeated read/write/resource-count checks.

**Windows:** file/standard/generic rights, allow/deny kinds, all 32 ACE flag combinations, ordinary/object/callback/opaque binary ACEs, GUID byte order, SID authority/count bounds, native SDDL conversion including a conditional ACE, selected-component queries and unqueried guards, owner/group/DACL update isolation, absent/null/empty states, explicit null consent, inheritance creation and existing-child propagation, protected and unprotected children, ordered access checks compared with actual opens, Unicode/extended-length/reparse/hard-link paths, held-handle rename and ownership, native ACL size experiments up to 65,532 bytes, optional auditing/label/backup-selection probes, and repeated handle/resource checks.

The oracle is independent of the Crystal code: macOS uses libSystem entry construction/export plus raw `getattrlist`; Windows uses Advapi32/Kernel32, handle-based `GetSecurityInfo` (with `GetNamedSecurityInfoW` only as a diagnostic), `GetAce`, SID/SDDL conversion and `AccessCheck`. Exact binary model round-trips are checked separately from semantic filesystem comparisons, because kernel normalization and storage padding are not the same as model byte preservation.

## 7. Optional deeper runs

Preview without changing ACLs:

```sh
python3 run.py --list
```

Windows: `py -3 run.py --list` or `./run-windows.ps1 -List`.

Run the same suite on another existing filesystem by choosing a parent directory there; the kit creates a new child and does not alter the parent's ACL:

```sh
bash ./run-macos.sh --profile full --scratch-parent /Volumes/TestVolume
```

```powershell
.\run-windows.ps1 -Profile full -ScratchParent 'D:\ACL-lab-parent'
```

The parent must exist. A Windows filesystem that does not advertise persistent ACL support stops at preflight and still produces a diagnostic report. Unsupported native operations on other targets are recorded, not silently emulated.

Longer repeat/resource loops without re-running the full spec/SDK stages:

```sh
bash ./run-macos.sh --profile stress --only 'darwin.stress.*' --iterations 10000 --case-timeout 600 --skip-specs --skip-sdk
```

```powershell
.\run-windows.ps1 -Profile stress -Only 'windows.stress.*' -Iterations 10000 -CaseTimeout 600 -SkipSpecs -SkipSdk
```

Alternate seed/compiler, or selected failures:

```sh
bash ./run-macos.sh --seed 917263 --crystal /path/to/crystal --only 'darwin.inheritance.*'
```

```powershell
.\run-windows.ps1 -Seed 917263 -Crystal 'C:\path\crystal.exe' -Only 'windows.inheritance.*'
```

The default case deadline is 180 seconds; build/spec stages have a 600-second deadline. These are safety ceilings, not runtime estimates. Default generated-model input count is 1,000 per format; `--iterations` controls it, capped at 10,000 for model input generation. `stress` uses at least 10,000 iterations. Raw malformed binaries are sent only to bounded model decoders, never to unbounded native ACL importers.

## Exhaustive hosted behavior mapping

The manual `map` profile produces stable semantic JSONL rather than only named qualification cases:

```sh
gh workflow run native-acl.yml --ref main -f lane=all -f profile=map

gh workflow run native-acl.yml --ref main -f lane=windows-lab -f profile=map
```

The ordinary run covers macOS arm64/x64 and Windows Server 2025/2022 elevated/filtered tokens. The lab run separately creates disposable local users/groups. Generated case-sensitive APFS/HFS+ images, loopback SMB, and ReFS VHDX are attempted only inside runner-owned scratch space and have explicit cleanup evidence. Unsupported facilities remain visible observations.

Current map sizes are **2,173 Darwin rows**, **52,989 ordinary Windows rows**, and **53,295 Windows rows with the real-account domain**. See `docs/BEHAVIOR-MAPPING.md` before interpreting these rows as pass/fail claims.

## 8. What this kit does not establish

The default matrix does not establish cross-account behavior. The opt-in local-account lab does test local cross-user/group authorization, but it does not implement domain/AD authorization, a conditional-expression evaluator, resource-claim policy evaluation, arbitrary reparse-tag behavior, cross-model ACL translation, atomic read-modify-write, adversarial concurrent pathname replacement, arbitrary fault injection, or a complete Windows backup/restore contract. Object/callback ACE storage tests are not proof of their authorization meaning on every resource manager. A filtered SACL query is not a full SACL backup. Remote servers and other filesystem types require their own runs. Other users' files are deliberately not examined.

## 9. Validation performed before delivery

Hosted run `41800279553` executed the checkpoint-5 source on macOS arm64 and two Windows Server 2025 tokens. macOS completed all 248 selected cases without a shard failure. Windows completed the native SDK mapper and exposed the two defects corrected in checkpoint 6: path writes that needed `READ_CONTROL`, and a relative path whose resolved spelling exceeded `MAX_PATH`.

The checkpoint-6 production changes were then verified on Linux with both supported Crystal compiler lanes, portable models, Python orchestration tests, and Windows x86-64/ARM64 object generation. **Checkpoint 7 retains that native acceptance boundary and adds behavior maps that also require hosted execution before those two runtime regressions are closed.** The focused commands are in `docs/checkpoint-6.md`; native local-account authorization remains a separate `windows-lab` dispatch.

## Native Windows selector/access map

The ordinary Windows launcher now runs an additional standalone C executable
when `cl.exe` or `clang-cl.exe` is available. No extra switch is required.
Use `-Privileged` to let that short-lived process attempt to enable its
assigned security/backup/restore/take-ownership privileges before mapping.
It never changes machine policy and all objects are created below the owned
scratch directory.

The most useful returned files are:

```text
stages/windows-native-map.jsonl
stages/windows-native-map-summary.json
stages/windows-native-map-build/
stages/windows-native-map-run/
```

Each selector record separates:

```text
monotonic attempt ID
requested selector
SDK-calculated access mask
specific access-mask variant
fresh fixture-creation result
CreateFileW result
source-descriptor query result (set operations)
GetSecurityInfo or SetSecurityInfo result
fresh fixture-cleanup result
optional actual granted-access mask from NtQueryObject
```

Do not reduce these records to a single pass/fail count. In particular, a
successful open followed by a failed security API call and a failed open are
different facts. The mapper intentionally records unsupported selectors and
privilege failures on older systems.
