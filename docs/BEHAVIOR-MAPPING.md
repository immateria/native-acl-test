# Exhaustive native ACL behavior mapping

The `map` profile is an evidence generator, not a larger pass/fail qualification suite. It records one stable JSONL row for every semantic key in the reviewed catalog. Each domain runs in a separate process, writes incrementally, and ends with a self-describing summary. The final evidence gate independently validates every row, key, status, count, and catalog digest.

Ordinary pushes remain bounded to the smoke profile. Mapping is manual because the current catalogs contain **2,173 Darwin rows** and **53,295 Windows rows** when the real-account domain is included.

## Profiles

| Profile | Purpose | Darwin rows | Windows rows | Scheduling |
|---|---|---:|---:|---|
| `smoke` | Fast structural/native sanity | 25 | 52 | Push and manual |
| `full` | Named qualification-adjacent observations | 661 | 793 | Manual |
| `map` | Exhaustive semantic matrices | 2,173 | 52,989 ordinary / 53,295 lab | Manual only in practice |
| `stress` | Existing bounded repetition/resource cases | Smoke behavior catalog | Smoke behavior catalog | Manual |

The 306 `multiuser-map` rows are emitted only by `windows-lab`. They require disposable local accounts and groups and are not silently skipped into ordinary Windows artifacts.

## Darwin domains

| Domain | Map rows | What varies |
|---|---:|---|
| `storage` | 868 | Every right bit, known aggregate masks, allow/deny, file/directory, every modeled ACE flag combination, ACL flags, and entry-count boundaries |
| `inheritance` | 256 | Create, move, copy, hard-link events; allow/deny; every five-bit inheritance combination |
| `mode-access` | 912 | Six POSIX modes, eight ACL policies, file and directory operations including data, metadata, xattr, traversal, deletion, and ACL access |
| `lifecycle` | 27 | Rename, replacement, held descriptors, hard links, copy/clone, chmod/chown/chgrp, symlinks, FIFO, and generated filesystem roots |
| `api` | 110 | Path/fd/link presence states, libc versus `getattrlist`, undersized buffers, record boundaries, and malformed serialized layouts |

The mapper preserves the distinction between absent ACL evidence, a native no-ACL marker, and a present zero-entry ACL with flags. Raw native bytes remain in the artifact even when semantic comparison suppresses host UUID noise.

## Windows domains

| Domain | Map rows | What varies |
|---|---:|---|
| `descriptor-storage` | 47,158 | File/directory, DACL/SACL placement, ACE types 0–21 plus opaque 254, ACL revisions 2/4, every ACE flag byte, absent/null/empty/present state, defaulted/protected/auto-inheritance control bits |
| `selector-combinations` | 2,216 | Every non-empty combination of nine component selectors, backup selection, protected/unprotected DACL/SACL controls, contradictory controls, query/set, file/directory, and exact handle-access variants |
| `access-evaluation` | 520 | File/directory, ordered allow/deny/null/empty/owner/group policies, concrete/standard/generic/maximum rights, native access check, handle open, and actual operation boundaries |
| `inheritance-events` | 1,920 | Create/move/copy/propagate, allow/deny, all ACE inheritance flags, file/directory child, inherited versus protected child, and resulting control/order evidence |
| `lifecycle` | 43 | Rename/replacement/delete-pending, hard links, ADS, reparse forms, namespace/path spellings, file-ID opens, attributes, SMB/ReFS roots, and share modes |
| `token-privilege` | 52 | Token classes, group attributes, restricted/deny-only SIDs, owner rights, four states for five privileges, integrity levels, backup/restore/take-ownership operations |
| `authz` | 1,080 | Conditional allow/deny and unknown truth, user/device/resource claims, callback/object callback behavior, compound expressions, cache/object-type-list/CAP boundaries, and desired-access matrices |
| `multiuser-map` | 306 | Three local users, direct/group/deny-only/restricting/owner/delegated/stale-token scenarios, six rights, primary versus impersonation tokens |

The independent C selector mapper remains separate from these Python/ctypes workers. It records `CreateFileW` failure separately from `GetSecurityInfo`/`SetSecurityInfo`, uses a fresh fixture per attempt, and maps SDK, zero, `READ_CONTROL` variants, `SYNCHRONIZE`, and `MAXIMUM_ALLOWED` masks.

## Native runner and filesystem matrix

Manual `lane=all profile=map` expands to:

- macOS 15 arm64;
- macOS 15 Intel;
- Windows Server 2025 elevated and UAC-filtered;
- Windows Server 2022 elevated and UAC-filtered.

`windows-lab` is a separate manual dispatch because it creates disposable local users and groups.

Map runs also attempt generated filesystems beneath the owned runner scratch tree:

- case-sensitive APFS and case-sensitive HFS+ disk images on macOS;
- a loopback Windows SMB share;
- a disposable ReFS VHDX when the hosted image exposes Hyper-V/ReFS support.

Unsupported generated filesystems are recorded with the native error. Creation and cleanup are separate evidence stages. Cleanup validates bounded device/share/VHD identities and fails the evidence gate when a generated resource remains attached or published.

## Evidence and comparison

Each domain file contains:

```json
{"schema":1,"platform":"windows","domain":"selector-combinations","key":"...","status":"observe","details":{}}
```

Statuses are `ok`, `observe`, `skip`, and `error`. A native rejection can be a valid observation; serialization failures, unsafe fixture placement, worker crashes, missing keys, duplicate keys, contradictory summaries, and cleanup failures are errors.

`ci.compare` joins rows by `(domain, key)`. Its semantic projection suppresses runner paths, timings, generated account names, machine-local SIDs, Darwin principal UUIDs, and raw binary identity bytes. Parsed ACL semantics remain compared. The original JSONL and raw descriptors are never rewritten or discarded.

`ci.evidence` independently revalidates all behavior JSONL files, recursively hashes the complete `ci-out` tree, and records row counts and per-domain catalog digests in `gate.json`.

## Running

```sh
gh workflow run native-acl.yml --ref main -f lane=all -f profile=map

gh workflow run native-acl.yml --ref main -f lane=windows-lab -f profile=map
```

Compare two extracted lane artifacts:

```sh
python -m ci.compare old/acl-windows-elevated-* new/acl-windows-elevated-*
```

## Deliberate limits

This map is broad, but it is not literally every Windows authorization environment or filesystem implementation. Important remaining external laboratories include:

- Active Directory domain groups, device identities, claims, resource properties, and central access policies;
- Security Event Log auditing under explicitly configured audit policy;
- real remote Windows SMB and Samba servers rather than loopback SMB;
- production ReFS/cluster/storage appliances;
- arbitrary third-party reparse tags and minifilter behavior;
- Windows ARM64 native execution;
- adversarial concurrent path replacement and kernel fault injection.

Those boundaries remain explicit so byte preservation is not mislabeled as authorization-semantic certification.
