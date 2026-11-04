# Coverage manifest

Case counts are selected process-isolated scenarios, not native pass claims. Seeded subcases are reported inside the two model scenarios.

## darwin

Full: **248**. Smoke: **18**. Privilege opt-in: **0**.

| Family | Cases |
|---|---:|
| `contract` | 8 |
| `path` | 16 |
| `model` | 2 |
| `rights` | 72 |
| `ace_flags` | 64 |
| `acl_flags` | 12 |
| `count` | 8 |
| `ordering` | 6 |
| `principal` | 6 |
| `inheritance` | 32 |
| `chmod` | 6 |
| `access` | 3 |
| `attr_buffer` | 8 |
| `libc` | 1 |
| `stress` | 4 |

## windows

Default full: **357**. With disposable local accounts: **393**. Smoke: **27**. Base privilege opt-in: **7**. Local-account opt-in: **36**, including **3** integrity cases that also require `-Privileged`.

| Family | Cases |
|---|---:|
| `contract` | 7 |
| `path` | 16 |
| `model` | 2 |
| `rights` | 80 |
| `ace_flags` | 64 |
| `count` | 12 |
| `sid` | 30 |
| `ace_binary` | 22 |
| `extended_ace_write` | 18 |
| `acl_limit` | 4 |
| `query` | 15 |
| `update` | 11 |
| `inheritance` | 16 |
| `propagation` | 4 |
| `access` | 30 |
| `sddl` | 12 |
| `sacl` | 9 |
| `stress` | 5 |
| `multiuser` (opt-in) | 36 |

## Assertions versus observations

- Each rights/flag round-trip compares the shard write with a direct native write on a separate fixture, then cross-checks the readback with the independent native oracle.
- Each model case compares exact bytes, not reformatted text. Windows filesystem comparison preserves ACE byte order/content and control state while ignoring non-semantic allocation layout/padding differences between independent OS queries.
- Windows access cases compare an OS AccessCheck on the same captured descriptor with an actual CreateFile request. The six policies are allow, deny, allow-then-deny, deny-then-allow, empty, and null; five concrete rights are requested.
- Darwin explicit deny enforcement runs under the current ordinary user, not a guessed UID or a new account.
- Maximum Windows file-ACL storage depends on the native OS/filesystem. Large structurally valid inputs are measured; matched rejection is an observation, not a passing storage claim. The count matrix uses the specified number of additional ACEs plus a recovery grant; the dedicated empty-DACL case has zero ACEs.
- Conditional SDDL and opaque callback payload preservation do not implement or certify a conditional access evaluator.
- Windows resource loops warm the selected operation, collect on both boundaries, sample four batches, and check a held/released 12-handle positive control. A separate no-op case provides a negative control. Darwin retains its original pre/post descriptor measurement. Small runtime bookkeeping tolerance is allowed; no fragile RSS threshold or cross-machine speed comparison is imposed.

## Evidence dependencies

Read the `config.json` for the exact seed, iteration count, privilege opt-in and compiler path for a case. Native bytes and every bridge input are stored alongside the case. A test failure is evidence for investigation, not proof that the shard rather than the harness/SDK/environment is necessarily wrong.

## Windows local-account matrix

`windows.multiuser.*` is selected only with `--local-accounts` / `-LocalAccounts`. It uses three real local users, two real local groups, fresh logon sessions, real bridge processes under alternate primary tokens, impersonation tokens, deny-only and restricting SID tokens, changed integrity levels, and actual file operations. Account creation/removal is a collector stage rather than a test assertion; failures and cleanup remnants are retained in `summary.json` and `REPORT.md`.

## Windows native selector/access mapper

Every native Windows run that has a C compiler/SDK now builds and executes
`probes/windows_acl_map.c` as a separate evidence stage. It is independent of
the Crystal bridge and the Python/ctypes oracle.

The mapper creates a fresh synthetic file or directory for every selector,
operation, and access-mask variant below the owned scratch root. This prevents
one `SetSecurityInfo` probe from changing the input to a later probe. It records
line-delimited JSON for:

- OS build, architecture, filesystem name and volume capability flags;
- current token user SID, integrity SID, group SID attributes and privileges;
- optional process-local attempts to enable `SeSecurityPrivilege`,
  `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeTakeOwnershipPrivilege`;
- `QuerySecurityAccessMask` and `SetSecurityAccessMask` results for owner,
  group, DACL, audit SACL, label, resource attribute, scope, process-trust
  label, access-filter, basic, combined audit+label, all-defined and backup
  selectors;
- zero, SDK-calculated, SDK-plus-`READ_CONTROL`, and (when distinct)
  SDK-minus-`READ_CONTROL` handle opens;
- a monotonic attempt ID plus fixture-creation and cleanup outcomes;
- the open result separately from `GetSecurityInfo`, source-descriptor query,
  and `SetSecurityInfo` results;
- optional `NtQueryObject(ObjectBasicInformation)` granted-access evidence,
  dynamically resolved and treated only as an unsupported diagnostic oracle.

Nonzero native outcomes are observations, not automatic suite failures. Fatal
probe setup/output failures fail the stage. Returned archives contain
`stages/windows-native-map.jsonl` and
`stages/windows-native-map-summary.json`.
