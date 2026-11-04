# Checkpoint 5 — Windows selector hardening and native access mapping

Checkpoint 5 advances the shard to **0.0.5**. It keeps the checkpoint-4 local
account lab and adds production-model corrections plus a native Windows SDK
mapping stage.

## Production changes

### Defined ACE categories

`ACL::Windows::ACE#category` distinguishes discretionary, system, and unknown
families without pretending that every body is semantically decoded. The
reserved compound-access type 4 is correctly classified as a DACL-family ACE;
it remains opaque for field editing.

### Selector-correct SACL updates

Known system ACE families now require their matching `Information` selector
before `SetSecurityInfo` can be called:

| ACE types | Required selector |
|---|---|
| audit/alarm and callback/object variants 2, 3, 7, 8, 13–16 | `SACL` |
| mandatory label 17 | `Label` |
| resource attribute 18 | `Attribute` |
| scoped policy ID 19 | `Scope` |
| process trust label 20 | `ProcessTrustLabel` |
| access filter 21 | `AccessFilter` |

A mixed SACL list must explicitly select the union. DACL/SACL family crossing
is rejected before native mutation. Unknown future ACE types remain opaque and
are passed to the OS rather than assigned guessed semantics.

### Path-open diagnostics

`ACL::Windows::PathOpenError < NativeError` retains every attempted access mask
and Win32 result when the widened path open and exact-mask fallback both fail.
A single failed native path open also carries its attempted mask. The final code
continues to be available through `NativeError#code`; borrowed-handle operations
and setter failures are not reclassified as path-open failures.

## Native Windows mapper

`probes/windows_acl_map.c` is a standalone C11 SDK oracle, independent of the
Crystal bridge and Python/ctypes implementation. On synthetic file and directory
objects it records:

- OS build, architecture, filesystem and volume capabilities;
- token user, integrity, groups and privileges;
- optional process-local privilege enable attempts;
- SDK query/set access masks for every supported security-information selector;
- zero, exact, plus-`READ_CONTROL`, and minus-`READ_CONTROL` handle attempts;
- one fresh file or directory for every selector/operation/access variant;
- fixture creation, open, source query, security API, and cleanup outcomes as
  separate fields with a monotonic attempt ID;
- optional granted-access evidence from dynamically resolved `NtQueryObject`.

Output is unbuffered JSONL so evidence survives a later probe failure. Nonzero
selector outcomes are data, not automatic assertion failures. Fatal mapper
setup/output failures fail the stage. The Linux gate compiles the same C source
against a strict portable declaration stub with warnings as errors; native SDK
compilation and execution remain required for authoritative results.

## Verification boundary

Linux verification can prove Crystal behavior, Python orchestration, C syntax,
and Windows/macOS Crystal object generation. It cannot prove SDK header/link
compatibility or runtime authorization. A native Windows result archive remains
the acceptance evidence for the mapper and the checkpoint-3 access-mask policy.
