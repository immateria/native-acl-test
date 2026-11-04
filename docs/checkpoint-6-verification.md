# Checkpoint 6 verification

## Native evidence consumed

Run `41800279553`, source commit
`7c99a8bd97462fd774944a9682ab1da4d77a685a`:

- macOS arm64: 240 PASS, 8 OBSERVE, no failures;
- Windows elevated: 338 PASS, 13 OBSERVE, 6 ERROR;
- Windows filtered: 337 PASS, 12 OBSERVE, 7 expected SKIP, 1 ERROR;
- independent Windows selector mapper built and ran on NTFS, Windows Server
  2025 build 26100.

The exact failure classification and mapper interpretation are retained in
`native-run-41800279553-review.md`.

## Regression cycle

The access-policy regression first failed because owner, group, SACL, label,
attribute, scope, process-trust-label, and access-filter writes did not add
`READ_CONTROL`. The long-path policy spec first failed because no path policy
existed. After the production changes, the focused Crystal suite completed 13
examples with zero failures.

The Python evidence regression first failed because `long_path_evidence` did not
exist. After implementation, the focused test passed and the record is emitted
before bridge I/O.

## Portable and host verification

| Gate | Result |
|---|---|
| Project setup script | passed |
| Python catalog lock | 248 Darwin / 393 expanded Windows cases |
| Python harness | 42/42 passed |
| Crystal 1.21.1 specs | 83/83 passed |
| Crystal 1.18.0 specs | 83/83 passed |
| Crystal formatting | passed |
| `shards check` | passed |
| Linux libacl ABI probe | passed |
| Linux POSIX example | passed |
| Linux release build | passed |
| Crystal API documentation | passed; expected no-LibXML2 notice |
| Model collector, Crystal 1.21.1 | 4/4 passed |
| Model collector, Crystal 1.18.0 | 4/4 passed |

## Cross-target object generation

Object generation—not native linking or execution—passed for:

- public surface: Darwin x86-64, FreeBSD x86-64, Windows x86-64;
- Darwin native API: x86-64 and ARM64 on Crystal 1.21.1 and 1.18.0;
- Windows native API: x86-64 and ARM64 on Crystal 1.21.1 and 1.18.0.

The generated Windows artifacts were valid COFF `.obj` files; Darwin artifacts
were valid Mach-O objects.

## Remaining acceptance gate

The changed `CreateFileW` behavior has not executed on Windows after the fix.
Checkpoint 6 therefore requires focused hosted reruns of:

- `windows.sacl.*` in the elevated lane;
- `windows.path.long_component` in elevated and filtered lanes;
- the separately dispatched `windows-lab` lane for delegated write-only
  fallback and real local-user/group authorization.
