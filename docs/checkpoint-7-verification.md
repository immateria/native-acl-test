# Checkpoint 7 verification

## Scope

Checkpoint 7 adds exhaustive native behavior mapping without changing the frozen named qualification catalogs: **248 Darwin cases** and **393 expanded Windows cases**. The behavior catalogs are separate:

- Darwin: 25 smoke, 661 full, **2,173 map** rows.
- Windows ordinary lanes: 52 smoke, 793 full, **52,989 map** rows.
- Windows lab: **53,295 map** rows including 306 real-account rows.

The new behavior rows have not yet executed on hosted macOS or Windows runners. This document records portable orchestration, model, compiler, and package verification only.

## Red/green regressions

The implementation was developed with focused failing tests for:

- behavior profile selection and one-process-per-domain isolation;
- Darwin and Windows catalog completeness and key decoding;
- exact Windows selector access variants and call-boundary evidence;
- protected/unprotected selector controls and descriptor control-state storage;
- hosted runner and generated-filesystem wiring;
- cleanup after partial macOS image and Windows SMB/VHD creation;
- independent domain-JSONL revalidation and recursive evidence hashing;
- semantic comparison by `(domain, key)` rather than row order;
- normalization of runner paths, local SIDs, Darwin UUIDs, generated accounts, and raw identity-bearing descriptor bytes;
- filtered-token access to a generated ReFS root.

The final author review found and corrected the last two items before packaging.

## Portable verification

| Gate | Result |
|---|---:|
| Python harness | **94/94 passed** |
| Frozen qualification inventory | **248 Darwin / 393 Windows** |
| Behavior catalog decoding | **2,173 Darwin / 53,295 Windows-lab map rows** |
| `ci/macos-volumes.sh` syntax | Passed |
| Portable strict C11 Windows mapper syntax | Passed |
| `git diff --check` | Passed |
| Project setup script | Passed |
| Shards | 0.20.0 |
| `shards check` | Passed |
| Crystal formatting | Passed |
| Crystal 1.21.1 specs | **83/83 passed** |
| Crystal 1.18.0 specs | **83/83 passed** |
| Model collector, Crystal 1.21.1 | **4/4 passed** |
| Model collector, Crystal 1.18.0 | **4/4 passed** |
| Linux libacl ABI probe | Passed |
| Linux POSIX example | Passed |
| Linux release-mode public API build | Passed |
| Crystal API documentation | Passed; expected no-LibXML2 notice |

## Cross-target object generation

Object generation—not native linking or execution—passed for:

- public API: Darwin x86-64, FreeBSD x86-64, Windows x86-64;
- Darwin native API: x86-64 and ARM64 with Crystal 1.21.1 and 1.18.0;
- Windows native API: x86-64 and ARM64 with Crystal 1.21.1 and 1.18.0.

The Darwin objects were Mach-O, Windows objects were COFF, and the FreeBSD public object was a FreeBSD ELF relocatable.

## Remaining native acceptance gate

Run the map on hosted kernels and return every artifact, including red lanes:

```sh
gh workflow run native-acl.yml --ref main -f lane=all -f profile=map

gh workflow run native-acl.yml --ref main -f lane=windows-lab -f profile=map
```

Native acceptance must confirm:

- workflow runner labels still resolve;
- generated APFSX/HFSX, loopback SMB, and ReFS setup/cleanup behavior;
- total runtime of the 47,158-row descriptor-storage domain;
- Windows SDK compilation and execution of the expanded selector mapper;
- Authz and local-account behavior on the hosted Windows build;
- no unexpected catalog omissions, duplicate rows, worker timeouts, or leftover native resources.
