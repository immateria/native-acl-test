# Checkpoint 7 — exhaustive native ACL behavior mapping

Checkpoint 7 advances the shard to **0.0.7** and separates two jobs that had become conflated:

1. bounded qualification, which remains suitable for every push; and
2. exhaustive behavior mapping, which is manual, domain-isolated, append-only, and evidence-first.

## New mapping framework

The `map` profile now emits **2,173 Darwin rows** and **52,989 ordinary Windows rows**. The separate `windows-lab` lane adds **306** real-account rows for a total of **53,295**.

Every semantic key is deterministic and reviewed in `lab/behavior_catalog.py`. Each domain runs in a fresh process and must emit exactly one row per key plus one final summary. Partial JSONL survives a crash. The aggregate evidence gate re-parses every file rather than trusting worker exit codes or summaries.

## New native breadth

Darwin mapping covers storage flags/rights/counts, inheritance events, POSIX-mode interaction with ACL policy, object lifecycle, libc/getattrlist boundaries, and malformed native record shapes.

Windows mapping covers the entire ACE flag byte across known/opaque ACE families and ACL revisions, descriptor-control states, every component-selector combination, protected/unprotected control selectors, access and inheritance matrices, lifecycle/namespace behavior, token and privilege state, Authz conditional/claim/callback boundaries, and real local-user/group authorization.

## Runner and filesystem breadth

Manual mapping runs across macOS arm64 and Intel plus Windows Server 2025 and 2022 with elevated and filtered tokens. Generated case-sensitive APFS/HFS+ images, loopback SMB, and ReFS VHDX fixtures are attempted under bounded runner-owned roots. Unsupported facilities remain observations. Cleanup failures make the lane red.

## Usable handbacks

- recursive evidence hashes include every domain JSONL and worker log;
- semantic comparison joins by stable domain/key;
- runner paths, timings, generated names, local SIDs, Darwin UUIDs, and raw identity bytes are normalized only in the comparison projection;
- raw evidence remains untouched;
- coverage additions/removals are reported separately from semantic changes.

See `docs/BEHAVIOR-MAPPING.md` for the exact domain counts and interpretation rules.

## Native acceptance boundary

Portable tests can prove catalog completeness, process isolation, serialization, evidence validation, semantic diffing, script safety, and cross-target compilation. They cannot establish the new OS behavior rows. The next native acceptance run is:

```sh
gh workflow run native-acl.yml --ref main -f lane=all -f profile=map

gh workflow run native-acl.yml --ref main -f lane=windows-lab -f profile=map
```
