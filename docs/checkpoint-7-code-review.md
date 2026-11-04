# Checkpoint 7 code review

## Review method

Self-review of `c698821..0d223fe`; no independent subagent reviewer was available. This is weaker than a fresh-context review. The pass checked plan alignment, catalog determinism, native fixture containment, privilege/account boundaries, partial-output salvage, cleanup, comparison stability, artifact integrity, and push-cost containment.

## Strengths

- Qualification and mapping are separate contracts. Pushes retain only the original three smoke lanes; the exhaustive matrix is manually dispatched.
- Every behavior domain is process-isolated, append-only, catalog-locked, and independently revalidated.
- Windows native selector evidence distinguishes fixture creation, handle open, source-descriptor query, security API result, and cleanup.
- The largest Windows matrices enumerate every ACE flag byte, both ACL revisions, selector combinations, access masks, inheritance states, and Authz desired masks without assuming success.
- Real-account mapping remains exclusive to the manually dispatched `windows-lab` lane.
- Generated filesystems are bounded to runner-owned roots and have separate creation and cleanup evidence.
- Cross-run comparison suppresses volatile identity/layout data only in a derived projection; raw evidence is retained.

## Findings corrected during review

### Important: raw descriptor strings caused false semantic changes

`ci.compare` normalized `descriptor_hex` and `raw`, but one lifecycle/access path used the field name `descriptor`. Two equivalent descriptors containing different machine-local SIDs could therefore report a semantic regression. A failing test was added, and `descriptor` is now treated as an identity-bearing binary field while parsed descriptor fields remain compared.

### Important: filtered token might not access the generated ReFS root

The VHDX was formatted and its fixture root created by the elevated wrapper. The filtered Python process uses the same user SID but cannot rely on the elevated token's default DACL or integrity label. Setup now explicitly grants the runner SID inheritable full access and sets medium integrity before exporting `ACL_WINDOWS_REFS_ROOT`. Focused tests pin both operations.

### Important: cleanup could fail on an already-detached VHD

Cleanup previously called `Dismount-VHD` unconditionally when the file existed. It now queries `Get-VHD`, dismounts only while attached, re-queries, and fails if attachment remains.

### Important: attached macOS images could leak after unexpected plist output

When `hdiutil attach` succeeded but the expected mount entity was absent or malformed, the old path could lose the device name. The script now parses every bounded `/dev/disk...` entry, detaches each, and records any failed detach for final cleanup.

## Remaining limitations

- The new PowerShell and native behavior paths were not executed on Windows in this environment.
- The 53k-row map may expose hosted-runner timeout or artifact-size limits; partial rows are retained, but limits may require deterministic domain sharding after the first run.
- Loopback SMB is not a substitute for a separate Windows or Samba server.
- Active Directory claims/CAP policy and real audit-log generation require a separate domain/policy lab.
- The manual workflow uses current hosted labels and therefore depends on GitHub continuing to provide those images.

## Assessment

**Ready for native mapping run: yes.** Portable correctness and packaging gates are green. The artifact should be treated as a test/research checkpoint until the new manual map lanes execute on native runners.
