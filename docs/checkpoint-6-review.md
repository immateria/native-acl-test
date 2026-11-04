# Checkpoint 6 implementation review

## Scope reviewed

- Windows path-open access policy and fallback behavior;
- long relative, absolute, UNC, and pre-namespaced path handling;
- integration into `CreateFileW` without changing diagnostic labels;
- regression coverage and returned native-run interpretation;
- repository/package hygiene.

## Strengths

- The access fix changes only the handle-open preference. It does not retry a
  setter, modify the selected descriptor components, enable privileges, or
  reopen borrowed handles.
- Exact-mask fallback remains guarded by an access-denied result from the
  augmented `CreateFileW`, preserving the delegated write-only experiment.
- Long path conversion is conditional. Ordinary short path spelling and native
  device namespaces are not rewritten.
- UTF-16 length, rather than UTF-8 byte length or Unicode scalar count, controls
  the `MAX_PATH` decision.
- The native test records path-length evidence before the first bridge call, so
  an early regression is diagnosable.
- Toolchain symlinks and compiler caches are no longer tracked in the repository.

## Findings addressed during review

1. Documentation initially called the runner Windows 11. The returned
   environment identifies Windows Server 2025, build 26100; all checkpoint-6
   documents now use that evidence.
2. The first cross-target verification looked for a Unix `.o` filename after a
   successful Windows cross-compile. The verification was corrected to accept
   the emitted `.obj`; all x86-64 and ARM64 objects then passed on both compiler
   lanes.
3. The prepared repository had tracked absolute `bin/` toolchain symlinks. They
   were removed, and `bin/` plus `.cache/` are now ignored and recreated only by
   the local setup script.

## Residual boundary

The pure policy uses Crystal's lexical Windows path expansion to construct an
absolute spelling for long relative paths. The returned failing case is covered,
and Windows target code generation passes, but the corrected `CreateFileW` path
has not yet executed on a Windows kernel. A focused Actions rerun is therefore a
checkpoint acceptance requirement, not optional polish.

## Assessment

No unresolved critical or important source issue was found in this change set.
It is suitable as a new research checkpoint. It is not evidence that the two
Windows runtime regressions are closed until the focused native lanes pass.
