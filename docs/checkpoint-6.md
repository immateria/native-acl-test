# Checkpoint 6 — native Windows return corrections

Checkpoint 6 advances the shard to **0.0.6** using the full hosted native run
`41800279553` as its runtime evidence. It does not alter the Darwin model or
backend because the macOS arm64 lane completed all 248 selected cases without a
failure.

## Production changes

### All path writes prefer READ_CONTROL

`SetSecurityAccessMask` remains the source of the selector-specific base mask.
The path opener now prefers `base | READ_CONTROL` for every write selector, not
only DACL writes. This matches the returned Windows Server 2025 / build 26100 SDK map,
where several
setters accepted the base handle open but returned access denied until the
handle also carried `READ_CONTROL`.

The compatibility boundary is unchanged:

1. open with the augmented mask;
2. only when that `CreateFileW` call itself returns access denied, retry the
   exact SDK mask once;
3. never retry `SetSecurityInfo`;
4. never reopen a borrowed handle or alter privileges.

This keeps delegated write-only handles possible while making normal path writes
work on the measured NTFS implementation.

### Manifest-independent long path handling

Before `CreateFileW`, an ordinary path is lexically resolved using Windows path
semantics only to determine its absolute UTF-16 length. Paths below 260 UTF-16
code units retain their original spelling. Longer paths are converted to:

```text
\\?\C:\...
\\?\UNC\server\share\...
```

Existing `\\?\` and `\\.\` paths pass through unchanged. Error messages continue
to name the caller's original path. This fixes the hosted runner case where a
legal 240-character component pushed the full path beyond `MAX_PATH`, while not
requiring the consuming executable to carry a long-path-aware manifest.

## Test and evidence changes

- Added focused access-policy regressions for owner, group, DACL, SACL, label,
  attribute, scope, process-trust-label, and access-filter writes.
- Added portable Windows path-policy tests for short, relative-long, UNC-long,
  pre-namespaced, and embedded-NUL inputs.
- The native long-component case records component, relative, and absolute
  UTF-16 lengths plus both ordinary and extended spellings before bridge I/O.
- The full native-run analysis is retained in
  `docs/native-run-41800279553-review.md`.

## Native acceptance boundary

Linux verification can prove the pure path/access policies, both supported
Crystal compiler lanes, portable models, and Windows/macOS target object
generation. The final acceptance evidence remains a new hosted Windows run:

```sh
gh workflow run native-acl.yml --ref main \
  -f lane=windows-elevated -f profile=full \
  -f 'only=windows.sacl.*' -f seed=20261103

gh workflow run native-acl.yml --ref main \
  -f lane=windows-filtered -f profile=full \
  -f 'only=windows.path.long_component' -f seed=20261103
```

After those focused runs, dispatch `lane=windows-lab` separately to exercise the
real-user/group and delegated-write fallback matrix.
