# Native run 41800279553 review

Source commit: `7c99a8bd97462fd774944a9682ab1da4d77a685a`

| Lane | PASS | OBSERVE | SKIP | ERROR | Gate |
|---|---:|---:|---:|---:|---|
| macOS arm64 / APFS | 240 | 8 | 0 | 0 | pass |
| Windows x64 elevated / NTFS | 338 | 13 | 0 | 6 | fail |
| Windows x64 filtered / NTFS | 337 | 12 | 7 | 1 | fail |

The macOS lane completed all 248 selected cases without a shard failure. No
Darwin production change is justified by this return.

## Windows root causes

### SetSecurityInfo needs READ_CONTROL on these path-opened handles

Five elevated cases reached `SetSecurityInfo` and returned Win32 error 5:

- `windows.sacl.audit_40`
- `windows.sacl.audit_80`
- `windows.sacl.audit_c0`
- `windows.sacl.label_write_low`
- `windows.sacl.audit_dacl_isolation`

The independent SDK mapper used a fresh fixture for each access variant. On the
same Windows Server 2025 / build 26100 runner it showed the same pattern
for audit-SACL, label,
attribute, and access-filter writes: the SDK-calculated write access opened the
handle but the setter returned error 5; adding `READ_CONTROL` made the setter
succeed. The existing exact-mask fallback remains necessary for a genuinely
delegated write-only trustee, so the shard now *prefers* the augmented mask for
all path writes and falls back only when that augmented `CreateFileW` call is
itself denied. A setter is never retried.

### Relative long path depends on the executable manifest

`windows.path.long_component` failed in both Windows lanes. The 240-character
component was legal and Python created it, but the relative spelling resolved
past the traditional `MAX_PATH` boundary under the Actions checkout. The Crystal
bridge's `CreateFileW` returned error 3 before any ACL query. Explicit extended
spelling already passed elsewhere in the same suite.

The backend now resolves only for the length decision and converts long local or
UNC paths to the Win32 extended namespace. Short spellings and paths already in
the `\\?\\` or `\\.\\` namespaces are unchanged. The original caller spelling is
retained in diagnostics.

The native case now records relative and absolute UTF-16 lengths before the first
bridge call, so a future early failure still carries the path evidence.

## Unchanged boundaries

- The filtered lane's seven privileged SACL skips are expected.
- The manual `windows-lab` lane is not part of `lane=all`; it still requires an
  explicit dispatch because it creates disposable local users and groups.
- Process-trust-label setters remained denied in the mapper even with
  `READ_CONTROL`; checkpoint 6 does not reclassify that native result as a shard
  failure or claim support the OS did not demonstrate.
