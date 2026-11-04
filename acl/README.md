# acl — native filesystem ACL research shard

Version 0.0.6; Crystal >= 1.18, < 2. No runtime shard dependencies.

| API | Model on any host | Native operations | Verified here |
|---|---|---|---|
| `ACL::POSIX` | Yes | Linux/libacl | Runtime and filesystem tests |
| `ACL::Darwin` | Yes | macOS/libc | Previous native APFS return; captured-byte specs |
| `ACL::Windows` | Yes | Windows/Advapi32 | Server 2025/NTFS return analyzed; checkpoint-6 fixes await native rerun |
| FreeBSD/NFSv4 | Not implemented | Not implemented | Source research only |

`require "acl"` loads all models and the current platform's backend. Standalone
`require "acl/darwin"` and `require "acl/windows"` load those models anywhere,
without attempting to link the foreign native APIs. The `ACL.access/default/set`
convenience surface remains **POSIX**, not an automatic format conversion API.

## Linux

```crystal
require "acl"

alias E = ACL::POSIX::Entry
alias P = ACL::POSIX::Permission
acl = ACL::POSIX::List.new(ACL::POSIX::Scope::Access, [
  E.owner(P::Read | P::Write), E.user(1234_u32, P::Read),
  E.owning_group(P::None), E.mask(P::Read), E.other(P::None),
])
ACL.set("example.txt", acl)
puts ACL.access("example.txt").to_text
```

`ACL.default(path)` returns `nil` when no directory default exists;
`ACL.delete_default(path)` removes it. Linux path APIs follow symlinks.

## Darwin/macOS

```crystal
require "acl/darwin"

path = "example.txt"
snapshot = ACL::Darwin.read(path, follow_symlinks: false)
puts snapshot.presence # NotReturned, Absent, or Present
if list = snapshot.list
  list.each { |entry| puts "#{entry.principal}: #{entry.permissions}" }
  ACL::Darwin.write(path, list, follow_symlinks: false)
end
# ACL::Darwin.write(path, nil) explicitly removes an extended ACL.
```

`read(fd : Int32)` and `write(fd : Int32, list : List?)` borrow the descriptor.
Reads return `Snapshot`: `NotReturned` means the successful attribute query did
not supply ACL evidence, not confirmed absence or proof of filesystem support.
`Absent` requires an explicit native NOACL marker. `Present` includes zero-entry
ACLs. `snapshot.list` is optional; do not turn an omitted list into a removal
write. Only an explicit `write(path, nil)` is a removal request.
The backend uses `getattrlist`/`fgetattrlist` with returned-attribute bitmaps and
full-size reporting, avoiding a zero-entry ACL loss in the uploaded libc statx
wrapper. A fixed bounded response buffer supports 128 entries and validates
references before decoding. Native syscall errors remain errors.
Ordered `Entry.allow/deny` take a UUID, native `Permission`, and optional raw
inheritance flags. `List#with_entry` and `#with_flags` return new snapshots.
Numeric UID/GID or account-name lookup is intentionally separate; this checkpoint
does not implement it. `List#to_bytes` is libc's portable ACL export format, not
an xattr or native struct dump. Unknown bits survive; unsupported ACE kinds are
readable but rejected before a native write. Native writes may normalize data.

No-follow controls the final path component, not intermediate symlinks. Its write
path uses an `O_SYMLINK` nonblocking read-only open; this can require read access
in addition to ACL modification rights. Use an existing fd when that matters.
An empty Darwin ACL is not Windows' empty-DACL deny-all policy.

## Windows

```crystal
require "acl/windows"

path = "example.txt"
snapshot = ACL::Windows.read(path) # owner, group, DACL; NOT SACL
puts snapshot.owner
if list = snapshot.dacl.list
  # A no-op example with an explicit component selection, not a full restore.
  descriptor = snapshot.descriptor.with_dacl(ACL::Windows::ACLState.present(list))
  update = ACL::Windows::Update.new(descriptor, ACL::Windows::Information::DACL)
  ACL::Windows.write(path, update)
end
```

`read_handle` and `write_handle` borrow a `Void*` FILE_OBJECT handle.
Path operations first obtain the SDK access mask. Every path-based write prefers
the SDK mask plus `READ_CONTROL`; audit-SACL reads do the same. Native Windows build 26100 evidence showed that a handle opened with only
the SDK write mask can still
reach `SetSecurityInfo` and be rejected there, while the same operation succeeds
with `READ_CONTROL` present. If the augmented *open* itself fails specifically
with access denied, the opener tries the unmodified SDK mask once, preserving
delegated write-only access. Only the open is retried: no successful handle is
replaced, no setter is invoked twice, and the component selection, share mode,
and reparse mode do not change. Failed path opens raise `PathOpenError`, a
`NativeError` subclass whose `attempts` retains every requested access mask and
Win32 code. No privilege is enabled. Borrowed handles are used as-is.

Short path spellings are passed through unchanged. When the resolved absolute
UTF-16 path reaches the traditional `MAX_PATH` boundary, the backend converts it
to an extended-length spelling before `CreateFileW`: local paths use `\\?\`
and UNC paths use `\\?\UNC\`. Existing `\\?\` and `\\.\` namespace
paths are preserved. This removes any dependency on the consuming executable's
long-path-aware manifest while retaining the caller's original path in errors.

`set_dacl(path, list, inheritance: :preserve)` is a DACL-only convenience.
Inheritance can explicitly be `:protect` or `:unprotect`; it is never inferred
from the source descriptor's protection bits. Directory inheritance changes can
propagate to existing descendants. Read/modify/write is not atomic or compare-and-swap.

`SID.parse` accepts numeric SIDs, not account names or SDDL aliases. `ACE.allow`,
`.deny`, `.audit`, `.callback`, and `.object` build supported layouts. Entries
support `with_mask`, `with_sid`, and `with_flags`; lists support `with_entry`,
`with_entries`, `inserted`, and `without_entry`. They preserve order; no sorting,
trustee merging, or access evaluation occurs. Unknown/compound ACEs remain opaque;
changing their SID or access mask is rejected rather than guessed. `ACE#category`
classifies defined DACL and SACL families without claiming to decode opaque
bodies; reserved compound type 4 remains a DACL-category entry.

Binary `SID`, `ACE`, `List`, and self-relative `Descriptor` are owned snapshots.
Unedited output preserves original bytes, including opaque bodies and padding.
Editing a descriptor preserves other components semantically, not its old offsets
or unused layout padding. Native `Descriptor.from_sddl` / `#to_sddl` are useful
textual views, not lossless archival serialization.

`ACLState.absent`, `.null`, and `.present(List.new)` are distinct. An unread
component is tracked separately in `Snapshot#queried`; reading it raises.
A null DACL native write requires `allow_null_dacl: true`. Absent DACL writes
are rejected. Writes select only the requested owner/group/DACL/SACL components.
`Update.from_snapshot` rejects applying data not obtained by that snapshot's query.
The low-level `snapshot.descriptor` is still a partial image, not a complete backup.

SACL auditing, mandatory labels, attributes, scope, process-trust labels, and
access filters have separate `Information` selectors. The OS decides support and
privilege requirements. This library never enables privileges. Full backup
restore, every descriptor-control bit, account lookup, conditional-ACE evaluation,
and effective-access checking are outside this checkpoint.

## Tests

`crystal spec --error-trace --error-on-warnings` runs portable and host-native specs.
See `../scripts/verify-native.sh` / `verify-native.ps1` for the additional native
SDK probes. The full native harness lives at the checkpoint root. The Windows
path policy and new integration cases require execution on a native host; older
native results and the portable evidence replay are distinct verification layers.
See `../docs/checkpoint-6.md` for the evidence behind this revision.
