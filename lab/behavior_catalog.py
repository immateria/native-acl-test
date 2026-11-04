"""Deterministic semantic keys for native ACL behavior maps.

The catalog is pure and portable: it does not inspect the host or import
platform-specific ctypes declarations. Native workers must emit exactly one row
for every selected key, even when the outcome is an error or unsupported
observation.
"""
from itertools import combinations, product

DEPTHS = ("smoke", "full", "map")
DARWIN_DOMAINS = ("storage", "inheritance", "mode-access", "lifecycle", "api")
WINDOWS_DOMAINS = (
    "descriptor-storage",
    "selector-combinations",
    "access-evaluation",
    "inheritance-events",
    "lifecycle",
    "token-privilege",
    "authz",
    "multiuser-map",
)

DARWIN_RIGHTS = {
    "read-data": 1 << 1,
    "write-data": 1 << 2,
    "execute": 1 << 3,
    "delete": 1 << 4,
    "append-data": 1 << 5,
    "delete-child": 1 << 6,
    "read-attributes": 1 << 7,
    "write-attributes": 1 << 8,
    "read-ext-attributes": 1 << 9,
    "write-ext-attributes": 1 << 10,
    "read-security": 1 << 11,
    "write-security": 1 << 12,
    "change-owner": 1 << 13,
    "synchronize": 1 << 20,
    "generic-all": 1 << 21,
    "generic-execute": 1 << 22,
    "generic-write": 1 << 23,
    "generic-read": 1 << 24,
}
WINDOWS_RIGHTS = {
    "read-data": 0x00000001,
    "write-data": 0x00000002,
    "append-data": 0x00000004,
    "read-ea": 0x00000008,
    "write-ea": 0x00000010,
    "execute": 0x00000020,
    "delete-child": 0x00000040,
    "read-attributes": 0x00000080,
    "write-attributes": 0x00000100,
    "delete": 0x00010000,
    "read-control": 0x00020000,
    "write-dac": 0x00040000,
    "write-owner": 0x00080000,
    "synchronize": 0x00100000,
    "maximum-allowed": 0x02000000,
    "generic-all": 0x10000000,
    "generic-execute": 0x20000000,
    "generic-write": 0x40000000,
    "generic-read": 0x80000000,
    "all-file": 0x001F01FF,
}


def _sorted(values):
    return sorted(set(values))


def _subset(smoke, full, mapping, depth):
    if depth == "smoke":
        return _sorted(smoke)
    if depth == "full":
        return _sorted(set(smoke) | set(full))
    if depth == "map":
        return _sorted(set(smoke) | set(full) | set(mapping))
    raise ValueError("unknown behavior depth")


def _darwin_storage(depth):
    smoke = [
        "storage:rights:file:allow:read-data",
        "storage:rights:file:deny:write-data",
        "storage:ace-flags:directory:allow:060",
        "storage:acl-flags:file:00020000",
        "storage:count:file:0",
        "storage:count:file:128",
    ]
    full = []
    right_names = list(DARWIN_RIGHTS) + ["zero", "all-known", "bit-00", "bit-14", "bit-31"]
    for obj, kind, name in product(("file", "directory"), ("allow", "deny"), right_names):
        full.append(f"storage:rights:{obj}:{kind}:{name}")
    full_flags = list(range(0, 1 << 9, 0x10)) + [0x200, 0x400, 0x600]
    for obj, kind, flags in product(("file", "directory"), ("allow", "deny"), full_flags):
        full.append(f"storage:ace-flags:{obj}:{kind}:{flags:03x}")
    for obj, flags in product(("file", "directory"), (0, 1, 0x10000, 0x20000, 0x30000, 0x20001, 0x2, 0x4)):
        full.append(f"storage:acl-flags:{obj}:{flags:08x}")
    for obj, count in product(("file", "directory"), (0, 1, 2, 16, 64, 127, 128, 129)):
        full.append(f"storage:count:{obj}:{count}")

    mapping = []
    map_right_names = [f"bit-{bit:02d}" for bit in range(32)] + ["zero", "all-known"]
    for obj, kind, name in product(("file", "directory"), ("allow", "deny"), map_right_names):
        mapping.append(f"storage:rights:{obj}:{kind}:{name}")
    for obj, kind, bits in product(("file", "directory"), ("allow", "deny"), range(128)):
        flags = sum(1 << (4 + bit) for bit in range(7) if bits & (1 << bit))
        mapping.append(f"storage:ace-flags:{obj}:{kind}:{flags:03x}")
    acl_bits = (0x1, 0x2, 0x4, 0x8, 0x10000, 0x20000)
    for obj, bits in product(("file", "directory"), range(1 << len(acl_bits))):
        flags = sum(value for index, value in enumerate(acl_bits) if bits & (1 << index))
        mapping.append(f"storage:acl-flags:{obj}:{flags:08x}")
    for obj, count in product(("file", "directory"), (0, 1, 2, 16, 64, 127, 128, 129, 255, 0xFFFFFFFF)):
        mapping.append(f"storage:count:{obj}:{count}")
    return _subset(smoke, full, mapping, depth)


def _darwin_inheritance(depth):
    smoke = [
        "inheritance:create:allow:060",
        "inheritance:create:deny:0e0",
        "inheritance:move:allow:060",
        "inheritance:copy:allow:060",
    ]
    full = [f"inheritance:create:{kind}:{flags:03x}"
            for kind, bits in product(("allow", "deny"), range(32))
            for flags in [sum(1 << (4 + bit) for bit in range(5) if bits & (1 << bit))]]
    mapping = [f"inheritance:{event}:{kind}:{flags:03x}"
               for event, kind, bits in product(("create", "move", "copy", "hardlink"), ("allow", "deny"), range(32))
               for flags in [sum(1 << (4 + bit) for bit in range(5) if bits & (1 << bit))]]
    return _subset(smoke, full, mapping, depth)


def _darwin_mode_access(depth):
    policies = ("none", "empty", "allow-user", "deny-user", "allow-everyone", "deny-everyone", "allow-deny", "deny-allow")
    file_ops = ("read", "write", "append", "execute", "stat", "utime", "getxattr", "setxattr", "acl-read", "acl-write")
    dir_ops = ("list", "create-file", "create-dir", "traverse", "delete-child", "stat", "utime", "acl-read", "acl-write")
    smoke = [
        "mode-access:file:600:deny-user:read",
        "mode-access:file:600:allow-user:write",
        "mode-access:directory:700:deny-user:list",
        "mode-access:directory:700:allow-user:create-file",
    ]
    full = []
    for obj, mode, policy, operation in product(("file",), (0, 0o600, 0o777), policies,
                                                 ("read", "write", "append", "execute", "acl-read")):
        full.append(f"mode-access:{obj}:{mode:o}:{policy}:{operation}")
    for obj, mode, policy, operation in product(("directory",), (0, 0o700, 0o777), policies,
                                                 ("list", "create-file", "traverse", "delete-child", "acl-read")):
        full.append(f"mode-access:{obj}:{mode:o}:{policy}:{operation}")
    mapping = []
    for mode, policy, operation in product((0, 0o600, 0o644, 0o700, 0o755, 0o777), policies, file_ops):
        mapping.append(f"mode-access:file:{mode:o}:{policy}:{operation}")
    for mode, policy, operation in product((0, 0o600, 0o644, 0o700, 0o755, 0o777), policies, dir_ops):
        mapping.append(f"mode-access:directory:{mode:o}:{policy}:{operation}")
    return _subset(smoke, full, mapping, depth)


def _darwin_lifecycle(depth):
    names = (
        "rename-path", "rename-open-fd", "unlink-open-fd", "replace-path", "hardlink-create",
        "hardlink-write", "copyfile", "copytree", "clonefile", "move-into-inheriting-directory",
        "move-out-of-inheriting-directory", "copy-into-inheriting-directory", "chmod-file", "chmod-directory",
        "fchmod-open-fd", "chown-same-owner", "chgrp-current-group", "truncate", "symlink-follow",
        "symlink-nofollow", "dangling-symlink", "directory-symlink", "intermediate-symlink", "fifo-nofollow",
    )
    smoke = [f"lifecycle:{name}" for name in ("rename-open-fd", "hardlink-write", "copyfile", "symlink-nofollow")]
    full = [f"lifecycle:{name}" for name in names]
    mapping = full + [
        "lifecycle:filesystem-primary",
        "lifecycle:filesystem-apfs-case-sensitive",
        "lifecycle:filesystem-hfs-plus",
    ]
    return _subset(smoke, full, mapping, depth)


def _darwin_api(depth):
    smoke = [
        "api:presence:path:removed", "api:presence:path:empty", "api:presence:fd:one",
        "api:getattrlist:path-follow:size-100", "api:getattrlist:path-nofollow:size-100",
        "api:libc:path:one", "api:malformed:truncated-header",
    ]
    full = []
    for source, state in product(("path", "fd", "link"), ("removed", "empty", "one")):
        full.append(f"api:presence:{source}:{state}")
    for source, size in product(("path-follow", "path-nofollow", "fd"), (4, 23, 24, 28, 32, 44, 68, 100, 128, 3148, 4096)):
        full.append(f"api:getattrlist:{source}:size-{size}")
    for source, state in product(("path", "fd", "link"), ("removed", "empty", "one")):
        full.append(f"api:libc:{source}:{state}")
    malformed = (
        "truncated-header", "wrong-magic", "filesec-owner", "filesec-group", "negative-reference",
        "unaligned-reference", "reference-before-field", "reference-past-buffer", "short-acl",
        "count-length-mismatch", "count-129", "noacl-extra-bytes", "unknown-kind", "audit-flags",
        "unknown-right", "private-acl-flags",
    )
    full += [f"api:malformed:{name}" for name in malformed]
    mapping = list(full)
    for source, size in product(("path-follow", "path-nofollow", "fd", "pack-invalid"),
                                (0, 1, 4, 23, 24, 27, 28, 31, 32, 43, 44, 67, 68, 99, 100, 127, 128, 3148, 4096)):
        mapping.append(f"api:getattrlist:{source}:size-{size}")
    return _subset(smoke, full, mapping, depth)


def _windows_descriptor_storage(depth):
    smoke = [
        "descriptor-storage:file:dacl:type-00:rev-2:flags-00",
        "descriptor-storage:file:sacl:type-02:rev-2:flags-c0",
        "descriptor-storage:directory:dacl:type-05:rev-4:flags-03",
        "descriptor-storage:state:file:dacl-empty",
        "descriptor-storage:state:file:dacl-null",
    ]
    full = []
    for obj, placement, ace_type in product(("file", "directory"), ("dacl", "sacl"), tuple(range(22)) + (254,)):
        revision = 4 if ace_type in (5, 6, 7, 8, 11, 12, 15, 16) else 2
        flags = 0xC0 if ace_type in (2, 7, 13, 15) else 0
        full.append(f"descriptor-storage:{obj}:{placement}:type-{ace_type:02x}:rev-{revision}:flags-{flags:02x}")
    states = (
        "owner-absent", "owner-present", "group-absent", "group-present", "dacl-absent", "dacl-null",
        "dacl-empty", "dacl-one", "sacl-absent", "sacl-null", "sacl-empty", "sacl-one",
        "dacl-protected", "dacl-unprotected", "sacl-protected", "sacl-unprotected",
        "owner-defaulted", "group-defaulted", "dacl-defaulted", "sacl-defaulted",
        "dacl-auto-inherit-req", "sacl-auto-inherit-req",
        "dacl-auto-inherited", "sacl-auto-inherited",
        "both-auto-inherit-req", "both-auto-inherited", "rm-control-valid",
    )
    full += [f"descriptor-storage:state:{obj}:{state}" for obj, state in product(("file", "directory"), states)]
    mapping = []
    # Map every ACE_HEADER flag byte, including reserved bits. Windows stores
    # some combinations, rejects others, and may normalize inheritance/audit
    # bits depending on ACE family and object type. Keep both ACL revisions so
    # the native corpus records those boundaries instead of assuming them.
    for obj, placement, ace_type, revision, flags in product(
        ("file", "directory"), ("dacl", "sacl"), tuple(range(22)) + (254,), (2, 4),
        range(256),
    ):
        mapping.append(f"descriptor-storage:{obj}:{placement}:type-{ace_type:02x}:rev-{revision}:flags-{flags:02x}")
    mapping += [f"descriptor-storage:state:{obj}:{state}" for obj, state in product(("file", "directory"), states)]
    return _subset(smoke, full, mapping, depth)


def _selector_values(depth):
    bits = (1, 2, 4, 8, 16, 32, 64, 128, 256)
    smoke = {1, 4, 7, 8, 16, 0x1FF, 0x10000}
    full = set(smoke) | set(bits)
    full |= {a | b for a, b in combinations(bits, 2)}
    full |= {7 | 8, 8 | 16, 8 | 32, 8 | 64, 8 | 128, 8 | 256, 7 | 16, 7 | 32, 7 | 64}
    mapping = {sum(bit for index, bit in enumerate(bits) if mask & (1 << index)) for mask in range(1, 1 << len(bits))}
    mapping |= {0x10000, 0x10000 | 7, 0x10000 | 8, 0x10000 | 0x1FF}
    # SetSecurityInfo uses high SECURITY_INFORMATION bits to protect or
    # unprotect DACL/SACL inheritance. Map individual, contradictory, and
    # cross-DACL/SACL combinations against representative component sets.
    dacl_controls = (0, 0x20000000, 0x80000000, 0xA0000000)
    sacl_controls = (0, 0x10000000, 0x40000000, 0x50000000)
    for base, dacl_control, sacl_control in product(
            (4, 8, 12, 7, 0x1FF), dacl_controls, sacl_controls):
        if dacl_control and not (base & 4):
            continue
        if sacl_control and not (base & 8):
            continue
        mapping.add(base | dacl_control | sacl_control)
    return _subset(smoke, full, mapping, depth)


def _windows_selectors(depth):
    values = _selector_values(depth)
    return _sorted(f"selector-combinations:{obj}:{operation}:{value:08x}"
                   for obj, operation, value in product(("file", "directory"), ("query", "set"), values))


def _windows_access(depth):
    policies = (
        "allow", "deny", "allow-deny", "deny-allow", "empty", "null",
        "owner-rights-allow", "owner-rights-deny", "inherited-allow", "inherited-deny",
    )
    smoke = [
        "access-evaluation:file:allow:read-data", "access-evaluation:file:deny:write-data",
        "access-evaluation:file:null:generic-read", "access-evaluation:directory:deny:delete-child",
    ]
    full_names = list(WINDOWS_RIGHTS)
    full = [f"access-evaluation:{obj}:{policy}:{name}"
            for obj, policy, name in product(("file", "directory"), policies[:6], full_names)]
    mapping_names = full_names + ["zero", "read-write", "read-execute", "generic-read-write", "standard-all", "specific-all"]
    mapping = [f"access-evaluation:{obj}:{policy}:{name}"
               for obj, policy, name in product(("file", "directory"), policies, mapping_names)]
    return _subset(smoke, full, mapping, depth)


def _windows_inheritance(depth):
    smoke = [
        "inheritance-events:create:allow:03", "inheritance-events:create:deny:0b",
        "inheritance-events:propagate-existing:allow:03", "inheritance-events:move-in:allow:03",
    ]
    full = [f"inheritance-events:create:{kind}:{flags:02x}"
            for kind, flags in product(("allow", "deny"), range(32))]
    events = ("create", "grandchild", "propagate-existing", "move-in", "copy-in", "hardlink-in")
    mapping = [f"inheritance-events:{event}:{kind}:{flags:02x}"
               for event, kind, flags in product(events, ("allow", "deny"), range(32))]
    # The compact matrix above preserves the original stable keys. The expanded
    # matrix answers the distinctions it deliberately omitted: file versus
    # directory children and protected versus inheriting child descriptors.
    mapping += [
        f"inheritance-events:matrix:{event}:{kind}:{flags:02x}:{child}:{protection}"
        for event, kind, flags, child, protection in product(
            events, ("allow", "deny"), range(32),
            ("file", "directory"), ("inherit", "protected"))
    ]
    return _subset(smoke, full, mapping, depth)


def _windows_lifecycle(depth):
    names = (
        "rename-path", "rename-open-handle", "replace-path", "delete-pending", "hardlink-create",
        "hardlink-write", "ads-create", "ads-write", "copy-file", "copy-directory", "move-same-volume",
        "move-into-inheriting-directory", "copy-into-inheriting-directory", "symlink-follow", "symlink-nofollow",
        "dangling-symlink", "directory-symlink", "junction-follow", "junction-nofollow", "intermediate-reparse",
        "extended-local", "extended-unc", "device-namespace", "volume-guid", "dos-short-name",
        "trailing-dot", "trailing-space", "reserved-name", "unicode-normalization", "case-sensitive-directory",
        "file-id-open", "open-by-id-after-rename", "readonly-attribute", "compressed-attribute", "sparse-file",
        "encrypted-file", "loopback-smb", "share-delete", "share-read", "share-write",
    )
    smoke = [f"lifecycle:{name}" for name in ("rename-open-handle", "hardlink-write", "ads-write", "symlink-nofollow")]
    full = [f"lifecycle:{name}" for name in names]
    mapping = full + [
        "lifecycle:filesystem-primary",
        "lifecycle:filesystem-loopback-smb",
        "lifecycle:filesystem-refs",
    ]
    return _subset(smoke, full, mapping, depth)


def _windows_token_privilege(depth):
    names = (
        "token-user", "token-groups", "token-restricted-sids", "token-owner", "token-primary-group",
        "token-default-dacl", "token-integrity", "token-elevation", "token-virtualization", "token-appcontainer",
        "owner-implicit-read-control", "owner-implicit-write-dac", "owner-rights-read-control",
        "owner-rights-write-dac", "deny-only-allow", "deny-only-deny", "restricting-sid-double-check",
        "maximum-allowed", "impersonation-vs-primary", "fresh-token-group-snapshot",
    )
    privileges = ("SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeChangeNotifyPrivilege")
    states = ("absent", "disabled", "enabled", "removed")
    names += tuple(f"privilege:{privilege}:{state}" for privilege, state in product(privileges, states))
    names += (
        "backup-query", "backup-set", "restore-owner", "restore-dacl", "restore-sacl", "take-ownership",
        "low-integrity-no-write-up", "low-integrity-no-read-up", "low-integrity-no-execute-up",
        "medium-integrity", "high-integrity", "system-integrity",
    )
    smoke = ["token-privilege:token-user", "token-privilege:token-integrity", "token-privilege:owner-implicit-read-control"]
    full = [f"token-privilege:{name}" for name in names]
    return _subset(smoke, full, full, depth)


def _windows_authz(depth):
    conditions = (
        "allow-true", "allow-false", "allow-unknown", "deny-true", "deny-false", "deny-unknown",
        "user-string-equal", "user-string-not-equal", "user-int-equal", "user-bool-equal",
        "user-sid-member", "user-any-of", "user-all-of", "device-attribute", "resource-attribute",
        "user-resource-intersection", "member-of", "not-member-of", "exists", "not-exists",
        "callback-accept", "callback-reject", "callback-object-accept", "callback-object-reject",
        "compound-and", "compound-or", "compound-not", "unknown-and-true", "unknown-and-false",
        "unknown-or-true", "unknown-or-false", "cached-access-check", "object-type-list",
        "principal-self", "central-policy-missing", "central-policy-disabled", "resource-claim-roundtrip",
        "conditional-binary-roundtrip", "malformed-condition", "opaque-callback-payload",
    )
    smoke = [f"authz:{name}" for name in ("allow-true", "allow-false", "allow-unknown", "opaque-callback-payload")]
    full = [f"authz:{name}" for name in conditions]
    # Evaluate every semantic condition against concrete and generic desired
    # masks. This captures generic mapping, partial grants, MAXIMUM_ALLOWED, and
    # error-array behavior without conflating those with expression truth.
    desired = tuple(WINDOWS_RIGHTS) + (
        "zero", "read-write", "read-execute", "generic-read-write",
        "standard-all", "specific-all",
    )
    mapping = list(full) + [
        f"authz:matrix:{condition}:{right}"
        for condition, right in product(conditions, desired)
    ]
    return _subset(smoke, full, mapping, depth)



def _windows_multiuser(depth):
    """Real local-SAM token matrix; intentionally map-only and manual-lane only."""
    if depth != "map":
        return []
    roles = ("alice", "bob", "carol")
    scenarios = (
        "direct-allow", "direct-deny",
        "allow-group-enabled", "allow-group-absent",
        "deny-group-enabled", "deny-group-deny-only",
        "owner-implicit", "owner-rights-allow", "owner-rights-deny",
        "delegated-write-dac", "delegated-read-control",
        "restricting-sid-granted", "restricting-sid-missing",
        "fresh-token-before-group-add", "fresh-token-after-group-add",
        "stale-token-after-group-remove", "primary-vs-impersonation",
    )
    rights = ("read-data", "write-data", "delete", "read-control",
              "write-dac", "maximum-allowed")
    return _sorted(f"multiuser-map:{role}:{scenario}:{right}"
                   for role, scenario, right in product(roles, scenarios, rights))

def manifest(platform, depth):
    """Return domain -> sorted semantic keys for one native mapping depth."""
    if depth not in DEPTHS:
        raise ValueError("unknown behavior depth")
    if platform == "darwin":
        return {
            "storage": _darwin_storage(depth),
            "inheritance": _darwin_inheritance(depth),
            "mode-access": _darwin_mode_access(depth),
            "lifecycle": _darwin_lifecycle(depth),
            "api": _darwin_api(depth),
        }
    if platform == "windows":
        return {
            "descriptor-storage": _windows_descriptor_storage(depth),
            "selector-combinations": _windows_selectors(depth),
            "access-evaluation": _windows_access(depth),
            "inheritance-events": _windows_inheritance(depth),
            "lifecycle": _windows_lifecycle(depth),
            "token-privilege": _windows_token_privilege(depth),
            "authz": _windows_authz(depth),
            "multiuser-map": _windows_multiuser(depth),
        }
    raise ValueError("unsupported behavior platform")
