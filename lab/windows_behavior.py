"""Windows filesystem ACL behavior mapping against public Win32 APIs.

The module deliberately separates bounded binary construction from native API
calls. Every mutating semantic key receives a fresh marker-owned fixture root;
native rejections are observations, while harness defects are errors.
"""
import contextlib
import ctypes as C
import os
import pathlib
import shutil
import stat
import struct
import tempfile
import traceback
import uuid

from . import behavior_catalog, core, wire
from . import map_controls
from .native import NativeFailure, SkipCase

OTHER_SID = "S-1-5-21-3981726199-1872936101-2918176103-424242"
WORLD_SID = "S-1-1-0"
SYSTEM_SID = "S-1-5-18"
OWNER_RIGHTS_SID = "S-1-3-4"
LOW_INTEGRITY_SID = "S-1-16-4096"
MEDIUM_INTEGRITY_SID = "S-1-16-8192"
OBJECT_GUID = "00112233-4455-6677-8899-aabbccddeeff"
INHERITED_GUID = "ffeeddcc-bbaa-9988-7766-554433221100"
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
DACL_CONTROL_INFORMATION = (UNPROTECTED_DACL_SECURITY_INFORMATION |
                            PROTECTED_DACL_SECURITY_INFORMATION)
SACL_CONTROL_INFORMATION = (UNPROTECTED_SACL_SECURITY_INFORMATION |
                            PROTECTED_SACL_SECURITY_INFORMATION)


DACL_TYPES = frozenset((0, 1, 4, 5, 6, 9, 10, 11, 12))
SACL_TYPES = frozenset((2, 3, 7, 8, 13, 14, 15, 16, 17, 18, 19, 20, 21))
CALLBACK_TYPES = frozenset((9, 10, 11, 12, 13, 14, 15, 16))


def right_mask(name):
    if name in behavior_catalog.WINDOWS_RIGHTS:
        return behavior_catalog.WINDOWS_RIGHTS[name]
    combinations = {
        "zero": 0,
        "read-write": 0x00000003,
        "read-execute": 0x00000021,
        "generic-read-write": 0xC0000000,
        "standard-all": 0x001F0000,
        "specific-all": 0x000001FF,
    }
    try:
        return combinations[name]
    except KeyError as exc:
        raise ValueError(f"unknown Windows right: {name}") from exc


def descriptor_dimensions(key):
    parts = key.split(":")
    if parts[0] != "descriptor-storage":
        raise ValueError("not a Windows descriptor-storage key")
    if parts[1] == "state":
        if len(parts) != 4:
            raise ValueError("invalid descriptor state key")
        return ("state", parts[2], parts[3])
    if len(parts) != 6:
        raise ValueError("invalid descriptor ACE key")
    obj, placement = parts[1], parts[2]
    ace_type = int(parts[3].split("-", 1)[1], 16)
    revision = int(parts[4].split("-", 1)[1])
    flags = int(parts[5].split("-", 1)[1], 16)
    return ("ace", obj, placement, ace_type, revision, flags)


def selector_dimensions(key):
    domain, obj, operation, selector = key.split(":", 3)
    if domain != "selector-combinations":
        raise ValueError("not a Windows selector key")
    return obj, operation, int(selector, 16)


def access_dimensions(key):
    domain, obj, policy, right = key.split(":", 3)
    if domain != "access-evaluation":
        raise ValueError("not a Windows access key")
    return obj, policy, right


def inheritance_dimensions(key):
    parts = key.split(":")
    if not parts or parts[0] != "inheritance-events":
        raise ValueError("not a Windows inheritance key")
    if len(parts) == 4:
        _, event, kind, flags = parts
        return event, kind, int(flags, 16), "both", "inherit"
    if len(parts) == 7 and parts[1] == "matrix":
        _, _, event, kind, flags, child, protection = parts
        if child not in ("file", "directory") or protection not in ("inherit", "protected"):
            raise ValueError("invalid Windows inheritance matrix key")
        return event, kind, int(flags, 16), child, protection
    raise ValueError("invalid Windows inheritance key")


def lifecycle_dimensions(key):
    domain, name = key.split(":", 1)
    if domain != "lifecycle" or not name:
        raise ValueError("not a Windows lifecycle key")
    return name


def token_privilege_dimensions(key):
    parts = key.split(":")
    if parts[0] != "token-privilege" or len(parts) < 2:
        raise ValueError("not a Windows token/privilege key")
    name = parts[1]
    if name == "privilege":
        if len(parts) != 4:
            raise ValueError("invalid privilege state key")
        return ("privilege", parts[2], parts[3])
    if name.startswith("token-"):
        return ("token", name[6:])
    if name.endswith("integrity") or name.startswith(("low-integrity", "medium-integrity",
                                                       "high-integrity", "system-integrity")):
        return ("integrity", ":".join(parts[1:]))
    return ("case", ":".join(parts[1:]))


def authz_dimensions(key):
    parts = key.split(":")
    if not parts or parts[0] != "authz":
        raise ValueError("not a Windows Authz key")
    if len(parts) == 2 and parts[1]:
        return parts[1], None
    if len(parts) == 4 and parts[1] == "matrix" and parts[2] and parts[3]:
        return parts[2], parts[3]
    raise ValueError("invalid Windows Authz key")


def multiuser_dimensions(key):
    parts = key.split(":")
    if len(parts) != 4 or parts[0] != "multiuser-map":
        raise ValueError("not a Windows multiuser key")
    return parts[1], parts[2], parts[3]


def token_information_plan():
    """Stable TOKEN_INFORMATION_CLASS inventory used by native snapshots."""
    return {
        "user": (1, "sid-and-attributes"),
        "groups": (2, "groups"),
        "privileges": (3, "privileges"),
        "owner": (4, "pointer-box"),
        "primary-group": (5, "pointer-box"),
        "default-dacl": (6, "acl-pointer-box"),
        "restricted-sids": (11, "groups"),
        "elevation-type": (18, "u32"),
        "linked-token": (19, "handle"),
        "elevation": (20, "u32"),
        "virtualization-allowed": (23, "u32"),
        "virtualization-enabled": (24, "u32"),
        "integrity": (25, "sid-and-attributes"),
        "is-appcontainer": (29, "u32"),
        "capabilities": (30, "groups"),
        "appcontainer-sid": (31, "pointer-box"),
        "appcontainer-number": (32, "u32"),
        "user-claims": (33, "claims"),
        "device-claims": (34, "claims"),
    }


def _conditional_sddl(ace, expression):
    ace_type = "XA" if ace == "allow" else "XD"
    return f"D:({ace_type};;FR;;;WD;({expression}))"


def authz_case_plan(key):
    """Return the conditional expression and expected three-valued effect."""
    name, desired_name = authz_dimensions(key)
    true_expr = "Member_of {SID(S-1-1-0)}"
    false_expr = f"Member_of {{SID({OTHER_SID})}}"
    unknown_expr = '@User.__AclMissing=="x"'
    direct = {
        "allow-true": ("allow", true_expr, "true", "allow"),
        "allow-false": ("allow", false_expr, "false", "ignore"),
        "allow-unknown": ("allow", unknown_expr, "unknown", "ignore"),
        "deny-true": ("deny", true_expr, "true", "deny"),
        "deny-false": ("deny", false_expr, "false", "ignore"),
        "deny-unknown": ("deny", unknown_expr, "unknown", "deny"),
        "compound-and": ("allow", f"({true_expr} && {true_expr})", "true", "allow"),
        "compound-or": ("allow", f"({false_expr} || {true_expr})", "true", "allow"),
        "compound-not": ("allow", f"!({false_expr})", "true", "allow"),
        "unknown-and-true": ("allow", f"({unknown_expr} && {true_expr})", "unknown", "ignore"),
        "unknown-and-false": ("allow", f"({unknown_expr} && {false_expr})", "false", "ignore"),
        "unknown-or-true": ("allow", f"({unknown_expr} || {true_expr})", "true", "allow"),
        "unknown-or-false": ("allow", f"({unknown_expr} || {false_expr})", "unknown", "ignore"),
    }
    if name in direct:
        ace, expression, truth, expected = direct[name]
        return {"name": name, "desired_name": desired_name, "ace": ace,
                "expression": expression, "truth": truth, "expected": expected,
                "sddl": _conditional_sddl(ace, expression), "claims": {}}
    claim_cases = {
        "user-string-equal": ('@User.Title=="PM"', {"user": {"Title": ["PM"]}}, "true"),
        "user-string-not-equal": ('@User.Title!="Sales"', {"user": {"Title": ["PM"]}}, "true"),
        "user-int-equal": ("@User.Level==7", {"user": {"Level": [7]}}, "true"),
        "user-bool-equal": ("@User.Enabled==1", {"user": {"Enabled": [True]}}, "true"),
        "user-sid-member": ("Member_of {SID(S-1-1-0)}", {}, "true"),
        "user-any-of": ('@User.Project Any_of {"A","B"}', {"user": {"Project": ["B"]}}, "true"),
        "user-all-of": ('@User.Project Contains {"A","B"}', {"user": {"Project": ["A", "B"]}}, "true"),
        "device-attribute": ('@Device.Managed==1', {"device": {"Managed": [1]}}, "true"),
        "resource-attribute": ('@Resource.Project=="A"', {"resource": {"Project": ["A"]}}, "true"),
        "user-resource-intersection": ("@User.Project Any_of @Resource.Project",
                                       {"user": {"Project": ["A"]}, "resource": {"Project": ["A"]}}, "true"),
        "member-of": (true_expr, {}, "true"),
        "not-member-of": (f"!({false_expr})", {}, "true"),
        "exists": ("Exists @User.Title", {"user": {"Title": ["PM"]}}, "true"),
        "not-exists": ("!Exists @User.__AclMissing", {}, "true"),
    }
    if name in claim_cases:
        expression, claims, truth = claim_cases[name]
        return {"name": name, "desired_name": desired_name, "ace": "allow",
                "expression": expression, "truth": truth,
                "expected": "allow" if truth == "true" else "ignore",
                "sddl": _conditional_sddl("allow", expression), "claims": claims}
    # Callback/cached/object-list/policy/round-trip cases still receive a stable
    # baseline descriptor; the native implementation adds the specialized call.
    return {"name": name, "desired_name": desired_name, "ace": "allow",
            "expression": true_expr, "truth": "true", "expected": "allow",
            "sddl": _conditional_sddl("allow", true_expr), "claims": {}}


def selector_access_variants(sdk_mask):
    """Return distinct access masks in stable diagnostic order."""
    sdk_mask = int(sdk_mask) & 0xFFFFFFFF
    candidates = (
        ("zero", 0),
        ("sdk", sdk_mask),
        ("plus-read-control", sdk_mask | 0x00020000),
        ("minus-read-control", sdk_mask & ~0x00020000),
        ("plus-synchronize", sdk_mask | 0x00100000),
        ("maximum-allowed", 0x02000000),
    )
    result = {}
    seen = set()
    for name, mask in candidates:
        mask &= 0xFFFFFFFF
        if mask in seen:
            continue
        seen.add(mask)
        result[name] = mask
    return result


def representative_ace(ace_type, flags, sid, mask=1):
    """Construct one bounded representative for every defined/reserved type."""
    ace_type = int(ace_type)
    flags = int(flags) & 0xFF
    if ace_type not in wire.BASIC_TYPES | wire.OBJECT_TYPES:
        # Compound ACE type 4 is reserved; 0xfe is the corpus' future/unknown
        # sentinel. Keep these byte-preserving and semantically opaque.
        return struct.pack("<BBH", ace_type & 0xFF, flags, 8) + b"OPAQ"
    kwargs = {}
    if ace_type in wire.OBJECT_TYPES:
        kwargs.update(object_guid=OBJECT_GUID, inherited_guid=INHERITED_GUID)
    if ace_type in CALLBACK_TYPES or ace_type in (18, 21):
        kwargs["payload"] = b"\0\0\0\0"
    return wire.ace(ace_type, flags, int(mask) & 0xFFFFFFFF,
                    wire.sid_bytes(sid), **kwargs)


def policy_entries(policy, sid, mask):
    allow = lambda who, flags=0: wire.ace(0, flags, mask, wire.sid_bytes(who))
    deny = lambda who, flags=0: wire.ace(1, flags, mask, wire.sid_bytes(who))
    if policy == "null":
        return None
    if policy == "empty":
        return []
    if policy == "allow":
        return [allow(sid)]
    if policy == "deny":
        return [deny(sid)]
    if policy == "allow-deny":
        return [allow(sid), deny(sid)]
    if policy == "deny-allow":
        return [deny(sid), allow(sid)]
    if policy == "owner-rights-allow":
        return [allow(OWNER_RIGHTS_SID)]
    if policy == "owner-rights-deny":
        return [deny(OWNER_RIGHTS_SID)]
    if policy == "inherited-allow":
        return [allow(sid, 0x10)]
    if policy == "inherited-deny":
        return [deny(sid, 0x10)]
    raise ValueError(f"unknown Windows access policy: {policy}")


def _native_error(exc):
    return dict(type=exc.__class__.__name__, operation=getattr(exc, "operation", None),
                code=getattr(exc, "code", getattr(exc, "winerror", getattr(exc, "errno", None))),
                message=str(exc))


def _json_safe(value):
    """Normalize native evidence into deterministic JSON-compatible values."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"encoding": "hex", "length": len(raw), "hex": raw.hex()}
    if isinstance(value, pathlib.Path):
        return os.fspath(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(item) for item in value), key=repr)
    if isinstance(value, C._SimpleCData):
        return _json_safe(value.value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {"type": value.__class__.__name__, "repr": repr(value)}


def _capture(call):
    try:
        return dict(ok=True, value=_json_safe(call()))
    except (NativeFailure, OSError, ValueError) as exc:
        return dict(ok=False, error=_native_error(exc))


def _case_root(workspace, domain, key):
    base = pathlib.Path(workspace).resolve()
    base.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid5(uuid.NAMESPACE_URL, key).hex[:16]
    path = pathlib.Path(tempfile.mkdtemp(prefix=f"windows-{domain}-{token}-", dir=base))
    (path / ".acl-behavior-owned").write_text(key + "\n", encoding="utf-8")
    return path


def _emit_case(writer, oracle, workspace, key, function):
    root = _case_root(workspace, writer.domain, key)
    status = "ok"
    details = {}
    try:
        details = function(root)
        if not isinstance(details, dict):
            details = {"value": details}
        if details.get("measurement_stage") in ("conversion-only", "descriptor-rejected", "api-rejected"):
            status = "observe"  # no authorization decision was obtained
        if details.get("control_failures"):
            status = "error"  # keep the actual API replies available for diagnosis
    except SkipCase as exc:
        status, details = "skip", {"reason": str(exc)}
    except (NativeFailure, OSError) as exc:
        status, details = "observe", {"native_error": _native_error(exc)}
    except BaseException as exc:
        status, details = "error", {"exception": repr(exc), "traceback": traceback.format_exc()}
    try:
        # A denied DACL can make ordinary traversal fail. Platform-specific
        # domains must restore through a retained handle before returning.
        core.safe_remove_tree(root)
    except BaseException as exc:
        status = "error"
        details["cleanup_error"] = repr(exc)
    writer.emit(key, status, _json_safe(details))



def _fixture(root, name="target", directory=False):
    path = pathlib.Path(root) / name
    if directory:
        path.mkdir(parents=True)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"native ACL behavior fixture\n")
    return path


def _recovery_entries(oracle, inherited=False):
    flags = 0x03 if inherited else 0
    return [
        wire.ace(0, flags, 0x001F01FF, wire.sid_bytes(oracle.current_sid())),
        wire.ace(0, flags, 0x001F01FF, wire.sid_bytes(SYSTEM_SID)),
    ]


def _recovery_descriptor(oracle, inherited=False):
    return wire.descriptor(dacl=wire.acl(_recovery_entries(oracle, inherited)), control=0x1000)


def _descriptor_snapshot(oracle, path, information=7, follow=True):
    def read():
        raw = oracle.read(path, information, follow)
        result = {
            "raw": raw.hex(),
            "descriptor": wire.parse_descriptor(raw),
        }
        try:
            result["sddl"] = oracle.to_sddl(raw, information & 0x1FF)
        except (NativeFailure, ValueError) as exc:
            result["sddl_error"] = _native_error(exc)
        return result
    return _capture(read)


def _native_descriptor_valid(oracle, data):
    wire.parse_descriptor(data)
    buffer = C.create_string_buffer(data)
    return bool(oracle.a.IsValidSecurityDescriptor(buffer))


def _ace_selector(ace_type):
    if ace_type == 17:
        return 0x10
    if ace_type == 18:
        return 0x20
    if ace_type == 19:
        return 0x40
    if ace_type == 20:
        return 0x80
    if ace_type == 21:
        return 0x100
    return 8 if ace_type in SACL_TYPES else 4


def _descriptor_for_ace(oracle, placement, candidate_acl):
    if placement == "dacl":
        parsed = wire.parse_acl(candidate_acl)
        entries = _recovery_entries(oracle, inherited=True) + [bytes.fromhex(entry["hex"])
                                                               for entry in parsed["entries"]]
        return wire.descriptor(dacl=wire.acl(entries, revision=parsed["revision"]), control=0x1000)
    return wire.descriptor(dacl=wire.acl(_recovery_entries(oracle, inherited=True)),
                           sacl=candidate_acl, control=0x3000)


def _state_descriptor(oracle, state):
    owner = wire.sid_bytes(oracle.current_sid())
    group = wire.sid_bytes(WORLD_SID)
    recovery = wire.acl(_recovery_entries(oracle, inherited=True))
    audit = wire.acl([representative_ace(2, 0xC0, OTHER_SID)])
    kwargs = dict(owner=owner, group=group, dacl=recovery, sacl=wire.ABSENT, control=0)
    information = 7
    inheritance = "Preserve"
    if state == "owner-absent":
        kwargs["owner"] = None; information = 1
    elif state == "owner-present":
        information = 1
    elif state == "group-absent":
        kwargs["group"] = None; information = 2
    elif state == "group-present":
        information = 2
    elif state == "dacl-absent":
        kwargs["dacl"] = wire.ABSENT; information = 4
    elif state == "dacl-null":
        kwargs["dacl"] = None; information = 4
    elif state == "dacl-empty":
        kwargs["dacl"] = wire.acl([]); information = 4
    elif state == "dacl-one":
        kwargs["dacl"] = wire.acl(_recovery_entries(oracle) + [representative_ace(0, 0, OTHER_SID)]); information = 4
    elif state == "sacl-absent":
        kwargs["sacl"] = wire.ABSENT; information = 8
    elif state == "sacl-null":
        kwargs["sacl"] = None; information = 8
    elif state == "sacl-empty":
        kwargs["sacl"] = wire.acl([]); information = 8
    elif state == "sacl-one":
        kwargs["sacl"] = audit; information = 8
    elif state == "dacl-protected":
        information = 4; inheritance = "Protect"
    elif state == "dacl-unprotected":
        information = 4; inheritance = "Unprotect"
    elif state == "sacl-protected":
        kwargs["sacl"] = audit; information = 8; inheritance = "Protect"
    elif state == "sacl-unprotected":
        kwargs["sacl"] = audit; information = 8; inheritance = "Unprotect"
    elif state == "owner-defaulted":
        kwargs["control"] |= 0x0001; information = 1
    elif state == "group-defaulted":
        kwargs["control"] |= 0x0002; information = 2
    elif state == "dacl-defaulted":
        kwargs["control"] |= 0x0008; information = 4
    elif state == "sacl-defaulted":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x0020; information = 8
    elif state == "dacl-auto-inherit-req":
        kwargs["control"] |= 0x0100; information = 4
    elif state == "sacl-auto-inherit-req":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x0200; information = 8
    elif state == "dacl-auto-inherited":
        kwargs["control"] |= 0x0400; information = 4
    elif state == "sacl-auto-inherited":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x0800; information = 8
    elif state == "both-auto-inherit-req":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x0300; information = 12
    elif state == "both-auto-inherited":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x0C00; information = 12
    elif state == "rm-control-valid":
        kwargs["sacl"] = audit; kwargs["control"] |= 0x4000; information = 12
    else:
        raise ValueError(f"unknown Windows descriptor state: {state}")
    return wire.descriptor(**kwargs), information, inheritance


def _descriptor_storage(oracle, key, root, privilege_state=None):
    dimensions = descriptor_dimensions(key)
    if dimensions[0] == "state":
        _, obj, state = dimensions
        path = _fixture(root, "target", obj == "directory")
        data, information, inheritance = _state_descriptor(oracle, state)
        result = {
            "object": obj,
            "state": state,
            "selection": information,
            "inheritance": inheritance,
            "requested_hex": data.hex(),
            "bounded": wire.parse_descriptor(data),
            "native_valid": _capture(lambda: _native_descriptor_valid(oracle, data)),
            "privilege_setup": privilege_state or {},
        }
        with map_controls.fixture_guard(oracle, path, _recovery_descriptor(oracle)) as handle:
            result["write"] = _capture(lambda: oracle.write(path, data, information, inheritance))
            read_information = 7 | (information if information & 0x1F8 else 0)
            result["read"] = _descriptor_snapshot(oracle, path, read_information)
            # Compare the same owner/group/DACL selection on both routes. Do not
            # request SACL privileges on the independent recovery handle.
            result["fresh_read_7"] = _descriptor_snapshot(oracle, path, 7)
            result["held_read_7"] = _capture(lambda: oracle.read_handle(handle, 7))
        return result

    _, obj, placement, ace_type, revision, flags = dimensions
    path = _fixture(root, "target", obj == "directory")
    sid = MEDIUM_INTEGRITY_SID if ace_type == 17 else OTHER_SID
    candidate = representative_ace(ace_type, flags, sid)
    candidate_acl = wire.acl([candidate], revision=revision)
    data = _descriptor_for_ace(oracle, placement, candidate_acl)
    selection = _ace_selector(ace_type) if placement == "sacl" else 4
    result = {
        "object": obj,
        "placement": placement,
        "ace_type": ace_type,
        "acl_revision": revision,
        "ace_flags": flags,
        "selection": selection,
        "candidate_ace_hex": candidate.hex(),
        "candidate_acl_hex": candidate_acl.hex(),
        "requested_hex": data.hex(),
        "bounded": wire.parse_descriptor(data),
        "candidate_native_valid": _capture(lambda: oracle.validate_acl(candidate_acl)),
        "descriptor_native_valid": _capture(lambda: _native_descriptor_valid(oracle, data)),
        "privilege_setup": privilege_state or {},
    }
    result["write"] = _capture(lambda: oracle.write(path, data, selection, "Protect"))
    read_information = 7 | (selection if selection & 0x1F8 else 0)
    result["read"] = _descriptor_snapshot(oracle, path, read_information)
    if result["read"]["ok"]:
        raw = bytes.fromhex(result["read"]["value"]["raw"])
        result["native_dacl_entries"] = _capture(lambda: oracle.native_entries(raw, False))
        result["native_sacl_entries"] = _capture(lambda: oracle.native_entries(raw, True))
    return result


def _selector_sacl(selector):
    entries = []
    if selector & 8:
        entries.append(representative_ace(2, 0xC0, OTHER_SID, 1))
    if selector & 16:
        entries.append(representative_ace(17, 0, MEDIUM_INTEGRITY_SID, 1))
    if selector & 32:
        entries.append(representative_ace(18, 0, OTHER_SID, 1))
    if selector & 64:
        entries.append(representative_ace(19, 0, OTHER_SID, 1))
    if selector & 128:
        entries.append(representative_ace(20, 0, "S-1-19-512-4096", 1))
    if selector & 256:
        entries.append(representative_ace(21, 0, OTHER_SID, 1))
    return wire.acl(entries, revision=4) if entries else wire.ABSENT


def selector_components(selector):
    """Return the descriptor components implicated by selector control bits."""
    components = int(selector) & 0x1FF
    if selector & DACL_CONTROL_INFORMATION:
        components |= 4
    if selector & SACL_CONTROL_INFORMATION:
        components |= 8
    return components


def _selector_descriptor(oracle, selector):
    components = selector_components(selector)
    owner = wire.sid_bytes(oracle.current_sid()) if components & 1 else None
    group = wire.sid_bytes(WORLD_SID) if components & 2 else None
    dacl = wire.acl(_recovery_entries(oracle, inherited=True)) if components & 4 else wire.ABSENT
    sacl = _selector_sacl(components)
    control = 0x1000 if selector & PROTECTED_DACL_SECURITY_INFORMATION else 0
    control |= 0x2000 if selector & PROTECTED_SACL_SECURITY_INFORMATION else 0
    return wire.descriptor(owner=owner, group=group, dacl=dacl, sacl=sacl,
                           control=control)


def _selector_combinations(oracle, key, root, privilege_state=None):
    obj, operation, selector = selector_dimensions(key)
    sdk = oracle.query_access_mask(selector) if operation == "query" else oracle.set_access_mask(selector)
    variants = selector_access_variants(sdk)
    details = {
        "object": obj,
        "operation": operation,
        "selector": selector,
        "sdk_access": sdk,
        "privilege_setup": privilege_state or {},
        "attempts": {},
    }
    data = _selector_descriptor(oracle, selector)
    details["requested_hex"] = data.hex()
    details["bounded"] = wire.parse_descriptor(data)
    for variant, desired in variants.items():
        variant_root = root / variant
        variant_root.mkdir()
        path = _fixture(variant_root, "target", obj == "directory")
        if operation == "query":
            details["attempts"][variant] = oracle.query_attempt(path, selector, desired)
        else:
            with map_controls.fixture_guard(oracle, path, _recovery_descriptor(oracle)) as handle:
                attempt = _capture(lambda: oracle.set_attempt(path, data, selector, desired))
                details["attempts"][variant] = attempt
                attempt["readback"] = _descriptor_snapshot(
                    oracle, path, 7 | (selector_components(selector) & 0x1F8))
                attempt["fresh_read_7"] = _descriptor_snapshot(oracle, path, 7)
                attempt["held_read_7"] = _capture(lambda: oracle.read_handle(handle, 7))
    return details


def _policy_descriptor(oracle, policy, desired):
    entries = policy_entries(policy, oracle.current_sid(), desired)
    if entries is None:
        dacl = None
    else:
        dacl = wire.acl(entries)
    return wire.descriptor(owner=wire.sid_bytes(oracle.current_sid()),
                           group=wire.sid_bytes(WORLD_SID), dacl=dacl,
                           control=0x1000)


def _actual_operation(oracle, obj, right_name, path):
    """Attempt a concrete operation when the right has a stable file analogue."""
    if obj == "file":
        if right_name in ("read-data", "generic-read"):
            with open(path, "rb") as stream:
                return {"operation": "read", "bytes": stream.read(8).hex()}
        if right_name in ("write-data", "generic-write"):
            with open(path, "r+b") as stream:
                stream.write(b"W")
            return {"operation": "write"}
        if right_name == "append-data":
            with open(path, "ab") as stream:
                stream.write(b"A")
            return {"operation": "append"}
        if right_name == "read-attributes":
            return {"operation": "stat", "size": os.stat(path).st_size}
        if right_name == "write-attributes":
            os.utime(path, None)
            return {"operation": "utime", "mtime_ns": os.stat(path).st_mtime_ns}
        if right_name == "read-control":
            return {"operation": "read-security", "descriptor": oracle.read(path, 7).hex()}
        if right_name == "write-dac":
            data = _recovery_descriptor(oracle)
            oracle.write(path, data, 4, "Protect")
            return {"operation": "write-dac", "descriptor": oracle.read(path, 7).hex()}
    else:
        # The caller creates this child before applying policy. A denied stat or
        # speculative create here would measure setup rather than list/traverse.
        child = path / "child"
        if right_name in ("read-data", "generic-read"):
            return {"operation": "list", "entries": sorted(os.listdir(path))}
        if right_name in ("write-data", "generic-write"):
            created = path / "created-file"
            created.write_bytes(b"x")
            return {"operation": "create-file", "created": created.exists()}
        if right_name == "append-data":
            created = path / "created-directory"
            created.mkdir()
            return {"operation": "create-directory", "created": created.exists()}
        if right_name in ("execute", "generic-execute"):
            return {"operation": "traverse", "size": os.stat(child).st_size}
        if right_name == "delete-child":
            child.unlink()
            return {"operation": "delete-child", "exists": child.exists()}
        if right_name == "read-attributes":
            return {"operation": "stat", "mode": stat.S_IMODE(os.stat(path).st_mode)}
        if right_name == "write-attributes":
            os.utime(path, None)
            return {"operation": "utime", "mtime_ns": os.stat(path).st_mtime_ns}
        if right_name == "read-control":
            return {"operation": "read-security", "descriptor": oracle.read(path, 7).hex()}
        if right_name == "write-dac":
            data = _recovery_descriptor(oracle, inherited=True)
            oracle.write(path, data, 4, "Protect")
            return {"operation": "write-dac", "descriptor": oracle.read(path, 7).hex()}
    return {"operation": "open-only", "reason": "no safe one-call analogue in this mapper"}


def _access_evaluation(oracle, key, root):
    obj, policy, right_name = access_dimensions(key)
    desired = right_mask(right_name)
    path = _fixture(root, "target", obj == "directory")
    if obj == "directory":
        (path / "child").write_bytes(b"child")
    data = _policy_descriptor(oracle, policy, desired)
    recovery = _recovery_descriptor(oracle, inherited=obj == "directory")
    result = {
        "object": obj,
        "policy": policy,
        "right": right_name,
        "desired": desired,
        "requested_hex": data.hex(),
        "bounded": wire.parse_descriptor(data),
        "access_check": _capture(lambda: oracle.access_check(data, desired)),
    }
    # Retain a pre-policy handle that can restore WRITE_DAC even when the case
    # intentionally removes all access from the process token.
    recovery_access = 0x001F01FF
    with oracle.handle(path, recovery_access) as recovery_handle:
        try:
            oracle.write_handle(recovery_handle, data, 4, "Protect")
            result["installed"] = _descriptor_snapshot(oracle, path, 7)
            result["installed_held"] = _capture(lambda: oracle.read_handle(recovery_handle, 7))
            if result["installed_held"]["ok"]:
                actual = bytes.fromhex(result["installed_held"]["value"]["hex"])
                result["access_check_installed"] = _capture(lambda: oracle.access_check(actual, desired))
            result["create_file"] = oracle.try_open(path, desired)
            result["open_controls"] = map_controls.open_controls(oracle, path, desired)
            result["operation"] = _capture(lambda: _actual_operation(oracle, obj, right_name, path))
            result["after"] = _descriptor_snapshot(oracle, path, 7)
        finally:
            oracle.write_handle(recovery_handle, recovery, 4, "Protect")
    return result


def _inheritance_snapshot(oracle, root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.name.startswith(".acl-behavior"):
            continue
        rel = path.relative_to(root).as_posix()
        result[rel] = _descriptor_snapshot(oracle, path, 7)
    return result


def _inheritance_events(oracle, key, root):
    event, kind, flags, child_kind, protection = inheritance_dimensions(key)
    parent = root / "parent"
    parent.mkdir()
    candidate = representative_ace(0 if kind == "allow" else 1, flags,
                                   OTHER_SID, 0x001F01FF)
    data = wire.descriptor(
        dacl=wire.acl(_recovery_entries(oracle, inherited=True) + [candidate]),
        control=0x1000,
    )
    details = {
        "event": event,
        "kind": kind,
        "flags": flags,
        "child_kind": child_kind,
        "protection": protection,
        "requested_hex": data.hex(),
        "bounded": wire.parse_descriptor(data),
    }

    selected = ("file", "directory") if child_kind == "both" else (child_kind,)

    def create_at(base, stem, selected_kind):
        path = base / stem
        if selected_kind == "directory":
            path.mkdir()
        else:
            path.write_bytes(b"x")
        return path

    def protect(path):
        protected = _recovery_descriptor(oracle)
        return _capture(lambda: oracle.write(path, protected, 4, "Protect"))

    preexisting = []
    # Protected objects must exist before the parent update; otherwise CreateFile
    # would inherit before the mapper could protect them. This is intentional and
    # recorded so the row distinguishes create-time inheritance from subsequent
    # propagation to protected children.
    if event == "propagate-existing" or protection == "protected":
        for selected_kind in selected:
            path = create_at(parent, f"existing-{selected_kind}", selected_kind)
            preexisting.append(path)
            if protection == "protected":
                details.setdefault("child_protection", {})[path.name] = protect(path)

    details["parent_write"] = _capture(lambda: oracle.write(parent, data, 4, "Protect"))
    if not details["parent_write"]["ok"]:
        details["objects"] = _inheritance_snapshot(oracle, parent)
        return details

    if event == "create":
        if not preexisting:
            for selected_kind in selected:
                create_at(parent, selected_kind, selected_kind)
    elif event == "grandchild":
        child = parent / "child-dir"
        if not child.exists():
            child.mkdir()
        if protection == "protected":
            details.setdefault("child_protection", {})[child.name] = protect(child)
        for selected_kind in selected:
            create_at(child, f"grand-{selected_kind}", selected_kind)
            if selected_kind == "directory":
                create_at(child / f"grand-{selected_kind}", "great-file", "file")
    elif event == "propagate-existing":
        pass
    elif event in ("move-in", "copy-in"):
        for selected_kind in selected:
            source = create_at(root, f"source-{selected_kind}", selected_kind)
            if selected_kind == "directory":
                create_at(source, "child", "file")
            if protection == "protected":
                details.setdefault("source_protection", {})[source.name] = protect(source)
            destination = parent / f"{event}-{selected_kind}"
            if event == "move-in":
                os.replace(source, destination)
            elif selected_kind == "directory":
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
    elif event == "hardlink-in":
        source = _fixture(root, "source-file")
        if protection == "protected":
            details["source_protection"] = protect(source)
        os.link(source, parent / "hardlink")
        if child_kind == "directory":
            details["applicability"] = "hard links target files; directory axis retained as evidence"
    else:
        raise ValueError(f"unknown Windows inheritance event: {event}")

    details["parent"] = _descriptor_snapshot(oracle, parent, 7)
    details["objects"] = _inheritance_snapshot(oracle, parent)
    return details



def _extended_path(path):
    value = os.path.abspath(os.fspath(path))
    if value.startswith("\\\\?\\") or value.startswith("\\\\.\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _path_state(oracle, path, *, follow=True, information=7):
    value = {"path": os.fspath(path), "exists": os.path.lexists(path), "follow": bool(follow)}
    value["identity"] = _capture(lambda: oracle.file_identity(path, follow))
    value["descriptor"] = _descriptor_snapshot(oracle, path, information, follow)
    try:
        value["lstat"] = {
            "mode": stat.S_IFMT(os.lstat(path).st_mode),
            "size": os.lstat(path).st_size,
            "attributes": getattr(os.lstat(path), "st_file_attributes", None),
            "reparse_tag": getattr(os.lstat(path), "st_reparse_tag", None),
        }
    except OSError as exc:
        value["lstat_error"] = _native_error(exc)
    return value


def _filesystem_observation(oracle, candidate, label):
    if not candidate:
        return {"supported": False, "filesystem": label,
                "reason": f"generated {label} root is not configured"}
    base = pathlib.Path(candidate)
    if not base.is_dir():
        return {"supported": False, "filesystem": label,
                "root": os.fspath(base), "reason": "configured root is not a directory"}
    fixture = base / ("acl-map-" + uuid.uuid4().hex)
    fixture.mkdir()
    (fixture / ".acl-behavior-owned").write_text(label + "\n", encoding="utf-8")
    details = {"supported": True, "filesystem": label, "root": os.fspath(base),
               "environment": _capture(lambda: oracle.environment(base))}
    try:
        target = fixture / "target"
        target.write_bytes(b"generated filesystem ACL map\n")
        requested = _recovery_descriptor(oracle)
        details["acl_write"] = _capture(lambda: oracle.write(target, requested, 4, "Protect"))
        details["target"] = _path_state(oracle, target)
        hardlink = fixture / "hardlink"
        os.link(target, hardlink)
        details["hardlink"] = {
            "target": _path_state(oracle, target),
            "link": _path_state(oracle, hardlink),
        }
        stream = pathlib.Path(os.fspath(target) + ":acl-map")
        details["alternate_data_stream"] = _capture(lambda: (
            stream.write_bytes(b"stream"), stream.read_bytes().hex()))
        upper = fixture / "CaseProbe"
        lower = fixture / "caseprobe"
        upper.write_bytes(b"upper")
        details["case_behavior"] = {
            "lower_exists_after_upper": lower.exists(),
            "upper": _capture(lambda: oracle.file_identity(upper)),
            "lower": _capture(lambda: oracle.file_identity(lower)) if lower.exists() else None,
        }
        details["volume"] = _capture(lambda: oracle.volume_guid_path(target))
        details["attributes"] = _capture(lambda: oracle.attributes(target))
    finally:
        core.safe_remove_tree(fixture)
    return details


def _lifecycle(oracle, key, root):
    name = lifecycle_dimensions(key)
    details = {"case": name, "before_handles": _capture(oracle.handle_count)}

    if name == "rename-path":
        source = _fixture(root, "source")
        target = root / "target"
        details["before"] = _path_state(oracle, source)
        os.replace(source, target)
        details["source_after"] = _path_state(oracle, source)
        details["target_after"] = _path_state(oracle, target)
    elif name == "rename-open-handle":
        source = _fixture(root, "source")
        target = root / "target"
        with oracle.handle(source, 0x00110080) as handle:
            details["handle_before"] = oracle.file_identity_handle(handle)
            details["descriptor_before"] = _capture(lambda: oracle.read_handle(handle, 7))
            os.replace(source, target)
            details["handle_after"] = oracle.file_identity_handle(handle)
            details["descriptor_after"] = _capture(lambda: oracle.read_handle(handle, 7))
            details["target"] = _path_state(oracle, target)
    elif name == "replace-path":
        source = _fixture(root, "source")
        target = _fixture(root, "target")
        target.write_bytes(b"old target")
        details["source_before"] = _path_state(oracle, source)
        details["target_before"] = _path_state(oracle, target)
        os.replace(source, target)
        details["target_after"] = _path_state(oracle, target)
    elif name == "delete-pending":
        path = _fixture(root, "target")
        details["before"] = _path_state(oracle, path)
        details["marked"] = _capture(lambda: oracle.set_delete_pending(path))
        details["after_close"] = _path_state(oracle, path)
    elif name in ("hardlink-create", "hardlink-write"):
        source = _fixture(root, "source")
        link = root / "hardlink"
        os.link(source, link)
        details["source"] = _path_state(oracle, source)
        details["link"] = _path_state(oracle, link)
        if name == "hardlink-write":
            link.write_bytes(b"written through hard link")
            details["source_content"] = source.read_bytes().hex()
            details["source_after"] = _path_state(oracle, source)
    elif name in ("ads-create", "ads-write"):
        path = _fixture(root, "target")
        stream = pathlib.Path(str(path) + ":acl-map")
        with open(stream, "wb") as output:
            output.write(b"alternate stream")
        details["base"] = _path_state(oracle, path)
        details["stream"] = _path_state(oracle, stream)
        if name == "ads-write":
            with open(stream, "ab") as output:
                output.write(b"+write")
            details["stream_content"] = open(stream, "rb").read().hex()
    elif name == "copy-file":
        source = _fixture(root, "source")
        target = root / "copy"
        details["source"] = _path_state(oracle, source)
        shutil.copy2(source, target)
        details["copy"] = _path_state(oracle, target)
    elif name == "copy-directory":
        source = _fixture(root, "source", True)
        _fixture(source, "child")
        target = root / "copy"
        details["source"] = _path_state(oracle, source)
        shutil.copytree(source, target)
        details["copy"] = _path_state(oracle, target)
        details["copy_child"] = _path_state(oracle, target / "child")
    elif name == "move-same-volume":
        source = _fixture(root, "source")
        target_dir = _fixture(root, "target-dir", True)
        details["before"] = _path_state(oracle, source)
        target = target_dir / "moved"
        os.replace(source, target)
        details["after"] = _path_state(oracle, target)
    elif name in ("move-into-inheriting-directory", "copy-into-inheriting-directory"):
        source = _fixture(root, "source")
        parent = _fixture(root, "parent", True)
        inheritable = representative_ace(0, 0x03, OTHER_SID, 0x1)
        descriptor = wire.descriptor(
            dacl=wire.acl(_recovery_entries(oracle, inherited=True) + [inheritable]),
            control=0x1000)
        details["parent_write"] = _capture(lambda: oracle.write(parent, descriptor, 4, "Protect"))
        target = parent / ("moved" if name.startswith("move") else "copied")
        if name.startswith("move"):
            os.replace(source, target)
        else:
            shutil.copy2(source, target)
        details["source_or_target"] = _path_state(oracle, target)
        details["parent"] = _path_state(oracle, parent)
    elif name in ("symlink-follow", "symlink-nofollow", "dangling-symlink",
                  "directory-symlink", "intermediate-reparse"):
        target = root / "target"
        if name == "directory-symlink":
            target.mkdir()
            _fixture(target, "child")
        elif name != "dangling-symlink":
            target.write_bytes(b"target")
        link = root / "link"
        os.symlink(target if name != "dangling-symlink" else root / "missing",
                   link, target_is_directory=name == "directory-symlink")
        if name == "intermediate-reparse":
            child = link / "child"
            details["intermediate"] = _path_state(oracle, child, follow=True)
        elif name == "symlink-follow":
            details["link"] = _path_state(oracle, link, follow=True)
            details["target"] = _path_state(oracle, target, follow=True)
        else:
            details["link_nofollow"] = _path_state(oracle, link, follow=False)
            details["link_follow"] = _path_state(oracle, link, follow=True)
    elif name in ("junction-follow", "junction-nofollow"):
        target = _fixture(root, "junction-target", True)
        _fixture(target, "child")
        link = root / "junction"
        details["creation"] = _capture(lambda: oracle.create_junction(link, target))
        if details["creation"]["ok"]:
            details["junction"] = _path_state(oracle, link, follow=name.endswith("follow") and not name.endswith("nofollow"))
            details["target"] = _path_state(oracle, target)
    elif name == "extended-local":
        path = _fixture(root, "target")
        extended = _extended_path(path)
        details["ordinary"] = oracle.try_open_detailed(path, 0x80)
        details["extended"] = oracle.try_open_detailed(extended, 0x80)
        details["spellings"] = {"ordinary": str(path), "extended": extended}
    elif name == "extended-unc":
        candidate = os.environ.get("ACL_LOOPBACK_SMB_ROOT")
        if not candidate:
            details.update(supported=False, reason="ACL_LOOPBACK_SMB_ROOT is not configured")
        else:
            path = pathlib.Path(candidate) / ("acl-map-" + uuid.uuid4().hex)
            path.write_bytes(b"unc")
            try:
                details["ordinary"] = oracle.try_open_detailed(path, 0x80)
                details["extended"] = oracle.try_open_detailed(_extended_path(path), 0x80)
            finally:
                path.unlink(missing_ok=True)
    elif name == "device-namespace":
        path = _fixture(root, "target")
        absolute = os.path.abspath(path)
        device = "\\\\.\\" + absolute
        details["ordinary"] = oracle.try_open_detailed(path, 0x80)
        details["device"] = oracle.try_open_detailed(device, 0x80)
        details["device_spelling"] = device
    elif name == "volume-guid":
        path = _fixture(root, "target")
        volume = oracle.volume_guid_path(path)
        absolute = os.path.abspath(path)
        drive, tail = os.path.splitdrive(absolute)
        guid_path = volume["guid"] + tail.lstrip("\\/")
        details["volume"] = volume
        details["guid_path"] = guid_path
        details["open"] = oracle.try_open_detailed(guid_path, 0x80)
    elif name == "dos-short-name":
        path = _fixture(root, "long file name for ACL behavior.txt")
        details["long"] = _path_state(oracle, path)
        details["short"] = _capture(lambda: oracle.short_path(path))
        if details["short"]["ok"]:
            details["short_open"] = oracle.try_open_detailed(details["short"]["value"], 0x80)
    elif name in ("trailing-dot", "trailing-space", "reserved-name"):
        component = {"trailing-dot": "name.", "trailing-space": "name ",
                     "reserved-name": "CON"}[name]
        ordinary = root / component
        extended = _extended_path(ordinary)
        details["ordinary"] = oracle.try_open_detailed(ordinary, 0, share=7, creation=1, flags=0x80)
        details["extended"] = oracle.try_open_detailed(extended, 0, share=7, creation=1, flags=0x80)
        details["spellings"] = {"ordinary": str(ordinary), "extended": extended}
    elif name == "unicode-normalization":
        nfc = root / "é"
        nfd = root / "e\u0301"
        nfc.write_bytes(b"nfc")
        details["nfc_before"] = _path_state(oracle, nfc)
        details["nfd_open_before_create"] = oracle.try_open_detailed(nfd, 0x80)
        try:
            nfd.write_bytes(b"nfd")
            details["nfd_created"] = _path_state(oracle, nfd)
        except OSError as exc:
            details["nfd_create_error"] = _native_error(exc)
        details["directory_entries"] = sorted(p.name for p in root.iterdir())
    elif name == "case-sensitive-directory":
        directory = _fixture(root, "case-dir", True)
        details["enable"] = _capture(lambda: oracle.set_case_sensitive(directory, True))
        upper = directory / "Case"
        lower = directory / "case"
        upper.write_bytes(b"upper")
        try:
            lower.write_bytes(b"lower")
            details["lower_create"] = {"ok": True}
        except OSError as exc:
            details["lower_create"] = {"ok": False, "error": _native_error(exc)}
        details["entries"] = sorted(p.name for p in directory.iterdir())
        details["upper"] = _path_state(oracle, upper)
        details["lower"] = _path_state(oracle, lower)
    elif name in ("file-id-open", "open-by-id-after-rename"):
        path = _fixture(root, "target")
        details["before"] = _path_state(oracle, path)
        if name == "open-by-id-after-rename":
            renamed = root / "renamed"
            os.replace(path, renamed)
            path = renamed
        details["open_by_id"] = _capture(lambda: oracle.open_by_id(path))
        details["after"] = _path_state(oracle, path)
    elif name == "readonly-attribute":
        path = _fixture(root, "target")
        before = oracle.attributes(path)
        details["before"] = before
        details["set"] = _capture(lambda: oracle.set_attributes(path, before | 0x1))
        details["write"] = _capture(lambda: path.write_bytes(b"write after readonly"))
        oracle.set_attributes(path, before)
    elif name == "compressed-attribute":
        path = _fixture(root, "target")
        details["before"] = oracle.attributes(path)
        details["set_compression"] = _capture(
            lambda: oracle.device_control(path, 0x0009C040, struct.pack("<H", 1)))
        details["after"] = oracle.attributes(path)
    elif name == "sparse-file":
        path = _fixture(root, "target")
        details["before"] = oracle.attributes(path)
        details["set_sparse"] = _capture(lambda: oracle.device_control(path, 0x000900C4))
        details["after"] = oracle.attributes(path)
    elif name == "encrypted-file":
        path = _fixture(root, "target")
        details["before"] = oracle.attributes(path)
        details["encrypt"] = _capture(lambda: bool(oracle.check(oracle.a.EncryptFileW(str(path)), "EncryptFileW")))
        details["after"] = _capture(lambda: oracle.attributes(path))
        if details["encrypt"]["ok"]:
            details["decrypt"] = _capture(lambda: bool(oracle.check(oracle.a.DecryptFileW(str(path), 0), "DecryptFileW")))
    elif name == "loopback-smb":
        candidate = os.environ.get("ACL_LOOPBACK_SMB_ROOT")
        if not candidate:
            details.update(supported=False, reason="ACL_LOOPBACK_SMB_ROOT is not configured")
        else:
            path = pathlib.Path(candidate) / ("acl-map-" + uuid.uuid4().hex)
            path.write_bytes(b"smb")
            try:
                details["path"] = _path_state(oracle, path)
                details["environment"] = oracle.environment(path)
            finally:
                path.unlink(missing_ok=True)
    elif name == "filesystem-primary":
        details.update(_filesystem_observation(oracle, root, "primary"))
    elif name == "filesystem-loopback-smb":
        details.update(_filesystem_observation(oracle, os.environ.get("ACL_LOOPBACK_SMB_ROOT"), "loopback-smb"))
    elif name == "filesystem-refs":
        details.update(_filesystem_observation(oracle, os.environ.get("ACL_WINDOWS_REFS_ROOT"), "refs"))
    elif name in ("share-delete", "share-read", "share-write"):
        path = _fixture(root, "target")
        requested = {"share-delete": 4, "share-read": 1, "share-write": 2}[name]
        first = oracle.k.CreateFileW(str(path), 0x00100080, requested, None, 3, 0x80, None)
        if first == C.c_void_p(-1).value:
            raise NativeFailure("CreateFileW(first share handle)", C.get_last_error())
        try:
            details["first_share"] = requested
            details["second_read"] = oracle.try_open_detailed(path, 0x80000000, share=7, flags=0x80)
            details["second_write"] = oracle.try_open_detailed(path, 0x40000000, share=7, flags=0x80)
            details["second_delete"] = oracle.try_open_detailed(path, 0x00010000, share=7, flags=0x80)
        finally:
            oracle.k.CloseHandle(first)
    else:
        raise ValueError(f"unknown Windows lifecycle case: {name}")

    details["after_handles"] = _capture(oracle.handle_count)
    return details


def _token_snapshot_case(snapshot, name):
    fields = {
        "user": ("user_sid",),
        "groups": ("groups",),
        "restricted-sids": ("restricted_sids",),
        "owner": ("owner_sid",),
        "primary-group": ("primary_group_sid",),
        "default-dacl": ("default_dacl",),
        "integrity": ("integrity_sid",),
        "elevation": ("elevated", "elevation_type", "linked_token"),
        "virtualization": ("virtualization_allowed", "virtualization_enabled"),
        "appcontainer": ("is_appcontainer", "appcontainer_sid", "appcontainer_number", "capabilities"),
    }
    selected = fields.get(name)
    if selected is None:
        raise ValueError(f"unknown token snapshot case: {name}")
    return {key: snapshot.get(key) for key in selected}


def _first_group_sid(snapshot):
    for group in snapshot.get("groups", ()):
        if (group.get("enabled") and not group.get("integrity")
                and not group.get("logon_id") and group.get("sid") not in (WORLD_SID,)):
            return group.get("sid")
    return None


def _descriptor_with_entries(owner_sid, entries, *, sacl=None, control=0x8004):
    dacl = None if entries is None else wire.acl(entries)
    return wire.descriptor(owner=wire.sid_bytes(owner_sid) if owner_sid else None,
                           dacl=dacl, sacl=sacl, control=control)


def _token_privilege(oracle, key, root, privileged=False):
    from .windows_accounts import WindowsTokenLab

    dimensions = token_privilege_dimensions(key)
    category, name = dimensions[:2]
    lab = WindowsTokenLab()
    details = {"category": category, "case": name, "privileged_lane": bool(privileged)}
    with lab.current_token() as current:
        current_snapshot = lab.token_snapshot(current)
        details["current"] = current_snapshot

        if category == "token":
            details["selected"] = _token_snapshot_case(current_snapshot, name)
            return details

        current_sid = current_snapshot["user_sid"]
        desired = 0x00020000
        if name.endswith("write-dac"):
            desired = 0x00040000

        if name in ("owner-implicit-read-control", "owner-implicit-write-dac"):
            descriptor = _descriptor_with_entries(current_sid, [])
            details["descriptor"] = wire.parse_descriptor(descriptor)
            details["access_check"] = _capture(
                lambda: oracle.access_check_token(descriptor, desired, current))
            return details

        if name in ("owner-rights-read-control", "owner-rights-write-dac"):
            entries = [wire.ace(1, 0, desired, wire.sid_bytes(OWNER_RIGHTS_SID)),
                       wire.ace(0, 0, 0x001F01FF, wire.sid_bytes(current_sid))]
            descriptor = _descriptor_with_entries(current_sid, entries)
            details["descriptor"] = wire.parse_descriptor(descriptor)
            details["access_check"] = _capture(
                lambda: oracle.access_check_token(descriptor, desired, current))
            return details

        if name in ("deny-only-allow", "deny-only-deny", "restricting-sid-double-check"):
            group_sid = _first_group_sid(current_snapshot)
            details["selected_group_sid"] = group_sid
            if not group_sid:
                details.update(supported=False, reason="no eligible enabled group SID")
                return details
            if name == "restricting-sid-double-check":
                restricted = lab._restricted(current, (), (group_sid,), False, ())
                entries = [wire.ace(0, 0, 0x001F01FF, wire.sid_bytes(current_sid)),
                           wire.ace(0, 0, 0x001F01FF, wire.sid_bytes(group_sid))]
            else:
                restricted = lab._restricted(current, (group_sid,), (), False, ())
                ace_type = 0 if name == "deny-only-allow" else 1
                entries = [wire.ace(ace_type, 0, 0x001F01FF, wire.sid_bytes(group_sid))]
            try:
                descriptor = _descriptor_with_entries(current_sid, entries)
                details["restricted"] = lab.token_snapshot(restricted)
                details["descriptor"] = wire.parse_descriptor(descriptor)
                details["access_check"] = _capture(
                    lambda: oracle.access_check_token(descriptor, 0x1, restricted))
            finally:
                lab.k.CloseHandle(restricted)
            return details

        if name == "maximum-allowed":
            descriptor = _descriptor_with_entries(
                current_sid,
                [wire.ace(0, 0, 0x001F01FF, wire.sid_bytes(current_sid))])
            details["access_check"] = _capture(
                lambda: oracle.access_check_token(descriptor, 0x02000000, current))
            return details

        if name == "impersonation-vs-primary":
            with lab.duplicate(current) as duplicate:
                details["primary"] = current_snapshot
                details["duplicate"] = lab.token_snapshot(duplicate)
                with lab.impersonate_token(duplicate):
                    details["impersonated_current_sid"] = _capture(oracle.current_sid)
            return details

        if name == "fresh-token-group-snapshot":
            with lab.duplicate(current) as first, lab.duplicate(current) as second:
                details["first"] = lab.token_snapshot(first)
                details["second"] = lab.token_snapshot(second)
                details["same_group_rows"] = details["first"].get("groups") == details["second"].get("groups")
            details["scope"] = "same process token; real membership mutation is mapped by multiuser-map"
            return details

        if category == "privilege":
            _, privilege, state = dimensions
            assigned = next((entry for entry in current_snapshot["privileges"]
                             if entry.get("name") == privilege), None)
            details["privilege"] = privilege
            details["requested_state"] = state
            details["assigned_before"] = assigned
            if state == "absent":
                restricted = lab._restricted(current, (), (), False, (privilege,))
                try:
                    details["after"] = lab.token_snapshot(restricted)
                finally:
                    lab.k.CloseHandle(restricted)
            else:
                with lab.duplicate(current) as duplicate:
                    details["adjust"] = _capture(
                        lambda: lab.adjust_privilege(duplicate, privilege, state))
                    details["after"] = lab.token_snapshot(duplicate)
            return details

        if name in ("backup-query", "backup-set", "restore-owner", "restore-dacl",
                    "restore-sacl", "take-ownership"):
            path = _fixture(root, "target")
            privilege = {
                "backup-query": "SeBackupPrivilege",
                "backup-set": "SeBackupPrivilege",
                "restore-owner": "SeRestorePrivilege",
                "restore-dacl": "SeRestorePrivilege",
                "restore-sacl": "SeRestorePrivilege",
                "take-ownership": "SeTakeOwnershipPrivilege",
            }[name]
            with lab.duplicate(current) as duplicate:
                details["enable"] = _capture(
                    lambda: lab.adjust_privilege(duplicate, privilege, "enabled"))
                with lab.impersonate_token(duplicate):
                    if name == "backup-query":
                        details["open"] = oracle.try_open_detailed(
                            path, 0x00020000 | 0x01000000, flags=0x02000000)
                        details["query"] = _descriptor_snapshot(oracle, path, 0x10000)
                    elif name == "backup-set":
                        details["open"] = oracle.try_open_detailed(
                            path, 0x00040000, flags=0x02000000)
                    elif name == "restore-owner":
                        data = wire.descriptor(owner=wire.sid_bytes(current_sid))
                        details["set"] = _capture(lambda: oracle.write(path, data, 1))
                    elif name == "restore-dacl":
                        data = _recovery_descriptor(oracle)
                        details["set"] = _capture(lambda: oracle.write(path, data, 4, "Protect"))
                    elif name == "restore-sacl":
                        data = oracle.sddl("S:(AU;SA;FR;;;WD)")
                        details["set"] = _capture(lambda: oracle.write(path, data, 8))
                    else:
                        data = wire.descriptor(owner=wire.sid_bytes(current_sid))
                        details["set"] = _capture(lambda: oracle.write(path, data, 1))
            details["after"] = _descriptor_snapshot(oracle, path, 0x1F)
            return details

        integrity_cases = {
            "low-integrity-no-write-up": (LOW_INTEGRITY_SID, "NW", 0x2),
            "low-integrity-no-read-up": (LOW_INTEGRITY_SID, "NR", 0x1),
            "low-integrity-no-execute-up": (LOW_INTEGRITY_SID, "NX", 0x20),
            "medium-integrity": (MEDIUM_INTEGRITY_SID, "NW", 0x2),
            "high-integrity": ("S-1-16-12288", "NW", 0x2),
            "system-integrity": ("S-1-16-16384", "NW", 0x2),
        }
        if name in integrity_cases:
            integrity_sid, policy, access = integrity_cases[name]
            path = _fixture(root, "target")
            descriptor = oracle.sddl(f"D:(A;;GA;;;WD)S:(ML;;{policy};;;ME)")
            details["install"] = _capture(lambda: oracle.write(path, descriptor, 0x14, "Protect"))
            token = lab._with_integrity(current, integrity_sid)
            try:
                details["token"] = lab.token_snapshot(token)
                details["access_check"] = _capture(
                    lambda: oracle.access_check_token(descriptor, access, token))
                with lab.impersonate_token(token):
                    details["create_file"] = oracle.try_open_detailed(path, access, flags=0x80)
            finally:
                lab.k.CloseHandle(token)
            return details

    raise ValueError(f"unknown Windows token/privilege case: {key}")


def _authz_descriptor(oracle, plan):
    name = plan["name"]
    if name == "malformed-condition":
        return oracle.sddl('D:(XA;;FR;;;WD;(@User.Title==))')
    if name in ("callback-accept", "callback-reject"):
        ace = representative_ace(9, 0, WORLD_SID, 0x001F01FF)
        return wire.descriptor(dacl=wire.acl([ace]))
    if name in ("callback-object-accept", "callback-object-reject"):
        ace = representative_ace(11, 0, WORLD_SID, 0x001F01FF)
        return wire.descriptor(dacl=wire.acl([ace]), control=0x8004)
    if name == "opaque-callback-payload":
        payload = b"opaque-callback\x00\xff"
        ace = wire.ace(9, 0, 0x001F01FF, wire.sid_bytes(WORLD_SID),
                       payload=payload + bytes(-len(payload) % 4))
        return wire.descriptor(dacl=wire.acl([ace]))
    if name == "principal-self":
        return _descriptor_with_entries(None, [
            wire.ace(0, 0, 0x001F01FF, wire.sid_bytes("S-1-5-10"))
        ])
    if name == "object-type-list":
        ace = wire.ace(5, 0, 0x001F01FF, wire.sid_bytes(WORLD_SID),
                       object_guid=OBJECT_GUID, inherited_guid=INHERITED_GUID)
        return wire.descriptor(dacl=wire.acl([ace]), control=0x8004)
    if name in ("resource-attribute", "user-resource-intersection", "resource-claim-roundtrip"):
        # The resource attribute is carried in the descriptor SACL. The Authz
        # context still receives a matching dynamic attribute so the row records
        # which mechanism the current build honors.
        condition = plan["expression"]
        return oracle.sddl(
            f'D:(XA;;FR;;;WD;({condition}))S:(RA;;;;;WD;("Project",TS,0,"A"))')
    return oracle.sddl(plan["sddl"])


def _authz(oracle, key, root):
    from .windows_authz import (
        AUTHZ_CONTEXT_INFO_DEVICE_CLAIMS,
        AUTHZ_CONTEXT_INFO_USER_CLAIMS,
        Authz,
    )

    plan = authz_case_plan(key)
    desired_name = plan.get("desired_name") or "read-data"
    desired = right_mask(desired_name)
    name = plan["name"]
    details = {
        "case": name,
        "desired_name": desired_name,
        "desired": desired,
        "plan": plan,
    }
    if name == "malformed-condition":
        details["conversion"] = _capture(lambda: _authz_descriptor(oracle, plan))
        details["measurement_stage"] = "conversion-only"
        return details

    descriptor_result = _capture(lambda: _authz_descriptor(oracle, plan))
    details["descriptor_build"] = descriptor_result
    if not descriptor_result["ok"]:
        details["measurement_stage"] = "descriptor-rejected"
        return details
    encoded = descriptor_result["value"]
    if isinstance(encoded, dict) and encoded.get("encoding") == "hex":
        descriptor = bytes.fromhex(encoded["hex"])
    else:
        raise ValueError("Authz descriptor evidence did not retain raw bytes")
    details["input_descriptor_hex"] = descriptor.hex()
    # Use an unrelated synthetic owner to avoid an implicit grant to the caller.
    descriptor = map_controls.with_owner(descriptor, OTHER_SID)
    details["descriptor"] = wire.parse_descriptor(descriptor)
    details["descriptor_hex"] = descriptor.hex()
    details["descriptor_sddl"] = _capture(lambda: oracle.to_sddl(descriptor, 0x1F))

    authz = Authz()
    callback_result = None
    if name in ("callback-accept", "callback-object-accept", "opaque-callback-payload"):
        callback_result = True
    elif name in ("callback-reject", "callback-object-reject"):
        callback_result = False
    central_policies = name == "central-policy-missing"
    context_keepalive = []
    manager_options = dict(callback_result=callback_result,
                           central_policies=central_policies)
    with authz.context(**manager_options) as context:
        if key == "authz:allow-true":  # in smoke, full and map; once per lane
            details["controls"], details["control_failures"] = map_controls.authz_controls(
                authz, context, OTHER_SID, _capture)
        claims = plan.get("claims", {})
        if claims.get("user"):
            try:
                owner = authz.modify_claims(context, AUTHZ_CONTEXT_INFO_USER_CLAIMS,
                                             claims["user"])
                context_keepalive.append(owner)
                details["user_claims_modify"] = {"ok": True, "count": len(claims["user"])}
            except (NativeFailure, OSError, ValueError, TypeError) as exc:
                details["user_claims_modify"] = {"ok": False, "error": _native_error(exc)}
            details["user_claims_context"] = _capture(
                lambda: authz.context_information(context, AUTHZ_CONTEXT_INFO_USER_CLAIMS))
        if claims.get("device"):
            try:
                owner = authz.modify_claims(context, AUTHZ_CONTEXT_INFO_DEVICE_CLAIMS,
                                             claims["device"])
                context_keepalive.append(owner)
                details["device_claims_modify"] = {"ok": True, "count": len(claims["device"])}
            except (NativeFailure, OSError, ValueError, TypeError) as exc:
                details["device_claims_modify"] = {"ok": False, "error": _native_error(exc)}
            details["device_claims_context"] = _capture(
                lambda: authz.context_information(context, AUTHZ_CONTEXT_INFO_DEVICE_CLAIMS))
        if claims.get("resource"):
            try:
                owner = authz.modify_security_attributes(context, claims["resource"])
                context_keepalive.append(owner)
                details["resource_attributes_modify"] = {"ok": True, "count": len(claims["resource"])}
            except (NativeFailure, OSError, ValueError, TypeError) as exc:
                details["resource_attributes_modify"] = {"ok": False, "error": _native_error(exc)}

        principal_self = (oracle.sid_native(oracle.current_sid())
                          if name == "principal-self" else None)
        object_types = None
        if name in ("object-type-list", "callback-object-accept", "callback-object-reject"):
            object_types = [(0, OBJECT_GUID), (1, INHERITED_GUID)]
        optional = b"native-acl-optional\x00" if name.startswith("callback") else None
        cache = name == "cached-access-check"
        def check_once():
            # One call owns one cache; never serialize a handle or its backing arrays.
            result, cached, keepalive = authz.access_check(
                context, descriptor, desired, principal_self=principal_self,
                object_types=object_types, optional_arguments=optional, cache=cache)
            try:
                if cache:
                    details["initial_cached_result"] = result
                    details["cached_result"] = _capture(
                        lambda: authz.cached_access_check(cached, desired,
                                                          principal_self=principal_self))
                return result
            finally:
                if cached:
                    authz.free_cached(cached)
        details["access_check"] = _capture(check_once)
        details["measurement_stage"] = "evaluated" if details["access_check"]["ok"] else "api-rejected"
        details["callback_events"] = authz.callback_events

    if name in ("conditional-binary-roundtrip", "resource-claim-roundtrip"):
        details["roundtrip"] = _capture(
            lambda: oracle.sddl(oracle.to_sddl(descriptor, 0x1F)))
    if name == "central-policy-missing":
        details["central_policy_mode"] = "enabled-without-domain-policy"
    elif name == "central-policy-disabled":
        details["central_policy_mode"] = "AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES"
    return details


def _multiuser_policy(oracle, secret, role, scenario, mask):
    user_sid = secret["users"][role]["sid"]
    allow_sid = secret["groups"]["allow"]["sid"]
    deny_sid = secret["groups"]["deny"]["sid"]
    owner = None
    entries = []
    recovery = _recovery_entries(oracle)
    if scenario == "direct-allow":
        entries.append(wire.ace(0, 0, mask, wire.sid_bytes(user_sid)))
    elif scenario == "direct-deny":
        entries.extend((wire.ace(1, 0, mask, wire.sid_bytes(user_sid)),
                        wire.ace(0, 0, mask, wire.sid_bytes(user_sid))))
    elif scenario in ("allow-group-enabled", "allow-group-absent",
                      "fresh-token-before-group-add", "fresh-token-after-group-add",
                      "stale-token-after-group-remove"):
        entries.append(wire.ace(0, 0, mask, wire.sid_bytes(allow_sid)))
    elif scenario in ("deny-group-enabled", "deny-group-deny-only"):
        entries.extend((wire.ace(1, 0, mask, wire.sid_bytes(deny_sid)),
                        wire.ace(0, 0, mask, wire.sid_bytes(user_sid))))
    elif scenario == "owner-implicit":
        owner = user_sid
    elif scenario == "owner-rights-allow":
        owner = user_sid
        entries.append(wire.ace(0, 0, mask, wire.sid_bytes(OWNER_RIGHTS_SID)))
    elif scenario == "owner-rights-deny":
        owner = user_sid
        entries.extend((wire.ace(1, 0, mask, wire.sid_bytes(OWNER_RIGHTS_SID)),
                        wire.ace(0, 0, mask, wire.sid_bytes(user_sid))))
    elif scenario == "delegated-write-dac":
        entries.append(wire.ace(0, 0, 0x00040000, wire.sid_bytes(user_sid)))
    elif scenario == "delegated-read-control":
        entries.append(wire.ace(0, 0, 0x00020000, wire.sid_bytes(user_sid)))
    elif scenario == "restricting-sid-granted":
        entries.extend((wire.ace(0, 0, mask, wire.sid_bytes(user_sid)),
                        wire.ace(0, 0, mask, wire.sid_bytes(allow_sid))))
    elif scenario == "restricting-sid-missing":
        entries.append(wire.ace(0, 0, mask, wire.sid_bytes(user_sid)))
    elif scenario == "primary-vs-impersonation":
        entries.append(wire.ace(0, 0, mask, wire.sid_bytes(user_sid)))
    else:
        raise ValueError(f"unknown multiuser policy: {scenario}")
    return _descriptor_with_entries(owner, recovery + entries), {
        "owner_sid": owner,
        "user_sid": user_sid,
        "allow_group_sid": allow_sid,
        "deny_group_sid": deny_sid,
    }


def _restore_account_memberships(manager):
    manager.set_member("allow", "alice", False)
    manager.set_member("deny", "alice", False)
    manager.set_member("allow", "bob", True)
    manager.set_member("deny", "bob", True)
    manager.set_member("allow", "carol", True)
    manager.set_member("deny", "carol", False)


def _multiuser_map(oracle, key, root, manager, secret):
    from .windows_accounts import WindowsTokenLab

    role, scenario, right_name = multiuser_dimensions(key)
    desired = right_mask(right_name)
    account = secret["users"][role]
    lab = WindowsTokenLab()
    details = {
        "role": role,
        "scenario": scenario,
        "right": right_name,
        "desired": desired,
        "account": {"name": account["name"], "domain": account.get("domain"),
                    "sid": account["sid"]},
        "groups": {name: {"name": value["name"], "sid": value["sid"],
                           "members": list(value.get("members", ())) }
                   for name, value in secret["groups"].items()},
    }
    _restore_account_memberships(manager)
    try:
        if scenario in ("allow-group-absent", "fresh-token-before-group-add"):
            manager.set_member("allow", role, False)
        elif scenario == "fresh-token-after-group-add":
            manager.set_member("allow", role, True)
        elif scenario == "stale-token-after-group-remove":
            manager.set_member("allow", role, True)

        descriptor, policy = _multiuser_policy(oracle, secret, role, scenario, desired)
        details["policy"] = policy
        details["descriptor"] = wire.parse_descriptor(descriptor)
        path = _fixture(root, "target")
        information = 5 if policy["owner_sid"] else 4
        details["install"] = _capture(
            lambda: oracle.write(path, descriptor, information, "Protect"))

        if scenario == "stale-token-after-group-remove":
            with lab.logon(account) as primary:
                before = lab.token_snapshot(primary)
                manager.set_member("allow", role, False)
                details["stale_token_before_remove"] = before
                with lab.duplicate(primary) as impersonation:
                    details["stale_access_check"] = _capture(
                        lambda: oracle.access_check_token(descriptor, desired, impersonation))
                    with lab.impersonate_token(impersonation):
                        details["stale_open"] = oracle.try_open_detailed(path, desired, flags=0x80)
                with lab.logon(account) as fresh_primary:
                    details["fresh_token_after_remove"] = lab.token_snapshot(fresh_primary)
                    with lab.duplicate(fresh_primary) as fresh_impersonation:
                        details["fresh_access_check"] = _capture(
                            lambda: oracle.access_check_token(descriptor, desired, fresh_impersonation))
            return details

        with lab.logon(account) as primary:
            details["primary_token"] = lab.token_snapshot(primary)
            token = primary
            owned = []
            try:
                if scenario == "deny-group-deny-only":
                    token = lab._restricted(primary, (secret["groups"]["deny"]["sid"],),
                                            (), False, ())
                    owned.append(token)
                elif scenario == "restricting-sid-granted":
                    token = lab._restricted(primary, (),
                                            (secret["groups"]["allow"]["sid"],), False, ())
                    owned.append(token)
                elif scenario == "restricting-sid-missing":
                    token = lab._restricted(primary, (), (OTHER_SID,), False, ())
                    owned.append(token)

                with lab.duplicate(token) as impersonation:
                    details["impersonation_token"] = lab.token_snapshot(impersonation)
                    details["access_check"] = _capture(
                        lambda: oracle.access_check_token(descriptor, desired, impersonation))
                    with lab.impersonate_token(impersonation):
                        details["actual_open"] = oracle.try_open_detailed(path, desired, flags=0x80)
                        if scenario == "primary-vs-impersonation":
                            details["thread_current_sid"] = _capture(oracle.current_sid)
                if scenario == "primary-vs-impersonation":
                    details["primary_access_check"] = _capture(
                        lambda: oracle.access_check_token(descriptor, desired, primary))
            finally:
                for handle in reversed(owned):
                    lab.k.CloseHandle(handle)
        details["after"] = _descriptor_snapshot(oracle, path, 7)
        return details
    finally:
        _restore_account_memberships(manager)

IMPLEMENTED_DOMAINS = (
    "descriptor-storage",
    "selector-combinations",
    "access-evaluation",
    "inheritance-events",
    "lifecycle",
    "token-privilege",
    "authz",
    "multiuser-map",
)


def implemented_domains():
    return IMPLEMENTED_DOMAINS


def _privilege_setup(oracle, privileged, domain):
    result = {"requested": bool(privileged), "attempts": {}}
    if not privileged:
        return result
    names = []
    if domain in ("descriptor-storage", "selector-combinations"):
        names.append("SeSecurityPrivilege")
    for name in names:
        result["attempts"][name] = _capture(lambda name=name: oracle.enable_privilege(name))
    return result


def run_domain(domain, depth, workspace, writer, privileged=False, local_accounts=False):
    from .windows import Windows

    oracle = Windows()
    privilege_state = _privilege_setup(oracle, privileged, domain)
    dispatch = {
        "descriptor-storage": lambda key, root: _descriptor_storage(oracle, key, root, privilege_state),
        "selector-combinations": lambda key, root: _selector_combinations(oracle, key, root, privilege_state),
        "access-evaluation": lambda key, root: _access_evaluation(oracle, key, root),
        "inheritance-events": lambda key, root: _inheritance_events(oracle, key, root),
        "lifecycle": lambda key, root: _lifecycle(oracle, key, root),
        "token-privilege": lambda key, root: _token_privilege(oracle, key, root, privileged),
        "authz": lambda key, root: _authz(oracle, key, root),
    }
    if domain == "multiuser-map":
        if not local_accounts:
            for key in writer.expected:
                writer.emit(key, "skip", {
                    "reason": "multiuser mapping requires --local-accounts",
                    "local_accounts": False,
                })
            return
        if not privileged:
            for key in writer.expected:
                writer.emit(key, "skip", {
                    "reason": "local account provisioning requires an elevated lane",
                    "local_accounts": True,
                    "privileged": False,
                })
            return
        from .windows_accounts import LocalAccountManager
        manager = LocalAccountManager("map-" + uuid.uuid4().hex[:8])
        secret = manager.provision()
        cleanup_failures = []
        try:
            for key in writer.expected:
                _emit_case(writer, oracle, workspace, key,
                           lambda root, key=key: _multiuser_map(
                               oracle, key, root, manager, secret))
        finally:
            cleanup_failures = manager.cleanup()
        if cleanup_failures:
            raise RuntimeError(f"local account cleanup failed: {cleanup_failures}")
        return

    if domain not in dispatch:
        raise NotImplementedError(f"Windows behavior domain not implemented yet: {domain}")
    for key in writer.expected:
        _emit_case(writer, oracle, workspace, key,
                   lambda root, key=key: dispatch[domain](key, root))
