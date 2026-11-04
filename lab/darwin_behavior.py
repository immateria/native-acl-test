"""Darwin ACL behavior mapping against libSystem and filesystem operations."""
import ctypes
import errno
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import traceback
import unicodedata
import uuid

from . import behavior_catalog, core, wire
from .native import NativeFailure, SkipCase

NOBODY = str(uuid.UUID(bytes=bytes.fromhex("abcdefabcdefabcdefabcdef") + bytes.fromhex("fffffffe")))
EVERYONE = str(uuid.UUID(bytes=bytes.fromhex("abcdefabcdefabcdefabcdef") + bytes.fromhex("0000000c")))


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _setxattr(path, name, value):
    # Python 3.14 removed os.setxattr on macOS; call libSystem directly.
    if hasattr(os, "setxattr"):
        os.setxattr(path, name, value)
        return
    if _libc().setxattr(os.fsencode(path), os.fsencode(name), value, len(value), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "setxattr", os.fspath(path))


def _getxattr(path, name):
    if hasattr(os, "getxattr"):
        return os.getxattr(path, name)
    buffer = ctypes.create_string_buffer(256)
    size = _libc().getxattr(os.fsencode(path), os.fsencode(name), buffer, len(buffer), 0, 0)
    if size < 0:
        raise OSError(ctypes.get_errno(), "getxattr", os.fspath(path))
    return buffer.raw[:size]


def _restore_tree(oracle, path):
    # Undo experiment mutations (deny ACLs, mode 0) so the fixture can be
    # deleted. Best effort: any leak is still reported by the generic remover.
    if os.path.islink(path):
        return
    try:
        oracle.write(path, wire.darwin_export([], 0x20000))
    except Exception:
        pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    try:
        children = list(os.scandir(path))
    except OSError:
        return
    for entry in children:
        _restore_tree(oracle, pathlib.Path(entry.path))


def right_mask(name):
    if name in behavior_catalog.DARWIN_RIGHTS:
        return behavior_catalog.DARWIN_RIGHTS[name]
    if name == "zero":
        return 0
    if name == "all-known":
        return sum(behavior_catalog.DARWIN_RIGHTS.values())
    if name.startswith("bit-"):
        bit = int(name[4:])
        if 0 <= bit < 32:
            return 1 << bit
    raise ValueError(f"unknown Darwin right: {name}")


def policy_entries(policy, user, everyone, mask):
    allow = lambda principal: dict(principal=principal, raw_flags=1, raw_rights=mask)
    deny = lambda principal: dict(principal=principal, raw_flags=2, raw_rights=mask)
    if policy == "none":
        return None
    if policy == "empty":
        return []
    if policy == "allow-user":
        return [allow(user)]
    if policy == "deny-user":
        return [deny(user)]
    if policy == "allow-everyone":
        return [allow(everyone)]
    if policy == "deny-everyone":
        return [deny(everyone)]
    if policy == "allow-deny":
        return [allow(user), deny(user)]
    if policy == "deny-allow":
        return [deny(user), allow(user)]
    raise ValueError(f"unknown Darwin ACL policy: {policy}")


def mode_access_dimensions(key):
    domain, obj, mode, policy, operation = key.split(":", 4)
    if domain != "mode-access":
        raise ValueError("not a Darwin mode/access key")
    return obj, int(mode, 8), policy, operation


def inheritance_dimensions(key):
    domain, event, kind, flags = key.split(":", 3)
    if domain != "inheritance":
        raise ValueError("not a Darwin inheritance key")
    return event, kind, int(flags, 16)


_OPERATION_RIGHTS = {
    "file": {
        "read": "read-data", "write": "write-data", "append": "append-data", "execute": "execute",
        "stat": "read-attributes", "utime": "write-attributes", "getxattr": "read-ext-attributes",
        "setxattr": "write-ext-attributes", "acl-read": "read-security", "acl-write": "write-security",
    },
    "directory": {
        "list": "read-data", "create-file": "write-data", "create-dir": "append-data", "traverse": "execute",
        "delete-child": "delete-child", "stat": "read-attributes", "utime": "write-attributes",
        "acl-read": "read-security", "acl-write": "write-security",
    },
}


def operation_right(obj, operation):
    try:
        return right_mask(_OPERATION_RIGHTS[obj][operation])
    except KeyError as exc:
        raise ValueError(f"unknown Darwin operation: {obj}/{operation}") from exc


def _native_error(exc):
    return dict(type=exc.__class__.__name__, operation=getattr(exc, "operation", None),
                code=getattr(exc, "code", getattr(exc, "errno", None)), message=str(exc))


def _capture(call):
    try:
        return dict(ok=True, value=call())
    except (NativeFailure, OSError, ValueError) as exc:
        return dict(ok=False, error=_native_error(exc))


def _snapshot(oracle, path, follow=True, fd=None):
    return _capture(lambda: oracle.read(path, follow=follow, fd=fd))


def _write(oracle, path, data, follow=True, fd=None):
    return _capture(lambda: oracle.write(path, data, follow=follow, fd=fd))


def _fixture(root, name, directory=False):
    path = root / name
    if directory:
        path.mkdir()
    else:
        path.write_bytes(b"native ACL behavior fixture\n")
    return path


def _case_root(workspace, domain, key):
    base = pathlib.Path(workspace).resolve()
    base.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid5(uuid.NAMESPACE_URL, key).hex[:16]
    path = pathlib.Path(tempfile.mkdtemp(prefix=f"darwin-{domain}-{token}-", dir=base))
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
    except SkipCase as exc:
        status, details = "skip", {"reason": str(exc)}
    except (NativeFailure, OSError) as exc:
        status, details = "observe", {"native_error": _native_error(exc)}
    except BaseException as exc:
        status, details = "error", {"exception": repr(exc), "traceback": traceback.format_exc()}
    try:
        _restore_tree(oracle, root)
        core.safe_remove_tree(root)
    except BaseException as exc:
        status = "error"
        details["cleanup_error"] = repr(exc)
    writer.emit(key, status, details)


def _storage(oracle, key, root):
    parts = key.split(":")
    category = parts[1]
    obj = parts[2]
    path = _fixture(root, "target", directory=obj == "directory")
    if category == "count":
        count = int(parts[3])
        init = oracle.init_count(count)
        details = {"requested_count": count, "acl_init": init}
        if count <= 128:
            entries = [dict(principal=NOBODY, raw_flags=1 + (index & 1), raw_rights=2 << (index % 4))
                       for index in range(count)]
            data = wire.darwin_export(entries)
            details.update(requested_hex=data.hex(), write=_write(oracle, path, data), read=_snapshot(oracle, path),
                           libc=_capture(lambda: oracle.libc_read(path)))
        return details
    if category == "rights":
        kind = 1 if parts[3] == "allow" else 2
        mask = right_mask(parts[4])
        entries = [dict(principal=NOBODY, raw_flags=kind, raw_rights=mask)]
        flags = 0
    elif category == "ace-flags":
        kind = 1 if parts[3] == "allow" else 2
        flags_ace = int(parts[4], 16)
        entries = [dict(principal=NOBODY, raw_flags=kind | flags_ace, raw_rights=2)]
        flags = 0
    elif category == "acl-flags":
        entries = []
        flags = int(parts[3], 16)
    else:
        raise ValueError(f"unknown Darwin storage category: {category}")
    data = wire.darwin_export(entries, flags)
    result = dict(requested_hex=data.hex(), write=_write(oracle, path, data))
    result["path_read"] = _snapshot(oracle, path)
    if not path.is_dir():
        fd = os.open(path, os.O_RDONLY)
        try:
            result["fd_read"] = _snapshot(oracle, path, fd=fd)
        finally:
            os.close(fd)
    result["libc_read"] = _capture(lambda: oracle.libc_read(path))
    return result


def _tree_state(oracle, root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.name.startswith(".acl-behavior"):
            continue
        result[path.relative_to(root).as_posix()] = _snapshot(oracle, path, follow=not path.is_symlink())
    return result


def _inheritance(oracle, key, root):
    event, kind, flags = inheritance_dimensions(key)
    parent = root / "parent"
    parent.mkdir()
    entry = dict(principal=NOBODY, raw_flags=(1 if kind == "allow" else 2) | flags, raw_rights=2 | 4 | 8)
    requested = wire.darwin_export([entry])
    write = _write(oracle, parent, requested)
    details = {"event": event, "requested_hex": requested.hex(), "parent_write": write}
    if not write["ok"]:
        return details
    if event == "create":
        (parent / "file").write_bytes(b"x")
        (parent / "dir").mkdir()
        (parent / "dir" / "grandfile").write_bytes(b"x")
        (parent / "dir" / "granddir").mkdir()
        (parent / "dir" / "granddir" / "greatfile").write_bytes(b"x")
    elif event == "move":
        source_file = _fixture(root, "source-file")
        source_dir = _fixture(root, "source-dir", True)
        (source_dir / "child").write_bytes(b"x")
        os.rename(source_file, parent / "moved-file")
        os.rename(source_dir, parent / "moved-dir")
    elif event == "copy":
        source_file = _fixture(root, "source-file")
        source_dir = _fixture(root, "source-dir", True)
        (source_dir / "child").write_bytes(b"x")
        shutil.copy2(source_file, parent / "copied-file")
        shutil.copytree(source_dir, parent / "copied-dir")
    elif event == "hardlink":
        source = _fixture(root, "source-file")
        os.link(source, parent / "hardlink")
    else:
        raise ValueError(f"unknown Darwin inheritance event: {event}")
    details["parent"] = _snapshot(oracle, parent)
    details["objects"] = _tree_state(oracle, parent)
    return details


def _apply_policy(oracle, path, policy, user, mask):
    entries = policy_entries(policy, user, EVERYONE, mask)
    if entries is None:
        return _write(oracle, path, None)
    return _write(oracle, path, wire.darwin_export(entries))


def _operation(oracle, obj, operation, path, root, requested_acl):
    if obj == "file":
        if operation == "read":
            with path.open("rb") as stream:
                return {"bytes": stream.read(16).hex()}
        if operation == "write":
            fd = os.open(path, os.O_WRONLY)
            try:
                return {"written": os.write(fd, b"W")}
            finally:
                os.close(fd)
        if operation == "append":
            fd = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                return {"written": os.write(fd, b"A")}
            finally:
                os.close(fd)
        if operation == "execute":
            result = subprocess.run([str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            return {"returncode": result.returncode, "stdout": result.stdout.hex(), "stderr": result.stderr.hex()}
        if operation == "stat":
            value = os.stat(path)
            return {"mode": stat.S_IMODE(value.st_mode), "size": value.st_size}
        if operation == "utime":
            now = time.time() - 60
            os.utime(path, (now, now))
            return {"mtime_ns": os.stat(path).st_mtime_ns}
        if operation == "getxattr":
            return {"value": _getxattr(path, "com.openai.native-acl-test").hex()}
        if operation == "setxattr":
            _setxattr(path, "com.openai.native-acl-test", b"changed")
            return {"value": _getxattr(path, "com.openai.native-acl-test").hex()}
        if operation == "acl-read":
            return oracle.read(path)
        if operation == "acl-write":
            oracle.write(path, requested_acl)
            return oracle.read(path)
    else:
        child = path / "existing-child"
        if operation == "list":
            return {"entries": sorted(os.listdir(path))}
        if operation == "create-file":
            created = path / "created-file"
            created.write_bytes(b"x")
            return {"created": created.exists()}
        if operation == "create-dir":
            created = path / "created-dir"
            created.mkdir()
            return {"created": created.is_dir()}
        if operation == "traverse":
            return {"size": os.stat(child).st_size}
        if operation == "delete-child":
            child.unlink()
            return {"exists": child.exists()}
        if operation == "stat":
            return {"mode": stat.S_IMODE(os.stat(path).st_mode)}
        if operation == "utime":
            now = time.time() - 60
            os.utime(path, (now, now))
            return {"mtime_ns": os.stat(path).st_mtime_ns}
        if operation == "acl-read":
            return oracle.read(path)
        if operation == "acl-write":
            oracle.write(path, requested_acl)
            return oracle.read(path)
    raise ValueError(f"unimplemented Darwin operation {obj}/{operation}")


def _mode_access(oracle, key, root):
    obj, mode, policy, operation = mode_access_dimensions(key)
    path = _fixture(root, "target", directory=obj == "directory")
    if obj == "file":
        if operation == "execute":
            path.write_text("#!/bin/sh\nprintf mapped\\n", encoding="utf-8")
        try:
            _setxattr(path, "com.openai.native-acl-test", b"initial")
        except OSError:
            pass
    else:
        (path / "existing-child").write_bytes(b"x")
    user = oracle.principal()
    mask = operation_right(obj, operation)
    entries = policy_entries(policy, user, EVERYONE, mask)
    requested_acl = None if entries is None else wire.darwin_export(entries)
    policy_result = _apply_policy(oracle, path, policy, user, mask)
    chmod_result = _capture(lambda: os.chmod(path, mode))
    before = dict(mode=stat.S_IMODE(os.lstat(path).st_mode), acl=_snapshot(oracle, path, follow=not path.is_symlink()))
    operation_result = _capture(lambda: _operation(oracle, obj, operation, path, root, requested_acl or wire.darwin_export([])))
    after = dict(exists=path.exists(), mode=stat.S_IMODE(os.lstat(path).st_mode) if path.exists() else None,
                 acl=_snapshot(oracle, path, follow=not path.is_symlink()) if path.exists() else None)
    return dict(object=obj, requested_mode=mode, policy=policy, right=mask,
                policy_write=policy_result, chmod=chmod_result, before=before,
                operation=operation_result, after=after)


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
               "environment": oracle.environment(base)}
    try:
        target = fixture / "target"
        target.write_bytes(b"generated filesystem ACL map\n")
        requested = wire.darwin_export([
            dict(principal=NOBODY, raw_flags=1, raw_rights=2 | 4),
        ], 0x20000)
        details["acl_write"] = _write(oracle, target, requested)
        details["target"] = _snapshot(oracle, target)
        hardlink = fixture / "hardlink"
        os.link(target, hardlink)
        details["hardlink"] = {
            "target_inode": os.stat(target).st_ino,
            "link_inode": os.stat(hardlink).st_ino,
            "acl": _snapshot(oracle, hardlink),
        }
        upper = fixture / "CaseProbe"
        lower = fixture / "caseprobe"
        upper.write_bytes(b"upper")
        details["case_behavior"] = {
            "lower_exists_after_upper": lower.exists(),
            "upper_inode": os.stat(upper).st_ino,
            "lower_inode": os.stat(lower).st_ino if lower.exists() else None,
        }
        nfc = fixture / "é"
        nfd = fixture / unicodedata.normalize("NFD", "é")
        nfc.write_bytes(b"unicode")
        details["normalization"] = {
            "spellings_equal": os.fspath(nfc) == os.fspath(nfd),
            "nfd_exists_after_nfc": nfd.exists(),
            "nfc_inode": os.stat(nfc).st_ino,
            "nfd_inode": os.stat(nfd).st_ino if nfd.exists() else None,
            "entries": sorted(path.name for path in fixture.iterdir()),
        }
        details["xattr"] = _capture(lambda: (
            _setxattr(target, "com.openai.native-acl-map", b"value"),
            _getxattr(target, "com.openai.native-acl-map").hex(),
        )[1])
    finally:
        _restore_tree(oracle, fixture)
        core.safe_remove_tree(fixture)
    return details


def _lifecycle(oracle, key, root):
    name = key.split(":", 1)[1]
    data_a = wire.darwin_export([dict(principal=NOBODY, raw_flags=1, raw_rights=2)])
    data_b = wire.darwin_export([dict(principal=NOBODY, raw_flags=2, raw_rights=4)])
    source = _fixture(root, "source")
    oracle.write(source, data_a)
    details = {"case": name, "before": _snapshot(oracle, source)}
    if name == "rename-path":
        destination = root / "renamed"
        os.rename(source, destination)
        details.update(after=_snapshot(oracle, destination))
    elif name == "rename-open-fd":
        fd = os.open(source, os.O_RDONLY)
        try:
            destination = root / "renamed"
            os.rename(source, destination)
            details.update(fd_after=_snapshot(oracle, destination, fd=fd), path_after=_snapshot(oracle, destination))
        finally:
            os.close(fd)
    elif name == "unlink-open-fd":
        fd = os.open(source, os.O_RDONLY)
        try:
            source.unlink()
            details.update(fd_after=_snapshot(oracle, source, fd=fd), path_after=_snapshot(oracle, source))
        finally:
            os.close(fd)
    elif name == "replace-path":
        fd = os.open(source, os.O_RDONLY)
        replacement = _fixture(root, "replacement")
        oracle.write(replacement, data_b)
        try:
            os.replace(replacement, source)
            details.update(old_fd=_snapshot(oracle, source, fd=fd), new_path=_snapshot(oracle, source))
        finally:
            os.close(fd)
    elif name in ("hardlink-create", "hardlink-write"):
        link = root / "hardlink"
        os.link(source, link)
        if name == "hardlink-write":
            oracle.write(link, data_b)
        details.update(source=_snapshot(oracle, source), link=_snapshot(oracle, link),
                       inode_source=os.stat(source).st_ino, inode_link=os.stat(link).st_ino)
    elif name == "copyfile":
        destination = root / "copy"
        shutil.copy2(source, destination)
        details.update(destination=_snapshot(oracle, destination))
    elif name == "copytree":
        source.unlink()
        source.mkdir()
        child = source / "child"
        child.write_bytes(b"x")
        oracle.write(source, data_a)
        destination = root / "copytree"
        shutil.copytree(source, destination)
        details.update(source=_tree_state(oracle, source), destination=_tree_state(oracle, destination),
                       destination_acl=_snapshot(oracle, destination))
    elif name == "clonefile":
        destination = root / "clone"
        oracle.clonefile(source, destination)
        details.update(destination=_snapshot(oracle, destination))
    elif name in ("move-into-inheriting-directory", "move-out-of-inheriting-directory", "copy-into-inheriting-directory"):
        parent = root / "inheriting"
        parent.mkdir()
        inherited = wire.darwin_export([dict(principal=NOBODY, raw_flags=1 | 0x20 | 0x40, raw_rights=8)])
        oracle.write(parent, inherited)
        if name == "move-into-inheriting-directory":
            destination = parent / "moved"
            os.rename(source, destination)
        elif name == "copy-into-inheriting-directory":
            destination = parent / "copied"
            shutil.copy2(source, destination)
        else:
            inside = parent / "inside"
            os.rename(source, inside)
            destination = root / "moved-out"
            os.rename(inside, destination)
        details.update(parent=_snapshot(oracle, parent), destination=_snapshot(oracle, destination))
    elif name in ("chmod-file", "fchmod-open-fd"):
        if name == "fchmod-open-fd":
            fd = os.open(source, os.O_RDONLY)
            try:
                os.fchmod(fd, 0o640)
                details.update(fd_after=_snapshot(oracle, source, fd=fd))
            finally:
                os.close(fd)
        else:
            os.chmod(source, 0o640)
        details.update(after=_snapshot(oracle, source), mode=stat.S_IMODE(os.stat(source).st_mode))
    elif name == "chmod-directory":
        source.unlink()
        source.mkdir()
        oracle.write(source, data_a)
        os.chmod(source, 0o750)
        details.update(after=_snapshot(oracle, source), mode=stat.S_IMODE(os.stat(source).st_mode))
    elif name == "chown-same-owner":
        os.chown(source, os.geteuid(), -1)
        details.update(after=_snapshot(oracle, source))
    elif name == "chgrp-current-group":
        os.chown(source, -1, os.getegid())
        details.update(after=_snapshot(oracle, source))
    elif name == "truncate":
        os.truncate(source, 1)
        details.update(after=_snapshot(oracle, source), size=os.stat(source).st_size)
    elif name in ("symlink-follow", "symlink-nofollow", "dangling-symlink", "directory-symlink", "intermediate-symlink"):
        target = source
        if name == "directory-symlink":
            source.unlink(); source.mkdir(); target = source
        if name == "intermediate-symlink":
            source.unlink(); source.mkdir(); (source / "child").write_bytes(b"x")
        link = root / "link"
        os.symlink(root / "missing" if name == "dangling-symlink" else target, link, target_is_directory=target.is_dir())
        query = link / "child" if name == "intermediate-symlink" else link
        details.update(follow=_snapshot(oracle, query, follow=True), nofollow=_snapshot(oracle, link, follow=False))
    elif name == "fifo-nofollow":
        source.unlink()
        os.mkfifo(source)
        details.update(nofollow=_snapshot(oracle, source, follow=False), mode=stat.S_IFMT(os.lstat(source).st_mode))
    elif name == "filesystem-primary":
        details.update(_filesystem_observation(oracle, root, "primary"))
    elif name == "filesystem-apfs-case-sensitive":
        details.update(_filesystem_observation(oracle, os.environ.get("ACL_MACOS_APFSX_ROOT"), "apfs-case-sensitive"))
    elif name == "filesystem-hfs-plus":
        details.update(_filesystem_observation(oracle, os.environ.get("ACL_MACOS_HFSX_ROOT"), "hfs-plus"))
    else:
        raise ValueError(f"unimplemented Darwin lifecycle case: {name}")
    return details


def _set_state(oracle, path, state, follow=True, fd=None):
    if state == "removed":
        data = None
    elif state == "empty":
        data = wire.darwin_export([], 0x20000)
    elif state == "one":
        data = wire.darwin_export([dict(principal=NOBODY, raw_flags=1, raw_rights=2)])
    else:
        raise ValueError("unknown Darwin ACL state")
    oracle.write(path, data, follow=follow, fd=fd)
    return data


def _malformed(name):
    base = bytearray(wire.darwin_export([]))
    if name == "truncated-header":
        return bytes(base[:20])
    if name == "wrong-magic":
        base[0:4] = b"BAD!"
    elif name == "filesec-owner":
        base[4] = 1
    elif name == "filesec-group":
        base[20] = 1
    elif name == "count-length-mismatch":
        base[36:40] = (1).to_bytes(4, "big")
    elif name == "count-129":
        base[36:40] = (129).to_bytes(4, "big")
    elif name == "noacl-extra-bytes":
        base[36:40] = (0xFFFFFFFF).to_bytes(4, "big"); base += b"\0" * 24
    elif name in ("negative-reference", "unaligned-reference", "reference-before-field", "reference-past-buffer", "short-acl"):
        return bytes(base)
    elif name == "unknown-kind":
        return wire.darwin_export([dict(principal=NOBODY, raw_flags=15, raw_rights=2)])
    elif name == "audit-flags":
        return wire.darwin_export([dict(principal=NOBODY, raw_flags=1 | 0x600, raw_rights=2)])
    elif name == "unknown-right":
        return wire.darwin_export([dict(principal=NOBODY, raw_flags=1, raw_rights=1 << 31)])
    elif name == "private-acl-flags":
        return wire.darwin_export([], 0xF)
    return bytes(base)


def _api(oracle, key, root):
    parts = key.split(":")
    category = parts[1]
    target = _fixture(root, "target")
    if category == "presence":
        source, state = parts[2], parts[3]
        link = root / "link"
        fd = None
        query = target
        follow = True
        if source == "link":
            os.symlink(target, link)
            query = link
            follow = False
            _set_state(oracle, query, state, follow=False)
        elif source == "fd":
            fd = os.open(target, os.O_RDONLY)
            _set_state(oracle, target, state, fd=fd)
        else:
            _set_state(oracle, target, state)
        try:
            return dict(source=source, state=state, attribute=oracle.read(query, follow=follow, fd=fd),
                        libc=oracle.libc_read(query, follow=follow) if fd is None else None)
        finally:
            if fd is not None:
                os.close(fd)
    if category == "getattrlist":
        source = parts[2]
        size = int(parts[3].split("-", 1)[1])
        oracle.write(target, wire.darwin_export([dict(principal=NOBODY, raw_flags=1, raw_rights=2)]))
        fd = None
        try:
            if source == "fd":
                fd = os.open(target, os.O_RDONLY)
            return oracle.raw_attribute(target, follow=source != "path-nofollow", fd=fd, size=size,
                                        options=4 | (8 if source == "pack-invalid" else 0))
        finally:
            if fd is not None:
                os.close(fd)
    if category == "libc":
        source, state = parts[2], parts[3]
        link = root / "link"
        query = target
        follow = True
        fd = None
        if source == "link":
            os.symlink(target, link); query = link; follow = False
            _set_state(oracle, query, state, follow=False)
        elif source == "fd":
            fd = os.open(target, os.O_RDONLY); _set_state(oracle, target, state, fd=fd)
        else:
            _set_state(oracle, target, state)
        try:
            if fd is not None:
                return oracle.libc_read_fd(fd)
            return oracle.libc_read(query, follow=follow)
        finally:
            if fd is not None:
                os.close(fd)
    if category == "malformed":
        name = parts[2]
        data = _malformed(name)
        parser = _capture(lambda: wire.parse_darwin_export(data))
        native = None
        if name in ("unknown-kind", "audit-flags", "unknown-right", "private-acl-flags"):
            native = dict(write=_write(oracle, target, data), read=_snapshot(oracle, target))
        return dict(name=name, hex=data.hex(), bounded_parser=parser, native=native,
                    native_not_called=native is None)
    raise ValueError(f"unknown Darwin API key: {key}")


def run_domain(domain, depth, workspace, writer, privileged=False):
    from .darwin import Darwin

    oracle = Darwin()
    dispatch = {
        "storage": lambda key, root: _storage(oracle, key, root),
        "inheritance": lambda key, root: _inheritance(oracle, key, root),
        "mode-access": lambda key, root: _mode_access(oracle, key, root),
        "lifecycle": lambda key, root: _lifecycle(oracle, key, root),
        "api": lambda key, root: _api(oracle, key, root),
    }
    if domain not in dispatch:
        raise ValueError(f"unknown Darwin behavior domain: {domain}")
    for key in writer.expected:
        _emit_case(writer, oracle, workspace, key, lambda root, key=key: dispatch[domain](key, root))
