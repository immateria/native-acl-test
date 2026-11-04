"""Controls for distinguishing authorization, fixture setup and evidence quality."""
from contextlib import contextmanager
import struct
from . import wire


def with_owner(descriptor, sid):
    """Supply Authz's required owner, preserving self-relative ACL offsets and bytes."""
    decoded = wire.parse_descriptor(descriptor)
    if decoded['dacl']['presence'] == 'Absent':
        raise ValueError('Authz fixture must supply DACL information')
    if decoded['owner'] is not None:
        return descriptor
    result = bytearray(descriptor)
    result.extend(bytes(-len(result) % 4))
    struct.pack_into('<I', result, 4, len(result))
    result.extend(wire.sid_bytes(sid))
    return bytes(result)


@contextmanager
def fixture_guard(oracle, path, recovery):
    """Restore a private disposable fixture's DACL via a pre-mutation handle.

    This is fixture cleanup, not a general security descriptor restore. OWNER,
    GROUP and SACL are not restored. Do not use on caller-owned paths.
    """
    with oracle.handle(path, 0x00060000) as handle:  # READ_CONTROL | WRITE_DAC
        try:
            yield handle
        finally:
            try:
                oracle.write_handle(handle, recovery, 4, 'Protect')
            except OSError as exc:
                # A cleanup failure is an infrastructure error, not an observation.
                raise RuntimeError(f'held-handle DACL recovery failed: {exc}') from exc


def open_controls(oracle, path, desired):
    """Matched CreateFileW calls: explicit SYNCHRONIZE versus asynchronous mode."""
    controls = {}
    for mode, extra_flags in (('sync', 0), ('overlapped', 0x40000000)):
        flags = 0x02000000 | extra_flags  # FILE_FLAG_BACKUP_SEMANTICS on both
        for variant, mask in (('requested', desired), ('with_sync', desired | 0x100000)):
            key = f'{mode}.{variant}'
            controls[key] = {'desired': mask, 'flags': flags, 'share': 7, 'creation': 3,
                             'result': oracle.try_open_detailed(path, mask, share=7, creation=3, flags=flags)}
    return controls


def authz_controls(authz, context, owner, capture):
    """Assert that API failure and an evaluated deny are distinguishable.

    Buffers stay in memory. Never attach these descriptors to a file.
    All controls request the same concrete bit from the same native context.
    """
    ace = wire.ace(0, 0, 1, wire.sid_bytes('S-1-1-0'))
    base = wire.descriptor(dacl=wire.acl([ace]))
    fixtures = {
        'ownerless': base,
        'allow_read': with_owner(base, owner),
        'empty_dacl': with_owner(wire.descriptor(dacl=wire.acl([])), owner),
    }
    results, failures = {}, []
    for name, raw in fixtures.items():
        reply = capture(lambda: authz.access_check(context, raw, 1, cache=False)[0])
        value = reply.get('value') or {}
        if name == 'ownerless':
            expected = 'API error 87'
            matched = not reply['ok'] and reply['error']['code'] == 87
        elif name == 'allow_read':
            expected = 'API success, result error 0, read granted'
            matched = reply['ok'] and value.get('errors') == [0] and value.get('granted') == [1]
        else:
            expected = 'API success, result error 5, no grant'
            matched = reply['ok'] and value.get('errors') == [5] and value.get('granted') == [0]
        results[name] = {'descriptor_hex': raw.hex(), 'desired': 1, 'reply': reply,
                         'expected': expected, 'matched': bool(matched)}
        if not matched:
            failures.append(name)
    return results, failures
