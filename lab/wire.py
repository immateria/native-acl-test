"""Independent, bounds-checked fixture encoders and evidence decoders.

Only locally constructed valid buffers go to unbounded native APIs. Mutated
buffers go exclusively to the Crystal shard's bounded model decoder.
"""
import struct
import uuid

ABSENT = object()
OBJECT_TYPES = {5, 6, 7, 8, 11, 12, 15, 16}
BASIC_TYPES = {0, 1, 2, 3, 9, 10, 13, 14, 17, 18, 19, 20, 21}

def take(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError('binary range outside buffer')
    return data[offset:offset + length]

def sid_bytes(text):
    parts = text.split('-')
    if len(parts) < 3 or parts[0] != 'S' or parts[1] != '1':
        raise ValueError('SID revision must be 1')
    try:
        authority = int(parts[2], 0) if parts[2].startswith('0x') else int(parts[2])
        subs = [int(v) for v in parts[3:]]
    except (ValueError, OverflowError) as exc:
        raise ValueError('invalid SID') from exc
    if not 0 <= authority < 2**48 or len(subs) > 15 or any(not 0 <= s < 2**32 for s in subs):
        raise ValueError('SID fields out of range')
    return bytes([1, len(subs)]) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in subs)

def sid_length(data, offset=0):
    head = take(data, offset, 8)
    if head[0] != 1 or head[1] > 15:
        raise ValueError('invalid SID header')
    length = 8 + 4 * head[1]
    take(data, offset, length)
    return length

def sid_text(data):
    length = sid_length(data)
    return 'S-1-' + str(int.from_bytes(data[2:8], 'big')) + ''.join('-' + str(x[0]) for x in struct.iter_unpack('<I', data[8:length]))

def ace(kind, flags, mask, sid, object_guid=None, inherited_guid=None, payload=b''):
    sid_length(sid)
    body = struct.pack('<I', mask)
    if kind in OBJECT_TYPES:
        body += struct.pack('<I', (1 if object_guid else 0) | (2 if inherited_guid else 0))
        if object_guid: body += uuid.UUID(object_guid).bytes_le
        if inherited_guid: body += uuid.UUID(inherited_guid).bytes_le
    body += sid + payload
    size = len(body) + 4
    if size % 4 or size > 65532: raise ValueError('unaligned/oversized ACE')
    return struct.pack('<BBH', kind, flags, size) + body

def acl(entries, revision=2, padding=b''):
    body = b''.join(entries) + padding
    if len(body) + 8 > 65535 or len(entries) > 65535:
        raise ValueError('oversized ACL')
    return struct.pack('<BBHHH', revision, 0, len(body) + 8, len(entries), 0) + body

def descriptor(owner=None, group=None, dacl=ABSENT, sacl=ABSENT, control=0):
    control = (control | 0x8000) & ~0x14
    if dacl is not ABSENT: control |= 4
    if sacl is not ABSENT: control |= 16
    offsets = []
    body = bytearray()
    for item in (owner, group, sacl, dacl):
        if item is None or item is ABSENT:
            offsets.append(0)
        else:
            offsets.append(20 + len(body)); body.extend(item)
    return struct.pack('<BBHIIII', 1, 0, control, *offsets) + body

def parse_acl(data):
    revision, _, size, count, _ = struct.unpack('<BBHHH', take(data, 0, 8))
    if size < 8: raise ValueError('short ACL')
    data = take(data, 0, size)
    entries = []
    offset = 8
    for _ in range(count):
        kind, flags, length = struct.unpack('<BBH', take(data, offset, 4))
        if length < 4 or length % 4: raise ValueError('invalid ACE length')
        raw = take(data, offset, length)
        entry = dict(type=kind, flags=flags, hex=raw.hex())
        if kind in BASIC_TYPES | OBJECT_TYPES:
            entry['mask'] = struct.unpack('<I', take(raw, 4, 4))[0]
            cursor = 8
            if kind in OBJECT_TYPES:
                object_flags = struct.unpack('<I', take(raw, 8, 4))[0]
                entry['object_flags'] = object_flags
                cursor = 12
                for bit, key in [(1, 'object_type'), (2, 'inherited_object_type')]:
                    if object_flags & bit:
                        entry[key] = str(uuid.UUID(bytes_le=take(raw, cursor, 16))); cursor += 16
            n = sid_length(raw, cursor)
            entry['sid'] = sid_text(take(raw, cursor, n))
            entry['application_data'] = raw[cursor + n:].hex()
        entries.append(entry)
        offset += length
    return dict(presence='Present', revision=revision, size=size, entries=entries, padding=data[offset:].hex(), hex=data.hex())

def parse_descriptor(data):
    rev, rm, control, owner, group, sacl, dacl = struct.unpack('<BBHIIII', take(data, 0, 20))
    if rev != 1 or not control & 0x8000: raise ValueError('invalid relative descriptor')
    result = dict(control=control, resource_manager=rm, hex=data.hex())
    for key, offset in [('owner', owner), ('group', group)]:
        if offset and (offset < 20 or offset % 4): raise ValueError('invalid SID offset')
        result[key] = sid_text(take(data, offset, sid_length(data, offset))) if offset else None
    for key, offset, bit in [('dacl', dacl, 4), ('sacl', sacl, 16)]:
        if not control & bit:
            if offset: raise ValueError('absent ACL has storage')
            result[key] = dict(presence='Absent')
        elif offset == 0:
            result[key] = dict(presence='Null')
        else:
            if offset < 20 or offset % 4: raise ValueError('invalid ACL offset')
            result[key] = parse_acl(data[offset:])
    return result

def darwin_export(entries, flags=0):
    if len(entries) > 128: raise ValueError('too many Darwin entries')
    head = struct.pack('>I', 0x012cc16d) + b'\0' * 32 + struct.pack('>II', len(entries), flags)
    return head + b''.join(uuid.UUID(e['principal']).bytes + struct.pack('>II', e['raw_flags'], e['raw_rights']) for e in entries)

def parse_darwin_export(data):
    take(data, 0, 44)
    magic, = struct.unpack_from('>I', data)
    count, flags = struct.unpack_from('>II', data, 36)
    if magic != 0x012cc16d or count > 128 or len(data) != 44 + count * 24:
        raise ValueError('invalid Darwin export')
    entries = []
    for n in range(count):
        offset = 44 + n * 24
        raw_flags, raw_rights = struct.unpack_from('>II', data, offset + 16)
        entries.append(dict(principal=str(uuid.UUID(bytes=data[offset:offset+16])), raw_flags=raw_flags, raw_rights=raw_rights))
    return dict(flags=flags, entries=entries, hex=data.hex())
