"""Independent ctypes wrapper for the Windows Authz authorization engine.

The wrapper intentionally exposes raw result arrays and native error codes. It
is used only by the observational behavior mapper; the Crystal shard does not
depend on Authz.dll.
"""
from __future__ import annotations

import contextlib
import ctypes as C
import os

from .native import NativeFailure

U16 = C.c_uint16
U32 = C.c_uint32
I32 = C.c_int32
I64 = C.c_int64
U64 = C.c_uint64
P = C.c_void_p
WINFUNCTYPE = getattr(C, "WINFUNCTYPE", C.CFUNCTYPE)

AUTHZ_RM_FLAG_NO_AUDIT = 0x1
AUTHZ_RM_FLAG_INITIALIZE_UNDER_IMPERSONATION = 0x2
AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES = 0x4
AUTHZ_ACCESS_CHECK_NO_DEEP_COPY_SD = 0x1

AUTHZ_CONTEXT_INFO_USER_CLAIMS = 13
AUTHZ_CONTEXT_INFO_DEVICE_CLAIMS = 14
AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL = 1

AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64 = 0x0001
AUTHZ_SECURITY_ATTRIBUTE_TYPE_UINT64 = 0x0002
AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING = 0x0003
AUTHZ_SECURITY_ATTRIBUTE_TYPE_SID = 0x0005
AUTHZ_SECURITY_ATTRIBUTE_TYPE_BOOLEAN = 0x0006


class LUID(C.Structure):
    _fields_ = [("low", U32), ("high", I32)]


class GUID(C.Structure):
    _fields_ = [("data1", U32), ("data2", U16), ("data3", U16),
                ("data4", C.c_ubyte * 8)]


class OBJECT_TYPE_LIST(C.Structure):
    _fields_ = [("level", U16), ("sbz", U16), ("object_type", C.POINTER(GUID))]


class AUTHZ_ACCESS_REQUEST(C.Structure):
    _fields_ = [("desired_access", U32), ("principal_self_sid", P),
                ("object_type_list", C.POINTER(OBJECT_TYPE_LIST)),
                ("object_type_list_length", U32), ("optional_arguments", P)]


class AUTHZ_ACCESS_REPLY(C.Structure):
    _fields_ = [("result_list_length", U32),
                ("granted_access_mask", C.POINTER(U32)),
                ("sacl_evaluation_results", C.POINTER(U32)),
                ("error", C.POINTER(U32))]


class AUTHZ_SECURITY_ATTRIBUTE_V1(C.Structure):
    _fields_ = [("name", C.c_wchar_p), ("value_type", U16),
                ("reserved", U16), ("flags", U32), ("value_count", U32),
                ("values", P)]


class AUTHZ_SECURITY_ATTRIBUTES_INFORMATION(C.Structure):
    _fields_ = [("version", U16), ("reserved", U16),
                ("attribute_count", U32), ("attributes", P)]


CALLBACK = WINFUNCTYPE(I32, P, P, P, C.POINTER(I32))


def guid_bytes(text: str) -> GUID:
    """Parse canonical GUID text into Windows in-memory field order."""
    import uuid
    value = uuid.UUID(text)
    raw = value.bytes
    return GUID(int.from_bytes(raw[0:4], "big"), int.from_bytes(raw[4:6], "big"),
                int.from_bytes(raw[6:8], "big"),
                (C.c_ubyte * 8)(*raw[8:16]))


class ClaimBuffer:
    """Own all ctypes allocations backing one Authz claim-information object."""

    def __init__(self, claims):
        self.keepalive = []
        attributes = []
        for name, values in claims.items():
            if not isinstance(values, (list, tuple)) or not values:
                raise ValueError("Authz claim values must be a non-empty sequence")
            first = values[0]
            if isinstance(first, str):
                value_type = AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING
                array = (C.c_wchar_p * len(values))(*[str(v) for v in values])
            elif isinstance(first, bool):
                value_type = AUTHZ_SECURITY_ATTRIBUTE_TYPE_BOOLEAN
                array = (U64 * len(values))(*[1 if v else 0 for v in values])
            elif isinstance(first, int):
                value_type = AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64
                array = (I64 * len(values))(*[int(v) for v in values])
            else:
                raise TypeError(f"unsupported Authz claim value type: {type(first).__name__}")
            self.keepalive.append(array)
            attributes.append(AUTHZ_SECURITY_ATTRIBUTE_V1(
                str(name), value_type, 0, 0, len(values), C.cast(array, P)))
        self.array = (AUTHZ_SECURITY_ATTRIBUTE_V1 * len(attributes))(*attributes)
        self.keepalive.append(self.array)
        self.info = AUTHZ_SECURITY_ATTRIBUTES_INFORMATION(
            1, 0, len(attributes), C.cast(self.array, P))
        self.operation = I32(AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL)


class Authz:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Authz behavior mapping requires native Windows")
        self.dll = C.WinDLL("authz", use_last_error=True)
        self.adv = C.WinDLL("advapi32", use_last_error=True)
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self._callbacks = []
        self.callback_events = []
        self._configure()

    def _configure(self):
        d = self.dll
        d.AuthzInitializeResourceManager.argtypes = [U32, P, P, P, C.c_wchar_p, C.POINTER(P)]
        d.AuthzInitializeResourceManager.restype = I32
        d.AuthzFreeResourceManager.argtypes = [P]
        d.AuthzFreeResourceManager.restype = I32
        d.AuthzInitializeContextFromToken.argtypes = [U32, P, P, P, LUID, P, C.POINTER(P)]
        d.AuthzInitializeContextFromToken.restype = I32
        d.AuthzFreeContext.argtypes = [P]
        d.AuthzFreeContext.restype = I32
        d.AuthzAccessCheck.argtypes = [U32, P, C.POINTER(AUTHZ_ACCESS_REQUEST), P, P,
                                       C.POINTER(P), U32, C.POINTER(AUTHZ_ACCESS_REPLY),
                                       C.POINTER(P)]
        d.AuthzAccessCheck.restype = I32
        d.AuthzCachedAccessCheck.argtypes = [U32, P, C.POINTER(AUTHZ_ACCESS_REQUEST), P,
                                             C.POINTER(AUTHZ_ACCESS_REPLY)]
        d.AuthzCachedAccessCheck.restype = I32
        d.AuthzFreeHandle.argtypes = [P]
        d.AuthzFreeHandle.restype = I32
        d.AuthzModifyClaims.argtypes = [P, I32, C.POINTER(I32),
                                        C.POINTER(AUTHZ_SECURITY_ATTRIBUTES_INFORMATION)]
        d.AuthzModifyClaims.restype = I32
        d.AuthzModifySecurityAttributes.argtypes = [P, C.POINTER(I32),
                                                     C.POINTER(AUTHZ_SECURITY_ATTRIBUTES_INFORMATION)]
        d.AuthzModifySecurityAttributes.restype = I32
        d.AuthzGetInformationFromContext.argtypes = [P, I32, U32, C.POINTER(U32), P]
        d.AuthzGetInformationFromContext.restype = I32
        self.adv.OpenProcessToken.argtypes = [P, U32, C.POINTER(P)]
        self.adv.OpenProcessToken.restype = I32
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = P
        self.kernel.CloseHandle.argtypes = [P]
        self.kernel.CloseHandle.restype = I32

    @staticmethod
    def _check(value, operation):
        if not value:
            raise NativeFailure(operation, C.get_last_error())
        return value

    @contextlib.contextmanager
    def resource_manager(self, *, callback_result=None, central_policies=False,
                         under_impersonation=False):
        callback = None
        callback_pointer = P()
        if callback_result is not None:
            applicable = bool(callback_result)

            @CALLBACK
            def callback(client, ace, args, output):
                self.callback_events.append({
                    "client_context": int(client or 0),
                    "ace_pointer": int(ace or 0),
                    "arguments_pointer": int(args or 0),
                    "applicable": applicable,
                })
                output[0] = 1 if applicable else 0
                return 1

            self._callbacks.append(callback)
            callback_pointer = C.cast(callback, P)
        flags = AUTHZ_RM_FLAG_NO_AUDIT
        if not central_policies:
            flags |= AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES
        if under_impersonation:
            flags |= AUTHZ_RM_FLAG_INITIALIZE_UNDER_IMPERSONATION
        manager = P()
        self._check(self.dll.AuthzInitializeResourceManager(
            flags, callback_pointer, None, None, "native-acl-test", C.byref(manager)),
            "AuthzInitializeResourceManager")
        try:
            yield manager
        finally:
            self._check(self.dll.AuthzFreeResourceManager(manager),
                        "AuthzFreeResourceManager")
            if callback is not None:
                self._callbacks.remove(callback)

    @contextlib.contextmanager
    def current_token(self):
        token = P()
        self._check(self.adv.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8,
                                              C.byref(token)), "OpenProcessToken(Authz)")
        try:
            yield token
        finally:
            self.kernel.CloseHandle(token)

    @contextlib.contextmanager
    def context(self, token=None, **manager_options):
        with self.resource_manager(**manager_options) as manager:
            owned_token = token is None
            if owned_token:
                token_cm = self.current_token()
                token = token_cm.__enter__()
            context = P()
            try:
                self._check(self.dll.AuthzInitializeContextFromToken(
                    0, token, manager, None, LUID(0, 0), None, C.byref(context)),
                    "AuthzInitializeContextFromToken")
                try:
                    yield context
                finally:
                    self._check(self.dll.AuthzFreeContext(context), "AuthzFreeContext")
            finally:
                if owned_token:
                    token_cm.__exit__(None, None, None)

    def modify_claims(self, context, claim_class, claims):
        buffer = ClaimBuffer(claims)
        self._check(self.dll.AuthzModifyClaims(
            context, int(claim_class), C.byref(buffer.operation), C.byref(buffer.info)),
            "AuthzModifyClaims")
        return buffer

    def modify_security_attributes(self, context, attributes):
        buffer = ClaimBuffer(attributes)
        self._check(self.dll.AuthzModifySecurityAttributes(
            context, C.byref(buffer.operation), C.byref(buffer.info)),
            "AuthzModifySecurityAttributes")
        return buffer

    def context_information(self, context, info_class):
        size = U32()
        self.dll.AuthzGetInformationFromContext(context, int(info_class), 0,
                                                C.byref(size), None)
        code = C.get_last_error()
        if not size.value:
            raise NativeFailure("AuthzGetInformationFromContext(size)", code)
        buffer = C.create_string_buffer(size.value)
        self._check(self.dll.AuthzGetInformationFromContext(
            context, int(info_class), size, C.byref(size), buffer),
            "AuthzGetInformationFromContext")
        return buffer.raw[:size.value]

    def access_check(self, context, descriptor, desired=0x00120089, *,
                     principal_self=None, object_types=None, optional_arguments=None,
                     cache=False):
        from . import wire
        wire.parse_descriptor(descriptor)
        sd = C.create_string_buffer(descriptor)
        sid_buffer = None
        sid_pointer = P()
        if principal_self is not None:
            sid_buffer = C.create_string_buffer(principal_self)
            sid_pointer = C.cast(sid_buffer, P)
        guid_keepalive = []
        object_array = None
        object_pointer = C.POINTER(OBJECT_TYPE_LIST)()
        object_count = 0
        if object_types:
            values = []
            for level, guid_text in object_types:
                guid = guid_bytes(guid_text)
                guid_keepalive.append(guid)
                values.append(OBJECT_TYPE_LIST(int(level), 0, C.pointer(guid)))
            object_array = (OBJECT_TYPE_LIST * len(values))(*values)
            object_pointer = C.cast(object_array, C.POINTER(OBJECT_TYPE_LIST))
            object_count = len(values)
        optional_pointer = P()
        optional_keepalive = None
        if optional_arguments is not None:
            optional_keepalive = C.create_string_buffer(optional_arguments)
            optional_pointer = C.cast(optional_keepalive, P)
        request = AUTHZ_ACCESS_REQUEST(int(desired) & 0xFFFFFFFF, sid_pointer,
                                       object_pointer, object_count, optional_pointer)
        count = max(1, object_count)
        granted = (U32 * count)()
        sacl = (U32 * count)()
        errors = (U32 * count)()
        reply = AUTHZ_ACCESS_REPLY(count, granted, sacl, errors)
        cached = P()
        self._check(self.dll.AuthzAccessCheck(
            0, context, C.byref(request), None, sd, None, 0, C.byref(reply),
            C.byref(cached) if cache else None), "AuthzAccessCheck")
        result = {
            "desired": int(desired) & 0xFFFFFFFF,
            "result_count": count,
            "granted": [int(v) for v in granted],
            "sacl": [int(v) for v in sacl],
            "errors": [int(v) for v in errors],
        }
        return result, cached, (sd, sid_buffer, object_array, guid_keepalive,
                                optional_keepalive, request, reply, granted, sacl, errors)

    def cached_access_check(self, cached, desired=0x00120089, *, principal_self=None):
        sid_buffer = None
        sid_pointer = P()
        if principal_self is not None:
            sid_buffer = C.create_string_buffer(principal_self)
            sid_pointer = C.cast(sid_buffer, P)
        request = AUTHZ_ACCESS_REQUEST(int(desired) & 0xFFFFFFFF, sid_pointer,
                                       None, 0, None)
        granted = (U32 * 1)()
        sacl = (U32 * 1)()
        errors = (U32 * 1)()
        reply = AUTHZ_ACCESS_REPLY(1, granted, sacl, errors)
        self._check(self.dll.AuthzCachedAccessCheck(
            0, cached, C.byref(request), None, C.byref(reply)),
            "AuthzCachedAccessCheck")
        return {"desired": int(desired) & 0xFFFFFFFF,
                "granted": [int(v) for v in granted],
                "sacl": [int(v) for v in sacl],
                "errors": [int(v) for v in errors]}

    def free_cached(self, handle):
        if handle:
            self._check(self.dll.AuthzFreeHandle(handle), "AuthzFreeHandle")
