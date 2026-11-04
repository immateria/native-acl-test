"""Disposable Windows local-account lab and alternate-token process runner.

The account lifecycle is opt-in and requires elevation. Secrets live only in the
owned scratch tree and are never returned in result archives.
"""
from __future__ import annotations

import contextlib
import ctypes as C
import json
import os
import pathlib
import secrets
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

from .native import NativeFailure


def account_names(run_id: str) -> dict:
    """Return short collision-resistant local account names (SAM limit: 20)."""
    token = ''.join(ch for ch in run_id.lower() if ch.isalnum())[-8:] or secrets.token_hex(4)
    return {
        'users': {
            'alice': f'aclA_{token}',
            'bob': f'aclB_{token}',
            'carol': f'aclC_{token}',
        },
        'groups': {
            'allow': f'aclGA_{token}',
            'deny': f'aclGD_{token}',
        },
    }


def public_account_description(secret: dict) -> dict:
    """Copy account metadata while dropping every credential field."""
    users = {
        role: {k: v for k, v in value.items() if k not in ('password', 'credential')}
        for role, value in secret.get('users', {}).items()
    }
    groups = {
        role: {k: v for k, v in value.items() if k not in ('password', 'credential')}
        for role, value in secret.get('groups', {}).items()
    }
    return {'users': users, 'groups': groups, 'schema': 1}


def qualified_account_name(domain: str, name: str) -> str:
    """Return the explicit DOMAIN\\name form required by NetAPI level 3."""
    if not domain or not name or "\\" in domain or "\\" in name:
        raise ValueError("invalid account domain/name")
    return domain + "\\" + name


def generate_password() -> str:
    """Generate a policy-friendly random password without shell-sensitive whitespace."""
    alphabet = string.ascii_letters + string.digits + '!#$%&*+-.:=?@^_'
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(40))
        if all(any(ch in chars for ch in value) for chars in
               (string.ascii_lowercase, string.ascii_uppercase, string.digits, '!#$%&*+-.:=?@^_')):
            return value


# Windows implementation is defined lazily so this module remains importable by
# the Linux verification suite.
if sys.platform == 'win32':
    U32 = C.c_uint32
    P = C.c_void_p

    class USER_INFO_1(C.Structure):
        _fields_ = [('name', C.c_wchar_p), ('password', C.c_wchar_p),
                    ('password_age', U32), ('priv', U32), ('home_dir', C.c_wchar_p),
                    ('comment', C.c_wchar_p), ('flags', U32), ('script_path', C.c_wchar_p)]

    class LOCALGROUP_INFO_1(C.Structure):
        _fields_ = [('name', C.c_wchar_p), ('comment', C.c_wchar_p)]

    class LOCALGROUP_MEMBERS_INFO_3(C.Structure):
        _fields_ = [('domainandname', C.c_wchar_p)]

    class SID_AND_ATTRIBUTES(C.Structure):
        _fields_ = [('sid', P), ('attributes', U32)]

    class LUID(C.Structure):
        _fields_ = [('low', U32), ('high', C.c_int32)]

    class LUID_AND_ATTRIBUTES(C.Structure):
        _fields_ = [('luid', LUID), ('attributes', U32)]

    class SECURITY_ATTRIBUTES(C.Structure):
        _fields_ = [('length', U32), ('security_descriptor', P), ('inherit_handle', C.c_int)]

    class STARTUPINFOW(C.Structure):
        _fields_ = [('cb', U32), ('reserved', C.c_wchar_p), ('desktop', C.c_wchar_p),
                    ('title', C.c_wchar_p), ('x', U32), ('y', U32), ('x_size', U32),
                    ('y_size', U32), ('x_count_chars', U32), ('y_count_chars', U32),
                    ('fill_attribute', U32), ('flags', U32), ('show_window', C.c_uint16),
                    ('reserved2_size', C.c_uint16), ('reserved2', C.POINTER(C.c_ubyte)),
                    ('stdin', P), ('stdout', P), ('stderr', P)]

    class PROCESS_INFORMATION(C.Structure):
        _fields_ = [('process', P), ('thread', P), ('process_id', U32), ('thread_id', U32)]


@dataclass
class AccountRunResult:
    returncode: Optional[int]
    timed_out: bool
    elapsed_seconds: float
    stdout: str
    stderr: str
    launch_error: Optional[str] = None


class LocalAccountManager:
    """Create, inspect, mutate, and remove one disposable local account set."""

    USER_PRIV_USER = 1
    UF_SCRIPT = 0x0001
    UF_NORMAL_ACCOUNT = 0x0200
    UF_DONT_EXPIRE_PASSWD = 0x10000
    NERR_SUCCESS = 0
    ERROR_MEMBER_IN_ALIAS = 1378
    ERROR_NO_SUCH_MEMBER = 1387

    def __init__(self, run_id: str):
        if sys.platform != 'win32':
            raise OSError('local account management requires native Windows')
        self.names = account_names(run_id)
        self.net = C.WinDLL('netapi32', use_last_error=True)
        self.adv = C.WinDLL('advapi32', use_last_error=True)
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self._configure()
        self.secret = {'users': {}, 'groups': {}, 'schema': 1}
        self.created_users = []
        self.created_groups = []

    def _configure(self):
        self.net.NetUserAdd.argtypes = [C.c_wchar_p, U32, P, C.POINTER(U32)]
        self.net.NetUserAdd.restype = U32
        self.net.NetUserDel.argtypes = [C.c_wchar_p, C.c_wchar_p]
        self.net.NetUserDel.restype = U32
        self.net.NetLocalGroupAdd.argtypes = [C.c_wchar_p, U32, P, C.POINTER(U32)]
        self.net.NetLocalGroupAdd.restype = U32
        self.net.NetLocalGroupDel.argtypes = [C.c_wchar_p, C.c_wchar_p]
        self.net.NetLocalGroupDel.restype = U32
        self.net.NetLocalGroupAddMembers.argtypes = [C.c_wchar_p, C.c_wchar_p, U32, P, U32]
        self.net.NetLocalGroupAddMembers.restype = U32
        self.net.NetLocalGroupDelMembers.argtypes = [C.c_wchar_p, C.c_wchar_p, U32, P, U32]
        self.net.NetLocalGroupDelMembers.restype = U32
        self.adv.LookupAccountNameW.argtypes = [C.c_wchar_p, C.c_wchar_p, P, C.POINTER(U32),
                                                C.c_wchar_p, C.POINTER(U32), C.POINTER(U32)]
        self.adv.LookupAccountNameW.restype = C.c_int
        self.adv.ConvertSidToStringSidW.argtypes = [P, C.POINTER(P)]
        self.adv.ConvertSidToStringSidW.restype = C.c_int
        self.kernel.LocalFree.argtypes = [P]
        self.kernel.LocalFree.restype = P

    @staticmethod
    def _net_check(code: int, operation: str):
        if code != 0:
            raise NativeFailure(operation, code)

    def lookup_sid(self, name: str) -> str:
        sid_size = U32(0)
        domain_size = U32(0)
        use = U32(0)
        self.adv.LookupAccountNameW(None, name, None, C.byref(sid_size), None,
                                    C.byref(domain_size), C.byref(use))
        if C.get_last_error() != 122 or not sid_size.value:
            raise NativeFailure('LookupAccountNameW(size)', C.get_last_error())
        sid = C.create_string_buffer(sid_size.value)
        domain = C.create_unicode_buffer(max(1, domain_size.value))
        if not self.adv.LookupAccountNameW(None, name, sid, C.byref(sid_size), domain,
                                           C.byref(domain_size), C.byref(use)):
            raise NativeFailure('LookupAccountNameW', C.get_last_error())
        text = P()
        if not self.adv.ConvertSidToStringSidW(sid, C.byref(text)):
            raise NativeFailure('ConvertSidToStringSidW', C.get_last_error())
        try:
            return C.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def create_group(self, role: str):
        name = self.names['groups'][role]
        info = LOCALGROUP_INFO_1(name, 'Disposable Crystal ACL authorization lab group')
        parameter = U32()
        self._net_check(self.net.NetLocalGroupAdd(None, 1, C.byref(info), C.byref(parameter)),
                        'NetLocalGroupAdd')
        self.created_groups.append(name)
        self.secret['groups'][role] = {'name': name, 'sid': self.lookup_sid(name), 'members': []}

    def create_user(self, role: str):
        name = self.names['users'][role]
        password = generate_password()
        info = USER_INFO_1(name, password, 0, self.USER_PRIV_USER, None,
                           'Disposable Crystal ACL authorization lab user',
                           self.UF_SCRIPT | self.UF_NORMAL_ACCOUNT | self.UF_DONT_EXPIRE_PASSWD,
                           None)
        parameter = U32()
        self._net_check(self.net.NetUserAdd(None, 1, C.byref(info), C.byref(parameter)),
                        'NetUserAdd')
        self.created_users.append(name)
        domain = os.environ.get('COMPUTERNAME') or '.'
        self.secret['users'][role] = {'name': name, 'password': password,
                                      'sid': self.lookup_sid(name), 'domain': domain}

    def set_member(self, group_role: str, user_role: str, present: bool):
        group = self.secret['groups'][group_role]
        user = self.secret['users'][user_role]
        entry = LOCALGROUP_MEMBERS_INFO_3(qualified_account_name(user.get('domain', '.'), user['name']))
        if present:
            code = self.net.NetLocalGroupAddMembers(None, group['name'], 3, C.byref(entry), 1)
            if code not in (0, self.ERROR_MEMBER_IN_ALIAS):
                raise NativeFailure('NetLocalGroupAddMembers', code)
            if user_role not in group['members']:
                group['members'].append(user_role)
        else:
            code = self.net.NetLocalGroupDelMembers(None, group['name'], 3, C.byref(entry), 1)
            if code not in (0, 1377, self.ERROR_NO_SUCH_MEMBER):
                raise NativeFailure('NetLocalGroupDelMembers', code)
            if user_role in group['members']:
                group['members'].remove(user_role)

    def provision(self) -> dict:
        try:
            self.create_group('allow')
            self.create_group('deny')
            for role in ('alice', 'bob', 'carol'):
                self.create_user(role)
            self.set_member('allow', 'bob', True)
            self.set_member('allow', 'carol', True)
            self.set_member('deny', 'bob', True)
            return self.secret
        except BaseException:
            self.cleanup()
            raise

    @classmethod
    def attach(cls, secret: dict):
        manager = cls('attached')
        manager.secret = secret
        return manager

    def cleanup(self) -> list:
        failures = []
        for name in reversed(self.created_users):
            code = self.net.NetUserDel(None, name)
            if code not in (0, 2221):
                failures.append({'operation': 'NetUserDel', 'name': name, 'code': int(code)})
        self.created_users.clear()
        for name in reversed(self.created_groups):
            code = self.net.NetLocalGroupDel(None, name)
            if code not in (0, 2220):
                failures.append({'operation': 'NetLocalGroupDel', 'name': name, 'code': int(code)})
        self.created_groups.clear()
        return failures


def write_secret_file(path: pathlib.Path, secret: dict):
    """Write credentials only below the owned scratch tree; never under results/."""
    path.write_text(json.dumps(secret, sort_keys=True) + '\n', encoding='utf-8')
    if os.name == 'nt':
        # The scratch root is already protected to the runner and SYSTEM. Keep
        # inheritance; do not shell out or print credentials.
        os.chmod(path, 0o600)


def read_secret_file(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))

class WindowsTokenLab:
    """Logon, impersonation, restricted-token, and low-integrity helpers."""

    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0
    DISABLE_MAX_PRIVILEGE = 0x1
    TOKEN_ALL_ACCESS = 0x000F01FF
    SECURITY_IMPERSONATION = 2
    TOKEN_IMPERSONATION = 2
    TOKEN_INTEGRITY_LEVEL = 25
    SE_GROUP_INTEGRITY = 0x20
    SE_GROUP_INTEGRITY_ENABLED = 0x40

    def __init__(self):
        if sys.platform != 'win32':
            raise OSError('token lab requires native Windows')
        self.a = C.WinDLL('advapi32', use_last_error=True)
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self._configure()

    def _configure(self):
        self.a.LogonUserW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_wchar_p,
                                      U32, U32, C.POINTER(P)]
        self.a.LogonUserW.restype = C.c_int
        self.a.ImpersonateLoggedOnUser.argtypes = [P]
        self.a.ImpersonateLoggedOnUser.restype = C.c_int
        self.a.RevertToSelf.argtypes = []
        self.a.RevertToSelf.restype = C.c_int
        self.a.CreateRestrictedToken.argtypes = [P, U32, U32, C.POINTER(SID_AND_ATTRIBUTES),
                                                 U32, P, U32, C.POINTER(SID_AND_ATTRIBUTES), C.POINTER(P)]
        self.a.CreateRestrictedToken.restype = C.c_int
        self.a.DuplicateTokenEx.argtypes = [P, U32, P, U32, U32, C.POINTER(P)]
        self.a.DuplicateTokenEx.restype = C.c_int
        self.a.SetTokenInformation.argtypes = [P, U32, P, U32]
        self.a.SetTokenInformation.restype = C.c_int
        self.a.ConvertStringSidToSidW.argtypes = [C.c_wchar_p, C.POINTER(P)]
        self.a.ConvertStringSidToSidW.restype = C.c_int
        self.a.ConvertSidToStringSidW.argtypes = [P, C.POINTER(P)]
        self.a.ConvertSidToStringSidW.restype = C.c_int
        self.a.GetLengthSid.argtypes = [P]
        self.a.GetLengthSid.restype = U32
        self.a.GetTokenInformation.argtypes = [P, U32, P, U32, C.POINTER(U32)]
        self.a.GetTokenInformation.restype = C.c_int
        self.a.OpenProcessToken.argtypes = [P, U32, C.POINTER(P)]
        self.a.OpenProcessToken.restype = C.c_int
        self.a.AdjustTokenPrivileges.argtypes = [P, C.c_int, P, U32, P, C.POINTER(U32)]
        self.a.AdjustTokenPrivileges.restype = C.c_int
        self.a.LookupPrivilegeValueW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.POINTER(LUID)]
        self.a.LookupPrivilegeValueW.restype = C.c_int
        self.a.LookupPrivilegeNameW.argtypes = [C.c_wchar_p, C.POINTER(LUID), C.c_wchar_p, C.POINTER(U32)]
        self.a.LookupPrivilegeNameW.restype = C.c_int
        self.k.GetCurrentProcess.argtypes = []
        self.k.GetCurrentProcess.restype = P
        self.k.CloseHandle.argtypes = [P]
        self.k.CloseHandle.restype = C.c_int
        self.k.LocalFree.argtypes = [P]
        self.k.LocalFree.restype = P

    def _check(self, value, operation):
        if not value:
            raise NativeFailure(operation, C.get_last_error())
        return value


    @contextlib.contextmanager
    def current_token(self, access=0x000F01FF):
        token = P()
        self._check(self.a.OpenProcessToken(self.k.GetCurrentProcess(), int(access),
                                            C.byref(token)), 'OpenProcessToken')
        try:
            yield token
        finally:
            self.k.CloseHandle(token)

    @contextlib.contextmanager
    def duplicate(self, token, access=0x000F01FF):
        output = P()
        self._check(self.a.DuplicateTokenEx(token, int(access), None,
                                            self.SECURITY_IMPERSONATION, self.TOKEN_IMPERSONATION,
                                            C.byref(output)), 'DuplicateTokenEx')
        try:
            yield output
        finally:
            self.k.CloseHandle(output)

    def adjust_privilege(self, token, name, state):
        attributes = {'disabled': 0, 'enabled': 2, 'removed': 4}[state]
        luid = LUID()
        self._check(self.a.LookupPrivilegeValueW(None, name, C.byref(luid)),
                    'LookupPrivilegeValueW(adjust)')
        value = LUID_AND_ATTRIBUTES(luid, attributes)
        class OnePrivilege(C.Structure):
            _fields_ = [('count', U32), ('value', LUID_AND_ATTRIBUTES)]
        update = OnePrivilege(1, value)
        C.set_last_error(0)
        self._check(self.a.AdjustTokenPrivileges(token, False, C.byref(update), 0, None, None),
                    'AdjustTokenPrivileges')
        code = C.get_last_error()
        if code:
            raise NativeFailure('AdjustTokenPrivileges', code)
        return self.token_snapshot(token)

    @contextlib.contextmanager
    def sid(self, text: str):
        pointer = P()
        self._check(self.a.ConvertStringSidToSidW(text, C.byref(pointer)),
                    'ConvertStringSidToSidW')
        try:
            yield pointer
        finally:
            self.k.LocalFree(pointer)

    @contextlib.contextmanager
    def logon(self, account: dict):
        token = P()
        self._check(self.a.LogonUserW(account['name'], account.get('domain', '.'),
                                     account['password'], self.LOGON32_LOGON_INTERACTIVE,
                                     self.LOGON32_PROVIDER_DEFAULT, C.byref(token)), 'LogonUserW')
        try:
            yield token
        finally:
            self.k.CloseHandle(token)

    def _restricted(self, token, disable_sids, restrict_sids, disable_max_privileges, delete_privileges):
        allocated = []
        disabled_array = None
        restricted_array = None
        privilege_array = None
        try:
            disabled = []
            for text in disable_sids:
                pointer = P()
                self._check(self.a.ConvertStringSidToSidW(text, C.byref(pointer)),
                            'ConvertStringSidToSidW(disable)')
                allocated.append(pointer)
                disabled.append(SID_AND_ATTRIBUTES(pointer, 0))
            restricted = []
            for text in restrict_sids:
                pointer = P()
                self._check(self.a.ConvertStringSidToSidW(text, C.byref(pointer)),
                            'ConvertStringSidToSidW(restrict)')
                allocated.append(pointer)
                restricted.append(SID_AND_ATTRIBUTES(pointer, 0))
            if disabled:
                disabled_array = (SID_AND_ATTRIBUTES * len(disabled))(*disabled)
            if restricted:
                restricted_array = (SID_AND_ATTRIBUTES * len(restricted))(*restricted)
            privileges = []
            for name in delete_privileges:
                luid = LUID()
                self._check(self.a.LookupPrivilegeValueW(None, name, C.byref(luid)),
                            'LookupPrivilegeValueW(delete)')
                privileges.append(LUID_AND_ATTRIBUTES(luid, 0))
            if privileges:
                privilege_array = (LUID_AND_ATTRIBUTES * len(privileges))(*privileges)
            output = P()
            self._check(self.a.CreateRestrictedToken(
                token, self.DISABLE_MAX_PRIVILEGE if disable_max_privileges else 0,
                len(disabled), disabled_array, len(privileges), privilege_array,
                len(restricted), restricted_array, C.byref(output)), 'CreateRestrictedToken')
            return output
        finally:
            for pointer in allocated:
                self.k.LocalFree(pointer)

    def _with_integrity(self, token, integrity_sid):
        output = P()
        self._check(self.a.DuplicateTokenEx(token, self.TOKEN_ALL_ACCESS, None,
                                            self.SECURITY_IMPERSONATION, self.TOKEN_IMPERSONATION,
                                            C.byref(output)), 'DuplicateTokenEx')
        try:
            with self.sid(integrity_sid) as sid:
                label = SID_AND_ATTRIBUTES(sid, self.SE_GROUP_INTEGRITY | self.SE_GROUP_INTEGRITY_ENABLED)
                length = C.sizeof(label) + self.a.GetLengthSid(sid)
                self._check(self.a.SetTokenInformation(output, self.TOKEN_INTEGRITY_LEVEL,
                                                       C.byref(label), length),
                            'SetTokenInformation(TokenIntegrityLevel)')
            return output
        except BaseException:
            self.k.CloseHandle(output)
            raise

    @contextlib.contextmanager
    def impersonate(self, account: dict, *, disable_sids=(), restrict_sids=(),
                    disable_max_privileges=False, delete_privileges=(), integrity_sid=None):
        with self.logon(account) as original:
            token = original
            owned = []
            try:
                if disable_sids or restrict_sids or disable_max_privileges or delete_privileges:
                    token = self._restricted(token, disable_sids, restrict_sids,
                                             disable_max_privileges, delete_privileges)
                    owned.append(token)
                if integrity_sid:
                    token = self._with_integrity(token, integrity_sid)
                    owned.append(token)
                self._check(self.a.ImpersonateLoggedOnUser(token), 'ImpersonateLoggedOnUser')
                try:
                    yield token
                finally:
                    self._check(self.a.RevertToSelf(), 'RevertToSelf')
            finally:
                for handle in reversed(owned):
                    self.k.CloseHandle(handle)


    @contextlib.contextmanager
    def impersonate_token(self, token):
        self._check(self.a.ImpersonateLoggedOnUser(token), 'ImpersonateLoggedOnUser')
        try:
            yield token
        finally:
            self._check(self.a.RevertToSelf(), 'RevertToSelf')

    def _token_data(self, token, kind):
        size = U32()
        self.a.GetTokenInformation(token, kind, None, 0, C.byref(size))
        if C.get_last_error() != 122 or not size.value:
            raise NativeFailure('GetTokenInformation(size)', C.get_last_error())
        buffer = C.create_string_buffer(size.value)
        self._check(self.a.GetTokenInformation(token, kind, buffer, size.value, C.byref(size)),
                    'GetTokenInformation')
        return buffer

    def _sid_text(self, pointer):
        output = P()
        self._check(self.a.ConvertSidToStringSidW(pointer, C.byref(output)),
                    'ConvertSidToStringSidW')
        try:
            return C.wstring_at(output)
        finally:
            self.k.LocalFree(output)

    def _optional_token_data(self, token, kind):
        try:
            return self._token_data(token, kind), None
        except NativeFailure as exc:
            return None, {'operation': exc.operation, 'code': exc.code}

    def _groups_from_buffer(self, buffer):
        pointer_size = C.sizeof(P)
        count = int.from_bytes(bytes(buffer[:4]), 'little')
        offset = (4 + pointer_size - 1) & ~(pointer_size - 1)
        stride = (pointer_size + 4 + pointer_size - 1) & ~(pointer_size - 1)
        if count > 4096 or offset + count * stride > C.sizeof(buffer):
            raise ValueError('invalid TOKEN_GROUPS extent')
        values = []
        for index in range(count):
            base = offset + index * stride
            sid_pointer = int.from_bytes(bytes(buffer[base:base + pointer_size]), 'little')
            attributes = int.from_bytes(bytes(buffer[base + pointer_size:base + pointer_size + 4]), 'little')
            values.append({'sid': self._sid_text(sid_pointer), 'attributes': attributes,
                           'enabled': bool(attributes & 0x4),
                           'enabled_by_default': bool(attributes & 0x2),
                           'mandatory': bool(attributes & 0x1),
                           'deny_only': bool(attributes & 0x10),
                           'integrity': bool(attributes & 0x20),
                           'integrity_enabled': bool(attributes & 0x40),
                           'owner': bool(attributes & 0x8),
                           'logon_id': bool(attributes & 0xC0000000)})
        return values

    def _pointer_sid(self, buffer):
        pointer_size = C.sizeof(P)
        pointer = int.from_bytes(bytes(buffer[:pointer_size]), 'little')
        return self._sid_text(pointer) if pointer else None

    def token_snapshot(self, token):
        pointer_size = C.sizeof(P)
        user = self._token_data(token, 1)
        user_pointer = int.from_bytes(bytes(user[:pointer_size]), 'little')
        groups = self._groups_from_buffer(self._token_data(token, 2))
        integrity = self._token_data(token, 25)
        integrity_pointer = int.from_bytes(bytes(integrity[:pointer_size]), 'little')
        privilege_data = self._token_data(token, 3)
        privilege_count = int.from_bytes(bytes(privilege_data[:4]), 'little')
        if privilege_count > 4096 or 4 + privilege_count * 12 > C.sizeof(privilege_data):
            raise ValueError('invalid TOKEN_PRIVILEGES extent')
        privileges = []
        for index in range(privilege_count):
            low = int.from_bytes(bytes(privilege_data[4 + index*12:8 + index*12]), 'little')
            high = int.from_bytes(bytes(privilege_data[8 + index*12:12 + index*12]), 'little', signed=True)
            attributes = int.from_bytes(bytes(privilege_data[12 + index*12:16 + index*12]), 'little')
            luid = LUID(low, high)
            size = U32(0)
            self.a.LookupPrivilegeNameW(None, C.byref(luid), None, C.byref(size))
            name = None
            if size.value:
                buffer = C.create_unicode_buffer(size.value + 1)
                capacity = U32(len(buffer))
                if self.a.LookupPrivilegeNameW(None, C.byref(luid), buffer, C.byref(capacity)):
                    name = buffer.value
            privileges.append({'name': name, 'luid_low': low, 'luid_high': high,
                               'attributes': attributes, 'enabled': bool(attributes & 2),
                               'enabled_by_default': bool(attributes & 1),
                               'removed': bool(attributes & 4),
                               'used_for_access': bool(attributes & 0x80000000)})

        result = {'user_sid': self._sid_text(user_pointer), 'groups': groups,
                  'integrity_sid': self._sid_text(integrity_pointer),
                  'privileges': privileges}
        simple = {18: 'elevation_type', 20: 'elevated', 23: 'virtualization_allowed',
                  24: 'virtualization_enabled', 29: 'is_appcontainer',
                  32: 'appcontainer_number'}
        for kind, name in simple.items():
            data, error = self._optional_token_data(token, kind)
            if data is not None and C.sizeof(data) >= 4:
                result[name] = int.from_bytes(bytes(data[:4]), 'little')
            else:
                result[name + '_error'] = error
        for kind, name in ((11, 'restricted_sids'), (30, 'capabilities')):
            data, error = self._optional_token_data(token, kind)
            if data is not None:
                result[name] = self._groups_from_buffer(data)
            else:
                result[name + '_error'] = error
        for kind, name in ((4, 'owner_sid'), (5, 'primary_group_sid'),
                           (31, 'appcontainer_sid')):
            data, error = self._optional_token_data(token, kind)
            if data is not None:
                result[name] = self._pointer_sid(data)
            else:
                result[name + '_error'] = error
        default_dacl, error = self._optional_token_data(token, 6)
        if default_dacl is not None:
            pointer = int.from_bytes(bytes(default_dacl[:pointer_size]), 'little')
            if pointer:
                header = C.string_at(pointer, 8)
                size = int.from_bytes(header[2:4], 'little')
                if 8 <= size <= 65535:
                    from . import wire
                    raw = C.string_at(pointer, size)
                    result['default_dacl'] = {'raw': raw.hex(),
                                              'parsed': wire.parse_acl(raw)}
                else:
                    result['default_dacl_error'] = {'reason': 'invalid ACL extent', 'size': size}
            else:
                result['default_dacl'] = None
        else:
            result['default_dacl_error'] = error
        for kind, name in ((33, 'user_claims'), (34, 'device_claims')):
            data, error = self._optional_token_data(token, kind)
            result[name] = ({'available': True, 'size': C.sizeof(data)} if data is not None
                            else {'available': False, 'error': error})
        linked, error = self._optional_token_data(token, 19)
        if linked is not None and C.sizeof(linked) >= pointer_size:
            handle = int.from_bytes(bytes(linked[:pointer_size]), 'little')
            result['linked_token'] = bool(handle)
            if handle:
                self.k.CloseHandle(handle)
        else:
            result['linked_token_error'] = error
        return result



class AccountProcessRunner:
    """Run the line-oriented Crystal bridge as a real local logon account."""

    STARTF_USESTDHANDLES = 0x00000100
    CREATE_NO_WINDOW = 0x08000000
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258

    def __init__(self):
        if sys.platform != 'win32':
            raise OSError('alternate-account process launch requires native Windows')
        self.a = C.WinDLL('advapi32', use_last_error=True)
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.a.CreateProcessWithLogonW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_wchar_p,
                                                   U32, C.c_wchar_p, C.c_wchar_p, U32,
                                                   P, C.c_wchar_p, C.POINTER(STARTUPINFOW),
                                                   C.POINTER(PROCESS_INFORMATION)]
        self.a.CreateProcessWithLogonW.restype = C.c_int
        self.k.WaitForSingleObject.argtypes = [P, U32]
        self.k.WaitForSingleObject.restype = U32
        self.k.TerminateProcess.argtypes = [P, U32]
        self.k.TerminateProcess.restype = C.c_int
        self.k.GetExitCodeProcess.argtypes = [P, C.POINTER(U32)]
        self.k.GetExitCodeProcess.restype = C.c_int
        self.k.CloseHandle.argtypes = [P]
        self.k.CloseHandle.restype = C.c_int

    def run(self, account: dict, executable: pathlib.Path, cwd: pathlib.Path,
            request: bytes, prefix: pathlib.Path, timeout: float) -> AccountRunResult:
        import msvcrt
        prefix.parent.mkdir(parents=True, exist_ok=True)
        stdin_path = prefix.with_suffix('.stdin.jsonl')
        stdout_path = prefix.with_suffix('.stdout.txt')
        stderr_path = prefix.with_suffix('.stderr.txt')
        stdin_path.write_bytes(request)
        started = time.monotonic()
        process = PROCESS_INFORMATION()
        launch_error = None
        timed_out = False
        returncode = None
        with stdin_path.open('rb', buffering=0) as stdin, \
                stdout_path.open('wb', buffering=0) as stdout, \
                stderr_path.open('wb', buffering=0) as stderr:
            for stream in (stdin, stdout, stderr):
                os.set_inheritable(stream.fileno(), True)
            startup = STARTUPINFOW()
            startup.cb = C.sizeof(startup)
            startup.flags = self.STARTF_USESTDHANDLES
            startup.stdin = msvcrt.get_osfhandle(stdin.fileno())
            startup.stdout = msvcrt.get_osfhandle(stdout.fileno())
            startup.stderr = msvcrt.get_osfhandle(stderr.fileno())
            command = C.create_unicode_buffer(subprocess.list2cmdline([str(executable)]))
            try:
                ok = self.a.CreateProcessWithLogonW(
                    account['name'], account.get('domain', '.'), account['password'], 0,
                    str(executable), command, self.CREATE_NO_WINDOW, None, str(cwd),
                    C.byref(startup), C.byref(process))
            finally:
                for stream in (stdin, stdout, stderr):
                    os.set_inheritable(stream.fileno(), False)
            if not ok:
                launch_error = f'CreateProcessWithLogonW failed: {C.get_last_error()}'
            else:
                try:
                    wait = self.k.WaitForSingleObject(process.process, max(1, int(timeout * 1000)))
                    if wait == self.WAIT_TIMEOUT:
                        timed_out = True
                        self.k.TerminateProcess(process.process, 124)
                        self.k.WaitForSingleObject(process.process, 20000)
                    elif wait != self.WAIT_OBJECT_0:
                        launch_error = f'WaitForSingleObject failed: {C.get_last_error()}'
                    code = U32()
                    if self.k.GetExitCodeProcess(process.process, C.byref(code)):
                        returncode = int(code.value)
                finally:
                    self.k.CloseHandle(process.thread)
                    self.k.CloseHandle(process.process)
        return AccountRunResult(
            returncode=returncode,
            timed_out=timed_out,
            elapsed_seconds=round(time.monotonic() - started, 6),
            stdout=stdout_path.read_text(encoding='utf-8', errors='replace'),
            stderr=stderr_path.read_text(encoding='utf-8', errors='replace'),
            launch_error=launch_error,
        )
