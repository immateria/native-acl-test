"""Independent Windows oracle using public Advapi32/Kernel32 entrypoints.

No packages, subprocess PowerShell, or Get-Acl formatting are used for the
oracle. Native allocated buffers are copied while live and freed with LocalFree.
"""
import contextlib
import ctypes as C
import os
import struct
from . import wire
from .native import NativeFailure, SkipCase

U32=C.c_uint32
I32=C.c_int32
P=C.c_void_p
PP=C.POINTER(P)

class LUID(C.Structure):
    _fields_=[('low',U32),('high',I32)]
class Privileges(C.Structure):
    _fields_=[('count',U32),('luid',LUID),('attributes',U32)]
class Mapping(C.Structure):
    _fields_=[('read',U32),('write',U32),('execute',U32),('all',U32)]

class FileTime(C.Structure):
    _fields_=[('low',U32),('high',U32)]
class ByHandleFileInformation(C.Structure):
    _fields_=[('attributes',U32),('creation',FileTime),('last_access',FileTime),
              ('last_write',FileTime),('volume_serial',U32),('file_size_high',U32),
              ('file_size_low',U32),('link_count',U32),('file_index_high',U32),
              ('file_index_low',U32)]
class FileDispositionInfo(C.Structure):
    _fields_=[('delete_file',I32)]
class FileId128(C.Structure):
    _fields_=[('identifier',C.c_ubyte*16)]
class FileIdInfo(C.Structure):
    _fields_=[('volume_serial',C.c_uint64),('file_id',FileId128)]

class FileCaseSensitiveInfo(C.Structure):
    _fields_=[('flags',U32)]
class FileIdDescriptorUnion(C.Union):
    _fields_=[('file_id',C.c_int64),('object_id',C.c_ubyte*16),
              ('extended_file_id',FileId128)]
class FileIdDescriptor(C.Structure):
    _anonymous_=('value',)
    _fields_=[('size',U32),('kind',I32),('value',FileIdDescriptorUnion)]

class Windows:
    def __init__(self):
        self.a=C.WinDLL('advapi32',use_last_error=True)
        self.k=C.WinDLL('kernel32',use_last_error=True)
        signatures={
            'GetNamedSecurityInfoW':(U32,[C.c_wchar_p,U32,U32,PP,PP,PP,PP,PP]),
            'GetSecurityInfo':(U32,[P,U32,U32,PP,PP,PP,PP,PP]),
            'SetSecurityInfo':(U32,[P,U32,U32,P,P,P,P]),
            'QuerySecurityAccessMask':(None,[U32,C.POINTER(U32)]),
            'SetSecurityAccessMask':(None,[U32,C.POINTER(U32)]),
            'GetSecurityDescriptorControl':(I32,[P,C.POINTER(C.c_uint16),C.POINTER(U32)]),
            'GetSecurityDescriptorLength':(U32,[P]),
            'GetSecurityDescriptorOwner':(I32,[P,PP,C.POINTER(I32)]),
            'GetSecurityDescriptorGroup':(I32,[P,PP,C.POINTER(I32)]),
            'GetSecurityDescriptorDacl':(I32,[P,C.POINTER(I32),PP,C.POINTER(I32)]),
            'GetSecurityDescriptorSacl':(I32,[P,C.POINTER(I32),PP,C.POINTER(I32)]),
            'MakeSelfRelativeSD':(I32,[P,P,C.POINTER(U32)]),
            'IsValidSecurityDescriptor':(I32,[P]),'IsValidAcl':(I32,[P]),'IsValidSid':(I32,[P]),
            'GetLengthSid':(U32,[P]),'GetAce':(I32,[P,U32,PP]),
            'ConvertStringSidToSidW':(I32,[C.c_wchar_p,PP]),
            'ConvertSidToStringSidW':(I32,[P,PP]),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW':(I32,[C.c_wchar_p,U32,PP,C.POINTER(U32)]),
            'ConvertSecurityDescriptorToStringSecurityDescriptorW':(I32,[P,U32,U32,PP,C.POINTER(U32)]),
            'OpenProcessToken':(I32,[P,U32,PP]),'GetTokenInformation':(I32,[P,U32,P,U32,C.POINTER(U32)]),
            'LookupPrivilegeNameW':(I32,[C.c_wchar_p,C.POINTER(LUID),C.c_wchar_p,C.POINTER(U32)]),
            'LookupPrivilegeValueW':(I32,[C.c_wchar_p,C.c_wchar_p,C.POINTER(LUID)]),
            'AdjustTokenPrivileges':(I32,[P,I32,P,U32,P,C.POINTER(U32)]),
            'DuplicateToken':(I32,[P,U32,PP]),
            'MapGenericMask':(None,[C.POINTER(U32),C.POINTER(Mapping)]),
            'AccessCheck':(I32,[P,P,U32,C.POINTER(Mapping),P,C.POINTER(U32),C.POINTER(U32),C.POINTER(I32)]),
            'EncryptFileW':(I32,[C.c_wchar_p]),'DecryptFileW':(I32,[C.c_wchar_p,U32]),
        }
        for name,(ret,args) in signatures.items():
            f=getattr(self.a,name);f.restype=ret;f.argtypes=args
        signatures={
            'GetCurrentProcess':(P,[]),'CloseHandle':(I32,[P]),'LocalFree':(P,[P]),
            'CreateFileW':(P,[C.c_wchar_p,U32,U32,P,U32,U32,P]),
            'GetFileInformationByHandleEx':(I32,[P,I32,P,U32]),
            'GetFileInformationByHandle':(I32,[P,C.POINTER(ByHandleFileInformation)]),
            'SetFileInformationByHandle':(I32,[P,I32,P,U32]),
            'GetFinalPathNameByHandleW':(U32,[P,C.c_wchar_p,U32,U32]),
            'CreateHardLinkW':(I32,[C.c_wchar_p,C.c_wchar_p,P]),
            'GetShortPathNameW':(U32,[C.c_wchar_p,C.c_wchar_p,U32]),
            'GetVolumeNameForVolumeMountPointW':(I32,[C.c_wchar_p,C.c_wchar_p,U32]),
            'GetFileAttributesW':(U32,[C.c_wchar_p]),
            'SetFileAttributesW':(I32,[C.c_wchar_p,U32]),
            'DeviceIoControl':(I32,[P,U32,P,U32,P,U32,C.POINTER(U32),P]),
            'OpenFileById':(P,[P,C.POINTER(FileIdDescriptor),U32,U32,P,U32]),
            'GetVolumeInformationW':(I32,[C.c_wchar_p,C.c_wchar_p,U32,C.POINTER(U32),C.POINTER(U32),C.POINTER(U32),C.c_wchar_p,U32]),
            'GetVolumePathNameW':(I32,[C.c_wchar_p,C.c_wchar_p,U32]),
            'GetProcessHandleCount':(I32,[P,C.POINTER(U32)]),
        }
        for name,(ret,args) in signatures.items():
            f=getattr(self.k,name);f.restype=ret;f.argtypes=args

    def check(self,value,operation):
        if not value: raise NativeFailure(operation,C.get_last_error())
        return value

    @contextlib.contextmanager
    def handle(self,path,desired=0x20000,follow=True):
        h=self.k.CreateFileW(str(path),desired,7,None,3,0x02000000 | (0 if follow else 0x00200000),None)
        if h==P(-1).value: raise NativeFailure('oracle.CreateFileW',C.get_last_error())
        try: yield h
        finally: self.k.CloseHandle(h)

    @contextlib.contextmanager
    def token(self,access=8):
        token=P()
        self.check(self.a.OpenProcessToken(self.k.GetCurrentProcess(),access,C.byref(token)),'OpenProcessToken')
        try: yield token
        finally: self.k.CloseHandle(token)

    def token_data(self,cls):
        with self.token() as t:
            size=U32()
            self.a.GetTokenInformation(t,cls,None,0,C.byref(size))
            if not 0<size.value<=1024*1024: raise NativeFailure('GetTokenInformation(size)',C.get_last_error())
            buf=C.create_string_buffer(size.value)
            self.check(self.a.GetTokenInformation(t,cls,buf,size,C.byref(size)),'GetTokenInformation')
            return buf

    def current_sid(self):
        data=self.token_data(1) # TOKEN_USER; first field is a native PSID
        pointer=P.from_buffer(data).value
        return self.sid_string(pointer)

    def sid_string(self,pointer):
        output=P()
        self.check(self.a.ConvertSidToStringSidW(pointer,C.byref(output)),'ConvertSidToStringSidW')
        try: return C.wstring_at(output)
        finally: self.k.LocalFree(output)

    def sid_native(self,text):
        output=P()
        self.check(self.a.ConvertStringSidToSidW(text,C.byref(output)),'ConvertStringSidToSidW')
        try: return C.string_at(output,self.a.GetLengthSid(output))
        finally: self.k.LocalFree(output)

    def copy_descriptor(self,pointer):
        self.check(self.a.IsValidSecurityDescriptor(pointer),'IsValidSecurityDescriptor')
        control=C.c_uint16();revision=U32()
        self.check(self.a.GetSecurityDescriptorControl(pointer,C.byref(control),C.byref(revision)),'GetSecurityDescriptorControl')
        if control.value&0x8000:
            length=self.a.GetSecurityDescriptorLength(pointer)
            if not 20<=length<=1024*1024: raise ValueError('unexpected descriptor size')
            return C.string_at(pointer,length)
        length=U32()
        self.a.MakeSelfRelativeSD(pointer,None,C.byref(length))
        if C.get_last_error()!=122 or not 20<=length.value<=1024*1024: raise ValueError('MakeSelfRelativeSD size query failed')
        buf=C.create_string_buffer(length.value)
        self.check(self.a.MakeSelfRelativeSD(pointer,buf,C.byref(length)),'MakeSelfRelativeSD')
        return buf.raw[:length.value]

    def sddl(self,text):
        pointer=P();length=U32()
        self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,C.byref(pointer),C.byref(length)),'ConvertStringSecurityDescriptorToSecurityDescriptorW')
        try: return self.copy_descriptor(pointer)
        finally:
            if pointer: self.k.LocalFree(pointer)

    def to_sddl(self,data,information=7):
        wire.parse_descriptor(data)
        buf=C.create_string_buffer(data);pointer=P();length=U32()
        self.check(self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(buf,1,information,C.byref(pointer),C.byref(length)),'ConvertSecurityDescriptorToStringSecurityDescriptorW')
        try: return C.wstring_at(pointer)
        finally: self.k.LocalFree(pointer)

    def read_handle(self,handle,information=7):
        pointer=P()
        code=self.a.GetSecurityInfo(handle,1,information,None,None,None,None,C.byref(pointer))
        if code: raise NativeFailure('oracle.GetSecurityInfo',code)
        try: return self.copy_descriptor(pointer)
        finally:
            if pointer: self.k.LocalFree(pointer)

    def read_named(self,path,information=7):
        """Diagnostic only; the handle reader is the follow/no-follow oracle."""
        pointer=P()
        try:
            code=self.a.GetNamedSecurityInfoW(str(path),1,information,None,None,None,None,C.byref(pointer))
            if code:raise NativeFailure('GetNamedSecurityInfoW',code)
            return self.copy_descriptor(pointer)
        finally:
            if pointer:self.k.LocalFree(pointer)

    def query_access_mask(self,information):
        access=U32()
        self.a.QuerySecurityAccessMask(int(information),C.byref(access))
        return int(access.value)

    def set_access_mask(self,information):
        access=U32()
        self.a.SetSecurityAccessMask(int(information),C.byref(access))
        return int(access.value)

    def query_attempt(self,path,information,desired,follow=True):
        """Separate exact-mask handle-open failure from GetSecurityInfo failure."""
        flags=0x02000000 | (0 if follow else 0x00200000)
        handle=self.k.CreateFileW(str(path),int(desired)&0xffffffff,7,None,3,flags,None)
        if handle==P(-1).value:
            return dict(open=dict(ok=False,desired=int(desired)&0xffffffff,
                                  code=C.get_last_error()),api=None)
        try:
            opened=dict(ok=True,desired=int(desired)&0xffffffff)
            pointer=P()
            code=self.a.GetSecurityInfo(handle,1,int(information),None,None,None,None,C.byref(pointer))
            if code:
                return dict(open=opened,api=dict(ok=False,code=int(code)))
            try:
                raw=self.copy_descriptor(pointer)
                return dict(open=opened,api=dict(ok=True,code=0,raw=raw.hex(),
                                                 descriptor=wire.parse_descriptor(raw)))
            finally:
                if pointer:self.k.LocalFree(pointer)
        finally:
            self.k.CloseHandle(handle)

    def set_attempt(self,path,data,information,desired,inheritance='Preserve',follow=True):
        """Separate exact-mask handle-open failure from SetSecurityInfo failure."""
        wire.parse_descriptor(data)
        buffer=C.create_string_buffer(data)
        self.check(self.a.IsValidSecurityDescriptor(buffer),'IsValidSecurityDescriptor(set_attempt)')
        owner=P();group=P();dacl=P();sacl=P();defaulted=I32();present=I32()
        if information&1:
            self.check(self.a.GetSecurityDescriptorOwner(buffer,C.byref(owner),C.byref(defaulted)),
                       'GetSecurityDescriptorOwner(set_attempt)')
        if information&2:
            self.check(self.a.GetSecurityDescriptorGroup(buffer,C.byref(group),C.byref(defaulted)),
                       'GetSecurityDescriptorGroup(set_attempt)')
        if information&4:
            self.check(self.a.GetSecurityDescriptorDacl(buffer,C.byref(present),C.byref(dacl),C.byref(defaulted)),
                       'GetSecurityDescriptorDacl(set_attempt)')
        if information&0x1f8:
            self.check(self.a.GetSecurityDescriptorSacl(buffer,C.byref(present),C.byref(sacl),C.byref(defaulted)),
                       'GetSecurityDescriptorSacl(set_attempt)')
        flags=0x02000000 | (0 if follow else 0x00200000)
        handle=self.k.CreateFileW(str(path),int(desired)&0xffffffff,7,None,3,flags,None)
        if handle==P(-1).value:
            return dict(open=dict(ok=False,desired=int(desired)&0xffffffff,
                                  code=C.get_last_error()),api=None)
        try:
            opened=dict(ok=True,desired=int(desired)&0xffffffff)
            bits=int(information) | {'Preserve':0,'Protect':0x80000000,'Unprotect':0x20000000}[inheritance]
            code=self.a.SetSecurityInfo(handle,1,bits,owner,group,dacl,sacl)
            return dict(open=opened,api=dict(ok=code==0,code=int(code)))
        finally:
            self.k.CloseHandle(handle)

    def read(self,path,information=7,follow=True):
        # Select final-component follow behavior at open time, not by named query.
        access=U32(self.query_access_mask(information))
        # Oracle uses the working handle mask recorded on NTFS build 17763.
        access.value|=0x00020000
        with self.handle(path,access.value,follow) as h: return self.read_handle(h,information)

    def write_handle(self,handle,data,information=4,inheritance='Preserve'):
        wire.parse_descriptor(data) # own construction or an OS-produced descriptor only
        buf=C.create_string_buffer(data)
        self.check(self.a.IsValidSecurityDescriptor(buf),'IsValidSecurityDescriptor(write)')
        owner=P();group=P();dacl=P();sacl=P();defaulted=I32();present=I32()
        if information&1: self.check(self.a.GetSecurityDescriptorOwner(buf,C.byref(owner),C.byref(defaulted)),'GetSecurityDescriptorOwner')
        if information&2: self.check(self.a.GetSecurityDescriptorGroup(buf,C.byref(group),C.byref(defaulted)),'GetSecurityDescriptorGroup')
        if information&4: self.check(self.a.GetSecurityDescriptorDacl(buf,C.byref(present),C.byref(dacl),C.byref(defaulted)),'GetSecurityDescriptorDacl')
        if information&0x1f8: self.check(self.a.GetSecurityDescriptorSacl(buf,C.byref(present),C.byref(sacl),C.byref(defaulted)),'GetSecurityDescriptorSacl')
        bits=information | {'Preserve':0,'Protect':0x80000000,'Unprotect':0x20000000}[inheritance]
        code=self.a.SetSecurityInfo(handle,1,bits,owner,group,dacl,sacl)
        if code: raise NativeFailure('oracle.SetSecurityInfo',code)

    def write(self,path,data,information=4,inheritance='Preserve',follow=True):
        bits=information | {'Preserve':0,'Protect':0x80000000,'Unprotect':0x20000000}[inheritance]
        access=U32(self.set_access_mask(bits))
        # This is the independent fixture writer, not a minimum-rights assertion.
        access.value|=0x00020000
        with self.handle(path,access.value,follow) as h: self.write_handle(h,data,information,inheritance)

    def native_entries(self,data,sacl=False):
        """Cross-check the Python binary walk against OS GetAce enumeration."""
        wire.parse_descriptor(data)
        buf=C.create_string_buffer(data);present=I32();defaulted=I32();acl=P()
        getter=self.a.GetSecurityDescriptorSacl if sacl else self.a.GetSecurityDescriptorDacl
        self.check(getter(buf,C.byref(present),C.byref(acl),C.byref(defaulted)),'GetSecurityDescriptorAcl')
        if not present.value: return dict(presence='Absent')
        if not acl.value: return dict(presence='Null')
        header=C.string_at(acl,8)
        _,_,size,count,_=struct.unpack('<BBHHH',header)
        entries=[]
        for n in range(count):
            p=P();self.check(self.a.GetAce(acl,n,C.byref(p)),'GetAce')
            length=struct.unpack_from('<H',C.string_at(p,4),2)[0]
            if length<4 or length>size: raise ValueError('GetAce returned invalid extent')
            entries.append(C.string_at(p,length).hex())
        return dict(presence='Present',entries=entries)

    def validate_acl(self,data):
        wire.parse_acl(data) # do not send truncated/hostile inputs to unbounded APIs
        buf=C.create_string_buffer(data)
        return bool(self.a.IsValidAcl(buf))

    def access_check_token(self,data,desired,token):
        wire.parse_descriptor(data)
        buf=C.create_string_buffer(data)
        mapping=Mapping(0x120089,0x120116,0x1200a0,0x1f01ff)
        mask=U32(desired);self.a.MapGenericMask(C.byref(mask),C.byref(mapping))
        size=U32(4096);privs=C.create_string_buffer(size.value);granted=U32();status=I32()
        self.check(self.a.AccessCheck(buf,token,mask,C.byref(mapping),privs,C.byref(size),
                                     C.byref(granted),C.byref(status)),'AccessCheck')
        return dict(allowed=bool(status.value),granted=granted.value,mapped=mask.value,
                    privileges=privs.raw[:size.value].hex())

    def access_check(self,data,desired):
        with self.token(0x0a) as token:
            duplicate=P();self.check(self.a.DuplicateToken(token,2,C.byref(duplicate)),'DuplicateToken')
            try:return self.access_check_token(data,desired,duplicate)
            finally:self.k.CloseHandle(duplicate)


    def try_open_detailed(self,path,desired,share=7,creation=3,flags=0x02000000):
        desired=int(desired)&0xffffffff;share=int(share)&0xffffffff
        creation=int(creation)&0xffffffff;flags=int(flags)&0xffffffff
        handle=self.k.CreateFileW(str(path),desired,share,None,creation,flags,None)
        result=dict(desired=desired,share=share,creation=creation,flags=flags)
        if handle==P(-1).value:
            result['open']=dict(ok=False,code=C.get_last_error())
            return result
        try:
            result['open']=dict(ok=True,handle=int(handle))
            return result
        finally:
            self.k.CloseHandle(handle)

    def file_identity_handle(self,handle):
        info=ByHandleFileInformation()
        self.check(self.k.GetFileInformationByHandle(handle,C.byref(info)),
                   'GetFileInformationByHandle')
        file_id=(int(info.file_index_high)<<32)|int(info.file_index_low)
        size=(int(info.file_size_high)<<32)|int(info.file_size_low)
        return dict(volume_serial=int(info.volume_serial),file_id=f'{file_id:016x}',
                    link_count=int(info.link_count),size=size,attributes=int(info.attributes))

    def file_identity(self,path,follow=True):
        with self.handle(path,0x80,follow) as handle:
            result=self.file_identity_handle(handle)
            extended=FileIdInfo()
            if self.k.GetFileInformationByHandleEx(handle,18,C.byref(extended),C.sizeof(extended)):
                result['volume_serial_64']=int(extended.volume_serial)
                result['file_id_128']=bytes(extended.file_id.identifier).hex()
            else:
                result['file_id_128_error']=C.get_last_error()
            buffer=C.create_unicode_buffer(32768)
            length=self.k.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
            if 0<length<len(buffer):result['final_path']=buffer.value
            else:result['final_path_error']=C.get_last_error() if length==0 else 122
            return result

    def set_delete_pending(self,path):
        with self.handle(path,0x00010000,True) as handle:
            value=FileDispositionInfo(1)
            self.check(self.k.SetFileInformationByHandle(handle,4,C.byref(value),C.sizeof(value)),
                       'SetFileInformationByHandle(FileDispositionInfo)')
            return self.file_identity_handle(handle)

    def short_path(self,path):
        size=self.k.GetShortPathNameW(str(path),None,0)
        if not size:raise NativeFailure('GetShortPathNameW(size)',C.get_last_error())
        buffer=C.create_unicode_buffer(size+1)
        written=self.k.GetShortPathNameW(str(path),buffer,len(buffer))
        if not written:raise NativeFailure('GetShortPathNameW',C.get_last_error())
        return buffer.value

    def volume_guid_path(self,path):
        root=C.create_unicode_buffer(32768)
        self.check(self.k.GetVolumePathNameW(str(path),root,len(root)),'GetVolumePathNameW')
        output=C.create_unicode_buffer(32768)
        self.check(self.k.GetVolumeNameForVolumeMountPointW(root,output,len(output)),
                   'GetVolumeNameForVolumeMountPointW')
        return dict(root=root.value,guid=output.value)

    def attributes(self,path):
        value=self.k.GetFileAttributesW(str(path))
        if value==0xffffffff:raise NativeFailure('GetFileAttributesW',C.get_last_error())
        return int(value)

    def set_attributes(self,path,value):
        self.check(self.k.SetFileAttributesW(str(path),int(value)&0xffffffff),
                   'SetFileAttributesW')
        return self.attributes(path)

    def device_control(self,path,code,input_bytes=b'',desired=0x40000000):
        with self.handle(path,desired,True) as handle:
            input_buffer=C.create_string_buffer(input_bytes) if input_bytes else None
            returned=U32()
            self.check(self.k.DeviceIoControl(handle,int(code)&0xffffffff,
                       input_buffer,C.sizeof(input_buffer) if input_buffer else 0,
                       None,0,C.byref(returned),None),'DeviceIoControl')
            return dict(bytes_returned=int(returned.value),attributes=self.attributes(path))


    def set_case_sensitive(self,path,enabled):
        with self.handle(path,0x00000100,True) as handle:
            value=FileCaseSensitiveInfo(1 if enabled else 0)
            self.check(self.k.SetFileInformationByHandle(handle,23,C.byref(value),C.sizeof(value)),
                       'SetFileInformationByHandle(FileCaseSensitiveInfo)')
            output=FileCaseSensitiveInfo()
            self.check(self.k.GetFileInformationByHandleEx(handle,23,C.byref(output),C.sizeof(output)),
                       'GetFileInformationByHandleEx(FileCaseSensitiveInfo)')
            return int(output.flags)

    def open_by_id(self,path,desired=0x80):
        with self.handle(path,0x80,True) as hint:
            info=ByHandleFileInformation()
            self.check(self.k.GetFileInformationByHandle(hint,C.byref(info)),
                       'GetFileInformationByHandle(OpenFileById)')
            descriptor=FileIdDescriptor()
            descriptor.size=C.sizeof(FileIdDescriptor)
            descriptor.kind=0
            descriptor.file_id=(int(info.file_index_high)<<32)|int(info.file_index_low)
            opened=self.k.OpenFileById(hint,C.byref(descriptor),int(desired)&0xffffffff,7,None,0)
            if opened==P(-1).value:
                raise NativeFailure('OpenFileById',C.get_last_error())
            try:
                return self.file_identity_handle(opened)
            finally:
                self.k.CloseHandle(opened)

    def create_junction(self,link,target):
        link=os.fspath(link);target=os.path.abspath(os.fspath(target))
        os.mkdir(link)
        substitute='\\??\\'+target
        print_name=target
        substitute_raw=substitute.encode('utf-16-le')
        print_raw=print_name.encode('utf-16-le')
        path_buffer=substitute_raw+b'\x00\x00'+print_raw+b'\x00\x00'
        payload=struct.pack('<HHHH',0,len(substitute_raw),len(substitute_raw)+2,len(print_raw))+path_buffer
        raw=struct.pack('<IHH',0xA0000003,len(payload),0)+payload
        flags=0x02000000|0x00200000
        handle=self.k.CreateFileW(link,0x40000000,0,None,3,flags,None)
        if handle==P(-1).value:
            raise NativeFailure('CreateFileW(junction)',C.get_last_error())
        try:
            buffer=C.create_string_buffer(raw)
            returned=U32()
            self.check(self.k.DeviceIoControl(handle,0x000900A4,buffer,len(raw),None,0,
                                              C.byref(returned),None),
                       'DeviceIoControl(FSCTL_SET_REPARSE_POINT)')
        finally:
            self.k.CloseHandle(handle)
        return dict(link=link,target=target,attributes=self.attributes(link))

    def handle_count(self):
        value=U32()
        self.check(self.k.GetProcessHandleCount(self.k.GetCurrentProcess(),C.byref(value)),
                   'GetProcessHandleCount')
        return int(value.value)

    def attribute_probe(self,path):
        with self.handle(path,0x80) as h:
            buf=C.create_string_buffer(40)  # FILE_BASIC_INFO: 4 LARGE_INTEGERs + DWORD + padding
            ok=self.k.GetFileInformationByHandleEx(h,0,buf,len(buf))
            return dict(ok=bool(ok),error=0 if ok else C.get_last_error(),attributes=struct.unpack_from('<I',buf.raw,32)[0] if ok else None)

    def try_open(self,path,desired):
        try:
            with self.handle(path,desired): return dict(allowed=True,error=0)
        except NativeFailure as exc: return dict(allowed=False,error=exc.code)

    def enable_privilege(self,name):
        """Called only in the per-case child after explicit --privileged consent."""
        with self.token(0x28) as token:
            luid=LUID()
            self.check(self.a.LookupPrivilegeValueW(None,name,C.byref(luid)),'LookupPrivilegeValueW')
            state=Privileges(1,luid,2)
            C.set_last_error(0)
            self.check(self.a.AdjustTokenPrivileges(token,False,C.byref(state),0,None,None),'AdjustTokenPrivileges')
            code=C.get_last_error()
            if code==1300: raise SkipCase(name+' is not assigned to this token (ERROR_NOT_ALL_ASSIGNED)')
            if code: raise NativeFailure('AdjustTokenPrivileges',code)

    def secure_directory(self,path):
        sid=self.current_sid()
        data=self.sddl('D:P(A;OICI;FA;;;'+sid+')(A;OICI;FA;;;SY)')
        self.write(path,data,4,'Protect')

    def reset_for_cleanup(self,path):
        sid=self.current_sid()
        self.write(path,self.sddl('D:P(A;OICI;FA;;;'+sid+')(A;OICI;FA;;;SY)'),4,'Protect',follow=False)

    def privilege_snapshot(self):
        raw=self.token_data(3).raw
        count=struct.unpack_from('<I',raw)[0]
        if count>4096 or len(raw)<4+count*12:raise ValueError('invalid TOKEN_PRIVILEGES length')
        result=[]
        for index in range(count):
            low,high,attributes=struct.unpack_from('<IiI',raw,4+index*12)
            luid=LUID(low,high);name=C.create_unicode_buffer(256);size=U32(len(name))
            ok=self.a.LookupPrivilegeNameW(None,C.byref(luid),name,C.byref(size))
            result.append(dict(name=name.value if ok else None,luid_low=low,luid_high=high,
                               attributes=attributes,enabled=bool(attributes&2)))
        return result

    def environment(self,root):
        volume=C.create_unicode_buffer(32768)
        self.check(self.k.GetVolumePathNameW(str(root),volume,len(volume)),'GetVolumePathNameW')
        serial=U32();maxname=U32();flags=U32();filesystem=C.create_unicode_buffer(128)
        self.check(self.k.GetVolumeInformationW(volume,None,0,C.byref(serial),C.byref(maxname),C.byref(flags),filesystem,len(filesystem)),'GetVolumeInformationW')
        elevation=self.token_data(20)
        integrity=self.token_data(25)
        integrity_sid=self.sid_string(P.from_buffer(integrity).value)
        return dict(user_sid=self.current_sid(),integrity_sid=integrity_sid,privileges=self.privilege_snapshot(),elevated=bool(struct.unpack_from('<I',elevation.raw)[0]),
                    filesystem=filesystem.value,filesystem_flags=flags.value,persistent_acls=bool(flags.value&8),
                    maximum_component=maxname.value,volume_root=volume.value,
                    ctypes_sizes=dict(pointer=C.sizeof(P),DWORD=C.sizeof(U32),LUID=C.sizeof(LUID),TOKEN_PRIVILEGES_ONE=C.sizeof(Privileges)))
