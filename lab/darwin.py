"""Independent macOS oracle: libSystem ACL API and raw getattrlist evidence."""
import ctypes as C
import errno
import os
import struct
import uuid
from . import wire
from .native import NativeFailure

class Attributes(C.Structure):
    _fields_ = [('bitmapcount',C.c_uint16),('reserved',C.c_uint16),('common',C.c_uint32),
                ('volume',C.c_uint32),('directory',C.c_uint32),('file',C.c_uint32),('fork',C.c_uint32)]

class Darwin:
    def __init__(self):
        self.lib = C.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        v,p,i,u,z = C.c_void_p,C.c_void_p,C.c_int,C.c_uint32,C.c_ssize_t
        signatures = {
            'getattrlist':(i,[C.c_char_p,C.POINTER(Attributes),p,C.c_size_t,C.c_ulong]),
            'fgetattrlist':(i,[i,C.POINTER(Attributes),p,C.c_size_t,C.c_ulong]),
            'acl_init':(p,[i]),'acl_free':(i,[p]),'acl_size':(z,[p]),'acl_valid':(i,[p]),'acl_dup':(p,[p]),
            'acl_copy_int':(p,[p]),'acl_copy_ext':(z,[p,p,z]),
            'acl_set_file':(i,[C.c_char_p,u,p]),'acl_set_fd_np':(i,[i,p,u]),
            'acl_get_file':(p,[C.c_char_p,u]),'acl_get_link_np':(p,[C.c_char_p,u]),
            'acl_get_fd_np':(p,[i,u]),'acl_create_entry':(i,[C.POINTER(p),C.POINTER(p)]),
            'acl_set_tag_type':(i,[p,u]),'acl_set_qualifier':(i,[p,p]),
            'acl_get_permset':(i,[p,C.POINTER(p)]),'acl_add_perm':(i,[p,u]),
            'acl_get_flagset_np':(i,[p,C.POINTER(p)]),'acl_add_flag_np':(i,[p,u]),
            'mbr_uid_to_uuid':(i,[u,p]),'mbr_gid_to_uuid':(i,[u,p]),
            'clonefile':(i,[C.c_char_p,C.c_char_p,u]),
        }
        for name,(restype,args) in signatures.items():
            f=getattr(self.lib,name);f.restype=restype;f.argtypes=args

    def check(self, result, operation, pointer=False):
        if (not result) if pointer else result != 0:
            raise NativeFailure(operation,C.get_errno())
        return result

    def principal(self, group=False):
        b=C.create_string_buffer(16)
        name='mbr_gid_to_uuid' if group else 'mbr_uid_to_uuid'
        code=getattr(self.lib,name)(os.getegid() if group else os.geteuid(),b)
        if code: raise NativeFailure(name,code)
        return str(uuid.UUID(bytes=b.raw))

    def raw_attribute(self,path,follow=True,fd=None,size=4096,options=None):
        attributes=Attributes(5,0,0x80400000,0,0,0,0)
        buf=C.create_string_buffer(size)
        flags=(4 if options is None else int(options)) | (0 if follow else 1)
        if fd is None:
            ret=self.lib.getattrlist(os.fsencode(path),C.byref(attributes),buf,size,flags)
        else:
            ret=self.lib.fgetattrlist(fd,C.byref(attributes),buf,size,flags & ~1)
        code=C.get_errno() if ret else 0
        return dict(returncode=ret,errno=code,buffer_size=size,raw=buf.raw.hex())

    def read(self,path,follow=True,fd=None):
        raw=self.raw_attribute(path,follow,fd)
        if raw['returncode']: raise NativeFailure('oracle.getattrlist',raw['errno'])
        b=bytes.fromhex(raw['raw'])
        total=struct.unpack_from('<I',b)[0]
        if not 24<=total<=len(b): raise ValueError('oracle attribute response truncated')
        common=struct.unpack_from('<I',b,4)[0]
        result=dict(raw=b[:total].hex(),returned=common)
        if not common & 0x400000:
            return dict(result,presence='NotReturned',flags=None,entries=None,hex=None)
        relative,length=struct.unpack('<iI',wire.take(b,24,8))
        data=wire.take(b[:total],24+relative,length)
        magic,=struct.unpack('<I',wire.take(data,0,4))
        count,flags=struct.unpack('<II',wire.take(data,36,8))
        if magic!=0x012cc16d: raise ValueError('unexpected native filesec magic')
        result['filesec_identity_bytes']=data[4:36].hex()
        if count==0xffffffff:
            return dict(result,presence='Absent',flags=None,entries=None,hex=None)
        if count>128 or len(data)!=44+24*count: raise ValueError('invalid native count/length')
        entries=[]
        for n in range(count):
            at=44+n*24
            flags_ace,rights=struct.unpack_from('<II',data,at+16)
            entries.append(dict(principal=str(uuid.UUID(bytes=data[at:at+16])),raw_flags=flags_ace,raw_rights=rights))
        return dict(result,presence='Present',flags=flags,entries=entries,hex=wire.darwin_export(entries,flags).hex())

    def write(self,path,data,follow=True,fd=None):
        native=None
        try:
            if data is None:
                native=1
            else:
                wire.parse_darwin_export(data) # validates exact extent before lengthless native importer
                buf=C.create_string_buffer(data)
                native=self.check(self.lib.acl_copy_int(buf),'acl_copy_int',True)
            if fd is not None:
                self.check(self.lib.acl_set_fd_np(fd,native,0x100),'acl_set_fd_np')
            elif follow:
                self.check(self.lib.acl_set_file(os.fsencode(path),0x100,native),'acl_set_file')
            else:
                flags=0x00200000 | os.O_CLOEXEC | os.O_NONBLOCK
                handle=os.open(path,flags)
                try: self.check(self.lib.acl_set_fd_np(handle,native,0x100),'acl_set_fd_np(nofollow)')
                finally: os.close(handle)
        finally:
            if native and native!=1: self.lib.acl_free(native)

    def libc_read(self,path,follow=True):
        getter=self.lib.acl_get_file if follow else self.lib.acl_get_link_np
        native=getter(os.fsencode(path),0x100)
        if not native: return dict(ok=False,errno=C.get_errno())
        try:
            size=self.lib.acl_size(native)
            if not 44<=size<=44+128*24: raise ValueError('unexpected acl_size')
            buf=C.create_string_buffer(size)
            actual=self.lib.acl_copy_ext(buf,native,size)
            if actual<0: raise NativeFailure('acl_copy_ext',C.get_errno())
            return dict(ok=True,hex=buf.raw[:actual].hex())
        finally: self.lib.acl_free(native)

    def libc_read_fd(self,fd):
        """Read an extended ACL through the descriptor API with bounded export."""
        C.set_errno(0)
        native=self.lib.acl_get_fd_np(int(fd),0x100)
        if not native: return dict(ok=False,errno=C.get_errno())
        try:
            size=self.lib.acl_size(native)
            if not 44<=size<=44+128*24: raise ValueError('unexpected acl_size')
            buf=C.create_string_buffer(size)
            actual=self.lib.acl_copy_ext(buf,native,size)
            if actual<0: raise NativeFailure('acl_copy_ext',C.get_errno())
            if actual>size: raise ValueError('acl_copy_ext exceeded bounded buffer')
            return dict(ok=True,hex=buf.raw[:actual].hex())
        finally: self.lib.acl_free(native)

    def build_using_entry_api(self,principal,mask=2):
        """Construct via acl_create_entry rather than the shard's import format."""
        native=C.c_void_p(self.check(self.lib.acl_init(1),'acl_init',True))
        try:
            entry=C.c_void_p();perms=C.c_void_p()
            self.check(self.lib.acl_create_entry(C.byref(native),C.byref(entry)),'acl_create_entry')
            self.check(self.lib.acl_set_tag_type(entry,1),'acl_set_tag_type')
            ident=C.create_string_buffer(uuid.UUID(principal).bytes)
            self.check(self.lib.acl_set_qualifier(entry,ident),'acl_set_qualifier')
            self.check(self.lib.acl_get_permset(entry,C.byref(perms)),'acl_get_permset')
            self.check(self.lib.acl_add_perm(perms,mask),'acl_add_perm')
            n=self.lib.acl_size(native);buf=C.create_string_buffer(n)
            actual=self.lib.acl_copy_ext(buf,native,n)
            if actual<0: raise NativeFailure('acl_copy_ext',C.get_errno())
            return buf.raw[:actual]
        finally: self.lib.acl_free(native)


    def init_count(self,count):
        """Observe acl_init/count/size/valid without importing an unbounded buffer."""
        C.set_errno(0)
        native=self.lib.acl_init(int(count))
        if not native:
            return dict(ok=False,errno=C.get_errno(),count=int(count))
        try:
            size=self.lib.acl_size(native)
            valid=self.lib.acl_valid(native)
            return dict(ok=True,count=int(count),size=int(size),valid=int(valid),errno=C.get_errno() if valid else 0)
        finally:
            self.lib.acl_free(native)

    def clonefile(self,source,destination,flags=0):
        C.set_errno(0)
        result=self.lib.clonefile(os.fsencode(source),os.fsencode(destination),int(flags))
        if result:
            raise NativeFailure('clonefile',C.get_errno())

    def environment(self,root):
        v=os.statvfs(root)
        return dict(uid=os.geteuid(),gid=os.getegid(),user_uuid=self.principal(),group_uuid=self.principal(True),
                    statvfs=dict(block_size=v.f_bsize,flags=v.f_flag,name_max=v.f_namemax),
                    ctypes_sizes=dict(attrlist=C.sizeof(Attributes),pointer=C.sizeof(C.c_void_p),long=C.sizeof(C.c_ulong)))
