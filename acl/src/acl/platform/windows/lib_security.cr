require "c/fileapi"
require "c/handleapi"
require "c/errhandlingapi"
require "c/winbase"

# Narrow bindings cross-checked against the uploaded win32cr security and
# authorization files. BOOL is signed 32-bit even on Windows x64/ARM64.
module ACL::Platform::Windows
  @[Link("advapi32")]
  @[Link("kernel32")]
  lib C
    fun QuerySecurityAccessMask(information : UInt32, access : UInt32*) : Void
    fun SetSecurityAccessMask(information : UInt32, access : UInt32*) : Void
    fun GetSecurityInfo(handle : Void*, type : UInt32, information : UInt32, owner : Void**, group : Void**, dacl : Void**, sacl : Void**, descriptor : Void**) : UInt32
    fun SetSecurityInfo(handle : Void*, type : UInt32, information : UInt32, owner : Void*, group : Void*, dacl : Void*, sacl : Void*) : UInt32
    fun IsValidSecurityDescriptor(descriptor : Void*) : Int32
    fun GetSecurityDescriptorControl(descriptor : Void*, control : UInt16*, revision : UInt32*) : Int32
    fun GetSecurityDescriptorLength(descriptor : Void*) : UInt32
    fun MakeSelfRelativeSD(absolute : Void*, relative : Void*, length : UInt32*) : Int32
    fun IsValidAcl(acl : Void*) : Int32
    fun IsValidSid(sid : Void*) : Int32
    fun GetLengthSid(sid : Void*) : UInt32
    fun ConvertStringSecurityDescriptorToSecurityDescriptorW(text : UInt16*, revision : UInt32, descriptor : Void**, size : UInt32*) : Int32
    fun ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor : Void*, revision : UInt32, information : UInt32, text : UInt16**, length : UInt32*) : Int32
  end
end
