require "c/fcntl"
require "c/unistd"

# Uploaded XNU sys/attr.h fixes attrlist at 24 bytes and attrreference at 8;
# do not use the old man page's long/size_t spellings on a 64-bit target.
module ACL::Platform::Darwin
  lib LibACL
    alias Handle = Void*

    struct Attributes
      bitmapcount : UInt16
      reserved : UInt16
      commonattr : UInt32
      volattr : UInt32
      dirattr : UInt32
      fileattr : UInt32
      forkattr : UInt32
    end

    fun getattrlist(path : UInt8*, attributes : Attributes*, buffer : Void*, size : LibC::SizeT, options : LibC::ULong) : Int32
    fun fgetattrlist(fd : Int32, attributes : Attributes*, buffer : Void*, size : LibC::SizeT, options : LibC::ULong) : Int32
    fun acl_copy_int(buffer : Void*) : Handle
    fun acl_free(object : Void*) : Int32
    fun acl_set_file(path : UInt8*, type : UInt32, acl : Handle) : Int32
    # Darwin puts type AFTER acl, unlike several other platforms.
    fun acl_set_fd_np(fd : Int32, acl : Handle, type : UInt32) : Int32
  end
end
