# These values are pinned to the uploaded XNU bsd/sys/fcntl.h; portable so the
# syscall policy can be regression-tested on hosts without Darwin.
module ACL::Platform::Darwin::PathPolicy
  extend self

  def no_follow_open_flags : Int32
    0x00200000 | 0x01000000 | 0x00000004
  end
end
