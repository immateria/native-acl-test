module ACL
  # Base class for ACL-specific failures.
  class Error < Exception
  end

  # Raised when an in-memory ACL violates its native format's invariants.
  class InvalidACLError < Error
  end

  # Raised when the target platform or filesystem cannot perform an operation.
  class UnsupportedACLError < Error
  end

  # A failed native Unix ACL operation with stable operation/path metadata.
  class SystemError < Error
    # Native function or logical operation that failed.
    getter operation : String

    # Path supplied to the failed operation.
    getter path : String

    # Captured errno from the failing call.
    getter errno : Errno

    def initialize(@operation : String, @path : String, @errno : Errno = Errno.value)
      super("#{@operation} failed for #{@path.inspect}: #{@errno.message} (#{@errno.value})")
    end
  end
end
