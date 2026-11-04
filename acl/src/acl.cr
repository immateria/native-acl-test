require "./acl/version"
require "./acl/errors"
require "./acl/darwin"
require "./acl/windows"
require "./acl/posix/permission"
require "./acl/posix/entry"
require "./acl/posix/list"

{% if flag?(:linux) %}
  require "./acl/platform/linux/lib_acl"
  require "./acl/platform/linux/backend"

  module ACL
    # Reads the POSIX access ACL associated with *path*.
    def self.access(path : Path | String) : POSIX::List
      Platform::Linux.access(path)
    end

    # Reads a directory default ACL, or returns `nil` when none is associated.
    def self.default(path : Path | String) : POSIX::List?
      Platform::Linux.default(path)
    end

    # Replaces the access or default ACL selected by `acl.scope`.
    def self.set(path : Path | String, acl : POSIX::List) : Nil
      Platform::Linux.set(path, acl)
    end

    # Removes the directory default ACL associated with *path*.
    def self.delete_default(path : Path | String) : Nil
      Platform::Linux.delete_default(path)
    end
  end
{% else %}
  module ACL
    # Reads the POSIX access ACL associated with *path*.
    def self.access(path : Path | String) : POSIX::List
      raise UnsupportedACLError.new("POSIX ACL operations are unavailable on this target; use its platform-specific API")
    end

    def self.default(path : Path | String) : POSIX::List?
      raise UnsupportedACLError.new("POSIX ACL operations are unavailable on this target; use its platform-specific API")
    end

    def self.set(path : Path | String, acl : POSIX::List) : Nil
      raise UnsupportedACLError.new("POSIX ACL operations are unavailable on this target; use its platform-specific API")
    end

    def self.delete_default(path : Path | String) : Nil
      raise UnsupportedACLError.new("POSIX ACL operations are unavailable on this target; use its platform-specific API")
    end
  end
{% end %}
