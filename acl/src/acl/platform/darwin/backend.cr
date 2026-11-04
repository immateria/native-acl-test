require "./path_policy"

module ACL::Platform::Darwin
  extend self
  private alias List = ACL::Darwin::List
  private ACL_TYPE_EXTENDED = 0x100_u32
  private alias Snapshot = ACL::Darwin::Snapshot
  private REPORT_FULL_SIZE = 4_u64
  private NO_FOLLOW = 1_u64

  # Read ACL evidence directly. The uploaded libc statx wrapper discards a
  # 44-byte empty ACL because it compares against sizeof(kauth_filesec)=68.
  # RETURNED_ATTRS also keeps an omitted attribute distinct from confirmed
  # absence. The read has no secondary File.exists? or volume-capability probe.
  def read(path : Path | String, follow_symlinks : Bool = true) : Snapshot
    name = checked_path(path)
    attributes = requested_attributes
    bytes = Bytes.new(Snapshot::MAX_ATTRIBUTE_BYTES, 0_u8)
    options = REPORT_FULL_SIZE | (follow_symlinks ? 0_u64 : NO_FOLLOW)
    if LibACL.getattrlist(name, pointerof(attributes), bytes.to_unsafe, bytes.size, options) != 0
      raise SystemError.new("getattrlist(EXTENDED_SECURITY)", name)
    end
    Snapshot.from_attribute_bytes(bytes)
  end

  # Borrowed descriptor: never closed by this method.
  def read(fd : Int32) : Snapshot
    attributes = requested_attributes
    bytes = Bytes.new(Snapshot::MAX_ATTRIBUTE_BYTES, 0_u8)
    if LibACL.fgetattrlist(fd, pointerof(attributes), bytes.to_unsafe, bytes.size, REPORT_FULL_SIZE) != 0
      raise SystemError.new("fgetattrlist(EXTENDED_SECURITY)", "fd:#{fd}")
    end
    Snapshot.from_attribute_bytes(bytes)
  end

  private def requested_attributes : LibACL::Attributes
    LibACL::Attributes.new(bitmapcount: 5_u16, reserved: 0_u16,
      commonattr: Snapshot::RETURNED_ATTRIBUTES | Snapshot::EXTENDED_SECURITY,
      volattr: 0_u32, dirattr: 0_u32, fileattr: 0_u32, forkattr: 0_u32)
  end

  # Replaces only the ACL; nil explicitly removes it. Ownership and mode are
  # not passed to chmodx_np. A no-follow write opens the final component itself
  # with O_SYMLINK, avoiding libc acl_set_link_np's lstat/set race and ENOTSUP.
  # O_RDONLY is implicit: this path can require read access in addition to ACL
  # modification rights. Use an existing descriptor to avoid that extra open.
  def write(path : Path | String, list : List?, follow_symlinks : Bool = true) : Nil
    name = checked_path(path)
    if follow_symlinks
      with_native(list, name) do |acl|
        raise SystemError.new("acl_set_file", name) if LibACL.acl_set_file(name, ACL_TYPE_EXTENDED, acl) != 0
      end
    else
      fd = LibC.open(name, PathPolicy.no_follow_open_flags)
      raise SystemError.new("open(O_SYMLINK)", name) if fd < 0
      begin
        write(fd, list)
      ensure
        LibC.close(fd)
      end
    end
  end

  def write(fd : Int32, list : List?) : Nil
    label = "fd:#{fd}"
    with_native(list, label) do |acl|
      raise SystemError.new("acl_set_fd_np", label) if LibACL.acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) != 0
    end
  end

  private def checked_path(path : Path | String) : String
    name = path.to_s
    raise ArgumentError.new("path contains NUL") if name.includes?('\0')
    name
  end

  private def with_native(list : List?, label : String, &) : Nil
    # _FILESEC_REMOVE_ACL is explicitly handled by acl_size/acl_copy_ext_native.
    unless list
      yield Pointer(Void).new(1_u64)
      return
    end
    list.validate_for_write!
    bytes = list.to_bytes
    acl = LibACL.acl_copy_int(bytes.to_unsafe)
    raise SystemError.new("acl_copy_int", label) if acl.null?
    begin
      yield acl
    ensure
      LibACL.acl_free(acl)
    end
  end
end

module ACL::Darwin
  def self.read(path : Path | String, follow_symlinks : Bool = true) : Snapshot
    Platform::Darwin.read(path, follow_symlinks)
  end

  def self.read(fd : Int32) : Snapshot
    Platform::Darwin.read(fd)
  end

  def self.write(path : Path | String, list : List?, follow_symlinks : Bool = true) : Nil
    Platform::Darwin.write(path, list, follow_symlinks)
  end

  def self.write(fd : Int32, list : List?) : Nil
    Platform::Darwin.write(fd, list)
  end
end
