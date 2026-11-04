require "string/utf16"
require "./open_access"
require "./path_policy"

module ACL::Platform::Windows
  extend self
  private alias Descriptor = ACL::Windows::Descriptor
  private alias Snapshot = ACL::Windows::Snapshot
  private alias Update = ACL::Windows::Update
  private alias Information = ACL::Windows::Information
  private alias NativeError = ACL::Windows::NativeError

  private FILE_OBJECT          =          1_u32
  private BACKUP_SEMANTICS     = 0x02000000_u32
  private OPEN_REPARSE_POINT   = 0x00200000_u32
  private MAX_DESCRIPTOR_BYTES = 1024_u32 * 1024
  private INSUFFICIENT_BUFFER  = 122_u32

  # Path APIs open once, then query by handle. Share read/write/delete, support
  # directories, and target the final reparse point itself when no-follow is
  # requested. Intermediate path components are not constrained by this option.
  def read(path : Path | String, information : Information = Information::Basic,
           follow_symlinks : Bool = true) : Snapshot
    Snapshot.validate_information!(information)
    desired = 0_u32
    C.QuerySecurityAccessMask(information.value, pointerof(desired))
    with_file(path, OpenAccess.for_query(desired, information), follow_symlinks) do |handle, label|
      read_handle(handle, information, label)
    end
  end

  # Borrows a FILE_OBJECT handle; this API never closes the caller's handle.
  # Privileges are never enabled or changed implicitly.
  def read_handle(handle : Void*, information : Information = Information::Basic,
                  label : String = "borrowed file handle") : Snapshot
    Snapshot.validate_information!(information)
    descriptor = Pointer(Void).null
    begin
      code = C.GetSecurityInfo(handle, FILE_OBJECT, information.value, nil, nil, nil, nil, pointerof(descriptor))
      raise NativeError.new("GetSecurityInfo", label, code) unless code == 0
      raise InvalidACLError.new("GetSecurityInfo returned a null descriptor") if descriptor.null?
      Snapshot.new(copy_descriptor(descriptor, label), information)
    ensure
      LibC.LocalFree(descriptor) unless descriptor.null?
    end
  end

  # SetSecurityInfo may propagate inherited ACEs to existing descendants. No
  # optimistic locking, atomic read/modify/write, or exact-control-bit restore
  # is promised. Only Update's selected components are passed to the OS.
  def write(path : Path | String, update : Update, follow_symlinks : Bool = true) : Nil
    desired = 0_u32
    C.SetSecurityAccessMask(update.native_information, pointerof(desired))
    with_file(path, OpenAccess.for_update(desired, update.information), follow_symlinks) do |handle, label|
      write_handle(handle, update, label)
    end
  end

  def write_handle(handle : Void*, update : Update, label : String = "borrowed file handle") : Nil
    descriptor = update.descriptor
    owner = update.selected?(Information::Owner) ? descriptor.owner.try(&.to_bytes) : nil
    group = update.selected?(Information::Group) ? descriptor.group.try(&.to_bytes) : nil
    dacl = update.selected?(Information::DACL) ? descriptor.dacl.list.try(&.to_bytes) : nil
    sacl = update.sacl_selected? ? descriptor.sacl.list.try(&.to_bytes) : nil
    [owner, group].each do |sid|
      raise InvalidACLError.new("Windows rejected the SID structure") if sid && C.IsValidSid(sid.to_unsafe) == 0
    end
    [dacl, sacl].each do |acl|
      raise InvalidACLError.new("Windows rejected the ACL structure") if acl && C.IsValidAcl(acl.to_unsafe) == 0
    end
    # All byte buffers remain owned and live for this synchronous call. A nil
    # selected DACL can only reach here through Update's explicit consent gate.
    code = C.SetSecurityInfo(handle, FILE_OBJECT, update.native_information,
      pointer(owner), pointer(group), pointer(dacl), pointer(sacl))
    raise NativeError.new("SetSecurityInfo", label, code) unless code == 0
  end

  def from_sddl(text : String) : Descriptor
    wide = wide_string(text, "SDDL")
    descriptor = Pointer(Void).null
    length = 0_u32
    begin
      if C.ConvertStringSecurityDescriptorToSecurityDescriptorW(wide, 1_u32, pointerof(descriptor), pointerof(length)) == 0
        raise last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW", "SDDL")
      end
      raise InvalidACLError.new("SDDL conversion returned a null descriptor") if descriptor.null?
      copy_descriptor(descriptor, "SDDL")
    ensure
      LibC.LocalFree(descriptor) unless descriptor.null?
    end
  end

  # SDDL is an OS textual view, not a lossless archive format. Binary
  # serialization is required for opaque ACE bodies and all control state.
  def to_sddl(descriptor : Descriptor, information : Information = Information::Basic) : String
    Snapshot.validate_information!(information, allow_backup: false)
    if information.value & ~0x0f_u32 != 0
      raise UnsupportedACLError.new("SDDL output selects owner/group/DACL/SACL, not filtered query flags")
    end
    bytes = descriptor.to_bytes
    raise InvalidACLError.new("Windows rejected the security descriptor") if C.IsValidSecurityDescriptor(bytes.to_unsafe) == 0
    text = Pointer(UInt16).null
    length = 0_u32
    begin
      if C.ConvertSecurityDescriptorToStringSecurityDescriptorW(bytes.to_unsafe, 1_u32, information.value, pointerof(text), pointerof(length)) == 0
        raise last_error("ConvertSecurityDescriptorToStringSecurityDescriptorW", "descriptor")
      end
      unless !text.null? && length > 0 && length <= MAX_DESCRIPTOR_BYTES
        raise InvalidACLError.new("unexpected SDDL output length")
      end
      String.from_utf16(Slice.new(text, length.to_i), truncate_at_null: true)
    ensure
      LibC.LocalFree(text.as(Void*)) unless text.null?
    end
  end

  private def copy_descriptor(native : Void*, label : String) : Descriptor
    raise InvalidACLError.new("Windows returned an invalid security descriptor") if C.IsValidSecurityDescriptor(native) == 0
    control = 0_u16
    revision = 0_u32
    if C.GetSecurityDescriptorControl(native, pointerof(control), pointerof(revision)) == 0
      raise last_error("GetSecurityDescriptorControl", label)
    end
    if control & Descriptor::SELF_RELATIVE != 0
      length = C.GetSecurityDescriptorLength(native)
      check_length!(length)
      Descriptor.from_bytes(Slice.new(native.as(UInt8*), length.to_i))
    else
      # Do not assume GetSecurityInfo's buffer is self-relative. A pointer-rich
      # absolute descriptor must be converted before its allocation is freed.
      length = 0_u32
      result = C.MakeSelfRelativeSD(native, nil, pointerof(length))
      code = result == 0 ? LibC.GetLastError : 0_u32
      raise NativeError.new("MakeSelfRelativeSD(size)", label, code) unless result == 0 && code == INSUFFICIENT_BUFFER
      check_length!(length)
      bytes = Bytes.new(length.to_i)
      if C.MakeSelfRelativeSD(native, bytes.to_unsafe, pointerof(length)) == 0
        raise last_error("MakeSelfRelativeSD", label)
      end
      raise InvalidACLError.new("security descriptor length changed") if length > bytes.size
      Descriptor.from_bytes(bytes[0, length.to_i])
    end
  end

  private def check_length!(length : UInt32) : Nil
    unless Descriptor::HEADER_SIZE <= length <= MAX_DESCRIPTOR_BYTES
      raise InvalidACLError.new("unexpected security descriptor length #{length}")
    end
  end

  private def pointer(bytes : Bytes?) : Void*
    bytes ? bytes.to_unsafe.as(Void*) : Pointer(Void).null
  end

  private def wide_string(text : String, label : String) : Slice(UInt16)
    raise ArgumentError.new("#{label} contains NUL") if text.includes?('\0')
    raise ArgumentError.new("#{label} is not valid UTF-8") unless text.valid_encoding?
    # Crystal guarantees a trailing UTF-16 NUL outside the returned slice.
    text.to_utf16
  end

  private def with_file(path : Path | String, access : OpenAccess, follow_symlinks : Bool, &)
    label = path.to_s
    native_path = PathPolicy.native(label)
    wide = wide_string(native_path, "path")
    flags = BACKUP_SEMANTICS
    flags |= OPEN_REPARSE_POINT unless follow_symlinks
    handle = access.open(label) do |desired|
      opened = LibC.CreateFileW(wide, desired, 7_u32, nil, 3_u32, flags, nil)
      raise last_error("CreateFileW", label) if opened.address == UInt64::MAX
      opened
    end
    begin
      yield handle, label
    ensure
      LibC.CloseHandle(handle)
    end
  end

  private def last_error(operation : String, label : String) : NativeError
    code = LibC.GetLastError
    NativeError.new(operation, label, code)
  end
end

module ACL::Windows
  def self.read(path : Path | String, information : Information = Information::Basic,
                follow_symlinks : Bool = true) : Snapshot
    Platform::Windows.read(path, information, follow_symlinks)
  end

  def self.read_handle(handle : Void*, information : Information = Information::Basic) : Snapshot
    Platform::Windows.read_handle(handle, information)
  end

  def self.write(path : Path | String, update : Update, follow_symlinks : Bool = true) : Nil
    Platform::Windows.write(path, update, follow_symlinks)
  end

  def self.write_handle(handle : Void*, update : Update) : Nil
    Platform::Windows.write_handle(handle, update)
  end

  def self.set_dacl(path : Path | String, list : List, inheritance : Inheritance = Inheritance::Preserve,
                    follow_symlinks : Bool = true) : Nil
    descriptor = Descriptor.new(dacl: ACLState.present(list))
    write(path, Update.new(descriptor, Information::DACL, dacl_inheritance: inheritance), follow_symlinks)
  end

  class Descriptor
    def self.from_sddl(text : String) : self
      Platform::Windows.from_sddl(text)
    end

    def to_sddl(information : Information = Information::Basic) : String
      Platform::Windows.to_sddl(self, information)
    end
  end
end
