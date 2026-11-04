module ACL::Platform::Linux
  extend self

  def access(path : Path | String) : POSIX::List
    read(path, POSIX::Scope::Access).not_nil!
  end

  def default(path : Path | String) : POSIX::List?
    read(path, POSIX::Scope::Default)
  end

  def set(path : Path | String, acl : POSIX::List) : Nil
    path = normalized_path(path)
    acl = acl.canonical
    native_acl = build_native(acl, path)

    begin
      if LibACL.acl_set_file(path.to_unsafe, native_type(acl.scope), native_acl) != 0
        raise SystemError.new("acl_set_file", path)
      end
    ensure
      LibACL.acl_free(native_acl) unless native_acl.null?
    end
  end

  def delete_default(path : Path | String) : Nil
    path = normalized_path(path)
    if LibACL.acl_delete_def_file(path.to_unsafe) != 0
      raise SystemError.new("acl_delete_def_file", path)
    end
  end

  private def read(path : Path | String, scope : POSIX::Scope) : POSIX::List?
    path = normalized_path(path)
    native_acl = LibACL.acl_get_file(path.to_unsafe, native_type(scope))
    raise SystemError.new("acl_get_file", path) if native_acl.null?

    begin
      entries = read_entries(native_acl, path)
      return nil if scope.default? && entries.empty?
      POSIX::List.new(scope, entries).canonical
    ensure
      LibACL.acl_free(native_acl)
    end
  end

  private def read_entries(native_acl : LibACL::ACLHandle, path : String) : Array(POSIX::Entry)
    entries = [] of POSIX::Entry
    native_entry = LibACL::EntryHandle.null
    selector = ACL_FIRST_ENTRY

    loop do
      result = LibACL.acl_get_entry(native_acl, selector, pointerof(native_entry))
      case result
      when 1
        entries << read_entry(native_entry, path)
        selector = ACL_NEXT_ENTRY
      when 0
        break
      else
        raise SystemError.new("acl_get_entry", path)
      end
    end

    entries
  end

  private def read_entry(native_entry : LibACL::EntryHandle, path : String) : POSIX::Entry
    native_tag = 0
    if LibACL.acl_get_tag_type(native_entry, pointerof(native_tag)) != 0
      raise SystemError.new("acl_get_tag_type", path)
    end

    permissions = read_permissions(native_entry, path)
    case native_tag
    when ACL_USER_OBJ
      POSIX::Entry.owner(permissions)
    when ACL_USER
      POSIX::Entry.user(read_qualifier(native_entry, path), permissions)
    when ACL_GROUP_OBJ
      POSIX::Entry.owning_group(permissions)
    when ACL_GROUP
      POSIX::Entry.group(read_qualifier(native_entry, path), permissions)
    when ACL_MASK
      POSIX::Entry.mask(permissions)
    when ACL_OTHER
      POSIX::Entry.other(permissions)
    else
      raise UnsupportedACLError.new("unsupported Linux POSIX ACL tag 0x#{native_tag.to_s(16)}")
    end
  end

  private def read_qualifier(native_entry : LibACL::EntryHandle, path : String) : UInt32
    qualifier = LibACL.acl_get_qualifier(native_entry)
    raise SystemError.new("acl_get_qualifier", path) if qualifier.null?

    begin
      qualifier.as(UInt32*).value
    ensure
      LibACL.acl_free(qualifier)
    end
  end

  private def read_permissions(native_entry : LibACL::EntryHandle, path : String) : POSIX::Permission
    permission_set = LibACL::PermissionSetHandle.null
    if LibACL.acl_get_permset(native_entry, pointerof(permission_set)) != 0
      raise SystemError.new("acl_get_permset", path)
    end

    permissions = POSIX::Permission::None
    permissions |= POSIX::Permission::Read if permission?(permission_set, ACL_READ, path)
    permissions |= POSIX::Permission::Write if permission?(permission_set, ACL_WRITE, path)
    permissions |= POSIX::Permission::Execute if permission?(permission_set, ACL_EXECUTE, path)
    permissions
  end

  private def permission?(permission_set : LibACL::PermissionSetHandle, permission : UInt32, path : String) : Bool
    case LibACL.acl_get_perm(permission_set, permission)
    when 1
      true
    when 0
      false
    else
      raise SystemError.new("acl_get_perm", path)
    end
  end

  private def build_native(acl : POSIX::List, path : String) : LibACL::ACLHandle
    native_acl = LibACL.acl_init(acl.size)
    raise SystemError.new("acl_init", path) if native_acl.null?

    begin
      acl.each do |entry|
        native_entry = LibACL::EntryHandle.null
        if LibACL.acl_create_entry(pointerof(native_acl), pointerof(native_entry)) != 0
          raise SystemError.new("acl_create_entry", path)
        end
        write_entry(native_entry, entry, path)
      end

      if LibACL.acl_valid(native_acl) != 0
        raise SystemError.new("acl_valid", path)
      end
      native_acl
    rescue exception
      LibACL.acl_free(native_acl) unless native_acl.null?
      raise exception
    end
  end

  private def write_entry(native_entry : LibACL::EntryHandle, entry : POSIX::Entry, path : String) : Nil
    if LibACL.acl_set_tag_type(native_entry, native_tag(entry.tag)) != 0
      raise SystemError.new("acl_set_tag_type", path)
    end

    if qualifier = entry.qualifier
      native_qualifier = qualifier
      if LibACL.acl_set_qualifier(native_entry, pointerof(native_qualifier).as(Void*)) != 0
        raise SystemError.new("acl_set_qualifier", path)
      end
    end

    permission_set = LibACL::PermissionSetHandle.null
    if LibACL.acl_get_permset(native_entry, pointerof(permission_set)) != 0
      raise SystemError.new("acl_get_permset", path)
    end
    if LibACL.acl_clear_perms(permission_set) != 0
      raise SystemError.new("acl_clear_perms", path)
    end

    add_permission(permission_set, ACL_READ, path) if entry.permissions.includes?(POSIX::Permission::Read)
    add_permission(permission_set, ACL_WRITE, path) if entry.permissions.includes?(POSIX::Permission::Write)
    add_permission(permission_set, ACL_EXECUTE, path) if entry.permissions.includes?(POSIX::Permission::Execute)

    if LibACL.acl_set_permset(native_entry, permission_set) != 0
      raise SystemError.new("acl_set_permset", path)
    end
  end

  private def add_permission(permission_set : LibACL::PermissionSetHandle, permission : UInt32, path : String) : Nil
    if LibACL.acl_add_perm(permission_set, permission) != 0
      raise SystemError.new("acl_add_perm", path)
    end
  end

  private def native_type(scope : POSIX::Scope) : UInt32
    scope.access? ? ACL_TYPE_ACCESS : ACL_TYPE_DEFAULT
  end

  private def native_tag(tag : POSIX::Tag) : Int32
    case tag
    when .owner?
      ACL_USER_OBJ
    when .user?
      ACL_USER
    when .owning_group?
      ACL_GROUP_OBJ
    when .group?
      ACL_GROUP
    when .mask?
      ACL_MASK
    when .other?
      ACL_OTHER
    else
      raise "unreachable POSIX tag"
    end
  end

  private def normalized_path(path : Path | String) : String
    value = path.to_s
    raise ArgumentError.new("path contains NUL byte") if value.includes?('\0')
    value
  end
end
