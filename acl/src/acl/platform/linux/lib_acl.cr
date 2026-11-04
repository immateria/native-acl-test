module ACL::Platform::Linux
  @[Link("acl")]
  lib LibACL
    alias ACLHandle = Void*
    alias EntryHandle = Void*
    alias PermissionSetHandle = Void*

    fun acl_init(count : Int32) : ACLHandle
    fun acl_free(object : Void*) : Int32
    fun acl_valid(acl : ACLHandle) : Int32

    fun acl_create_entry(acl : ACLHandle*, entry : EntryHandle*) : Int32
    fun acl_get_entry(acl : ACLHandle, entry_id : Int32, entry : EntryHandle*) : Int32

    fun acl_add_perm(permission_set : PermissionSetHandle, permission : UInt32) : Int32
    fun acl_clear_perms(permission_set : PermissionSetHandle) : Int32
    fun acl_get_perm(permission_set : PermissionSetHandle, permission : UInt32) : Int32
    fun acl_get_permset(entry : EntryHandle, permission_set : PermissionSetHandle*) : Int32
    fun acl_set_permset(entry : EntryHandle, permission_set : PermissionSetHandle) : Int32

    fun acl_get_qualifier(entry : EntryHandle) : Void*
    fun acl_get_tag_type(entry : EntryHandle, tag : Int32*) : Int32
    fun acl_set_qualifier(entry : EntryHandle, qualifier : Void*) : Int32
    fun acl_set_tag_type(entry : EntryHandle, tag : Int32) : Int32

    fun acl_delete_def_file(path : UInt8*) : Int32
    fun acl_get_file(path : UInt8*, type : UInt32) : ACLHandle
    fun acl_set_file(path : UInt8*, type : UInt32, acl : ACLHandle) : Int32
  end

  ACL_FIRST_ENTRY = 0
  ACL_NEXT_ENTRY  = 1

  ACL_TYPE_ACCESS  = 0x8000_u32
  ACL_TYPE_DEFAULT = 0x4000_u32

  ACL_USER_OBJ  = 0x01
  ACL_USER      = 0x02
  ACL_GROUP_OBJ = 0x04
  ACL_GROUP     = 0x08
  ACL_MASK      = 0x10
  ACL_OTHER     = 0x20

  ACL_EXECUTE = 0x01_u32
  ACL_WRITE   = 0x02_u32
  ACL_READ    = 0x04_u32
end
