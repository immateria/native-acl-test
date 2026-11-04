module ACL::Darwin
  # An ordered, immutable native ACE. Unknown kind/flag/right bits are retained.
  # Numeric UIDs and account names are deliberately not substituted for UUIDs.
  struct Entry
    KIND_MASK         =  0x0f_u32
    INHERITED         =  0x10_u32
    FILE_INHERIT      =  0x20_u32
    DIRECTORY_INHERIT =  0x40_u32
    LIMIT_INHERIT     =  0x80_u32
    ONLY_INHERIT      = 0x100_u32

    getter principal : UUID
    getter raw_flags : UInt32
    getter raw_rights : UInt32

    def initialize(@principal : UUID, @raw_flags : UInt32, @raw_rights : UInt32)
    end

    def self.allow(principal : UUID, permissions : Permission, flags : UInt32 = 0) : self
      build(principal, 1_u32, permissions, flags)
    end

    def self.deny(principal : UUID, permissions : Permission, flags : UInt32 = 0) : self
      build(principal, 2_u32, permissions, flags)
    end

    private def self.build(principal, kind, permissions, flags) : self
      raise InvalidACLError.new("ACE flags must not contain kind bits") unless flags & KIND_MASK == 0
      new(principal, kind | flags, permissions.value)
    end

    def kind : UInt32
      @raw_flags & KIND_MASK
    end

    def allow? : Bool
      kind == 1
    end

    def deny? : Bool
      kind == 2
    end

    def inherited? : Bool
      @raw_flags & INHERITED != 0
    end

    def flags : UInt32
      @raw_flags & ~KIND_MASK
    end

    def permissions : Permission
      Permission.new(@raw_rights)
    end

    def with_permissions(permissions : Permission) : self
      self.class.new(@principal, @raw_flags, permissions.value)
    end

    def_equals_and_hash @principal, @raw_flags, @raw_rights
  end
end
