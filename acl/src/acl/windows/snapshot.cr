module ACL::Windows
  # Query/write selectors are not SECURITY_DESCRIPTOR_CONTROL flags.
  # SACL subcomponents have separate selectors; a partial label query is not
  # evidence that audit/resource-policy ACEs are absent.
  @[Flags]
  enum Information : UInt32
    Owner             = 0x00001
    Group             = 0x00002
    DACL              = 0x00004
    SACL              = 0x00008
    Label             = 0x00010
    Attribute         = 0x00020
    Scope             = 0x00040
    ProcessTrustLabel = 0x00080
    AccessFilter      = 0x00100
    Backup            = 0x10000
    Basic             = Owner | Group | DACL
  end

  # Carries what the OS was actually asked for alongside the returned bytes.
  # `descriptor` is the low-level partial image, not proof of a full snapshot.
  class Snapshot
    getter descriptor : Descriptor
    getter queried : Information

    def initialize(@descriptor : Descriptor, @queried : Information)
      self.class.validate_information!(@queried)
    end

    def self.validate_information!(information : Information, allow_backup : Bool = true) : Nil
      allowed = allow_backup ? 0x101ff_u32 : 0x1ff_u32
      if information.value == 0 || information.value & ~allowed != 0
        raise UnsupportedACLError.new("unsupported or empty security information selection")
      end
    end

    def require!(information : Information) : Nil
      self.class.validate_information!(information, allow_backup: false)
      return if @queried.includes?(Information::Backup)
      unless @queried.includes?(information)
        raise UnsupportedACLError.new("requested security component was not queried")
      end
    end

    def owner : SID?
      require!(Information::Owner)
      @descriptor.owner
    end

    def group : SID?
      require!(Information::Group)
      @descriptor.group
    end

    def dacl : ACLState
      require!(Information::DACL)
      @descriptor.dacl
    end

    # Audit SACL view; does not claim that separately selected mandatory-label,
    # resource-attribute or policy components were queried as well.
    def sacl : ACLState
      require!(Information::SACL)
      @descriptor.sacl
    end

    def sacl_components(information : Information) : ACLState
      if information.value & ~0x1f8_u32 != 0
        raise ArgumentError.new("selection contains non-SACL components")
      end
      require!(information)
      @descriptor.sacl
    end
  end
end
