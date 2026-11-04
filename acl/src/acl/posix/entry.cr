module ACL::POSIX
  # Selects the ACL associated directly with an object or inherited by children.
  enum Scope
    Access
    Default
  end

  # POSIX.1e ACL entry classes.
  enum Tag
    Owner
    User
    OwningGroup
    Group
    Mask
    Other
  end

  # One POSIX.1e ACL entry.
  #
  # Named-user and named-group entries carry numeric UID/GID qualifiers. The
  # owner, owning-group, mask, and other entries must not carry a qualifier.
  struct Entry
    getter tag : Tag
    getter permissions : Permission
    getter qualifier : UInt32?

    def initialize(
      @tag : Tag,
      @permissions : Permission,
      @qualifier : UInt32? = nil,
    )
      unsupported = @permissions.value & ~0x07_u8
      unless unsupported.zero?
        bits = unsupported.to_s(16).rjust(2, '0')
        raise ArgumentError.new("unsupported POSIX permission bits 0x#{bits}")
      end

      case @tag
      when .user?, .group?
        raise ArgumentError.new("#{@tag} entry requires a qualifier") unless @qualifier
      when .owner?, .owning_group?, .mask?, .other?
        raise ArgumentError.new("#{@tag} entry must not have a qualifier") if @qualifier
      else
        raise ArgumentError.new("unsupported POSIX tag value #{@tag.value}")
      end
    end

    def self.owner(permissions : Permission) : self
      new(Tag::Owner, permissions)
    end

    def self.user(id : UInt32, permissions : Permission) : self
      new(Tag::User, permissions, id)
    end

    def self.owning_group(permissions : Permission) : self
      new(Tag::OwningGroup, permissions)
    end

    def self.group(id : UInt32, permissions : Permission) : self
      new(Tag::Group, permissions, id)
    end

    def self.mask(permissions : Permission) : self
      new(Tag::Mask, permissions)
    end

    def self.other(permissions : Permission) : self
      new(Tag::Other, permissions)
    end

    def owner? : Bool
      @tag.owner?
    end

    def user? : Bool
      @tag.user?
    end

    def owning_group? : Bool
      @tag.owning_group?
    end

    def group? : Bool
      @tag.group?
    end

    def mask? : Bool
      @tag.mask?
    end

    def other? : Bool
      @tag.other?
    end
  end
end
