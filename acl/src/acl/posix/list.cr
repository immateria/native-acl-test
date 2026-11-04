module ACL::POSIX
  # A POSIX.1e access or directory-default ACL.
  #
  # Entries are exposed through independent snapshots. Use methods that return
  # a new `List` instead of expecting mutations to update this object.
  class List
    include Enumerable(Entry)

    @entries : Array(Entry)

    # Whether this is an access ACL or a directory-default ACL.
    getter scope : Scope

    def initialize(@scope : Scope, entries : Enumerable(Entry))
      unless @scope.access? || @scope.default?
        raise ArgumentError.new("unsupported POSIX scope value #{@scope.value}")
      end
      @entries = entries.to_a.dup
    end

    # Returns an independent snapshot of the entries in their current order.
    def entries : Indexable(Entry)
      @entries.dup
    end

    # Iterates over entries in their current order.
    def each(&block : Entry ->) : Nil
      @entries.each(&block)
    end

    # Returns the number of entries.
    def size : Int32
      @entries.size
    end

    def validate! : self
      require_exactly_one!(Tag::Owner, "owner")
      require_exactly_one!(Tag::OwningGroup, "owning group")
      require_exactly_one!(Tag::Other, "other")
      require_at_most_one!(Tag::Mask, "mask")
      reject_duplicate_qualifiers!(Tag::User, "named user")
      reject_duplicate_qualifiers!(Tag::Group, "named group")

      if @entries.any? { |entry| entry.user? || entry.group? } && mask.nil?
        raise InvalidACLError.new("named user or group entries require a mask entry")
      end

      self
    end

    def mask : Entry?
      @entries.find(&.mask?)
    end

    def calculated_mask : Permission
      @entries.reduce(Permission::None) do |permissions, entry|
        if entry.user? || entry.owning_group? || entry.group?
          permissions | entry.permissions
        else
          permissions
        end
      end
    end

    def with_calculated_mask : List
      replacement = Entry.mask(calculated_mask)
      normalized = @entries.reject(&.mask?) << replacement
      List.new(@scope, canonicalize(normalized)).tap(&.validate!)
    end

    def effective_permissions(entry : Entry) : Permission
      if entry.user? || entry.owning_group? || entry.group?
        if mask_entry = mask
          return entry.permissions & mask_entry.permissions
        end
      end
      entry.permissions
    end

    def canonical : List
      List.new(@scope, canonicalize(@entries)).tap(&.validate!)
    end

    def to_text : String
      canonical.entries.join('\n') { |entry| entry_to_text(entry) } + "\n"
    end

    private def entry_to_text(entry : Entry) : String
      prefix = case entry.tag
               when .owner?
                 "user:"
               when .user?
                 "user:#{entry.qualifier}"
               when .owning_group?
                 "group:"
               when .group?
                 "group:#{entry.qualifier}"
               when .mask?
                 "mask:"
               when .other?
                 "other:"
               else
                 raise "unreachable POSIX tag"
               end
      scope_prefix = @scope.default? ? "default:" : ""
      "#{scope_prefix}#{prefix}:#{entry.permissions.to_posix}"
    end

    private def canonicalize(entries : Enumerable(Entry)) : Array(Entry)
      entries.to_a.sort_by do |entry|
        case entry.tag
        when .owner?
          {0, 0_u32}
        when .user?
          {1, entry.qualifier.not_nil!}
        when .owning_group?
          {2, 0_u32}
        when .group?
          {3, entry.qualifier.not_nil!}
        when .mask?
          {4, 0_u32}
        when .other?
          {5, 0_u32}
        else
          raise "unreachable POSIX tag"
        end
      end
    end

    private def require_exactly_one!(tag : Tag, label : String) : Nil
      count = @entries.count { |entry| entry.tag == tag }
      return if count == 1
      raise InvalidACLError.new("ACL requires exactly one #{label} entry; found #{count}")
    end

    private def require_at_most_one!(tag : Tag, label : String) : Nil
      count = @entries.count { |entry| entry.tag == tag }
      return if count <= 1
      raise InvalidACLError.new("ACL permits at most one #{label} entry; found #{count}")
    end

    private def reject_duplicate_qualifiers!(tag : Tag, label : String) : Nil
      seen = Set(UInt32).new
      @entries.each do |entry|
        next unless entry.tag == tag
        qualifier = entry.qualifier.not_nil!
        unless seen.add?(qualifier)
          raise InvalidACLError.new("duplicate #{label} #{qualifier}")
        end
      end
    end
  end
end
