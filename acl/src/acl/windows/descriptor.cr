module ACL::Windows
  enum Presence
    Absent
    Null
    Present
  end

  # Presence is separate from content. A present zero-entry List is an empty
  # ACL, while a null DACL grants access. Unqueried state lives in Snapshot.
  struct ACLState
    getter presence : Presence
    getter list : List?

    private def initialize(@presence : Presence, @list : List? = nil)
    end

    def self.absent : self
      new(Presence::Absent)
    end

    def self.null : self
      new(Presence::Null)
    end

    def self.present(list : List) : self
      new(Presence::Present, list)
    end
  end

  # An owned SECURITY_DESCRIPTOR_RELATIVE. Unmodified serialization is exactly
  # byte preserving, including opaque ACEs, control bits, padding and RM byte.
  # This is a bounded structural decoder, NOT an access-check implementation.
  class Descriptor
    private alias Binary = ACL::Internal::Binary
    SELF_RELATIVE  = 0x8000_u16
    DACL_PRESENT   = 0x0004_u16
    SACL_PRESENT   = 0x0010_u16
    DACL_PROTECTED = 0x1000_u16
    SACL_PROTECTED = 0x2000_u16
    HEADER_SIZE    =         20

    @bytes : Bytes
    getter owner : SID?
    getter group : SID?
    getter dacl : ACLState
    getter sacl : ACLState
    getter control : UInt16
    getter resource_manager : UInt8

    def initialize(@owner : SID? = nil, @group : SID? = nil,
                   @dacl : ACLState = ACLState.absent, @sacl : ACLState = ACLState.absent,
                   control : UInt16 = 0, @resource_manager : UInt8 = 0)
      @control = (control | SELF_RELATIVE) & ~(DACL_PRESENT | SACL_PRESENT)
      @control |= DACL_PRESENT unless @dacl.presence.absent?
      @control |= SACL_PRESENT unless @sacl.presence.absent?
      parts = [@owner.try(&.to_bytes), @group.try(&.to_bytes), @sacl.list.try(&.to_bytes), @dacl.list.try(&.to_bytes)]
      size = HEADER_SIZE
      parts.each { |part| size += part.size if part }
      @bytes = Bytes.new(size, 0_u8)
      @bytes[0] = 1
      @bytes[1] = @resource_manager
      Binary.put_le16(@bytes, 2, @control)
      offset = HEADER_SIZE
      parts.each_with_index do |part, index|
        if part
          Binary.put_le32(@bytes, 4 + 4 * index, offset.to_u32)
          part.copy_to(@bytes[offset, part.size])
          offset += part.size
        end
      end
    end

    private def initialize(bytes : Bytes)
      @bytes = bytes.dup
      Binary.range!(@bytes, 0, HEADER_SIZE)
      raise InvalidACLError.new("unsupported security descriptor revision") unless @bytes[0] == 1
      @control = Binary.le16(@bytes, 2)
      raise InvalidACLError.new("absolute security descriptors cannot be decoded as bytes") if @control & SELF_RELATIVE == 0
      @resource_manager = @bytes[1]
      @owner = read_sid(4)
      @group = read_sid(8)
      @sacl = read_acl(12, SACL_PRESENT)
      @dacl = read_acl(16, DACL_PRESENT)
    end

    def self.from_bytes(bytes : Bytes) : self
      new(bytes)
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def dacl_protected? : Bool
      @control & DACL_PROTECTED != 0
    end

    def sacl_protected? : Bool
      @control & SACL_PROTECTED != 0
    end

    # Rebuilds a descriptor with one changed component; all other semantic
    # data is retained. Original layout padding is not part of an edited SD.
    def with_dacl(state : ACLState) : self
      self.class.new(@owner, @group, state, @sacl, @control, @resource_manager)
    end

    def with_sacl(state : ACLState) : self
      self.class.new(@owner, @group, @dacl, state, @control, @resource_manager)
    end

    private def offset_at(field : Int32) : Int32?
      offset = Binary.le32(@bytes, field).to_i64
      return nil if offset == 0
      unless offset >= HEADER_SIZE && offset % 4 == 0 && offset < @bytes.size
        raise InvalidACLError.new("invalid security descriptor offset #{offset}")
      end
      offset.to_i
    end

    private def read_sid(field : Int32) : SID?
      if offset = offset_at(field)
        SID.from_bytes(@bytes[offset, SID.size_at(@bytes, offset)])
      end
    end

    private def read_acl(field : Int32, flag : UInt16) : ACLState
      # MS-DTYP requires a zero offset when the presence bit is clear.
      if @control & flag == 0
        raise InvalidACLError.new("absent ACL has a nonzero offset") unless Binary.le32(@bytes, field) == 0
        return ACLState.absent
      end
      offset = offset_at(field)
      return ACLState.null unless offset
      Binary.range!(@bytes, offset, 8)
      length = Binary.le16(@bytes, offset + 2).to_i
      Binary.range!(@bytes, offset, length)
      ACLState.present(List.from_bytes(@bytes[offset, length]))
    end
  end
end
