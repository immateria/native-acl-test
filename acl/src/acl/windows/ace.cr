module ACL::Windows
  # An owned ACE, including its entire opaque body. Unknown ACE types and
  # callback/resource-attribute payloads are retained, never flattened into
  # EXPLICIT_ACCESS or reordered. Parsing is structural, not authorization.
  class ACE
    enum Category
      Discretionary
      System
      Unknown
    end

    private alias Binary = ACL::Internal::Binary
    private OBJECT_TYPES  = {5_u8, 6_u8, 7_u8, 8_u8, 11_u8, 12_u8, 15_u8, 16_u8}
    private BASIC_TYPES   = {0_u8, 1_u8, 2_u8, 3_u8, 9_u8, 10_u8, 13_u8, 14_u8, 17_u8, 18_u8, 19_u8, 20_u8, 21_u8}
    private PAYLOAD_TYPES = {9_u8, 10_u8, 11_u8, 12_u8, 13_u8, 14_u8, 15_u8, 16_u8, 18_u8, 21_u8}
    private GUID_ORDER    = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}

    OBJECT_INHERIT    = 0x01_u8
    CONTAINER_INHERIT = 0x02_u8
    NO_PROPAGATE      = 0x04_u8
    INHERIT_ONLY      = 0x08_u8
    INHERITED         = 0x10_u8
    SUCCESSFUL_ACCESS = 0x40_u8
    FAILED_ACCESS     = 0x80_u8

    @bytes : Bytes

    private def initialize(bytes : Bytes)
      @bytes = bytes.dup
      validate!
    end

    def self.from_bytes(bytes : Bytes) : self
      new(bytes)
    end

    def self.allow(sid : SID, mask : UInt32, flags : UInt8 = 0) : self
      basic(0_u8, sid, mask, flags)
    end

    def self.deny(sid : SID, mask : UInt32, flags : UInt8 = 0) : self
      basic(1_u8, sid, mask, flags)
    end

    def self.audit(sid : SID, mask : UInt32, success : Bool = true, failure : Bool = false, flags : UInt8 = 0) : self
      raise InvalidACLError.new("audit ACE requires success or failure auditing") unless success || failure
      flags |= SUCCESSFUL_ACCESS if success
      flags |= FAILED_ACCESS if failure
      basic(2_u8, sid, mask, flags)
    end

    def self.callback(type : UInt8, sid : SID, mask : UInt32, application_data : Bytes, flags : UInt8 = 0) : self
      unless {9_u8, 10_u8, 13_u8, 14_u8}.includes?(type)
        raise InvalidACLError.new("not a basic callback ACE type")
      end
      basic(type, sid, mask, flags, application_data)
    end

    def self.object(type : UInt8, sid : SID, mask : UInt32, flags : UInt8 = 0,
                    object_type : UUID? = nil, inherited_object_type : UUID? = nil,
                    application_data : Bytes = Bytes.empty) : self
      raise InvalidACLError.new("not an object ACE type") unless OBJECT_TYPES.includes?(type)
      unless application_data.empty? || PAYLOAD_TYPES.includes?(type)
        raise InvalidACLError.new("non-callback object ACE cannot contain application data")
      end
      object_flags = (object_type ? 1_u32 : 0_u32) | (inherited_object_type ? 2_u32 : 0_u32)
      offset = 12 + (object_type ? 16 : 0) + (inherited_object_type ? 16 : 0)
      bytes = header(type, flags, offset.to_i64 + sid.bytesize + application_data.size)
      Binary.put_le32(bytes, 4, mask)
      Binary.put_le32(bytes, 8, object_flags)
      cursor = 12
      if uuid = object_type
        encode_guid(bytes, cursor, uuid)
        cursor += 16
      end
      if uuid = inherited_object_type
        encode_guid(bytes, cursor, uuid)
      end
      sid.to_bytes.copy_to(bytes[offset, sid.bytesize])
      application_data.copy_to(bytes[offset + sid.bytesize, application_data.size])
      new(bytes)
    end

    private def self.basic(type, sid, mask, flags, payload = Bytes.empty) : self
      bytes = header(type, flags, 8_i64 + sid.bytesize + payload.size)
      Binary.put_le32(bytes, 4, mask)
      sid.to_bytes.copy_to(bytes[8, sid.bytesize])
      payload.copy_to(bytes[8 + sid.bytesize, payload.size])
      new(bytes)
    end

    private def self.header(type : UInt8, flags : UInt8, size : Int64) : Bytes
      unless size >= 4 && size <= 65532 && size % 4 == 0
        raise InvalidACLError.new("ACE size must be DWORD-aligned and fit UInt16")
      end
      bytes = Bytes.new(size.to_i, 0_u8)
      bytes[0] = type
      bytes[1] = flags
      Binary.put_le16(bytes, 2, size.to_u16)
      bytes
    end

    private def self.encode_guid(bytes, offset, uuid) : Nil
      raw = uuid.bytes
      GUID_ORDER.each_with_index { |source, i| bytes[offset + i] = raw[source] }
    end

    private def guid(offset) : UUID
      Binary.range!(@bytes, offset, 16)
      UUID.new(StaticArray(UInt8, 16).new { |i| @bytes[offset + GUID_ORDER[i]] })
    end

    def type : UInt8
      @bytes[0]
    end

    def flags : UInt8
      @bytes[1]
    end

    def inherited? : Bool
      flags & INHERITED != 0
    end

    def object? : Bool
      OBJECT_TYPES.includes?(type)
    end

    def known? : Bool
      object? || BASIC_TYPES.includes?(type)
    end

    # Classifies the native ACE header family without claiming that an opaque
    # body is semantically understood. Type 4 is the reserved compound-access
    # family and therefore belongs to a DACL, even though its body remains
    # intentionally opaque. Future types are not guessed.
    def category : Category
      case type
      when 0_u8, 1_u8, 4_u8, 5_u8, 6_u8, 9_u8, 10_u8, 11_u8, 12_u8
        Category::Discretionary
      when 2_u8, 3_u8, 7_u8, 8_u8, 13_u8, 14_u8, 15_u8, 16_u8,
           17_u8, 18_u8, 19_u8, 20_u8, 21_u8
        Category::System
      else
        Category::Unknown
      end
    end

    def mask : UInt32?
      Binary.le32(@bytes, 4) if known?
    end

    def sid : SID?
      if offset = sid_offset
        SID.from_bytes(@bytes[offset, SID.size_at(@bytes, offset)])
      end
    end

    def object_type : UUID?
      guid(12) if object? && Binary.le32(@bytes, 8) & 1 != 0
    end

    def inherited_object_type : UUID?
      return nil unless object?
      bits = Binary.le32(@bytes, 8)
      guid(12 + (bits & 1 != 0 ? 16 : 0)) if bits & 2 != 0
    end

    # Includes alignment padding: we cannot infer a callback's private grammar.
    def application_data : Bytes?
      if offset = sid_offset
        offset += SID.size_at(@bytes, offset)
        @bytes[offset, @bytes.size - offset].dup
      end
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def bytesize : Int32
      @bytes.size
    end

    def with_mask(value : UInt32) : self
      raise UnsupportedACLError.new("unknown ACE body cannot be edited as an access mask") unless known?
      bytes = @bytes.dup
      Binary.put_le32(bytes, 4, value)
      self.class.from_bytes(bytes)
    end

    # Replace only the trustee SID. GUIDs, mask, flags and uninterpreted tail
    # bytes remain unchanged. Unknown/compound layouts cannot be edited safely.
    def with_sid(value : SID) : self
      offset = sid_offset || raise UnsupportedACLError.new("unknown ACE layout cannot be edited as a SID")
      old_size = SID.size_at(@bytes, offset)
      new_size = @bytes.size - old_size + value.bytesize
      raise InvalidACLError.new("edited ACE exceeds native size bound") if new_size > 65532
      bytes = Bytes.new(new_size)
      @bytes[0, offset].copy_to(bytes[0, offset])
      value.to_bytes.copy_to(bytes[offset, value.bytesize])
      tail = @bytes[offset + old_size, @bytes.size - offset - old_size]
      tail.copy_to(bytes[offset + value.bytesize, tail.size])
      Binary.put_le16(bytes, 2, new_size.to_u16)
      self.class.from_bytes(bytes)
    end

    def with_flags(value : UInt8) : self
      bytes = @bytes.dup
      bytes[1] = value
      self.class.from_bytes(bytes)
    end

    private def sid_offset : Int32?
      if object?
        bits = Binary.le32(@bytes, 8)
        raise InvalidACLError.new("unsupported object ACE flags") unless bits & ~3_u32 == 0
        12 + (bits & 1 != 0 ? 16 : 0) + (bits & 2 != 0 ? 16 : 0)
      elsif BASIC_TYPES.includes?(type)
        8
      end
    end

    private def validate! : Nil
      Binary.range!(@bytes, 0, 4)
      size = Binary.le16(@bytes, 2)
      unless size >= 4 && size == @bytes.size && size % 4 == 0
        raise InvalidACLError.new("ACE length mismatch or misalignment")
      end
      if offset = sid_offset
        SID.size_at(@bytes, offset)
        # MS-DTYP permits extra AceSize bytes even for non-callback ACEs.
        # Keep these bytes without assigning them access-control semantics.
      end
    end

    def_equals_and_hash @bytes
  end
end
