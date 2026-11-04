module ACL::Windows
  # A present native ACL. A List is never an absent or null DACL/SACL.
  # Bytes retain reserved header values and unused allocation space. ACE order
  # is semantic: neither decoding nor editing performs canonical sorting.
  class List
    include Enumerable(ACE)
    private alias Binary = ACL::Internal::Binary
    @bytes : Bytes
    @entries : Array(ACE)
    @used : Int32

    def initialize(entries : Enumerable(ACE) = [] of ACE, revision : UInt8? = nil)
      values = entries.to_a.dup
      rev = revision || (values.any?(&.object?) ? 4_u8 : 2_u8)
      @bytes = self.class.encode(values, rev)
      @entries = values
      @used = @bytes.size
      validate_revision!
    end

    private def initialize(bytes : Bytes, entries : Array(ACE), @used : Int32)
      @bytes = bytes.dup
      @entries = entries.dup
      validate_revision!
    end

    def self.from_bytes(bytes : Bytes) : self
      Binary.range!(bytes, 0, 8)
      size = Binary.le16(bytes, 2).to_i
      unless size >= 8 && size == bytes.size && size % 4 == 0
        raise InvalidACLError.new("ACL length mismatch or misalignment")
      end
      count = Binary.le16(bytes, 4).to_i
      raise InvalidACLError.new("ACL ACE count exceeds buffer capacity") if count > (size - 8) // 4
      entries = Array(ACE).new(count)
      offset = 8
      count.times do
        Binary.range!(bytes, offset, 4)
        length = Binary.le16(bytes, offset + 2).to_i
        Binary.range!(bytes, offset, length)
        entries << ACE.from_bytes(bytes[offset, length])
        offset += length
      end
      new(bytes, entries, offset)
    end

    # :nodoc:
    def self.encode(entries : Array(ACE), revision : UInt8, padding : Bytes = Bytes.empty,
                    reserved1 : UInt8 = 0, reserved2 : UInt16 = 0) : Bytes
      size = 8_i64 + padding.size
      entries.each { |entry| size += entry.bytesize }
      if size > 65535 || entries.size > 65535 || size % 4 != 0
        raise InvalidACLError.new("Windows ACL exceeds native size/count bounds")
      end
      bytes = Bytes.new(size.to_i, 0_u8)
      bytes[0] = revision
      bytes[1] = reserved1
      Binary.put_le16(bytes, 2, size.to_u16)
      Binary.put_le16(bytes, 4, entries.size.to_u16)
      Binary.put_le16(bytes, 6, reserved2)
      offset = 8
      entries.each do |entry|
        entry.to_bytes.copy_to(bytes[offset, entry.bytesize])
        offset += entry.bytesize
      end
      padding.copy_to(bytes[offset, padding.size])
      bytes
    end

    def revision : UInt8
      @bytes[0]
    end

    def entries : Array(ACE)
      @entries.dup
    end

    def size : Int32
      @entries.size
    end

    def each(&block : ACE ->) : Nil
      @entries.each(&block)
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def with_entry(index : Int, entry : ACE) : self
      values = @entries.dup
      values[index] = entry
      with_entries(values)
    end

    def inserted(index : Int, entry : ACE) : self
      values = @entries.dup
      values.insert(index, entry)
      with_entries(values)
    end

    def without_entry(index : Int) : self
      values = @entries.dup
      values.delete_at(index)
      with_entries(values)
    end

    def with_entries(entries : Enumerable(ACE)) : self
      values = entries.to_a.dup
      rev = values.any?(&.object?) ? 4_u8 : revision
      bytes = self.class.encode(values, rev, @bytes[@used, @bytes.size - @used], @bytes[1], Binary.le16(@bytes, 6))
      self.class.from_bytes(bytes)
    end

    private def validate_revision! : Nil
      unless revision == 2 || revision == 4
        raise InvalidACLError.new("unsupported ACL revision #{revision}")
      end
      if revision != 4 && @entries.any?(&.object?)
        raise InvalidACLError.new("object ACEs require ACL_REVISION_DS")
      end
    end
  end
end
