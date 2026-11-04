module ACL::Darwin
  enum Presence
    # The query succeeded but did not return EXTENDED_SECURITY. This is not
    # proof that the filesystem supports ACLs or that no ACL exists.
    NotReturned
    Absent
    Present
  end

  # Per-query evidence, not an inference from volume capabilities. In particular
  # a present empty ACL must not be collapsed into an omitted ACL attribute.
  class Snapshot
    private alias Binary = ACL::Internal::Binary
    RETURNED_ATTRIBUTES = 0x80000000_u32
    EXTENDED_SECURITY   = 0x00400000_u32
    MAX_ATTRIBUTE_BYTES = 32 + List::EXTERNAL_HEADER_SIZE + List::MAX_ENTRIES * List::EXTERNAL_ENTRY_SIZE

    getter presence : Presence
    getter list : List?

    private def initialize(@presence : Presence, @list : List? = nil)
    end

    # :nodoc:
    # Decoder for exactly RETURNED_ATTRS | EXTENDED_SECURITY, without
    # PACK_INVAL_ATTRS. Both supported native targets are little-endian.
    def self.from_attribute_bytes(bytes : Bytes) : self
      Binary.range!(bytes, 0, 24) # total size + five returned-attribute groups
      total = Binary.le32(bytes, 0).to_i64
      unless 24 <= total <= bytes.size && total <= MAX_ATTRIBUTE_BYTES
        raise InvalidACLError.new("invalid or truncated Darwin attribute response length")
      end
      bytes = bytes[0, total.to_i]
      returned = Binary.le32(bytes, 4)
      unless returned & RETURNED_ATTRIBUTES != 0 && returned & ~(RETURNED_ATTRIBUTES | EXTENDED_SECURITY) == 0 && bytes[8, 16].all?(&.zero?)
        raise InvalidACLError.new("unexpected Darwin returned-attribute bitmap")
      end
      return new(Presence::NotReturned) if returned & EXTENDED_SECURITY == 0

      Binary.range!(bytes, 24, 8)
      relative = Binary.le32(bytes, 24).to_i64
      length = Binary.le32(bytes, 28).to_i64
      # This query's only variable field follows its reference. A negative
      # signed attr_dataoffset is invalid here, not an enormous allocation.
      unless relative >= 8 && relative <= Int32::MAX && relative % 4 == 0
        raise InvalidACLError.new("invalid Darwin ACL attribute reference")
      end
      offset = 24_i64 + relative
      Binary.range!(bytes, offset, length)
      unless length >= List::EXTERNAL_HEADER_SIZE && length <= MAX_ATTRIBUTE_BYTES - 32
        raise InvalidACLError.new("invalid Darwin native ACL length")
      end
      raw = bytes[offset.to_i, length.to_i]
      unless Binary.le32(raw, 0) == List::EXTERNAL_MAGIC && raw[4, 32].all?(&.zero?)
        raise InvalidACLError.new("unexpected Darwin ACL attribute header")
      end
      count = Binary.le32(raw, 36)
      if count == UInt32::MAX
        raise InvalidACLError.new("NOACL attribute has an invalid length") unless length == List::EXTERNAL_HEADER_SIZE
        return new(Presence::Absent)
      end
      if count > List::MAX_ENTRIES || length != List::EXTERNAL_HEADER_SIZE + count.to_i64 * List::EXTERNAL_ENTRY_SIZE
        raise InvalidACLError.new("Darwin ACL attribute count/length mismatch")
      end
      entries = Array(Entry).new(count.to_i) do |i|
        start = List::EXTERNAL_HEADER_SIZE + i * List::EXTERNAL_ENTRY_SIZE
        uuid = UUID.new(StaticArray(UInt8, 16).new { |j| raw[start + j] })
        Entry.new(uuid, Binary.le32(raw, start + 16), Binary.le32(raw, start + 20))
      end
      new(Presence::Present, List.new(entries, Binary.le32(raw, 40)))
    end
  end
end
