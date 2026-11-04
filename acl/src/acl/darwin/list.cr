module ACL::Darwin
  # A present Darwin ACL. Read-time presence belongs to Snapshot; nil in an
  # explicit write requests removal. An empty List is not Windows' deny-all policy.
  class List
    include Enumerable(Entry)
    private alias Binary = ACL::Internal::Binary

    MAX_ENTRIES          =            128
    EXTERNAL_MAGIC       = 0x012cc16d_u32
    LIBC_DEFER_INHERIT   = 0x00000001_u32 # public header explicitly calls this tentative
    KERNEL_DEFER_INHERIT = 0x00010000_u32 # kauth.h; NOT the same bit
    NO_INHERIT           = 0x00020000_u32
    PRIVATE_FLAGS_MASK   = 0x0000ffff_u32
    EXTERNAL_HEADER_SIZE =             44
    EXTERNAL_ENTRY_SIZE  =             24

    @entries : Array(Entry)
    getter flags : UInt32

    def initialize(entries : Enumerable(Entry) = [] of Entry, @flags : UInt32 = 0)
      @entries = entries.to_a.dup
      raise InvalidACLError.new("Darwin ACL exceeds #{MAX_ENTRIES} entries") if @entries.size > MAX_ENTRIES
    end

    def entries : Array(Entry)
      @entries.dup
    end

    def each(&block : Entry ->) : Nil
      @entries.each(&block)
    end

    def size : Int32
      @entries.size
    end

    def empty? : Bool
      @entries.empty?
    end

    def with_entry(index : Int, entry : Entry) : self
      entries = @entries.dup
      entries[index] = entry
      self.class.new(entries, @flags)
    end

    # No guessed sorting or flag normalization; filesystem-private bits survive.
    def with_flags(flags : UInt32) : self
      self.class.new(@entries, flags)
    end

    # libc acl_valid only checks its storage magic in the supplied Apple source.
    # Reject unsupported kinds explicitly instead of pretending that is enough.
    def validate_for_write! : self
      @entries.each do |entry|
        unless entry.allow? || entry.deny?
          raise UnsupportedACLError.new("Darwin ACE kind #{entry.kind} is preserved but not writable by this API")
        end
      end
      self
    end

    # libc acl_copy_ext's portable big-endian format. This is NOT a native
    # struct dump and NOT an xattr payload. Owner/group fields are zero because
    # acl_t does not carry ownership. Unknown ACE and ACL bits remain intact.
    def to_bytes : Bytes
      bytes = Bytes.new(EXTERNAL_HEADER_SIZE + EXTERNAL_ENTRY_SIZE * size, 0_u8)
      Binary.put_be32(bytes, 0, EXTERNAL_MAGIC)
      Binary.put_be32(bytes, 36, size.to_u32)
      Binary.put_be32(bytes, 40, @flags)
      @entries.each_with_index do |entry, index|
        offset = EXTERNAL_HEADER_SIZE + index * EXTERNAL_ENTRY_SIZE
        entry.principal.bytes.to_slice.copy_to(bytes[offset, 16])
        Binary.put_be32(bytes, offset + 16, entry.raw_flags)
        Binary.put_be32(bytes, offset + 20, entry.raw_rights)
      end
      bytes
    end

    def self.from_bytes(bytes : Bytes) : self
      Binary.range!(bytes, 0, EXTERNAL_HEADER_SIZE)
      raise InvalidACLError.new("invalid Darwin external ACL magic") unless Binary.be32(bytes, 0) == EXTERNAL_MAGIC
      count = Binary.be32(bytes, 36)
      raise InvalidACLError.new("invalid Darwin ACL entry count #{count}") if count > MAX_ENTRIES
      expected = EXTERNAL_HEADER_SIZE + EXTERNAL_ENTRY_SIZE * count.to_i
      raise InvalidACLError.new("Darwin external ACL length mismatch") unless bytes.size == expected
      unless bytes[4, 32].all?(&.zero?)
        raise InvalidACLError.new("input contains filesec ownership; expected acl_copy_ext output")
      end
      entries = Array(Entry).new(count.to_i) do |index|
        offset = EXTERNAL_HEADER_SIZE + index * EXTERNAL_ENTRY_SIZE
        uuid = UUID.new(StaticArray(UInt8, 16).new { |i| bytes[offset + i] })
        Entry.new(uuid, Binary.be32(bytes, offset + 16), Binary.be32(bytes, offset + 20))
      end
      new(entries, Binary.be32(bytes, 40))
    end
  end
end
