module ACL::Windows
  # An owned, immutable SID. Numeric identity is not resolved into an account
  # name. The 48-bit authority is big-endian; subauthorities are little-endian.
  class SID
    private alias Binary = ACL::Internal::Binary
    MAX_SUBAUTHORITIES = 15
    @bytes : Bytes

    private def initialize(bytes : Bytes)
      @bytes = bytes.dup
    end

    def self.from_bytes(bytes : Bytes) : self
      size = size_at(bytes, 0)
      raise InvalidACLError.new("SID length mismatch") unless bytes.size == size
      new(bytes)
    end

    # Validates a bounded SID embedded in a larger structure before slicing it.
    def self.size_at(bytes : Bytes, offset : Int) : Int32
      Binary.range!(bytes, offset, 8)
      raise InvalidACLError.new("unsupported SID revision") unless bytes[offset] == 1
      count = bytes[offset + 1].to_i
      raise InvalidACLError.new("too many SID subauthorities") if count > MAX_SUBAUTHORITIES
      size = 8 + count * 4
      Binary.range!(bytes, offset, size)
      size
    end

    # Numeric S-1-authority-subauthority form only; no SDDL account aliases.
    # Authorities may be decimal or 0x-prefixed hexadecimal (native SID text).
    def self.parse(text : String) : self
      parts = text.split('-')
      unless parts.size >= 3 && parts[0] == "S" && parts[1] == "1"
        raise InvalidACLError.new("invalid numeric SID")
      end
      count = parts.size - 3
      raise InvalidACLError.new("too many SID subauthorities") if count > MAX_SUBAUTHORITIES
      authority_text = parts[2]
      authority = if authority_text.starts_with?("0x")
                    digits = authority_text[2..]
                    raise InvalidACLError.new("invalid SID authority") unless digits.matches?(/\A[0-9a-fA-F]+\z/)
                    digits.to_u64?(16)
                  else
                    raise InvalidACLError.new("invalid SID authority") unless authority_text.matches?(/\A[0-9]+\z/)
                    authority_text.to_u64?
                  end
      unless authority && authority <= 0xffffffffffff_u64
        raise InvalidACLError.new("SID authority exceeds 48 bits")
      end
      bytes = Bytes.new(8 + 4 * count, 0_u8)
      bytes[0] = 1
      bytes[1] = count.to_u8
      6.times { |i| bytes[2 + i] = ((authority >> (8 * (5 - i))) & 0xff).to_u8 }
      count.times do |i|
        part = parts[3 + i]
        raise InvalidACLError.new("invalid SID subauthority") unless part.matches?(/\A[0-9]+\z/)
        value = part.to_u32?
        raise InvalidACLError.new("SID subauthority exceeds 32 bits") unless value
        Binary.put_le32(bytes, 8 + 4 * i, value)
      end
      new(bytes)
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def bytesize : Int32
      @bytes.size
    end

    def to_s(io : IO) : Nil
      authority = 0_u64
      6.times { |i| authority = (authority << 8) | @bytes[2 + i].to_u64 }
      io << "S-1-" << authority
      @bytes[1].to_i.times { |i| io << '-' << Binary.le32(@bytes, 8 + i * 4) }
    end

    def_equals_and_hash @bytes
  end
end
