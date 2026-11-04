# Bounds-checked fixed-width operations. No binary decoder dereferences pointers.
module ACL::Internal::Binary
  extend self

  def range!(bytes : Bytes, offset : Int, length : Int) : Nil
    if offset < 0 || length < 0 || offset > bytes.size || length > bytes.size - offset
      raise InvalidACLError.new("truncated binary ACL: offset #{offset}, length #{length}, buffer #{bytes.size}")
    end
  end

  def le16(bytes : Bytes, offset : Int) : UInt16
    range!(bytes, offset, 2)
    IO::ByteFormat::LittleEndian.decode(UInt16, bytes[offset, 2])
  end

  def le32(bytes : Bytes, offset : Int) : UInt32
    range!(bytes, offset, 4)
    IO::ByteFormat::LittleEndian.decode(UInt32, bytes[offset, 4])
  end

  def be32(bytes : Bytes, offset : Int) : UInt32
    range!(bytes, offset, 4)
    IO::ByteFormat::BigEndian.decode(UInt32, bytes[offset, 4])
  end

  def put_le16(bytes : Bytes, offset : Int, value : UInt16) : Nil
    range!(bytes, offset, 2)
    IO::ByteFormat::LittleEndian.encode(value, bytes[offset, 2])
  end

  def put_le32(bytes : Bytes, offset : Int, value : UInt32) : Nil
    range!(bytes, offset, 4)
    IO::ByteFormat::LittleEndian.encode(value, bytes[offset, 4])
  end

  def put_be32(bytes : Bytes, offset : Int, value : UInt32) : Nil
    range!(bytes, offset, 4)
    IO::ByteFormat::BigEndian.encode(value, bytes[offset, 4])
  end
end
