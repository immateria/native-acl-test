require "../../spec_helper"

private def darwin_attribute_buffer(count : UInt32? = nil, flags : UInt32 = 0_u32) : Bytes
  binary = ACL::Internal::Binary
  length = count ? 76 : 32
  bytes = Bytes.new(length, 0_u8)
  binary.put_le32(bytes, 0, length.to_u32)
  binary.put_le32(bytes, 4, count ? 0x80400000_u32 : 0x80000000_u32)
  if count
    binary.put_le32(bytes, 24, 8_u32)
    binary.put_le32(bytes, 28, 44_u32)
    binary.put_le32(bytes, 32, 0x012cc16d_u32)
    binary.put_le32(bytes, 68, count)
    binary.put_le32(bytes, 72, flags)
  end
  bytes
end

describe ACL::Darwin::Snapshot do
  it "preserves a present zero-entry ACL instead of libc statx's sizeof-struct collapse" do
    snapshot = ACL::Darwin::Snapshot.from_attribute_bytes(darwin_attribute_buffer(0_u32, 0x20000_u32))
    snapshot.presence.present?.should be_true
    snapshot.list.not_nil!.empty?.should be_true
    snapshot.list.not_nil!.flags.should eq(0x20000_u32)
  end

  it "does not promote an omitted returned-attribute bit to confirmed absence" do
    snapshot = ACL::Darwin::Snapshot.from_attribute_bytes(darwin_attribute_buffer)
    snapshot.presence.not_returned?.should be_true
    snapshot.list.should be_nil
  end

  it "recognizes an explicit native NOACL marker separately from omission" do
    snapshot = ACL::Darwin::Snapshot.from_attribute_bytes(darwin_attribute_buffer(UInt32::MAX))
    snapshot.presence.absent?.should be_true
    snapshot.list.should be_nil
  end

  it "decodes native-endian entry flags and rights without swapping UUID bytes" do
    bytes = darwin_attribute_buffer(0_u32, 0x20001_u32) + Bytes.new(24, 0_u8)
    binary = ACL::Internal::Binary
    binary.put_le32(bytes, 0, 100_u32)
    binary.put_le32(bytes, 28, 68_u32)
    binary.put_le32(bytes, 68, 1_u32)
    uuid = UUID.new("00112233-4455-6677-8899-aabbccddeeff")
    uuid.bytes.to_slice.copy_to(bytes[76, 16])
    binary.put_le32(bytes, 92, 0x80000121_u32)
    binary.put_le32(bytes, 96, 0x90000002_u32)
    snapshot = ACL::Darwin::Snapshot.from_attribute_bytes(bytes)
    list = snapshot.list.not_nil!
    list.flags.should eq(0x20001_u32)
    list.entries.should eq([ACL::Darwin::Entry.new(uuid, 0x80000121_u32, 0x90000002_u32)])
  end

  it "bounds the full length, attribute reference, and native ACL count" do
    bytes = darwin_attribute_buffer(0_u32)
    [0, 24, 28, 68].each do |field|
      bad = bytes.dup
      ACL::Internal::Binary.put_le32(bad, field, 0xfffffff0_u32)
      expect_raises(ACL::InvalidACLError) { ACL::Darwin::Snapshot.from_attribute_bytes(bad) }
    end
    (0...bytes.size).each do |size|
      expect_raises(ACL::InvalidACLError) { ACL::Darwin::Snapshot.from_attribute_bytes(bytes[0, size]) }
    end
  end
end
