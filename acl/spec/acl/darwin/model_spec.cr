require "../../spec_helper"
require "../../../src/acl/darwin"

private def darwin_entry
  ACL::Darwin::Entry.allow(UUID.new("00112233-4455-6677-8899-aabbccddeeff"), ACL::Darwin::Permission::ReadData)
end

describe ACL::Darwin::List do
  it "emits the documented big-endian external ACL layout without UUID byte swapping" do
    acl = ACL::Darwin::List.new([darwin_entry], flags: 0x00028001_u32)
    bytes = acl.to_bytes
    bytes.size.should eq(68)
    bytes[0, 4].hexstring.should eq("012cc16d")
    bytes[36, 8].hexstring.should eq("0000000100028001")
    bytes[44, 16].hexstring.should eq("00112233445566778899aabbccddeeff")
    bytes[60, 8].hexstring.should eq("0000000100000002")
    ACL::Darwin::List.from_bytes(bytes).to_bytes.should eq(bytes)
  end

  it "preserves order, unknown kinds, private ACL bits, and future ACE bits" do
    opaque = ACL::Darwin::Entry.new(darwin_entry.principal, 0x8000000e_u32, 0x90000002_u32)
    acl = ACL::Darwin::List.new([darwin_entry, opaque], flags: 0xf1238001_u32)
    copy = ACL::Darwin::List.from_bytes(acl.to_bytes)
    copy.entries.should eq(acl.entries)
    copy.flags.should eq(acl.flags)
    expect_raises(ACL::UnsupportedACLError) { copy.validate_for_write! }
  end

  it "does not let constructor or accessor arrays mutate the snapshot" do
    entries = [darwin_entry]
    acl = ACL::Darwin::List.new(entries)
    entries.clear
    acl.entries.clear
    acl.size.should eq(1)
  end

  it "represents an empty ACL independently from no ACL" do
    acl = ACL::Darwin::List.new
    acl.to_bytes.size.should eq(44)
    ACL::Darwin::List.from_bytes(acl.to_bytes).empty?.should be_true
  end

  it "rejects oversized counts before decoding or allocating" do
    bytes = ACL::Darwin::List.new.to_bytes
    bytes[36, 4].copy_from("ffffffff".hexbytes)
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.from_bytes(bytes) }
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.new(Array.new(129, darwin_entry)) }
  end

  it "rejects truncation, extra bytes, wrong magic and non-ACL owner data" do
    bytes = ACL::Darwin::List.new([darwin_entry]).to_bytes
    (0...bytes.size).each do |size|
      expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.from_bytes(bytes[0, size]) }
    end
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.from_bytes(bytes + Bytes[0]) }
    bad = bytes.dup
    bad[0] = 0
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.from_bytes(bad) }
    bad = bytes.dup
    bad[4] = 1
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::List.from_bytes(bad) }
  end

  it "keeps libc's tentative and XNU's actual defer-inherit bits distinct" do
    ACL::Darwin::List::LIBC_DEFER_INHERIT.should eq(1_u32)
    ACL::Darwin::List::KERNEL_DEFER_INHERIT.should eq(0x10000_u32)
  end

  it "changes one entry without reordering the rest" do
    a = darwin_entry
    b = ACL::Darwin::Entry.deny(a.principal, ACL::Darwin::Permission::WriteData)
    acl = ACL::Darwin::List.new([a, b], flags: 0x8001_u32)
    acl.with_entry(0, b).entries.should eq([b, b])
    acl.entries.should eq([a, b])
    acl.with_entry(0, b).flags.should eq(0x8001_u32)
  end
end

require "../../../src/acl/platform/darwin/path_policy"
describe ACL::Platform::Darwin::PathPolicy do
  it "opens symlinks themselves without rejecting them or blocking on FIFOs" do
    # XNU vn_authorize_open_existing returns ELOOP for VLNK + O_NOFOLLOW;
    # O_SYMLINK already disables following the final component in vn_open_auth.
    flags = ACL::Platform::Darwin::PathPolicy.no_follow_open_flags
    (flags & 0x00000100).should eq(0)     # no O_NOFOLLOW
    (flags & 0x00200000).should_not eq(0) # O_SYMLINK
    (flags & 0x01000000).should_not eq(0) # O_CLOEXEC
    (flags & 0x00000004).should_not eq(0) # O_NONBLOCK
  end
end
