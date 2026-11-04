require "../../spec_helper"

# Raw, principal-free bytes from the returned APFS fixtures (arm64 macOS 15.4.1).
describe "captured APFS getattrlist responses" do
  it "distinguishes removal from installing an empty flagged ACL on the same file" do
    omitted = ACL::Darwin::Snapshot.from_attribute_bytes("2000000000000080000000000000000000000000000000000000000000000000".hexbytes)
    empty = ACL::Darwin::Snapshot.from_attribute_bytes("4c0000000000408000000000000000000000000000000000080000002c0000006dc12c0100000000000000000000000000000000000000000000000000000000000000000000000000000200".hexbytes)
    omitted.presence.not_returned?.should be_true
    omitted.list.should be_nil
    empty.presence.present?.should be_true
    empty.list.not_nil!.empty?.should be_true
    empty.list.not_nil!.flags.should eq(0x20000_u32)
  end

  it "rejects the successful size-only response for the 100-byte record" do
    expect_raises(ACL::InvalidACLError) { ACL::Darwin::Snapshot.from_attribute_bytes("64000000".hexbytes) }
  end
end
