require "../../spec_helper"
require "../../../src/acl/platform/windows/open_access"

private alias Access = ACL::Platform::Windows::OpenAccess
private alias Selection = ACL::Windows::Information
private alias OpenError = ACL::Windows::NativeError

describe Access do
  it "adds READ_CONTROL to the DACL writer without replacing native rights" do
    Access.for_update(0x40000_u32, Selection::DACL).preferred.should eq(0x60000_u32)
    Access.for_update(0xc0000_u32, Selection::Owner | Selection::DACL).preferred.should eq(0xe0000_u32)
  end

  it "does not widen unrelated updates or filtered queries" do
    Access.for_update(0x80000_u32, Selection::Owner | Selection::Group).preferred.should eq(0x80000_u32)
    Access.for_update(0x1000000_u32, Selection::SACL).preferred.should eq(0x1000000_u32)
    Access.for_query(0x1234_u32, Selection::Label).preferred.should eq(0x1234_u32)
  end

  it "retains ACCESS_SYSTEM_SECURITY on a SACL query" do
    Access.for_query(0x1000000_u32, Selection::SACL).preferred.should eq(0x1020000_u32)
  end

  it "uses the exact delegated mask only if the augmented open was denied" do
    tried = [] of UInt32
    result = Access.for_update(0x40000_u32, Selection::DACL).open do |mask|
      tried << mask
      raise OpenError.new("CreateFileW", "fixture", 5_u32) if tried.size == 1
      :opened
    end
    result.should eq(:opened)
    tried.should eq([0x60000_u32, 0x40000_u32])
  end

  it "does not retry missing paths, privilege failures, or identical masks" do
    [{0x40000_u32, 2_u32}, {0x40000_u32, 1314_u32}, {0x60000_u32, 5_u32}].each do |base, code|
      attempts = 0
      error = expect_raises(OpenError) do
        Access.for_update(base, Selection::DACL).open do |_|
          attempts += 1
          raise OpenError.new("CreateFileW", "fixture", code)
        end
      end
      attempts.should eq(1)
      error.code.should eq(code)
    end
  end
  it "returns every attempted mask and error from a failed delegated open" do
    calls = [] of UInt32
    error = expect_raises(ACL::Windows::PathOpenError) do
      Access.for_query(0x1000000_u32, Selection::SACL).open("fixture") do |mask|
        calls << mask
        raise OpenError.new("CreateFileW", "fixture", calls.size == 1 ? 5_u32 : 1314_u32)
      end
    end
    calls.should eq([0x1020000_u32, 0x1000000_u32])
    error.code.should eq(1314_u32)
    error.attempts.map(&.access).should eq(calls)
    error.attempts.map(&.code).should eq([5_u32, 1314_u32])
    copy = error.attempts
    copy.clear
    error.attempts.size.should eq(2)
    error.message.not_nil!.should contain("0x01020000=>5")
    error.message.not_nil!.should contain("0x01000000=>1314")
  end

  it "wraps a single native path-open failure with its attempted mask" do
    error = expect_raises(ACL::Windows::PathOpenError) do
      Access.for_update(0x80000_u32, Selection::Owner).open("missing") do |mask|
        raise OpenError.new("CreateFileW", "missing", 2_u32) if mask == 0x80000_u32
        :unreachable
      end
    end
    error.attempts.size.should eq(1)
    error.attempts.first.access.should eq(0x80000_u32)
    error.attempts.first.code.should eq(2_u32)
  end

  it "does not interpret an access denial from a setter as an open failure" do
    calls = 0
    error = expect_raises(OpenError) do
      Access.for_update(0x40000_u32, Selection::DACL).open do |_|
        calls += 1
        raise OpenError.new("SetSecurityInfo", "fixture", 5_u32)
      end
    end
    calls.should eq(1)
    error.operation.should eq("SetSecurityInfo")
  end
end
