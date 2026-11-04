require "../../spec_helper"

alias POSIXEntryUnderTest = ACL::POSIX::Entry
alias POSIXPermissionUnderTest = ACL::POSIX::Permission
alias POSIXTagUnderTest = ACL::POSIX::Tag

describe ACL::POSIX::Entry do
  it "requires qualifiers only for named users and groups" do
    expect_raises(ArgumentError, /requires a qualifier/) do
      POSIXEntryUnderTest.new(POSIXTagUnderTest::User, POSIXPermissionUnderTest::Read)
    end

    expect_raises(ArgumentError, /must not have a qualifier/) do
      POSIXEntryUnderTest.new(POSIXTagUnderTest::Owner, POSIXPermissionUnderTest::Read, 1_u32)
    end
  end

  it "rejects undefined tag values" do
    invalid = POSIXTagUnderTest.new(99)

    expect_raises(ArgumentError, /unsupported POSIX tag value 99/) do
      POSIXEntryUnderTest.new(invalid, POSIXPermissionUnderTest::Read)
    end
  end

  it "rejects permission bits outside the POSIX rwx set" do
    invalid = POSIXPermissionUnderTest.new(0x08_u8)

    expect_raises(ArgumentError, /unsupported POSIX permission bits 0x08/) do
      POSIXEntryUnderTest.owner(invalid)
    end
  end

  it "formats permission bits in rwx order" do
    (POSIXPermissionUnderTest::Read | POSIXPermissionUnderTest::Execute).to_posix.should eq("r-x")
    POSIXPermissionUnderTest::None.to_posix.should eq("---")
  end
end
