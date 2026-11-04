require "../../spec_helper"

alias POSIXEntry = ACL::POSIX::Entry
alias POSIXPermission = ACL::POSIX::Permission
alias POSIXScope = ACL::POSIX::Scope

POSIX_MINIMAL_ENTRIES = -> {
  [
    POSIXEntry.owner(POSIXPermission::Read | POSIXPermission::Write),
    POSIXEntry.owning_group(POSIXPermission::Read),
    POSIXEntry.other(POSIXPermission::None),
  ]
}

describe ACL::POSIX::List do
  it "rejects undefined scope values" do
    invalid = POSIXScope.new(99)

    expect_raises(ArgumentError, /unsupported POSIX scope value 99/) do
      ACL::POSIX::List.new(invalid, POSIX_MINIMAL_ENTRIES.call)
    end
  end

  it "validates a minimal access ACL" do
    acl = ACL::POSIX::List.new(POSIXScope::Access, POSIX_MINIMAL_ENTRIES.call)
    acl.validate!.should be(acl)
  end

  it "owns its entries independently from constructor input and returned snapshots" do
    source = POSIX_MINIMAL_ENTRIES.call
    acl = ACL::POSIX::List.new(POSIXScope::Access, source)

    source << POSIXEntry.mask(POSIXPermission::None)
    acl.size.should eq(3)

    snapshot = acl.entries.as(Array(POSIXEntry))
    snapshot << POSIXEntry.mask(POSIXPermission::None)
    acl.size.should eq(3)
  end

  it "rejects duplicate named-user qualifiers" do
    acl = ACL::POSIX::List.new(POSIXScope::Access, POSIX_MINIMAL_ENTRIES.call + [
      POSIXEntry.user(42_u32, POSIXPermission::Read),
      POSIXEntry.user(42_u32, POSIXPermission::Write),
      POSIXEntry.mask(POSIXPermission::Read | POSIXPermission::Write),
    ])

    expect_raises(ACL::InvalidACLError, /duplicate named user 42/) do
      acl.validate!
    end
  end

  it "requires a mask when named user or group entries exist" do
    acl = ACL::POSIX::List.new(POSIXScope::Access, POSIX_MINIMAL_ENTRIES.call + [
      POSIXEntry.user(42_u32, POSIXPermission::Read),
    ])

    expect_raises(ACL::InvalidACLError, /mask/) do
      acl.validate!
    end
  end

  it "calculates the mask from named users, owning group, and named groups" do
    acl = ACL::POSIX::List.new(POSIXScope::Access, [
      POSIXEntry.owner(POSIXPermission::Read | POSIXPermission::Write | POSIXPermission::Execute),
      POSIXEntry.user(42_u32, POSIXPermission::Read),
      POSIXEntry.owning_group(POSIXPermission::Write),
      POSIXEntry.group(7_u32, POSIXPermission::Execute),
      POSIXEntry.mask(POSIXPermission::None),
      POSIXEntry.other(POSIXPermission::None),
    ])

    acl.calculated_mask.should eq(
      POSIXPermission::Read | POSIXPermission::Write | POSIXPermission::Execute
    )
  end

  it "replaces the mask and returns a canonical, validated ACL" do
    acl = ACL::POSIX::List.new(POSIXScope::Access, [
      POSIXEntry.other(POSIXPermission::None),
      POSIXEntry.group(9_u32, POSIXPermission::Execute),
      POSIXEntry.owner(POSIXPermission::Read | POSIXPermission::Write),
      POSIXEntry.user(100_u32, POSIXPermission::Read),
      POSIXEntry.owning_group(POSIXPermission::Write),
      POSIXEntry.mask(POSIXPermission::None),
      POSIXEntry.user(4_u32, POSIXPermission::Write),
    ])

    normalized = acl.with_calculated_mask
    normalized.validate!
    normalized.entries.map(&.tag).should eq([
      ACL::POSIX::Tag::Owner,
      ACL::POSIX::Tag::User,
      ACL::POSIX::Tag::User,
      ACL::POSIX::Tag::OwningGroup,
      ACL::POSIX::Tag::Group,
      ACL::POSIX::Tag::Mask,
      ACL::POSIX::Tag::Other,
    ])
    normalized.entries.select(&.user?).map(&.qualifier).should eq([4_u32, 100_u32])
    normalized.mask.not_nil!.permissions.should eq(
      POSIXPermission::Read | POSIXPermission::Write | POSIXPermission::Execute
    )
  end

  it "applies the mask only to the POSIX group class" do
    owner = POSIXEntry.owner(POSIXPermission::Read | POSIXPermission::Write)
    named_user = POSIXEntry.user(42_u32, POSIXPermission::Read | POSIXPermission::Write)
    group = POSIXEntry.owning_group(POSIXPermission::Read | POSIXPermission::Write)
    other = POSIXEntry.other(POSIXPermission::Read | POSIXPermission::Write)
    mask = POSIXEntry.mask(POSIXPermission::Read)
    acl = ACL::POSIX::List.new(POSIXScope::Access, [owner, named_user, group, mask, other])

    acl.effective_permissions(owner).should eq(owner.permissions)
    acl.effective_permissions(named_user).should eq(POSIXPermission::Read)
    acl.effective_permissions(group).should eq(POSIXPermission::Read)
    acl.effective_permissions(other).should eq(other.permissions)
  end

  it "renders deterministic numeric POSIX ACL text" do
    acl = ACL::POSIX::List.new(POSIXScope::Default, [
      POSIXEntry.owner(POSIXPermission::Read | POSIXPermission::Write | POSIXPermission::Execute),
      POSIXEntry.user(42_u32, POSIXPermission::Read),
      POSIXEntry.owning_group(POSIXPermission::Read | POSIXPermission::Execute),
      POSIXEntry.mask(POSIXPermission::Read | POSIXPermission::Execute),
      POSIXEntry.other(POSIXPermission::None),
    ])

    acl.to_text.should eq(
      "default:user::rwx\n" +
      "default:user:42:r--\n" +
      "default:group::r-x\n" +
      "default:mask::r-x\n" +
      "default:other::---\n"
    )
  end
end
