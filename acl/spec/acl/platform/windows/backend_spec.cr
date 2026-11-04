require "../../../spec_helper"
require "../../../../src/acl/windows"

{% if flag?(:win32) %}
  private def with_windows_file(&)
    path = File.tempname("acl-windows-雪")
    File.write(path, "fixture")
    begin
      yield path
    ensure
      File.delete?(path)
    end
  end

  describe "Windows native security descriptors" do
    it "uses native SDDL conversion without confusing null and empty DACLs" do
      null = ACL::Windows::Descriptor.from_sddl("D:NO_ACCESS_CONTROL")
      empty = ACL::Windows::Descriptor.from_sddl("D:")
      null.dacl.presence.null?.should be_true
      empty.dacl.presence.present?.should be_true
      empty.dacl.list.not_nil!.size.should eq(0)
      copy = ACL::Windows::Descriptor.from_sddl(empty.to_sddl(ACL::Windows::Information::DACL))
      copy.dacl.presence.present?.should be_true
      copy.dacl.list.not_nil!.size.should eq(0)
    end

    it "reads Unicode paths and records that SACL was not requested" do
      with_windows_file do |path|
        snapshot = ACL::Windows.read(path)
        snapshot.owner.should_not be_nil
        snapshot.queried.should eq(ACL::Windows::Information::Basic)
        expect_raises(ACL::UnsupportedACLError) { snapshot.sacl }
      end
    end

    it "writes only a DACL and restores the original protection policy" do
      with_windows_file do |path|
        before = ACL::Windows.read(path)
        original = before.dacl.list.not_nil!
        world = ACL::Windows::SID.parse("S-1-1-0")
        addition = ACL::Windows::ACE.allow(world, 0x00020080_u32) # read-control/attributes, not data
        begin
          ACL::Windows.set_dacl(path, original.with_entries(original.entries + [addition]), inheritance: :protect)
          after = ACL::Windows.read(path)
          after.owner.should eq(before.owner)
          after.group.should eq(before.group)
          after.descriptor.dacl_protected?.should be_true
          after.dacl.list.not_nil!.entries.any? { |ace| ace.sid == world && ace.mask == addition.mask }.should be_true
        ensure
          policy = before.descriptor.dacl_protected? ? ACL::Windows::Inheritance::Protect : ACL::Windows::Inheritance::Unprotect
          ACL::Windows.write(path, ACL::Windows::Update.from_snapshot(before, ACL::Windows::Information::DACL,
            dacl_inheritance: policy))
        end
      end
    end

    it "returns Win32 codes and rejects embedded NUL before opening a path" do
      expect_raises(ArgumentError) { ACL::Windows.read("a\0b") }
      error = expect_raises(ACL::Windows::NativeError) { ACL::Windows.read(File.tempname("acl-missing")) }
      error.operation.should eq("CreateFileW")
      error.code.should eq(2_u32) # ERROR_FILE_NOT_FOUND
    end

    {% if env("ACL_NATIVE_SACL_TESTS") == "1" %}
      it "requests backup security data only with caller-supplied privileges" do
        with_windows_file do |path|
          snapshot = ACL::Windows.read(path, ACL::Windows::Information::Backup)
          snapshot.sacl # must be readable even if structurally absent/null
          snapshot.queried.should eq(ACL::Windows::Information::Backup)
        end
      end
    {% end %}
  end
{% end %}
