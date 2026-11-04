require "../../../spec_helper"
require "../../../../src/acl/darwin"
require "file_utils"

{% if flag?(:darwin) %}
  lib DarwinMembershipSpec
    fun geteuid : UInt32
    fun mbr_uid_to_uuid(uid : UInt32, uuid : UInt8*) : Int32
  end

  private def current_darwin_principal : UUID
    bytes = StaticArray(UInt8, 16).new(0_u8)
    result = DarwinMembershipSpec.mbr_uid_to_uuid(DarwinMembershipSpec.geteuid, bytes.to_unsafe)
    raise "mbr_uid_to_uuid failed: #{result}" unless result == 0
    UUID.new(bytes)
  end

  private def with_darwin_file(&)
    path = File.tempname("acl-darwin")
    File.write(path, "fixture")
    begin
      yield path
    ensure
      File.delete?(path)
    end
  end

  describe "Darwin native filesystem ACLs" do
    it "records no returned ACL after removal without confusing a failed lookup" do
      with_darwin_file do |path|
        ACL::Darwin.write(path, nil)
        ACL::Darwin.read(path).list.should be_nil
        expect_raises(ACL::SystemError) { ACL::Darwin.read(path + ".missing") }
      end
    end

    it "reads and writes ordered UUID entries through paths and borrowed FDs" do
      with_darwin_file do |path|
        entry = ACL::Darwin::Entry.allow(current_darwin_principal, ACL::Darwin::Permission::ReadData)
        expected = ACL::Darwin::List.new([entry])
        ACL::Darwin.write(path, expected)
        ACL::Darwin.read(path).list.not_nil!.entries.should eq(expected.entries)
        File.open(path) do |file|
          ACL::Darwin.read(file.fd).list.not_nil!.entries.should eq(expected.entries)
          ACL::Darwin.write(file.fd, expected)
          file.read_char.should eq('f') # borrowed FD is still open
          ACL::Darwin.write(file.fd, nil)
          ACL::Darwin.read(file.fd).list.should be_nil
        end
      end
    end

    it "writes a symlink ACL without writing its target ACL" do
      with_darwin_file do |path|
        link = path + ".symlink"
        File.symlink(path, link)
        begin
          ACL::Darwin.write(path, nil)
          entry = ACL::Darwin::Entry.allow(current_darwin_principal, ACL::Darwin::Permission::ReadAttributes)
          acl = ACL::Darwin::List.new([entry])
          ACL::Darwin.write(link, acl, follow_symlinks: false)
          ACL::Darwin.read(link, follow_symlinks: false).list.not_nil!.entries.should eq(acl.entries)
          ACL::Darwin.read(path).list.should be_nil
          ACL::Darwin.write(link, nil, follow_symlinks: false)
        ensure
          File.delete?(link)
        end
      end
    end

    it "lets the kernel perform inheritance rather than synthesizing it" do
      directory = File.tempname("acl-darwin-inheritance")
      Dir.mkdir(directory)
      child = File.join(directory, "child")
      begin
        flags = ACL::Darwin::Entry::FILE_INHERIT | ACL::Darwin::Entry::DIRECTORY_INHERIT
        entry = ACL::Darwin::Entry.allow(current_darwin_principal, ACL::Darwin::Permission::ReadData, flags)
        ACL::Darwin.write(directory, ACL::Darwin::List.new([entry]))
        File.write(child, "child")
        acl = ACL::Darwin.read(child).list.not_nil!
        acl.entries.any? { |ace| ace.principal == entry.principal && ace.inherited? }.should be_true
      ensure
        File.delete?(child)
        Dir.delete(directory)
      end
    end

    it "reads a present zero-entry ACL without losing ACL-level flags" do
      with_darwin_file do |path|
        expected = ACL::Darwin::List.new(flags: ACL::Darwin::List::NO_INHERIT)
        ACL::Darwin.write(path, expected)
        snapshot = ACL::Darwin.read(path)
        snapshot.presence.present?.should be_true
        snapshot.list.not_nil!.empty?.should be_true
        snapshot.list.not_nil!.flags.should eq(expected.flags)
      end
    end

    it "rejects NUL paths before native calls" do
      expect_raises(ArgumentError) { ACL::Darwin.read("a\0b") }
      expect_raises(ArgumentError) { ACL::Darwin.write("a\0b", nil) }
    end
  end
{% end %}
