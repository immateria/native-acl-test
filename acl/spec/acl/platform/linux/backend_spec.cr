require "../../../spec_helper"
require "file_utils"

{% if flag?(:linux) %}
  alias LinuxPOSIXEntry = ACL::POSIX::Entry
  alias LinuxPOSIXPermission = ACL::POSIX::Permission
  alias LinuxPOSIXList = ACL::POSIX::List
  alias LinuxPOSIXScope = ACL::POSIX::Scope

  private def dropped_privilege_read(setpriv : String, path : String) : Process::Status
    Process.run(
      setpriv,
      ["--reuid=65534", "--regid=65534", "--clear-groups", "cat", path],
      output: Process::Redirect::Close,
      error: Process::Redirect::Close,
    )
  end

  describe ACL do
    it "reads the synthesized access ACL of a file without an extended ACL" do
      path = File.tempname("crystal-acl-access")
      File.write(path, "test")
      File.chmod(path, 0o640)

      begin
        acl = ACL.access(path)
        acl.scope.should eq(LinuxPOSIXScope::Access)
        acl.entries.should eq([
          LinuxPOSIXEntry.owner(LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write),
          LinuxPOSIXEntry.owning_group(LinuxPOSIXPermission::Read),
          LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
        ])
      ensure
        File.delete?(path)
      end
    end

    it "writes and reads an extended access ACL" do
      path = File.tempname("crystal-acl-extended")
      File.write(path, "test")

      expected = LinuxPOSIXList.new(LinuxPOSIXScope::Access, [
        LinuxPOSIXEntry.owner(LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write),
        LinuxPOSIXEntry.user(123_456_u32, LinuxPOSIXPermission::Read),
        LinuxPOSIXEntry.owning_group(LinuxPOSIXPermission::None),
        LinuxPOSIXEntry.mask(LinuxPOSIXPermission::Read),
        LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
      ]).canonical

      begin
        ACL.set(path, expected)
        actual = ACL.access(path)
        actual.entries.should eq(expected.entries)
        (File.info(path).permissions.value & 0o777).should eq(0o640)
      ensure
        File.delete?(path)
      end
    end

    it "inherits a directory default ACL and constrains it by the creation mode" do
      directory = File.tempname("crystal-acl-inheritance")
      Dir.mkdir(directory)
      child = File.join(directory, "child")

      defaults = LinuxPOSIXList.new(LinuxPOSIXScope::Default, [
        LinuxPOSIXEntry.owner(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.user(
          123_456_u32,
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.owning_group(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.mask(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
      ]).canonical

      old_umask = LibC.umask(0)
      begin
        ACL.set(directory, defaults)
        File.open(child, "w", 0o666) { }

        inherited = ACL.access(child)
        inherited.entries.should eq([
          LinuxPOSIXEntry.owner(LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write),
          LinuxPOSIXEntry.user(
            123_456_u32,
            LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
          ),
          LinuxPOSIXEntry.owning_group(
            LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
          ),
          LinuxPOSIXEntry.mask(LinuxPOSIXPermission::Read),
          LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
        ])
        inherited.effective_permissions(inherited.entries[1]).should eq(LinuxPOSIXPermission::Read)
      ensure
        LibC.umask(old_umask)
        FileUtils.rm_rf(directory)
      end
    end

    it "enforces the POSIX mask for a matching named user" do
      setpriv = "/usr/bin/setpriv"
      unless File.exists?(setpriv) && LibC.getuid == 0
        pending! "requires root and util-linux setpriv"
      end

      path = File.tempname("crystal-acl-mask-access", dir: "/tmp")
      File.write(path, "secret")

      allowed = LinuxPOSIXList.new(LinuxPOSIXScope::Access, [
        LinuxPOSIXEntry.owner(LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write),
        LinuxPOSIXEntry.user(65_534_u32, LinuxPOSIXPermission::Read),
        LinuxPOSIXEntry.owning_group(LinuxPOSIXPermission::None),
        LinuxPOSIXEntry.mask(LinuxPOSIXPermission::Read),
        LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
      ])
      masked = LinuxPOSIXList.new(LinuxPOSIXScope::Access, [
        LinuxPOSIXEntry.owner(LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write),
        LinuxPOSIXEntry.user(65_534_u32, LinuxPOSIXPermission::Read),
        LinuxPOSIXEntry.owning_group(LinuxPOSIXPermission::None),
        LinuxPOSIXEntry.mask(LinuxPOSIXPermission::None),
        LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
      ])

      begin
        ACL.set(path, allowed)
        dropped_privilege_read(setpriv, path).success?.should be_true

        ACL.set(path, masked)
        dropped_privilege_read(setpriv, path).success?.should be_false
      ensure
        File.delete?(path)
      end
    end

    it "writes, reads, and deletes a directory default ACL" do
      path = File.tempname("crystal-acl-default")
      Dir.mkdir(path)

      expected = LinuxPOSIXList.new(LinuxPOSIXScope::Default, [
        LinuxPOSIXEntry.owner(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Write | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.user(
          123_456_u32,
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.owning_group(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.mask(
          LinuxPOSIXPermission::Read | LinuxPOSIXPermission::Execute
        ),
        LinuxPOSIXEntry.other(LinuxPOSIXPermission::None),
      ]).canonical

      begin
        ACL.default(path).should be_nil
        ACL.set(path, expected)
        ACL.default(path).not_nil!.entries.should eq(expected.entries)
        ACL.delete_default(path)
        ACL.default(path).should be_nil
        ACL.delete_default(path) # idempotent when no default xattr exists
      ensure
        FileUtils.rm_rf(path)
      end
    end

    it "rejects embedded NUL bytes before entering native code" do
      expect_raises(ArgumentError, /NUL byte/) do
        ACL.access("bad\0path")
      end
    end

    it "reports native errors with the operation and path" do
      path = File.tempname("crystal-acl-missing")

      error = expect_raises(ACL::SystemError) do
        ACL.access(path)
      end
      error.operation.should eq("acl_get_file")
      error.path.should eq(path)
      error.errno.should eq(Errno::ENOENT)
    end
  end
{% end %}
