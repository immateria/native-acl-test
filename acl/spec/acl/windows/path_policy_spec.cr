require "../../spec_helper"
require "../../../src/acl/platform/windows/path_policy"

private alias PathPolicy = ACL::Platform::Windows::PathPolicy

describe PathPolicy do
  it "preserves short relative and absolute paths" do
    PathPolicy.native("fixture.txt", "C:\\work").should eq("fixture.txt")
    PathPolicy.native("C:\\work\\fixture.txt", "C:\\ignored").should eq("C:\\work\\fixture.txt")
  end

  it "converts a long relative path to an extended absolute path" do
    base = "C:\\" + "workspace\\" * 4 + "runner"
    relative = "x" * 240
    expected = "\\\\?\\#{base}\\#{relative}"
    PathPolicy.native(relative, base).should eq(expected)
  end

  it "converts a long UNC path to the extended UNC namespace" do
    path = "\\\\server\\share\\#{"directory\\" * 25}fixture.txt"
    PathPolicy.native(path, "C:\\ignored").should eq("\\\\?\\UNC\\#{path[2..]}")
  end

  it "preserves existing Win32 device namespace paths" do
    extended = "\\\\?\\C:\\#{"x" * 300}"
    device = "\\\\.\\PhysicalDrive0"
    PathPolicy.native(extended, "C:\\ignored").should eq(extended)
    PathPolicy.native(device, "C:\\ignored").should eq(device)
  end

  it "rejects embedded NUL before path conversion" do
    expect_raises(ArgumentError, "path contains NUL") do
      PathPolicy.native("bad\0path", "C:\\work")
    end
  end
end
