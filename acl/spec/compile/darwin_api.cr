require "../../src/acl/darwin"
# Runtime branches intentionally force every native path through type checking
# and LLVM code generation. This fixture must never be run on a real filesystem.
if ARGV.size == 456_789
  path = ARGV[0]
  list = ACL::Darwin.read(path).list
  ACL::Darwin.read(path, follow_symlinks: false)
  ACL::Darwin.read(0)
  ACL::Darwin.write(path, list)
  ACL::Darwin.write(path, list, follow_symlinks: false)
  ACL::Darwin.write(0, list)
  ACL::Darwin.write(path, nil)
  ACL::Darwin.write(0, ACL::Darwin::List.new)
end
