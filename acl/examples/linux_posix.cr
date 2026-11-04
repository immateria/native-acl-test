require "../src/acl"
require "file_utils"

alias Entry = ACL::POSIX::Entry
alias Permission = ACL::POSIX::Permission
alias List = ACL::POSIX::List
alias Scope = ACL::POSIX::Scope

path = File.tempname("crystal-acl-example")
File.write(path, "acl example\n")

begin
  desired = List.new(Scope::Access, [
    Entry.owner(Permission::Read | Permission::Write),
    Entry.user(123_456_u32, Permission::Read),
    Entry.owning_group(Permission::None),
    Entry.mask(Permission::Read),
    Entry.other(Permission::None),
  ])

  ACL.set(path, desired)
  puts ACL.access(path).to_text
ensure
  File.delete?(path)
end
