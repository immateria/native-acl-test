require "../../src/acl"

alias Entry = ACL::POSIX::Entry
alias Permission = ACL::POSIX::Permission
alias List = ACL::POSIX::List
alias Scope = ACL::POSIX::Scope

acl = List.new(Scope::Access, [
  Entry.owner(Permission::Read | Permission::Write),
  Entry.owning_group(Permission::Read),
  Entry.other(Permission::None),
])
acl.validate!
raise "unexpected" unless acl.to_text == "user::rw-\ngroup::r--\nother::---\n"
