require "../../src/acl/windows"
# Forces all native operations to instantiate; never run this fixture against
# a live path. Object generation is not a substitute for linking or execution.
if ARGV.size == 456_789
  path = ARGV[0]
  snapshot = ACL::Windows.read(path)
  ACL::Windows.read(path, ACL::Windows::Information::Backup, follow_symlinks: false)
  snapshot = ACL::Windows.read_handle(Pointer(Void).null)
  descriptor = ACL::Windows::Descriptor.from_sddl("D:(A;;GR;;;WD)")
  puts descriptor.to_sddl
  update = ACL::Windows::Update.new(descriptor, ACL::Windows::Information::DACL)
  ACL::Windows.write(path, update)
  ACL::Windows.write(path, update, follow_symlinks: false)
  ACL::Windows.write_handle(Pointer(Void).null, update)
  ACL::Windows.set_dacl(path, descriptor.dacl.list.not_nil!)
end
