require "../src/acl/windows"

{% if flag?(:win32) %}
  path = ARGV[0]? || __FILE__
  snapshot = ACL::Windows.read(path, follow_symlinks: false)
  puts "owner=#{snapshot.owner}, group=#{snapshot.group}"
  puts "DACL=#{snapshot.dacl.presence}, protected=#{snapshot.descriptor.dacl_protected?}"
  if list = snapshot.dacl.list
    list.each do |entry|
      puts "type=#{entry.type} flags=0x#{entry.flags.to_s(16)} SID=#{entry.sid} mask=#{entry.mask}"
    end
  end
  # SACL was deliberately not requested. snapshot.sacl would raise rather
  # than falsely report that no audit/mandatory-policy information exists.
{% else %}
  abort "This example requires Windows. The Windows binary model is available on any host."
{% end %}
