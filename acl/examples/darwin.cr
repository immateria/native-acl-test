require "../src/acl/darwin"

{% if flag?(:darwin) %}
  path = ARGV[0]? || __FILE__
  snapshot = ACL::Darwin.read(path, follow_symlinks: false)
  if list = snapshot.list
    puts "#{list.size} entries, ACL flags=0x#{list.flags.to_s(16)}"
    list.each do |entry|
      puts "#{entry.principal} kind=#{entry.kind} flags=0x#{entry.flags.to_s(16)} rights=0x#{entry.raw_rights.to_s(16)}"
    end
  else
    puts "ACL evidence: #{snapshot.presence}"
  end
{% else %}
  abort "This example requires macOS. The Darwin binary model is available on any host."
{% end %}
