# Line-oriented JSON bridge into the shard in this checkpoint. No shell evaluation.
require "json"
require "file_utils"
require "../acl/src/acl/darwin"
require "../acl/src/acl/windows"

{% if flag?(:win32) %}
  @[Link("kernel32")]
  lib LabWindows
    fun GetCurrentProcess : Void*
    fun GetProcessHandleCount(process : Void*, count : UInt32*) : Int32
    fun GetHandleInformation(handle : Void*, flags : UInt32*) : Int32
  end

  @[Link("advapi32")]
  lib LabImpersonation
    fun LogonUserW(username : UInt16*, domain : UInt16*, password : UInt16*, logon_type : UInt32, provider : UInt32, token : Void**) : Int32
    fun ImpersonateLoggedOnUser(token : Void*) : Int32
    fun RevertToSelf : Int32
    fun OpenThreadToken(thread : Void*, access : UInt32, open_as_self : Int32, token : Void**) : Int32
  end

  @[Link("kernel32")]
  lib LabThread
    fun GetCurrentThread : Void*
  end

  require "./windows_metrics"
{% end %}

module Bridge
  extend self

  def clock
    {% if compare_versions(Crystal::VERSION, "1.21.0") >= 0 %}
      Time.instant
    {% else %}
      Time.monotonic
    {% end %}
  end

  def number(req, name, default = 0_i64) : Int64
    req[name]?.try(&.as_i64) || default.to_i64
  end

  def darwin_value(snapshot : ACL::Darwin::Snapshot) : String
    list = snapshot.list
    {presence: snapshot.presence.to_s, flags: list.try(&.flags), hex: list.try(&.to_bytes.hexstring),
     entries: list.try { |l| l.entries.map { |e| {principal: e.principal.to_s, raw_flags: e.raw_flags, raw_rights: e.raw_rights} } }}.to_json
  end

  def acl_value(state : ACL::Windows::ACLState)
    {presence: state.presence.to_s, hex: state.list.try(&.to_bytes.hexstring),
     entries: state.list.try { |l| l.entries.map { |e|
       {type: e.type, flags: e.flags, mask: e.mask, sid: e.sid.try(&.to_s),
        object_type: e.object_type.try(&.to_s), inherited_object_type: e.inherited_object_type.try(&.to_s),
        application_data: e.application_data.try(&.hexstring), hex: e.to_bytes.hexstring}
     } }}
  end

  def windows_value(descriptor : ACL::Windows::Descriptor) : String
    {hex: descriptor.to_bytes.hexstring, control: descriptor.control, owner: descriptor.owner.try(&.to_s), group: descriptor.group.try(&.to_s),
     dacl: acl_value(descriptor.dacl), sacl: acl_value(descriptor.sacl)}.to_json
  end

  def dispatch(req : JSON::Any) : String
    op = req["op"].as_s
    case op
    when "model.darwin"
      list = ACL::Darwin::List.from_bytes(req["hex"].as_s.hexbytes)
      {hex: list.to_bytes.hexstring, count: list.size, flags: list.flags}.to_json
    when "model.windows"
      windows_value(ACL::Windows::Descriptor.from_bytes(req["hex"].as_s.hexbytes))
    when "model.sid"
      sid = ACL::Windows::SID.parse(req["sid"].as_s)
      {text: sid.to_s, hex: sid.to_bytes.hexstring}.to_json
    when "model.darwin_attribute"
      darwin_value(ACL::Darwin::Snapshot.from_attribute_bytes(req["hex"].as_s.hexbytes))
    when "model.update"
      desc = ACL::Windows::Descriptor.from_bytes(req["hex"].as_s.hexbytes)
      update = ACL::Windows::Update.new(desc, ACL::Windows::Information.new(number(req, "information", 4).to_u32),
        allow_null_dacl: req["allow_null"]?.try(&.as_bool) || false)
      {native_information: update.native_information}.to_json
    else
      {% if flag?(:darwin) %}
        native_darwin(req)
      {% elsif flag?(:win32) %}
        native_windows(req)
      {% else %}
        raise ACL::UnsupportedACLError.new("native operation requires macOS or Windows")
      {% end %}
    end
  end

  {% if flag?(:darwin) %}
    def native_darwin(req) : String
      op = req["op"].as_s
      path = req["path"]?.try(&.as_s) || ""
      follow = req["follow"]?.try(&.as_bool) != false
      case op
      when "darwin.read"
        if req["borrowed"]?.try(&.as_bool)
          File.open(path) do |file|
            value = darwin_value(ACL::Darwin.read(file.fd))
            raise "borrowed fd was closed" if LibC.fcntl(file.fd, LibC::F_GETFD, 0) < 0
            value
          end
        else
          darwin_value(ACL::Darwin.read(path, follow_symlinks: follow))
        end
      when "darwin.write"
        list = req["hex"]?.try(&.as_s?).try { |hex| ACL::Darwin::List.from_bytes(hex.hexbytes) }
        if req["borrowed"]?.try(&.as_bool)
          File.open(path) do |file|
            ACL::Darwin.write(file.fd, list)
            raise "borrowed fd was closed" if LibC.fcntl(file.fd, LibC::F_GETFD, 0) < 0
          end
        else
          ACL::Darwin.write(path, list, follow_symlinks: follow)
        end
        "{}"
      when "darwin.invalid_handle"
        darwin_value(ACL::Darwin.read(-1))
      when "darwin.rename_handle"
        File.open(path) do |file|
          first = ACL::Darwin.read(file.fd)
          File.rename(path, path + ".renamed")
          second = ACL::Darwin.read(file.fd)
          raise "renamed inode changed ACL" unless darwin_value(first) == darwin_value(second)
          darwin_value(second)
        end
      when "darwin.stress"
        n = number(req, "iterations", 1000).to_i
        mode = req["mode"].as_s
        before = Dir.children("/dev/fd").size
        started = clock
        original = ACL::Darwin.read(path)
        n.times do
          case mode
          when "read_write"
            ACL::Darwin.write(path, original.list)
            ACL::Darwin.read(path)
          when "invalid_handles"
            begin
              ACL::Darwin.read(-1)
              raise "invalid FD unexpectedly accepted"
            rescue ACL::SystemError
            end
          when "serialize"
            list = original.list.not_nil!
            raise "serialization drift" unless ACL::Darwin::List.from_bytes(list.to_bytes).to_bytes == list.to_bytes
          else
            ACL::Darwin.read(path)
          end
        end
        GC.collect
        {iterations: n, seconds: (clock - started).total_seconds, resources_before: before, resources_after: Dir.children("/dev/fd").size}.to_json
      else
        raise "unknown operation #{op}"
      end
    end
  {% end %}

  {% if flag?(:win32) %}
    def with_windows_handle(path : String, access : UInt32, follow : Bool, &)
      wide = path.to_utf16
      flags = 0x02000000_u32 | (follow ? 0_u32 : 0x00200000_u32)
      h = LibC.CreateFileW(wide, access, 7_u32, nil, 3_u32, flags, nil)
      raise ACL::Windows::NativeError.new("bridge.CreateFileW", path, LibC.GetLastError) if h.address == UInt64::MAX
      begin
        yield h
        flag = 0_u32
        raise "borrowed handle closed by shard" if LabWindows.GetHandleInformation(h, pointerof(flag)) == 0
      ensure
        LibC.CloseHandle(h)
      end
    end

    def update(req) : ACL::Windows::Update
      desc = ACL::Windows::Descriptor.from_bytes(req["hex"].as_s.hexbytes)
      policy = ACL::Windows::Inheritance.parse(req["inheritance"]?.try(&.as_s) || "Preserve")
      ACL::Windows::Update.new(desc, ACL::Windows::Information.new(number(req, "information", 4).to_u32),
        dacl_inheritance: policy, allow_null_dacl: req["allow_null"]?.try(&.as_bool) || false)
    end

    def native_windows(req) : String
      op = req["op"].as_s
      path = req["path"]?.try(&.as_s) || ""
      info = ACL::Windows::Information.new(number(req, "information", 7).to_u32)
      follow = req["follow"]?.try(&.as_bool) != false
      case op
      when "windows.token"
        token_evidence
      when "windows.create"
        if req["directory"]?.try(&.as_bool)
          Dir.mkdir(path)
        else
          File.write(path, req["contents"]?.try(&.as_s) || "ACL lab synthetic data\n")
        end
        windows_value(ACL::Windows.read(path).descriptor)
      when "windows.file_access"
        with_windows_handle(path, number(req, "access").to_u32, follow) { |_handle| }
        "{}"
      when "windows.file_operation"
        case req["operation"].as_s
        when "read"
          {bytes: File.read(path).bytesize}.to_json
        when "write"
          File.open(path, "r+") { |file| file.print(req["contents"]?.try(&.as_s) || "W") }
          "{}"
        when "append"
          File.open(path, "a") { |file| file.print(req["contents"]?.try(&.as_s) || "A") }
          "{}"
        when "delete"
          File.delete(path)
          "{}"
        when "mkdir"
          Dir.mkdir(path)
          "{}"
        when "rmdir"
          Dir.delete(path)
          "{}"
        when "stat"
          info = File.info(path)
          {size: info.size, directory: info.directory?}.to_json
        else
          raise ArgumentError.new("unknown file operation")
        end
      when "windows.read"
        if req["borrowed"]?.try(&.as_bool)
          result = ""
          desired = 0_u32
          ACL::Platform::Windows::C.QuerySecurityAccessMask(info.value, pointerof(desired))
          desired |= 0x20000_u32 if info.includes?(ACL::Windows::Information::SACL)
          desired = req["open_mask"].as_i64.to_u32 if req["open_mask"]?
          with_windows_handle(path, desired, follow) { |h| result = windows_value(ACL::Windows.read_handle(h, info).descriptor) }
          result
        else
          snapshot = ACL::Windows.read(path, info, follow_symlinks: follow)
          if guard = req["guard"]?.try(&.as_s)
            case guard
            when "owner" then snapshot.owner
            when "group" then snapshot.group
            when "dacl"  then snapshot.dacl
            when "sacl"  then snapshot.sacl
            end
          end
          windows_value(snapshot.descriptor)
        end
      when "windows.write"
        u = update(req)
        if req["borrowed"]?.try(&.as_bool)
          desired = 0_u32
          ACL::Platform::Windows::C.SetSecurityAccessMask(u.native_information, pointerof(desired))
          desired |= 0x20000_u32 if u.selected?(ACL::Windows::Information::DACL)
          desired = req["open_mask"].as_i64.to_u32 if req["open_mask"]?
          with_windows_handle(path, desired, follow) { |h| ACL::Windows.write_handle(h, u) }
        else
          ACL::Windows.write(path, u, follow_symlinks: follow)
        end
        "{}"
      when "windows.sddl"
        windows_value(ACL::Windows::Descriptor.from_sddl(req["sddl"].as_s))
      when "windows.to_sddl"
        {sddl: ACL::Windows::Descriptor.from_bytes(req["hex"].as_s.hexbytes).to_sddl(info)}.to_json
      when "windows.limited_handle"
        result = ""
        with_windows_handle(path, 0_u32, true) { |h| result = windows_value(ACL::Windows.read_handle(h).descriptor) }
        result
      when "windows.invalid_handle"
        windows_value(ACL::Windows.read_handle(Pointer(Void).null).descriptor)
      when "windows.rename_handle"
        result = ""
        with_windows_handle(path, 0x00020000_u32, true) do |h|
          first = ACL::Windows.read_handle(h)
          File.rename(path, path + ".renamed")
          second = ACL::Windows.read_handle(h)
          raise "renamed object changed descriptor" unless first.descriptor.to_bytes == second.descriptor.to_bytes
          result = windows_value(second.descriptor)
        end
        result
      when "windows.handle_cycle"
        result = ""
        with_windows_handle(path, 0x000e0000_u32, true) do |h|
          before = ACL::Windows.read_handle(h)
          begin
            ACL::Windows.write_handle(h, update(req))
            result = windows_value(ACL::Windows.read_handle(h).descriptor)
          ensure
            policy = before.descriptor.dacl_protected? ? ACL::Windows::Inheritance::Protect : ACL::Windows::Inheritance::Unprotect
            ACL::Windows.write_handle(h, ACL::Windows::Update.from_snapshot(before, ACL::Windows::Information::DACL,
              dacl_inheritance: policy, allow_null_dacl: true))
          end
        end
        result
      when "windows.stress"
        stress_windows(path, req["mode"].as_s, number(req, "iterations", 1000).to_i)
      else
        raise "unknown operation #{op}"
      end
    end
  {% end %}

  {% if flag?(:win32) %}
    private def with_impersonated_user(username : String, domain : String, &block : -> String) : String
      password = ENV["ACL_LAB_PASSWORD"]? || raise "missing ACL lab credential"
      token = Pointer(Void).null
      if LabImpersonation.LogonUserW(username.to_utf16, domain.to_utf16, password.to_utf16, 2_u32, 0_u32, pointerof(token)) == 0
        raise ACL::Windows::NativeError.new("LogonUserW", username, LibC.GetLastError)
      end
      begin
        if LabImpersonation.ImpersonateLoggedOnUser(token) == 0
          raise ACL::Windows::NativeError.new("ImpersonateLoggedOnUser", username, LibC.GetLastError)
        end
        begin
          block.call
        ensure
          if LabImpersonation.RevertToSelf == 0
            raise ACL::Windows::NativeError.new("RevertToSelf", username, LibC.GetLastError)
          end
        end
      ensure
        LibC.CloseHandle(token) unless token.null?
      end
    end
  {% end %}

  def respond(req : JSON::Any) : String
    raw = {% if flag?(:win32) %}
            if user = req["impersonate_user"]?.try(&.as_s?)
              domain = req["impersonate_domain"]?.try(&.as_s?) || "."
              with_impersonated_user(user, domain) { dispatch(req) }
            else
              dispatch(req)
            end
          {% else %}
            dispatch(req)
          {% end %}
    value = JSON.parse(raw)
    {ok: true, value: value}.to_json
  rescue e
    code = case e
           when ACL::Windows::NativeError then e.code.to_i64
           when ACL::SystemError          then e.errno.value.to_i64
           else                                nil
           end
    {ok: false, error: e.class.name, message: e.message, operation: e.as?(ACL::Windows::NativeError).try(&.operation), code: code}.to_json
  end
end

STDIN.each_line do |line|
  begin
    req = JSON.parse(line)
    puts Bridge.respond(req)
  rescue e
    puts({ok: false, error: e.class.name, message: e.message, code: nil}.to_json)
  end
  STDOUT.flush
end
