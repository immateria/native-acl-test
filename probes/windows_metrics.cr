# Test-only functions. Read the bridge's own primary token; do not adjust it.
module Bridge
  @[Link("advapi32")]
  lib TokenAPI
    fun OpenProcessToken(process : Void*, access : UInt32, token : Void**) : Int32
    fun GetTokenInformation(token : Void*, kind : UInt32, buffer : Void*, size : UInt32, returned : UInt32*) : Int32
    fun LookupPrivilegeValueW(system : UInt16*, name : UInt16*, luid : Int64*) : Int32
  end

  private def token_info(token : Void*, kind : UInt32) : Bytes
    size = 0_u32
    TokenAPI.GetTokenInformation(token, kind, nil, 0_u32, pointerof(size))
    unless size > 0 && size <= 1_048_576
      raise ACL::Windows::NativeError.new("GetTokenInformation(size)", "bridge", LibC.GetLastError)
    end
    bytes = Bytes.new(size.to_i)
    if TokenAPI.GetTokenInformation(token, kind, bytes.to_unsafe, bytes.size.to_u32, pointerof(size)) == 0
      raise ACL::Windows::NativeError.new("GetTokenInformation", "bridge", LibC.GetLastError)
    end
    bytes[0, size.to_i]
  end

  def token_evidence
    token = Pointer(Void).null
    source = "thread"
    if LabImpersonation.OpenThreadToken(LabThread.GetCurrentThread, 8_u32, 1, pointerof(token)) == 0
      code = LibC.GetLastError
      raise ACL::Windows::NativeError.new("OpenThreadToken", "bridge", code) unless code == 1008
      source = "process"
      if TokenAPI.OpenProcessToken(LabWindows.GetCurrentProcess, 8_u32, pointerof(token)) == 0
        raise ACL::Windows::NativeError.new("OpenProcessToken", "bridge", LibC.GetLastError)
      end
    end
    begin
      user = token_info(token, 1_u32)
      sid_pointer = Pointer(Void*).new(user.to_unsafe.address).value
      sid_length = ACL::Platform::Windows::C.GetLengthSid(sid_pointer)
      raise "invalid TOKEN_USER SID" unless 8 <= sid_length <= user.size
      user_sid = ACL::Windows::SID.from_bytes(Slice.new(sid_pointer.as(UInt8*), sid_length.to_i)).to_s

      groups_bytes = token_info(token, 2_u32)
      group_count = IO::ByteFormat::LittleEndian.decode(UInt32, groups_bytes)
      pointer_size = sizeof(Void*)
      group_offset = (4 + pointer_size - 1) & ~(pointer_size - 1)
      group_stride = (pointer_size + 4 + pointer_size - 1) & ~(pointer_size - 1)
      raise "truncated TOKEN_GROUPS" unless group_count <= 4096 && group_offset + group_count.to_i * group_stride <= groups_bytes.size
      groups = Array(NamedTuple(sid: String, attributes: UInt32, enabled: Bool, deny_only: Bool)).new(group_count.to_i)
      group_count.to_i.times do |index|
        pos = group_offset + index * group_stride
        group_pointer = Pointer(Void*).new(groups_bytes.to_unsafe.address + pos).value
        group_sid_length = ACL::Platform::Windows::C.GetLengthSid(group_pointer)
        raise "invalid TOKEN_GROUPS SID" unless 8 <= group_sid_length <= 68
        group_sid = ACL::Windows::SID.from_bytes(Slice.new(group_pointer.as(UInt8*), group_sid_length.to_i)).to_s
        attributes = IO::ByteFormat::LittleEndian.decode(UInt32, groups_bytes[pos + pointer_size, 4])
        groups << {sid: group_sid, attributes: attributes, enabled: attributes.bit(2) == 1, deny_only: attributes.bit(4) == 1}
      end

      integrity_bytes = token_info(token, 25_u32)
      integrity_pointer = Pointer(Void*).new(integrity_bytes.to_unsafe.address).value
      integrity_length = ACL::Platform::Windows::C.GetLengthSid(integrity_pointer)
      raise "invalid TOKEN_MANDATORY_LABEL SID" unless 8 <= integrity_length <= 68
      integrity_sid = ACL::Windows::SID.from_bytes(Slice.new(integrity_pointer.as(UInt8*), integrity_length.to_i)).to_s

      bytes = token_info(token, 3_u32)
      count = IO::ByteFormat::LittleEndian.decode(UInt32, bytes)
      raise "truncated TOKEN_PRIVILEGES" unless count <= (bytes.size - 4) // 12
      privileges = {} of String => String
      {"SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeChangeNotifyPrivilege"}.each do |name|
        luid = 0_i64
        if TokenAPI.LookupPrivilegeValueW(nil, name.to_utf16, pointerof(luid)) == 0
          raise ACL::Windows::NativeError.new("LookupPrivilegeValueW", name, LibC.GetLastError)
        end
        state = "unassigned"
        count.to_i.times do |i|
          pos = 4 + 12*i
          next unless IO::ByteFormat::LittleEndian.decode(Int64, bytes[pos, 8]) == luid
          attributes = IO::ByteFormat::LittleEndian.decode(UInt32, bytes[pos + 8, 4])
          state = attributes.bit(1) == 1 ? "enabled" : "disabled"
          break
        end
        privileges[name] = state
      end
      {user_sid: user_sid, token_source: source, integrity_sid: integrity_sid, groups: groups, privileges: privileges}.to_json
    ensure
      LibC.CloseHandle(token)
    end
  end

  def handle_count : Int64
    count = 0_u32
    if LabWindows.GetProcessHandleCount(LabWindows.GetCurrentProcess, pointerof(count)) == 0
      raise ACL::Windows::NativeError.new("GetProcessHandleCount", "bridge", LibC.GetLastError)
    end
    count.to_i64
  end

  def stress_windows(path : String, mode : String, n : Int32) : String
    raise ArgumentError.new("iterations out of range") unless (1..1_000_000).includes?(n)
    original = ACL::Windows.read(path)
    operation = -> do
      case mode
      when "read_handles" then ACL::Windows.read(path)
      when "read_write"
        ACL::Windows.write(path, ACL::Windows::Update.from_snapshot(original, ACL::Windows::Information::DACL))
        ACL::Windows.read(path)
      when "invalid_handles"
        begin
          ACL::Windows.read_handle(Pointer(Void).null)
          raise "invalid handle unexpectedly accepted"
        rescue e : ACL::Windows::NativeError
          raise e unless e.code == 6
        end
      when "serialize"
        bytes = original.descriptor.to_bytes
        raise "serialization drift" unless ACL::Windows::Descriptor.from_bytes(bytes).to_bytes == bytes
      when "noop" # Measurement-only negative control.
      else raise ArgumentError.new("unknown stress mode")
      end
      nil
    end
    # Prove this process's counter can see live, explicitly owned handles.
    held = [] of File
    initial = handle_count
    during = initial
    begin
      12.times { held << File.open(path) }
      during = handle_count
    ensure
      held.each &.close
    end
    released = handle_count
    32.times { operation.call }
    GC.collect
    samples = [handle_count]
    batches = Math.min(n, 4)
    started = clock
    batches.times do |i|
      (n // batches + (i < n % batches ? 1 : 0)).times { operation.call }
      GC.collect
      samples << handle_count
    end
    {iterations: n, warmup: 32, samples: samples, resources_before: samples.first, resources_after: samples.last,
     positive_control: {before: initial, held: during, released: released}, seconds: (clock - started).total_seconds}.to_json
  end
end
