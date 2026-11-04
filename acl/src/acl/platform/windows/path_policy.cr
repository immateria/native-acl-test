require "string/utf16"

# :nodoc:
# Win32 path APIs historically apply MAX_PATH unless the caller uses the
# extended-length namespace or the executable opts into long paths. A shard
# must not silently depend on every consuming executable carrying that
# manifest, so paths whose resolved spelling reaches MAX_PATH are namespaced
# before CreateFileW.
struct ACL::Platform::Windows::PathPolicy
  private MAX_PATH        = 260
  private EXTENDED_PREFIX = "\\\\?\\"
  private DEVICE_PREFIX   = "\\\\.\\"
  private UNC_PREFIX      = "\\\\"

  def self.native(path : String, base : String = Dir.current) : String
    validate!(path)
    return path if device_namespace?(path)

    expanded = Path.windows(path).expand(Path.windows(base)).to_s
    return path if expanded.to_utf16.size < MAX_PATH

    if expanded.starts_with?(UNC_PREFIX)
      "#{EXTENDED_PREFIX}UNC\\#{expanded[2..]}"
    else
      "#{EXTENDED_PREFIX}#{expanded}"
    end
  end

  private def self.device_namespace?(path : String) : Bool
    path.starts_with?(EXTENDED_PREFIX) || path.starts_with?(DEVICE_PREFIX)
  end

  private def self.validate!(path : String) : Nil
    raise ArgumentError.new("path contains NUL") if path.includes?('\0')
    raise ArgumentError.new("path is not valid UTF-8") unless path.valid_encoding?
  end
end
