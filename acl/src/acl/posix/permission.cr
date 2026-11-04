module ACL::POSIX
  # POSIX read, write, and execute/search permission bits.
  @[Flags]
  enum Permission : UInt8
    None    = 0_u8
    Execute = 1_u8
    Write   = 2_u8
    Read    = 4_u8

    # Renders this permission set as a three-character `rwx` field.
    def to_posix : String
      String.build(3) do |io|
        io << (includes?(Read) ? 'r' : '-')
        io << (includes?(Write) ? 'w' : '-')
        io << (includes?(Execute) ? 'x' : '-')
      end
    end
  end
end
