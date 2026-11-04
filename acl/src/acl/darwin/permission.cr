module ACL::Darwin
  # Native Darwin rights, not POSIX mode bits or Windows ACCESS_MASK values.
  @[Flags]
  enum Permission : UInt32
    ReadData           = 1_u32 << 1
    WriteData          = 1_u32 << 2
    Execute            = 1_u32 << 3
    Delete             = 1_u32 << 4
    AppendData         = 1_u32 << 5
    DeleteChild        = 1_u32 << 6
    ReadAttributes     = 1_u32 << 7
    WriteAttributes    = 1_u32 << 8
    ReadExtAttributes  = 1_u32 << 9
    WriteExtAttributes = 1_u32 << 10
    ReadSecurity       = 1_u32 << 11
    WriteSecurity      = 1_u32 << 12
    ChangeOwner        = 1_u32 << 13
    Synchronize        = 1_u32 << 20
    GenericAll         = 1_u32 << 21
    GenericExecute     = 1_u32 << 22
    GenericWrite       = 1_u32 << 23
    GenericRead        = 1_u32 << 24

    ListDirectory   = ReadData
    AddFile         = WriteData
    Search          = Execute
    AddSubdirectory = AppendData
  end
end
