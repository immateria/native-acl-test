# :nodoc:
# Path opens only. The OS calculates the base mask. Keep the selector (what is
# read/written) independent from the access mask (rights on the file handle).
struct ACL::Platform::Windows::OpenAccess
  private alias Selection = ACL::Windows::Information
  private READ_CONTROL = 0x00020000_u32

  getter preferred : UInt32

  private def initialize(@base : UInt32, read_control : Bool)
    @preferred = read_control ? (@base | READ_CONTROL) : @base
  end

  def self.for_update(base : UInt32, selection : Selection) : self
    # Current NTFS builds can accept the SDK-calculated write handle and still
    # reject SetSecurityInfo unless READ_CONTROL was granted on that handle.
    # Prefer the augmented mask for every selector. OpenAccess#open retains the
    # exact-mask fallback for delegated write-only handles whose augmented open
    # is itself denied.
    new(base, true)
  end

  def self.for_query(base : UInt32, selection : Selection) : self
    new(base, selection.includes?(Selection::SACL))
  end

  # The block is ONLY an open, never a query or mutation. On builds which
  # support delegated write-only access, do not make READ_CONTROL mandatory.
  # Every native open failure is retained so diagnostics do not lose the first
  # compatibility attempt when the exact-mask fallback also fails.
  def open(label : String = "path", &)
    attempts = [] of ACL::Windows::OpenAttempt
    begin
      return yield @preferred
    rescue error : ACL::Windows::NativeError
      raise error unless error.operation == "CreateFileW"
      attempts << ACL::Windows::OpenAttempt.new(@preferred, error.code)
      unless error.code == 5 && @preferred != @base
        raise ACL::Windows::PathOpenError.new(label, attempts)
      end
    end

    begin
      yield @base
    rescue error : ACL::Windows::NativeError
      raise error unless error.operation == "CreateFileW"
      attempts << ACL::Windows::OpenAttempt.new(@base, error.code)
      raise ACL::Windows::PathOpenError.new(label, attempts)
    end
  end
end
