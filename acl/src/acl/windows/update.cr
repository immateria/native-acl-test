module ACL::Windows
  enum Inheritance
    Preserve
    Protect
    Unprotect
  end

  # A preflighted, explicit selection for SetSecurityInfo. Building an Update
  # never changes the OS. Applying it is not a transaction/CAS, and Windows may
  # propagate inheritable ACEs to existing children.
  class Update
    getter descriptor : Descriptor
    getter information : Information
    getter native_information : UInt32

    def initialize(@descriptor : Descriptor, @information : Information,
                   dacl_inheritance : Inheritance = Inheritance::Preserve,
                   sacl_inheritance : Inheritance = Inheritance::Preserve,
                   allow_null_dacl : Bool = false)
      Snapshot.validate_information!(@information, allow_backup: false)
      if selected?(Information::Owner) && @descriptor.owner.nil?
        raise InvalidACLError.new("selected owner SID is absent")
      end
      if selected?(Information::Group) && @descriptor.group.nil?
        raise InvalidACLError.new("selected primary group SID is absent")
      end
      if selected?(Information::DACL)
        state = @descriptor.dacl
        raise InvalidACLError.new("cannot apply an absent DACL; select a present or explicit null DACL") if state.presence.absent?
        validate_categories!(state, dacl: true)
        if state.presence.null? && !allow_null_dacl
          raise InvalidACLError.new("null DACL requires allow_null_dacl: true")
        end
      elsif !dacl_inheritance.preserve?
        raise InvalidACLError.new("DACL inheritance change requires DACL selection")
      end
      if sacl_selected?
        raise InvalidACLError.new("selected SACL components are absent") if @descriptor.sacl.presence.absent?
        validate_categories!(@descriptor.sacl, dacl: false)
      elsif !sacl_inheritance.preserve?
        raise InvalidACLError.new("SACL inheritance change requires SACL selection")
      end
      unless sacl_inheritance.preserve? || selected?(Information::SACL)
        raise InvalidACLError.new("SACL protection change requires audit SACL selection, not only a filtered SACL component")
      end
      @native_information = @information.value
      @native_information |= inheritance_bits(dacl_inheritance, 0x80000000_u32, 0x20000000_u32)
      @native_information |= inheritance_bits(sacl_inheritance, 0x40000000_u32, 0x10000000_u32)
    end

    def self.from_snapshot(snapshot : Snapshot, information : Information, **options) : self
      snapshot.require!(information)
      new(snapshot.descriptor, information, **options)
    end

    def selected?(part : Information) : Bool
      @information.includes?(part)
    end

    def sacl_selected? : Bool
      @information.value & 0x1f8_u32 != 0
    end

    private def validate_categories!(state : ACLState, dacl : Bool) : Nil
      return unless list = state.list
      list.each do |entry|
        # Unknown future types remain opaque; the native OS decides whether
        # they are valid. Defined families must not cross DACL/SACL categories.
        case entry.category
        when ACE::Category::Discretionary
          unless dacl
            raise InvalidACLError.new("ACE type #{entry.type} is not valid in a SACL")
          end
        when ACE::Category::System
          if dacl
            raise InvalidACLError.new("ACE type #{entry.type} is not valid in a DACL")
          end
          validate_sacl_selector!(entry)
        when ACE::Category::Unknown
          # Preserve and pass through future opaque types rather than assigning
          # them to a selector that did not exist when this shard was built.
        end
      end
    end

    private def validate_sacl_selector!(entry : ACE) : Nil
      required = case entry.type
                 when 2_u8, 3_u8, 7_u8, 8_u8, 13_u8, 14_u8, 15_u8, 16_u8
                   Information::SACL
                 when 17_u8 then Information::Label
                 when 18_u8 then Information::Attribute
                 when 19_u8 then Information::Scope
                 when 20_u8 then Information::ProcessTrustLabel
                 when 21_u8 then Information::AccessFilter
                 else
                   return
                 end
      unless selected?(required)
        raise InvalidACLError.new("ACE type #{entry.type} requires #{required}")
      end
    end

    private def inheritance_bits(value : Inheritance, protect : UInt32, unprotect : UInt32) : UInt32
      case value
      when .preserve?  then 0_u32
      when .protect?   then protect
      when .unprotect? then unprotect
      else
        raise ArgumentError.new("invalid inheritance operation")
      end
    end
  end

  # Win32 ERROR_* codes are not errno and are not always GetLastError values.
  class NativeError < ACL::Error
    getter operation : String
    getter object : String
    getter code : UInt32

    def initialize(@operation : String, @object : String, @code : UInt32, detail : String? = nil)
      message = "#{@operation} failed for #{@object.inspect}: Win32 error #{@code}"
      message += " (#{detail})" if detail
      super(message)
    end
  end

  struct OpenAttempt
    getter access : UInt32
    getter code : UInt32

    def initialize(@access : UInt32, @code : UInt32)
    end
  end

  # A failed path open retains all access masks attempted by the compatibility
  # policy. The final Win32 code remains available through NativeError#code.
  class PathOpenError < NativeError
    @attempts : Array(OpenAttempt)

    def initialize(object : String, attempts : Enumerable(OpenAttempt))
      @attempts = attempts.to_a.dup
      raise ArgumentError.new("path-open error requires at least one attempt") if @attempts.empty?
      detail = @attempts.join(", ") { |attempt| "0x#{attempt.access.to_s(16).rjust(8, '0')}=>#{attempt.code}" }
      super("CreateFileW", object, @attempts.last.code, detail)
    end

    def attempts : Array(OpenAttempt)
      @attempts.dup
    end
  end
end
