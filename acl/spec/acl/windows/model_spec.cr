require "../../spec_helper"
require "../../../src/acl/windows"

private def world_sid
  ACL::Windows::SID.parse("S-1-1-0")
end

private def allowed_ace
  ACL::Windows::ACE.allow(world_sid, 0x00120089_u32)
end

describe ACL::Windows::SID do
  it "uses big-endian authority and little-endian subauthorities" do
    sid = ACL::Windows::SID.parse("S-1-281474976710655-16909060-4294967295")
    sid.to_bytes.hexstring.should eq("0102ffffffffffff04030201ffffffff")
    ACL::Windows::SID.from_bytes(sid.to_bytes).to_s.should eq(sid.to_s)
  end

  it "round-trips binary SIDs even when Win32 rejects its own zero-subauthority text" do
    {"0", "1", "5", "16", "4294967301", "281474976710655"}.each do |authority|
      text = "S-1-#{authority}"
      sid = ACL::Windows::SID.parse(text)
      sid.to_bytes.hexstring.should eq("0100" + authority.to_u64.to_s(16).rjust(12, '0'))
      ACL::Windows::SID.from_bytes(sid.to_bytes).to_s.should eq(text)
    end
  end

  it "owns its byte storage" do
    bytes = world_sid.to_bytes
    sid = ACL::Windows::SID.from_bytes(bytes)
    bytes[0] = 99
    sid.to_bytes[0] = 99
    sid.to_s.should eq("S-1-1-0")
  end

  it "bounds revision, authority, subauthorities and exact binary length" do
    ["S-2-1-0", "S-1-281474976710656-0", "S-1-1-4294967296", "S-1--1", "S-1-1-+2", "Everyone"].each do |text|
      expect_raises(ACL::InvalidACLError) { ACL::Windows::SID.parse(text) }
    end
    expect_raises(ACL::InvalidACLError) { ACL::Windows::SID.parse("S-1-1" + "-0" * 16) }
    expect_raises(ACL::InvalidACLError) { ACL::Windows::SID.from_bytes(world_sid.to_bytes + Bytes[0]) }
    (0...12).each do |length|
      expect_raises(ACL::InvalidACLError) { ACL::Windows::SID.from_bytes(world_sid.to_bytes[0, length]) }
    end
  end
end

describe ACL::Windows::ACE do
  it "encodes the basic allow ACE and decodes its SID and mask" do
    ace = allowed_ace
    ace.to_bytes.hexstring.should eq("0000140089001200010100000000000100000000")
    ace.type.should eq(0)
    ace.mask.should eq(0x00120089_u32)
    ace.sid.should eq(world_sid)
  end

  it "preserves object GUID byte order and callback application data" do
    uuid = UUID.new("00112233-4455-6677-8899-aabbccddeeff")
    ace = ACL::Windows::ACE.object(11_u8, world_sid, 0x12345678_u32,
      object_type: uuid, application_data: Bytes[1, 2, 3, 4])
    ace.object_type.should eq(uuid)
    ace.inherited_object_type.should be_nil
    ace.to_bytes[12, 16].hexstring.should eq("33221100554477668899aabbccddeeff")
    ace.application_data.should eq(Bytes[1, 2, 3, 4])
    ACL::Windows::ACE.from_bytes(ace.to_bytes).to_bytes.should eq(ace.to_bytes)
  end

  it "retains unknown ACE payloads without claiming to understand them" do
    bytes = Bytes[0xfe, 0x80, 8, 0, 0xde, 0xad, 0xbe, 0xef]
    ace = ACL::Windows::ACE.from_bytes(bytes)
    bytes[4] = 0
    ace.sid.should be_nil
    ace.mask.should be_nil
    ace.to_bytes.should eq(Bytes[0xfe, 0x80, 8, 0, 0xde, 0xad, 0xbe, 0xef])
    expect_raises(ACL::UnsupportedACLError) { ace.with_mask(1_u32) }
  end

  it "rejects truncated ACEs, invalid SID lengths and invalid object flags" do
    bytes = allowed_ace.to_bytes
    (0...bytes.size).each do |length|
      expect_raises(ACL::InvalidACLError) { ACL::Windows::ACE.from_bytes(bytes[0, length]) }
    end
    bad = bytes.dup
    bad[9] = 15
    expect_raises(ACL::InvalidACLError) { ACL::Windows::ACE.from_bytes(bad) }
    object = ACL::Windows::ACE.object(5_u8, world_sid, 1_u32).to_bytes
    object[8] = 4
    expect_raises(ACL::InvalidACLError) { ACL::Windows::ACE.from_bytes(object) }
  end

  it "edits only mask and flags without destroying application data" do
    ace = ACL::Windows::ACE.callback(9_u8, world_sid, 1_u32, Bytes[1, 2, 3, 4])
    changed = ace.with_mask(2_u32).with_flags(0x10_u8)
    changed.mask.should eq(2_u32)
    changed.flags.should eq(0x10_u8)
    changed.application_data.should eq(Bytes[1, 2, 3, 4])
    ace.mask.should eq(1_u32)
  end
end

describe ACL::Windows::List do
  it "preserves ACE order, header reserved bits, and trailing allocation padding" do
    a = allowed_ace
    b = ACL::Windows::ACE.deny(world_sid, 1_u32)
    bytes = ACL::Windows::List.new([a, b]).to_bytes + Bytes[0xaa, 0xbb, 0xcc, 0xdd]
    bytes[1] = 0x7f
    bytes[2] = bytes.size.to_u8
    bytes[6] = 0x81
    list = ACL::Windows::List.from_bytes(bytes)
    list.entries.map(&.type).should eq([0_u8, 1_u8])
    list.to_bytes.should eq(bytes)
    list.entries.clear
    list.size.should eq(2)
  end

  it "uses ACL_REVISION_DS for object ACEs and rejects a revision-2 object ACL" do
    ace = ACL::Windows::ACE.object(5_u8, world_sid, 1_u32)
    list = ACL::Windows::List.new([ace])
    list.revision.should eq(4)
    bytes = list.to_bytes
    bytes[0] = 2
    expect_raises(ACL::InvalidACLError) { ACL::Windows::List.from_bytes(bytes) }
  end

  it "rejects invalid ACL lengths and ACE counts" do
    bytes = ACL::Windows::List.new([allowed_ace]).to_bytes
    bad = bytes.dup
    bad[4] = 2
    expect_raises(ACL::InvalidACLError) { ACL::Windows::List.from_bytes(bad) }
    bad = bytes.dup
    bad[2] = 7
    expect_raises(ACL::InvalidACLError) { ACL::Windows::List.from_bytes(bad) }
    expect_raises(ACL::InvalidACLError) { ACL::Windows::List.from_bytes(bytes + Bytes[0]) }
  end

  it "replaces an entry without reordering or changing header/padding data" do
    list = ACL::Windows::List.new([allowed_ace, ACL::Windows::ACE.deny(world_sid, 2_u32)])
    changed = list.with_entry(0, allowed_ace.with_mask(3_u32))
    changed.entries.map(&.mask).should eq([3_u32, 2_u32])
    list.entries.first.mask.should eq(0x00120089_u32)
  end
end

private def categorized_ace(type : UInt8) : ACL::Windows::ACE
  if {5_u8, 6_u8, 7_u8, 8_u8, 11_u8, 12_u8, 15_u8, 16_u8}.includes?(type)
    ACL::Windows::ACE.object(type, world_sid, 1_u32)
  elsif type == 4_u8 || type > 21_u8
    ACL::Windows::ACE.from_bytes(Bytes[type, 0_u8, 4_u8, 0_u8])
  else
    bytes = allowed_ace.to_bytes
    bytes[0] = type
    ACL::Windows::ACE.from_bytes(bytes)
  end
end

describe ACL::Windows::ACE::Category do
  it "classifies every defined Windows ACE family without guessing future types" do
    {0_u8, 1_u8, 4_u8, 5_u8, 6_u8, 9_u8, 10_u8, 11_u8, 12_u8}.each do |type|
      categorized_ace(type).category.should eq(ACL::Windows::ACE::Category::Discretionary)
    end
    {2_u8, 3_u8, 7_u8, 8_u8, 13_u8, 14_u8, 15_u8, 16_u8, 17_u8, 18_u8, 19_u8, 20_u8, 21_u8}.each do |type|
      categorized_ace(type).category.should eq(ACL::Windows::ACE::Category::System)
    end
    ACL::Windows::ACE.from_bytes(Bytes[254_u8, 0_u8, 4_u8, 0_u8]).category.should eq(ACL::Windows::ACE::Category::Unknown)
  end
end

describe ACL::Windows::Descriptor do
  it "keeps absent, null and present-empty DACLs distinct" do
    states = [ACL::Windows::ACLState.absent, ACL::Windows::ACLState.null, ACL::Windows::ACLState.present(ACL::Windows::List.new)]
    states.each do |state|
      descriptor = ACL::Windows::Descriptor.new(dacl: state)
      decoded = ACL::Windows::Descriptor.from_bytes(descriptor.to_bytes)
      decoded.dacl.presence.should eq(state.presence)
      decoded.dacl.list.try(&.size).should eq(state.list.try(&.size))
    end
    states.map { |state| ACL::Windows::Descriptor.new(dacl: state).to_bytes.hexstring }.uniq.size.should eq(3)
  end

  it "round trips owner/group, SACL, DACL, control and resource manager byte" do
    dacl = ACL::Windows::ACLState.present(ACL::Windows::List.new([allowed_ace]))
    sacl = ACL::Windows::ACLState.present(ACL::Windows::List.new([ACL::Windows::ACE.audit(world_sid, 1_u32, success: true, failure: true)]))
    descriptor = ACL::Windows::Descriptor.new(owner: world_sid, group: world_sid, dacl: dacl, sacl: sacl,
      control: 0x7000_u16, resource_manager: 0xab_u8)
    bytes = descriptor.to_bytes
    copy = ACL::Windows::Descriptor.from_bytes(bytes)
    copy.owner.should eq(world_sid)
    copy.group.should eq(world_sid)
    copy.control.should eq(0xf014_u16)
    copy.resource_manager.should eq(0xab_u8)
    copy.to_bytes.should eq(bytes)
    changed = copy.with_dacl(ACL::Windows::ACLState.present(ACL::Windows::List.new))
    changed.sacl.list.not_nil!.to_bytes.should eq(sacl.list.not_nil!.to_bytes)
    changed.control.should eq(copy.control)
  end

  it "retains arbitrary trailing bytes and gives out independent buffers" do
    bytes = ACL::Windows::Descriptor.new.to_bytes + Bytes[1, 2, 3, 4]
    descriptor = ACL::Windows::Descriptor.from_bytes(bytes)
    descriptor.to_bytes.should eq(bytes)
    bytes[0] = 0
    descriptor.to_bytes[0] = 0
    descriptor.to_bytes[0].should eq(1)
  end

  it "bounds offsets, alignment, descriptor revision and self-relative state" do
    bytes = ACL::Windows::Descriptor.new(owner: world_sid).to_bytes
    ["ffffffff", "04000000", "15000000", "00010000"].each do |offset|
      bad = bytes.dup
      bad[4, 4].copy_from(offset.hexbytes)
      expect_raises(ACL::InvalidACLError) { ACL::Windows::Descriptor.from_bytes(bad) }
    end
    bad = bytes.dup
    bad[3] = 0
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Descriptor.from_bytes(bad) }
    bad = bytes.dup
    bad[0] = 2
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Descriptor.from_bytes(bad) }
  end

  it "does not mistake an unqueried SACL for an absent SACL" do
    snapshot = ACL::Windows::Snapshot.new(ACL::Windows::Descriptor.new, ACL::Windows::Information::DACL)
    expect_raises(ACL::UnsupportedACLError) { snapshot.sacl }
    expect_raises(ACL::UnsupportedACLError) { snapshot.owner }
    snapshot.dacl.presence.absent?.should be_true
  end
end

describe ACL::Windows::Update do
  it "requires explicit null-DACL consent and never maps absent to null" do
    info = ACL::Windows::Information::DACL
    absent = ACL::Windows::Descriptor.new
    null = ACL::Windows::Descriptor.new(dacl: ACL::Windows::ACLState.null)
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Update.new(absent, info, allow_null_dacl: true) }
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Update.new(null, info) }
    ACL::Windows::Update.new(null, info, allow_null_dacl: true).native_information.should eq(4_u32)
  end

  it "changes only selected components and makes inheritance policy explicit" do
    descriptor = ACL::Windows::Descriptor.new(dacl: ACL::Windows::ACLState.present(ACL::Windows::List.new))
    preserve = ACL::Windows::Update.new(descriptor, ACL::Windows::Information::DACL)
    protected_update = ACL::Windows::Update.new(descriptor, ACL::Windows::Information::DACL, dacl_inheritance: :protect)
    unprotected_update = ACL::Windows::Update.new(descriptor, ACL::Windows::Information::DACL, dacl_inheritance: :unprotect)
    preserve.native_information.should eq(4_u32)
    protected_update.native_information.should eq(0x80000004_u32)
    unprotected_update.native_information.should eq(0x20000004_u32)
    preserve.sacl_selected?.should be_false
  end

  it "rejects empty/unknown selections and missing selected identities" do
    descriptor = ACL::Windows::Descriptor.new
    expect_raises(ACL::UnsupportedACLError) { ACL::Windows::Update.new(descriptor, ACL::Windows::Information::None) }
    expect_raises(ACL::UnsupportedACLError) { ACL::Windows::Update.new(descriptor, ACL::Windows::Information.new(0x400_u32)) }
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Update.new(descriptor, ACL::Windows::Information::Owner) }
    expect_raises(ACL::UnsupportedACLError) { ACL::Windows::Update.new(descriptor, ACL::Windows::Information::Backup) }
  end

  it "does not apply unqueried data from a partial snapshot" do
    descriptor = ACL::Windows::Descriptor.new(sacl: ACL::Windows::ACLState.null)
    snapshot = ACL::Windows::Snapshot.new(descriptor, ACL::Windows::Information::Basic)
    expect_raises(ACL::UnsupportedACLError) { ACL::Windows::Update.from_snapshot(snapshot, ACL::Windows::Information::SACL) }
  end

  it "keeps a label-only SACL query distinct from an audit SACL query" do
    snapshot = ACL::Windows::Snapshot.new(ACL::Windows::Descriptor.new, ACL::Windows::Information::Label)
    expect_raises(ACL::UnsupportedACLError) { snapshot.sacl }
    snapshot.sacl_components(ACL::Windows::Information::Label).presence.absent?.should be_true
  end

  it "requires each known SACL ACE family to have its matching selector" do
    audit = ACL::Windows::ACE.audit(world_sid, 1_u32)
    label_bytes = allowed_ace.to_bytes
    label_bytes[0] = 17_u8
    label = ACL::Windows::ACE.from_bytes(label_bytes)
    both = ACL::Windows::ACLState.present(ACL::Windows::List.new([audit, label]))
    descriptor = ACL::Windows::Descriptor.new(sacl: both)

    ACL::Windows::Update.new(descriptor, ACL::Windows::Information::SACL | ACL::Windows::Information::Label)
    expect_raises(ACL::InvalidACLError, /ACE type 17 requires Label/) do
      ACL::Windows::Update.new(descriptor, ACL::Windows::Information::SACL)
    end
    expect_raises(ACL::InvalidACLError, /ACE type 2 requires SACL/) do
      ACL::Windows::Update.new(descriptor, ACL::Windows::Information::Label)
    end
  end

  it "maps every filtered SACL ACE family to its exact security-information selector" do
    {
      17_u8 => ACL::Windows::Information::Label,
      18_u8 => ACL::Windows::Information::Attribute,
      19_u8 => ACL::Windows::Information::Scope,
      20_u8 => ACL::Windows::Information::ProcessTrustLabel,
      21_u8 => ACL::Windows::Information::AccessFilter,
    }.each do |type, information|
      descriptor = ACL::Windows::Descriptor.new(
        sacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([categorized_ace(type)])))
      ACL::Windows::Update.new(descriptor, information)
      expect_raises(ACL::InvalidACLError, /requires/) do
        ACL::Windows::Update.new(descriptor, ACL::Windows::Information::SACL)
      end
    end
  end

  it "treats compound ACEs as opaque DACL entries and preserves future unknown types" do
    compound = ACL::Windows::ACE.from_bytes(Bytes[4_u8, 0_u8, 4_u8, 0_u8])
    unknown = ACL::Windows::ACE.from_bytes(Bytes[254_u8, 0_u8, 4_u8, 0_u8])

    dacl = ACL::Windows::Descriptor.new(dacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([compound, unknown])))
    ACL::Windows::Update.new(dacl, ACL::Windows::Information::DACL)

    sacl = ACL::Windows::Descriptor.new(sacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([compound])))
    expect_raises(ACL::InvalidACLError, /ACE type 4 is not valid in a SACL/) do
      ACL::Windows::Update.new(sacl, ACL::Windows::Information::SACL)
    end

    future = ACL::Windows::Descriptor.new(sacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([unknown])))
    ACL::Windows::Update.new(future, ACL::Windows::Information::Label)
  end
end

describe "Windows binary preservation regressions" do
  it "preserves uninterpreted trailing bytes even on non-callback ACEs" do
    # MS-DTYP ACE_HEADER explicitly permits AceSize greater than the fields;
    # non-callback trailing data is ignored semantically, not rejected/dropped.
    bytes = allowed_ace.to_bytes + Bytes[0xde, 0xad, 0xbe, 0xef]
    bytes[2] = bytes.size.to_u8
    ace = ACL::Windows::ACE.from_bytes(bytes)
    ace.to_bytes.should eq(bytes)
    ace.with_mask(7_u32).to_bytes[20, 4].should eq(Bytes[0xde, 0xad, 0xbe, 0xef])
    ace.sid.should eq(world_sid)
  end

  it "rejects active offsets masquerading as absent ACLs" do
    bytes = ACL::Windows::Descriptor.new(dacl: ACL::Windows::ACLState.present(ACL::Windows::List.new)).to_bytes
    bytes[2] = 0 # clear DACL_PRESENT while retaining its nonzero offset
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Descriptor.from_bytes(bytes) }
  end
end

describe "Windows targeted editing" do
  it "replaces a SID while preserving object GUIDs and opaque trailing bytes" do
    uuid = UUID.new("00112233-4455-6677-8899-aabbccddeeff")
    replacement = ACL::Windows::SID.parse("S-1-5-21-100-200-300-1001")
    ace = ACL::Windows::ACE.object(11_u8, world_sid, 1_u32, object_type: uuid, application_data: Bytes[7, 8, 9, 10])
    edited = ace.with_sid(replacement)
    edited.sid.should eq(replacement)
    edited.object_type.should eq(uuid)
    edited.application_data.should eq(Bytes[7, 8, 9, 10])
    ace.sid.should eq(world_sid)
  end

  it "inserts and removes entries by index rather than sorting or merging trustees" do
    a = allowed_ace
    b = ACL::Windows::ACE.deny(world_sid, 1_u32)
    list = ACL::Windows::List.new([a])
    edited = list.inserted(0, b)
    edited.entries.should eq([b, a])
    edited.without_entry(0).entries.should eq([a])
    list.entries.should eq([a])
  end

  it "rejects known audit/allow ACE category mismatches before native writes" do
    audit = ACL::Windows::ACE.audit(world_sid, 1_u32)
    bad_dacl = ACL::Windows::Descriptor.new(dacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([audit])))
    bad_sacl = ACL::Windows::Descriptor.new(sacl: ACL::Windows::ACLState.present(ACL::Windows::List.new([allowed_ace])))
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Update.new(bad_dacl, ACL::Windows::Information::DACL) }
    expect_raises(ACL::InvalidACLError) { ACL::Windows::Update.new(bad_sacl, ACL::Windows::Information::SACL) }
  end
end
