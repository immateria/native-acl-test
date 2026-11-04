require "../../spec_helper"
require "../../../src/acl/windows"
require "../../../src/acl/darwin"

describe "bounded binary decoders" do
  it "round trips 500 independently generated SIDs and object/callback ACEs" do
    random = Random.new(0x5eed_u64)
    500.times do |index|
      authority = random.rand(0_u64..0xffffffffffff_u64)
      subs = Array.new(random.rand(0..15)) { random.rand(UInt32) }
      sid = ACL::Windows::SID.parse("S-1-#{authority}" + subs.join { |value| "-#{value}" })
      ACL::Windows::SID.from_bytes(sid.to_bytes).should eq(sid)
      uuid = UUID.new(StaticArray(UInt8, 16).new { random.rand(UInt8) })
      payload = Bytes.new(random.rand(0..16) * 4) { random.rand(UInt8) }
      entry = ACL::Windows::ACE.object(11_u8, sid, random.rand(UInt32), random.rand(UInt8),
        object_type: index.even? ? uuid : nil,
        inherited_object_type: index % 3 == 0 ? uuid : nil,
        application_data: payload)
      decoded = ACL::Windows::ACE.from_bytes(entry.to_bytes)
      decoded.sid.should eq(sid)
      decoded.application_data.should eq(payload)
      decoded.object_type.should eq(entry.object_type)
      decoded.inherited_object_type.should eq(entry.inherited_object_type)
      ACL::Windows::List.from_bytes(ACL::Windows::List.new([entry]).to_bytes).entries.should eq([entry])
    end
  end

  it "rejects or losslessly retains 6000 corrupted bounded structures without bounds/overflow faults" do
    random = Random.new(0xbadac1_u64)
    sid = ACL::Windows::SID.parse("S-1-5-21-100-200-300-1001")
    ace = ACL::Windows::ACE.allow(sid, 0x001f01ff_u32)
    list = ACL::Windows::List.new([ace])
    descriptor = ACL::Windows::Descriptor.new(owner: sid, dacl: ACL::Windows::ACLState.present(list))
    darwin = ACL::Darwin::List.new([ACL::Darwin::Entry.allow(UUID.empty, ACL::Darwin::Permission::ReadData)])
    seeds = [sid.to_bytes, ace.to_bytes, list.to_bytes, descriptor.to_bytes, darwin.to_bytes, Bytes.empty]
    6000.times do |iteration|
      seed = seeds[iteration % seeds.size]
      bytes = seed.dup
      random.rand(1..4).times do
        bytes[random.rand(bytes.size)] = random.rand(UInt8) unless bytes.empty?
      end
      bytes = bytes[0, random.rand(0..bytes.size)] if iteration % 5 == 0
      begin
        output = case iteration % seeds.size
                 when 0 then ACL::Windows::SID.from_bytes(bytes).to_bytes
                 when 1 then ACL::Windows::ACE.from_bytes(bytes).to_bytes
                 when 2 then ACL::Windows::List.from_bytes(bytes).to_bytes
                 when 3 then ACL::Windows::Descriptor.from_bytes(bytes).to_bytes
                 when 4 then ACL::Darwin::List.from_bytes(bytes).to_bytes
                 else        ACL::Windows::Descriptor.from_bytes(bytes).to_bytes
                 end
        output.should eq(bytes)
      rescue ex : ACL::Error
        # Only a documented parse rejection is acceptable. Bounds/overflow and
        # other runtime exceptions escape this rescue and fail the regression.
      end
    end
  end
end
