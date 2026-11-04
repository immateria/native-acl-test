"""Bounded seeded generators; malformed input is NEVER passed to ctypes."""
import random
import struct
import uuid
from . import wire

def run(ctx):
    rng=random.Random(ctx.case['seed'])
    n=min(max(ctx.case['iterations'],128),10000)
    platform=ctx.case['platform']
    good=[]
    for index in range(n):
        if platform=='darwin':
            entries=[dict(principal=str(uuid.UUID(int=rng.getrandbits(128))),raw_flags=rng.getrandbits(32),raw_rights=rng.getrandbits(32)) for _ in range(rng.randrange(9))]
            data=wire.darwin_export(entries,rng.getrandbits(32))
        else:
            sid=wire.sid_bytes('S-1-'+str(rng.randrange(2**48))+''.join('-'+str(rng.getrandbits(32)) for _ in range(rng.randrange(16))))
            kind=rng.choice([0,1,2,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21])
            kwargs={}
            if kind in wire.OBJECT_TYPES:
                if rng.choice([True,False]): kwargs['object_guid']=str(uuid.UUID(int=rng.getrandbits(128)))
                if rng.choice([True,False]): kwargs['inherited_guid']=str(uuid.UUID(int=rng.getrandbits(128)))
            kwargs['payload']=bytes(rng.getrandbits(8) for _ in range(rng.randrange(5)*4))
            ace=wire.ace(kind,rng.randrange(256),rng.getrandbits(32),sid,**kwargs)
            data=wire.descriptor(owner=sid,group=sid,dacl=wire.acl([ace],revision=4 if kind in wire.OBJECT_TYPES else 2))
        good.append(data)
    if ctx.case['id'].endswith('seeded_valid'):
        requests=[dict(op='model.'+platform,hex=b.hex()) for b in good]
        results=ctx.batch(requests)
        for index,(data,result) in enumerate(zip(good,results)):
            ctx.require(result.get('ok'),f'valid generated input {index} rejected: {result}')
            ctx.equal(result['value']['hex'],data.hex(),f'generated input {index} lost bytes')
        ctx.record('generated-count',dict(valid_roundtrips=len(good),seed=ctx.case['seed']))
    else:
        bad=[]
        # Guaranteed-invalid structural mutations, not random bytes guessed invalid.
        for data in good:
            bad.append(data[:19] if platform=='windows' else data[:43])
            altered=bytearray(data)
            if platform=='windows': altered[0]=2
            else: altered[0]^=0xff
            bad.append(bytes(altered))
            altered=bytearray(data)
            if platform=='windows': struct.pack_into('<I',altered,16,0xfffffffc)
            else: struct.pack_into('>I',altered,36,129)
            bad.append(bytes(altered))
        results=ctx.batch([dict(op='model.'+platform,hex=b.hex()) for b in bad])
        for index,result in enumerate(results):
            ctx.require(not result.get('ok'),f'malformed case {index} accepted')
            ctx.require(result.get('error')=='ACL::InvalidACLError',f'malformed case {index} raised unexpected exception {result}')
        ctx.record('generated-count',dict(malformed_rejections=len(bad),seed=ctx.case['seed']))
