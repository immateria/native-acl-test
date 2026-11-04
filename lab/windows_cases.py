"""Windows native descriptor, inheritance, SDDL, token and access probes."""
import ctypes as C
import os
import pathlib
import struct
from . import wire,model_cases
from .windows import Windows
from .native import NativeFailure,SkipCase,Observation
from .context import BridgeFailure
from .windows_accounts import LocalAccountManager, WindowsTokenLab

OTHER='S-1-5-21-3981726199-1872936101-2918176103-424242'
WORLD=wire.sid_bytes('S-1-1-0')
GUID='00112233-4455-6677-8899-aabbccddeeff'
GUID2='ffeeddcc-bbaa-9988-7766-554433221100'

def acl_semantic(acl):
    if acl['presence']!='Present':return dict(presence=acl['presence'])
    return dict(presence='Present',entries=[e['hex'] for e in acl['entries']],revision=bytes.fromhex(acl['hex'])[0])

def semantic(value):
    return dict(control=value['control'],owner=value.get('owner'),group=value.get('group'),dacl=acl_semantic(value['dacl']),sacl=acl_semantic(value['sacl']))

def compare(ctx,oracle,path,information=7,follow=True,borrowed=False):
    raw=oracle.read(path,information,follow)
    native=ctx.record('native-descriptor',wire.parse_descriptor(raw))
    for sacl in [False,True]:
        enumerated=oracle.native_entries(raw,sacl)
        expected=native['sacl' if sacl else 'dacl']
        ctx.equal(enumerated['presence'],expected['presence'],'native ACL presence disagrees with independent wire parser')
        if enumerated['presence']=='Present':ctx.equal(enumerated['entries'],[a['hex'] for a in expected['entries']],'GetAce and binary decoder disagree')
    shard=ctx.bridge(dict(op='windows.read',path=str(path),information=information,follow=follow,borrowed=borrowed))
    ctx.equal(semantic(shard),semantic(native),'Crystal descriptor read differs from native API snapshot')
    # Also prove exact bytes of the independently acquired native SD are preserved.
    parsed=ctx.bridge(dict(op='model.windows',hex=raw.hex()))
    ctx.equal(parsed['hex'],raw.hex(),'model lost bytes from a native security descriptor')
    return shard

def dacl(oracle,entries,revision=2,inherit_guard=False):
    guard=wire.ace(0,3 if inherit_guard else 0,0x1f01ff,wire.sid_bytes(oracle.current_sid()))
    return wire.descriptor(dacl=wire.acl([guard]+entries,revision))

def roundtrip(ctx,oracle,entries,directory=False,revision=2):
    a=ctx.fixture('crystal-target',directory);b=ctx.fixture('oracle-target',directory)
    data=dacl(oracle,entries,revision)
    errors={}
    for name,path in [('crystal',a),('oracle',b)]:
        try:
            if name=='crystal':ctx.bridge(dict(op='windows.write',path=str(path),hex=data.hex(),information=4,inheritance='Protect'))
            else:oracle.write(path,data,4,'Protect')
        except (NativeFailure,BridgeFailure) as exc:errors[name]=dict(code=exc.code,error=str(exc))
    ctx.record('write-input-and-outcome',dict(hex=data.hex(),errors=errors))
    if errors:
        ctx.require(len(errors)==2,'only one implementation rejected the native write')
        ctx.equal(errors['crystal']['code'],errors['oracle']['code'],'native write errors disagree')
        raise Observation('both implementations rejected this matrix input; not counted as a passing round-trip')
    first=compare(ctx,oracle,a);second=compare(ctx,oracle,b)
    ctx.equal(semantic(first),semantic(second),'native/Crystal writes produced different descriptors')
    compare(ctx,oracle,a,borrowed=True)
    ctx.bridge(dict(op='windows.write',path=str(a),hex=data.hex(),information=4,inheritance='Protect',borrowed=True))
    compare(ctx,oracle,a)
    return a,first

def create_tree(root):
    result={}
    for rel,isdir in [('file',False),('dir',True),('dir/grandfile',False),('dir/granddir',True),('dir/granddir/greatfile',False)]:
        p=root/rel
        if isdir:p.mkdir()
        else:p.write_bytes(b'inheritance fixture')
        result[rel]=p
    return result

def run(ctx):
    oracle=Windows();group=ctx.case['group'];name=ctx.case['id'].split('.')[-1];p=ctx.case['params']
    if group=='model':return model_cases.run(ctx)
    if group=='multiuser':return multiuser(ctx,oracle,name)
    if group in ('rights','ace_flags'):
        return roundtrip(ctx,oracle,[wire.ace(p['kind'],p.get('flags',0),p.get('mask',1),wire.sid_bytes(OTHER))],directory=p.get('obj','dir')=='dir')
    if group=='count':
        return roundtrip(ctx,oracle,[wire.ace(i%2,0,1<<(i%9),wire.sid_bytes(OTHER)) for i in range(p['count'])],revision=p['revision'])
    if group=='sid':
        text='S-1-'+str(p['authority'])+''.join('-'+str((i*0x1020304+0xffffffff)&0xffffffff) for i in range(p['count']))
        expected=wire.sid_bytes(text)
        buf=C.create_string_buffer(expected)
        ctx.require(bool(oracle.a.IsValidSid(buf)),'native IsValidSid rejected generated SID')
        native_text=oracle.sid_string(buf)
        for value in [text,native_text]:
            parsed=ctx.bridge(dict(op='model.sid',sid=value));ctx.equal(parsed['hex'],expected.hex(),'Crystal SID text encoding differs from native')
        ctx.record('sid-oracle',dict(numeric=text,native=native_text,hex=expected.hex()))
        try: inverse=oracle.sid_native(native_text)
        except NativeFailure as exc:
            if p['count']==0 and exc.code==1337:
                raise Observation('Crystal and native binary/format checks passed; Win32 rejected its own zero-subauthority spelling (1337)') from exc
            raise
        ctx.equal(inverse,expected,'native SID text roundtrip changed bytes');return
    if group=='ace_binary':
        kind=p['kind'];kwargs={}
        if kind in wire.OBJECT_TYPES:kwargs=dict(object_guid=GUID,inherited_guid=GUID2)
        if kind in (9,10,11,12,13,14,15,16):kwargs['payload']=b'\0'*4
        raw=struct.pack('<BBH',254,0x12,8)+b'abcd' if kind==254 else wire.ace(kind,0xc0 if kind in (2,7,13,15) else 0,1,WORLD,**kwargs)
        native_acl=wire.acl([raw],revision=4 if kind in wire.OBJECT_TYPES else 2)
        native_valid=oracle.validate_acl(native_acl)
        # Descriptors with audit/policy ACEs belong in SACL, not DACL.
        data=wire.descriptor(sacl=native_acl) if kind in (2,3,7,8,13,14,15,16,17,18,19,20,21) else wire.descriptor(dacl=native_acl)
        result=ctx.bridge(dict(op='model.windows',hex=data.hex()))
        ctx.equal(result['hex'],data.hex(),'typed/opaque ACE lost bytes')
        ctx.record('native-ace-validation',dict(type=kind,is_valid_acl=native_valid,hex=native_acl.hex()))
        if not native_valid:raise Observation('Crystal structurally preserved ACE; native IsValidAcl rejects it. No filesystem write attempted.')
        return
    if group=='extended_ace_write':
        kind=p['kind'];kwargs={}
        if kind in wire.OBJECT_TYPES:
            if p['guids']&1:kwargs['object_guid']=GUID
            if p['guids']&2:kwargs['inherited_guid']=GUID2
        # Empty application data is structural only; this does not evaluate a condition.
        raw=wire.ace(kind,0,1,wire.sid_bytes(OTHER),**kwargs)
        return roundtrip(ctx,oracle,[raw],revision=4 if kind in wire.OBJECT_TYPES else 2)
    if group=='acl_limit':
        guard=wire.ace(0,0,0x1f01ff,wire.sid_bytes(oracle.current_sid()))
        additional=wire.ace(0,0,1,wire.sid_bytes(OTHER))
        count=(p['size']-8-len(guard))//len(additional)
        padding=b'\0'*(p['size']-8-len(guard)-count*len(additional))
        acl=wire.acl([guard]+[additional]*count,padding=padding)
        ctx.equal(len(acl),p['size'],'ACL boundary fixture size')
        ctx.require(oracle.validate_acl(acl),'native ACL validator rejected size fixture')
        data=wire.descriptor(dacl=acl)
        parsed=ctx.bridge(dict(op='model.windows',hex=data.hex()))
        ctx.equal(parsed['hex'],data.hex(),'large ACL/padding not preserved by bounded parser')
        a=ctx.fixture();b=ctx.fixture('reference')
        errors={}
        try:oracle.write(b,data,4,'Protect')
        except NativeFailure as exc:errors['oracle']=exc.code
        result=ctx.bridge(dict(op='windows.write',path=str(a),hex=data.hex(),information=4,inheritance='Protect'),True)
        if not result['ok']:errors['crystal']=result.get('code')
        if errors:
            ctx.record('size-write-errors',errors)
            ctx.require(len(errors)==2,'large ACL accepted by only one implementation')
            raise Observation('both write paths rejected this ACL size; native limits recorded')
        ctx.equal(semantic(compare(ctx,oracle,a)),semantic(compare(ctx,oracle,b)),'large ACL readback differs')
        return
    if group=='query':
        a=ctx.fixture();information=p['information'];errors={};native=None
        try:native=oracle.read(a,information)
        except NativeFailure as exc:errors['oracle']=exc.code
        result=ctx.bridge(dict(op='windows.read',path=str(a),information=information),True)
        if not result['ok']:errors['crystal']=result['code']
        if errors:
            ctx.record('query-errors',errors)
            ctx.require(len(errors)==2,'native and shard disagree on query support')
            # GetNamedSecurityInfo and CreateFileW/GetSecurityInfo can fail at different layers.
            # Preserve both codes instead of falsely requiring identical failure staging.
            raise Observation('selected information rejected by both APIs on this token/filesystem')
        ctx.equal(semantic(result['value']),semantic(wire.parse_descriptor(native)),'partial security selector changed evidence')
        ctx.record('query-native',dict(information=information,hex=native.hex()))
        for bit,guard in [(1,'owner'),(2,'group'),(4,'dacl'),(8,'sacl')]:
            if not information&bit:
                guarded=ctx.bridge(dict(op='windows.read',path=str(a),information=information,guard=guard),True)
                ctx.require(not guarded['ok'] and guarded['error']=='ACL::UnsupportedACLError','unqueried '+guard+' was exposed as observed data')
        return
    if group=='update' and name=='delegated_write_only':return delegated_write(ctx,oracle)
    if group=='update':return updates(ctx,oracle,name)
    if group in ('inheritance','propagation'):return inheritance(ctx,oracle,name,p)
    if group=='access':return access(ctx,oracle,p)
    if group=='sddl':return sddl(ctx,oracle,name)
    if group=='sacl':return sacl(ctx,oracle,name,p)
    if group=='path':return paths(ctx,oracle,name)
    if group=='contract':return contract(ctx,oracle,name)
    if group=='stress':
        a=ctx.fixture()
        result=ctx.bridge(dict(op='windows.stress',path=str(a),mode=name,iterations=ctx.case['iterations']))
        ctx.record('resource-measurements',result)
        control=result['positive_control']
        ctx.require(control['held']-control['before']>=12 and control['held']-control['released']>=12,'counter did not detect the acquisition and release of 12 live handles')
        ctx.require(max(result['samples'][1:])<=result['samples'][0]+4,'handle count grew above warmed baseline; inspect per-batch samples');return
    raise AssertionError('unimplemented Windows case '+ctx.case['id'])

def contract(ctx,oracle,name):
    if name=='invalid_handle':
        result=ctx.bridge(dict(op='windows.invalid_handle'),True)
        ctx.require(not result['ok'] and result['code']==6,'invalid handle did not yield ERROR_INVALID_HANDLE');return
    if name=='invalid_paths':
        a=ctx.fixture()
        for path in ['',str(ctx.root/'missing'),str(a/'child')]:
            result=ctx.bridge(dict(op='windows.read',path=path),True)
            ctx.require(not result['ok'] and result['code'] in (2,3,123,267),'path failure did not expose Win32 error: '+str(result))
        for op in ['windows.read','windows.write']:
            req=dict(op=op,path=str(a)+'\0suffix',hex=dacl(oracle,[]).hex(),information=4)
            result=ctx.bridge(req,True)
            ctx.require(not result['ok'] and result['error']=='ArgumentError','embedded NUL not rejected before native open')
        return
    a=ctx.fixture()
    if name=='baseline':compare(ctx,oracle,a);return
    if name=='borrowed_handle':
        compare(ctx,oracle,a,borrowed=True)
        ctx.bridge(dict(op='windows.write',path=str(a),hex=dacl(oracle,[]).hex(),information=4,borrowed=True));compare(ctx,oracle,a);return
    if name=='fd_or_handle_permissions':
        with oracle.handle(a,0) as h:
            try:oracle.read_handle(h);raise AssertionError('zero-access handle unexpectedly read security')
            except NativeFailure as exc:ctx.equal(exc.code,5,'restricted handle error')
        result=ctx.bridge(dict(op='windows.limited_handle',path=str(a)),True)
        ctx.require(not result['ok'] and result['code']==5,'shard did not surface borrowed-handle access denial');return
    if name in ('empty','null_or_remove'):
        before=semantic(wire.parse_descriptor(oracle.read(a)))
        data=wire.descriptor(dacl=wire.acl([]) if name=='empty' else None)
        value=ctx.bridge(dict(op='windows.handle_cycle',path=str(a),hex=data.hex(),information=4,inheritance='Protect',allow_null=True))
        ctx.equal(value['dacl']['presence'],'Present' if name=='empty' else 'Null','empty/null DACL collapsed')
        if name=='empty':ctx.equal(value['dacl']['entries'],[],'empty DACL populated unexpectedly')
        ctx.equal(semantic(wire.parse_descriptor(oracle.read(a))),before,'handle-cycle restoration changed original descriptor')
        return
    raise AssertionError('unknown contract '+name)

def delegated_write(ctx,oracle):
    """Simulate a WRITE_DAC-only delegate on a private file without creating accounts.

    An OWNER RIGHTS ACE removes the owner's implicit READ_CONTROL. Confirm this
    from actual opens before attributing the result to the narrow-access path.
    Keep the pre-existing recovery handle until restoration is complete.
    """
    a=ctx.fixture()
    owner_rights=wire.sid_bytes('S-1-3-4')
    policy=wire.descriptor(dacl=wire.acl([wire.ace(1,0,0x20000,owner_rights),wire.ace(0,0,0x40000,owner_rights)]))
    with oracle.handle(a,0x60000) as recovery:
        before=oracle.read_handle(recovery)
        try:
            oracle.write_handle(recovery,policy,4,'Protect')
            wide=oracle.try_open(a,0x60000);narrow=oracle.try_open(a,0x40000)
            ctx.record('delegated-open-rights',dict(wide=wide,narrow=narrow))
            if wide['allowed'] or not narrow['allowed']:
                raise Observation('fixture did not isolate WRITE_DAC-only rights on this token; no delegated-access claim')
            ctx.equal(wide['error'],5,'unexpected augmented open error')
            # Use the same idempotent update three ways. No widened handle or
            # second mutation is allowed inside the production path operation.
            with oracle.handle(a,0x40000) as h:
                try:oracle.write_handle(h,policy,4,'Protect');expected=0
                except NativeFailure as exc:
                    if exc.operation!='oracle.SetSecurityInfo' or exc.code!=5:raise
                    expected=exc.code
            req=dict(op='windows.write',path=str(a),hex=policy.hex(),information=4,inheritance='Protect')
            for result in ctx.batch([req,dict(req,borrowed=True,open_mask=0x40000)]):
                ctx.equal(result['ok'],expected==0,'path/borrowed outcome differs from native WRITE_DAC-only setter')
                if expected:
                    ctx.equal((result.get('operation'),result.get('code')),('SetSecurityInfo',expected),'did not reach setter on the narrow handle')
            ctx.equal(acl_semantic(wire.parse_descriptor(oracle.read_handle(recovery))['dacl']),
                      acl_semantic(wire.parse_descriptor(policy)['dacl']),'unexpected delegated DACL readback')
        finally:
            protection='Protect' if wire.parse_descriptor(before)['control']&0x1000 else 'Unprotect'
            oracle.write_handle(recovery,before,4,protection)

def updates(ctx,oracle,name):
    a=ctx.fixture();before=oracle.read(a);original=wire.parse_descriptor(before)
    if name=='unqueried_guard':
        r=ctx.bridge(dict(op='windows.read',path=str(a),information=4,guard='owner'),True)
        ctx.require(not r['ok'] and r['error']=='ACL::UnsupportedACLError','unqueried owner exposed as observed data');return
    if name in ('null_guard','absent_dacl','audit_in_dacl'):
        data=wire.descriptor(dacl=None) if name=='null_guard' else wire.descriptor()
        if name=='audit_in_dacl':data=wire.descriptor(dacl=wire.acl([wire.ace(2,0x40,1,WORLD)]))
        r=ctx.bridge(dict(op='model.update',hex=data.hex(),information=4),True)
        ctx.require(not r['ok'] and r['error']=='ACL::InvalidACLError','unsafe update not rejected');return
    if name in ('owner','group'):
        bit=1 if name=='owner' else 2
        ctx.bridge(dict(op='windows.write',path=str(a),hex=before.hex(),information=bit))
        after=compare(ctx,oracle,a)
        ctx.equal(semantic(after),semantic(original),'same-value owner/group write changed unrelated security');return
    policy={'protect':'Protect','unprotect':'Unprotect','preserve':'Preserve'}.get(name,'Protect')
    data=dacl(oracle,[wire.ace(0,0,1,wire.sid_bytes(OTHER))])
    ctx.bridge(dict(op='windows.write',path=str(a),hex=data.hex(),information=4,inheritance=policy))
    after=compare(ctx,oracle,a)
    ctx.equal(after['owner'],original['owner'],'DACL-only update changed owner');ctx.equal(after['group'],original['group'],'DACL-only update changed group')
    expected=True if policy=='Protect' else False if policy=='Unprotect' else bool(original['control']&0x1000)
    ctx.equal(bool(after['control']&0x1000),expected,'protection policy mismatch')

def inheritance(ctx,oracle,name,p):
    a=ctx.fixture('crystal-parent',True);b=ctx.fixture('native-parent',True)
    baseline=dacl(oracle,[],inherit_guard=True)
    for parent in [a,b]:oracle.write(parent,baseline,4,'Protect')
    trees=None
    if ctx.case['group']=='propagation':
        trees=[create_tree(a),create_tree(b)]
        if name in ('protected_child','unprotect_child'):
            for tree in trees:oracle.write(tree['dir'],baseline,4,'Protect')
    flags=p.get('flags',3)
    data=dacl(oracle,[wire.ace(0,flags,1,wire.sid_bytes(OTHER))],inherit_guard=True)
    ctx.bridge(dict(op='windows.write',path=str(a),hex=data.hex(),information=4,inheritance='Protect'))
    oracle.write(b,data,4,'Protect')
    if trees is None:trees=[create_tree(a),create_tree(b)]
    if name=='unprotect_child':
        ctx.bridge(dict(op='windows.write',path=str(trees[0]['dir']),hex=baseline.hex(),information=4,inheritance='Unprotect'))
        oracle.write(trees[1]['dir'],baseline,4,'Unprotect')
    for rel in trees[0]:
        first=compare(ctx,oracle,trees[0][rel]);second=compare(ctx,oracle,trees[1][rel])
        ctx.equal(semantic(first),semantic(second),'native vs Crystal inheritance mismatch: '+rel)
        if name=='protected_child' and rel.startswith('dir'):
            ctx.require(not any(e.get('sid')==OTHER for e in first['dacl']['entries']),'protected child inherited new parent ACE')
        if flags==3 and (ctx.case['group']=='inheritance' or name in ('existing_children','grandchildren')):
            ctx.require(any(e.get('sid')==OTHER and e['flags']&16 for e in first['dacl']['entries']),'ordinary OI|CI inheritance missing: '+rel)

def access(ctx,oracle,p):
    a=ctx.fixture();before=oracle.read(a);base=wire.parse_descriptor(before)
    guard=wire.ace(0,0,0x70000|0x100000,wire.sid_bytes(oracle.current_sid()))
    allow=wire.ace(0,0,p['mask'],WORLD);deny=wire.ace(1,0,p['mask'],WORLD)
    entries={'allow':[guard,allow],'deny':[guard,deny],'allow_then_deny':[guard,allow,deny],
             'deny_then_allow':[guard,deny,allow],'empty':[],'null':None}[p['order']]
    data=wire.descriptor(owner=wire.sid_bytes(base['owner']),group=wire.sid_bytes(base['group']),dacl=None if entries is None else wire.acl(entries))
    with oracle.handle(a,0x60000) as h:
        try:
            oracle.write_handle(h,data,4,'Protect')
            actual=oracle.read_handle(h)
            checked=oracle.access_check(actual,p['mask']);opened=oracle.try_open(a,p['mask'])
            ctx.record('access-evidence',dict(descriptor=actual.hex(),access_check=checked,actual_open=opened,requested=p))
            expected=p['order'] in ('allow','allow_then_deny','null')
            ctx.equal(checked['allowed'],expected,'ordered allow/deny/empty/null access result unexpected')
            parsed=ctx.bridge(dict(op='model.windows',hex=actual.hex()))
            ctx.equal(parsed['hex'],actual.hex(),'model changed access-control descriptor')
            if p['mask']==0x80 and p['order'] in ('deny','deny_then_allow') and not checked['allowed'] and opened['allowed']:
                ctx.record('attribute-operation',oracle.attribute_probe(a))
                raise Observation('ordered DACL and AccessCheck verified; FILE_READ_ATTRIBUTES open succeeded despite descriptor-only denial')
            ctx.equal(opened['allowed'],checked['allowed'],'AccessCheck and real CreateFile access disagree')
        finally:oracle.write_handle(h,before,4,'Protect' if base['control']&0x1000 else 'Unprotect')

def sddl(ctx,oracle,name):
    values={
      'basic':'D:(A;;FR;;;WD)','empty':'D:','null':'D:NO_ACCESS_CONTROL','owner_group':'O:SYG:BAD:(A;;FA;;;SY)',
      'protected':'D:P(A;;FR;;;WD)','inheritance':'D:(A;OICINPIO;FR;;;WD)',
      'object_guid':f'D:(OA;;GR;{GUID};;WD)','two_guids':f'D:(OD;;GW;{GUID};{GUID2};WD)',
      'audit':'S:(AU;SAFA;FR;;;WD)','label':'S:(ML;;NW;;;LW)',
      'conditional':'D:(XA;;FR;;;WD;(Member_of {SID(S-1-5-32-544)}))','invalid':'D:(NOT_AN_ACE)'}
    text=values[name];native=None;error=None
    try:native=oracle.sddl(text)
    except NativeFailure as exc:error=exc.code
    result=ctx.bridge(dict(op='windows.sddl',sddl=text),True)
    if error is not None:
        ctx.require(not result['ok'],'shard accepted SDDL rejected by native API');ctx.equal(result['code'],error,'SDDL errors differ')
        if name=='invalid':return
        raise Observation('SDDL form rejected on this Windows version; error recorded')
    ctx.require(result['ok'],'shard rejected native SDDL output: '+str(result))
    ctx.equal(semantic(result['value']),semantic(wire.parse_descriptor(native)),'SDDL semantic mismatch')
    ctx.equal(result['value']['hex'],native.hex(),'SDDL conversion binary mismatch')
    mask=8 if name in ('audit','label') else 7
    native_text=oracle.to_sddl(native,mask)
    converted=ctx.bridge(dict(op='windows.to_sddl',hex=native.hex(),information=mask))
    ctx.equal(converted['sddl'],native_text,'SDDL formatting differs from OS')

def sacl(ctx,oracle,name,p):
    a=ctx.fixture()
    if name=='label_read':compare(ctx,oracle,a,16);return
    if name=='no_enabled_privilege':
        token,read=ctx.batch([dict(op='windows.token'),dict(op='windows.read',path=str(a),information=8)])
        ctx.require(token['ok'],'could not inspect bridge token')
        if token['value']['privileges']['SeSecurityPrivilege']=='enabled':raise SkipCase('negative control needs a token without enabled SeSecurityPrivilege')
        ctx.require(not read['ok'] and read.get('code') in (5,1314),'unprivileged SACL query did not report access/privilege denial');return
    ctx.record('privileges-initial',oracle.privilege_snapshot())
    oracle.enable_privilege('SeSecurityPrivilege')
    ctx.record('privileges-after-security',oracle.privilege_snapshot())
    if name=='query_backup':
        # Record the distinct configurations; possession is not enablement.
        successful=False
        for extra in (None,'SeBackupPrivilege','SeRestorePrivilege'):
            if extra:
                try:oracle.enable_privilege(extra)
                except SkipCase as exc:
                    ctx.record('privilege-unassigned',dict(name=extra,reason=str(exc)));continue
            token,res=ctx.batch([dict(op='windows.token'),dict(op='windows.read',path=str(a),information=0x10000)])
            ctx.require(token['ok'] and (not extra or token['value']['privileges'][extra]=='enabled'),'bridge token did not inherit requested privilege')
            try: data=oracle.read(a,0x10000)
            except NativeFailure as exc:
                ctx.require(exc.code in (5,1314) and not res['ok'] and res.get('code') in (5,1314),'unexpected backup query failure or oracle disagreement');continue
            ctx.require(res['ok'],'Crystal backup query failed on a working oracle configuration')
            ctx.equal(semantic(res['value']),semantic(wire.parse_descriptor(data)),'backup query differs from native view');successful=True
        if not successful:raise Observation('backup queries denied in all available token configurations; no full backup claim')
        return
    information=16 if name=='label_write_low' else 8
    before=oracle.read(a,information)
    before_basic=wire.parse_descriptor(oracle.read(a))
    try:
        if information==16:
            data=oracle.sddl('S:(ML;;NW;;;LW)');expected=(17,0,1,'S-1-16-4096')
        else:
            flags=p.get('flags',0xc0)
            data=wire.descriptor(sacl=wire.acl([wire.ace(2,flags,1,WORLD)]));expected=(2,flags,1,'S-1-1-0')
        if name=='pure_read_handles':oracle.write(a,data,8)
        else:ctx.bridge(dict(op='windows.write',path=str(a),hex=data.hex(),information=information))
        after=compare(ctx,oracle,a,7|information)
        def assert_entry(view):
            actual=[(e['type'],e['flags'],e['mask'],e['sid']) for e in view['sacl'].get('entries') or []]
            ctx.require(expected in actual,'expected native audit/label ACE missing: '+str(actual))
        assert_entry(after)
        ctx.equal(acl_semantic(after['dacl']),acl_semantic(before_basic['dacl']),'SACL-only update changed DACL')
        for part in ('owner','group'):ctx.equal(after[part],before_basic[part],'SACL-only update changed '+part)
        if name=='pure_read_handles':
            request=dict(op='windows.read',path=str(a),information=8)
            token,path_result,narrow,wide=ctx.batch([dict(op='windows.token'),request,
                dict(request,borrowed=True,open_mask=0x1000000),dict(request,borrowed=True,open_mask=0x1020000)])
            ctx.record('sacl-only-matrix',dict(token=token,path=path_result,narrow=narrow,wide=wide))
            ctx.require(token['ok'] and token['value']['privileges']['SeSecurityPrivilege']=='enabled','SeSecurityPrivilege not enabled in Crystal bridge')
            reference=wire.parse_descriptor(oracle.read(a,8))
            for response in (path_result,wide):
                ctx.require(response['ok'],'expected working SACL-only path/handle: '+str(response));assert_entry(response['value'])
                ctx.equal(semantic(response['value']),semantic(reference),'pure SACL differs from independent reader')
            if narrow['ok']:assert_entry(narrow['value'])
            else:ctx.require(narrow.get('code')==5 and narrow.get('operation') in ('bridge.CreateFileW','GetSecurityInfo'),'unexpected narrow handle failure')
        if name=='audit_dacl_isolation':
            sacl_before=compare(ctx,oracle,a,8)
            ctx.bridge(dict(op='windows.write',path=str(a),hex=dacl(oracle,[]).hex(),information=4))
            ctx.equal(acl_semantic(compare(ctx,oracle,a,8)['sacl']),acl_semantic(sacl_before['sacl']),'DACL update erased audit SACL')
    finally:
        # This is a new disposable file. Never apply a label-only snapshot to
        # the audit SACL or synthesize a NULL mandatory label for restoration.
        if information==16:
            a.unlink()
        else:
            state=wire.parse_descriptor(before)['sacl']
            restore=before if state['presence']!='Absent' else wire.descriptor(sacl=None)
            oracle.write(a,restore,8)


def _account_data(ctx):
    secret=ctx.account_secrets()
    users=secret['users'];groups=secret['groups']
    return secret,users,groups

def _recovery_aces(oracle,inherit=False):
    flags='OICI' if inherit else ''
    return '(A;%s;FA;;;%s)(A;%s;FA;;;SY)'%(flags,oracle.current_sid(),flags)

def _set_sddl_dacl(oracle,path,aces,inherit=False):
    text='D:P'+_recovery_aces(oracle,inherit)+''.join(aces)
    data=oracle.sddl(text)
    oracle.write(path,data,4,'Protect')
    return data

def _prepare_root(ctx,oracle,roles=(),groups=(),inherit=True):
    _,users,group_data=_account_data(ctx)
    flags='OICI' if inherit else ''
    aces=[]
    for role in roles:aces.append('(A;%s;FA;;;%s)'%(flags,users[role]['sid']))
    for role in groups:aces.append('(A;%s;FA;;;%s)'%(flags,group_data[role]['sid']))
    return _set_sddl_dacl(oracle,ctx.root,aces,inherit=inherit)

def _create_as(ctx,oracle,role,name='owned',directory=False):
    _prepare_root(ctx,oracle,[role])
    path=ctx.root/name
    value=ctx.bridge_as(role,dict(op='windows.create',path=str(path),directory=directory))
    ctx.equal(value['owner'],ctx.account(role)['sid'],'created object owner does not match logon user')
    return path,value

def _expect_bridge_denied(ctx,role,request,label):
    response=ctx.bridge_as(role,request,allow_error=True)
    ctx.require(not response['ok'] and response.get('code') in (5,1314),label+': '+str(response))
    return response

def _token_try_open(ctx,oracle,lab,role,path,desired,**options):
    account=ctx.account(role)
    with lab.impersonate(account,**options) as token:
        snapshot=lab.token_snapshot(token)
        result=oracle.try_open(path,desired)
    return ctx.record('token-open-'+role,dict(role=role,desired=desired,token=snapshot,result=result))

def multiuser(ctx,oracle,name):
    secret,users,groups=_account_data(ctx)
    lab=WindowsTokenLab()
    # Repair the baseline before every isolated case. If a prior worker was
    # force-terminated during a membership mutation, later cases remain valid.
    baseline=LocalAccountManager.attach(secret)
    baseline.set_member('allow','alice',False)
    baseline.set_member('allow','bob',True)
    baseline.set_member('allow','carol',True)
    baseline.set_member('deny','alice',False)
    baseline.set_member('deny','bob',True)
    baseline.set_member('deny','carol',False)
    if name=='identities':
        values={'users':{role:value['sid'] for role,value in users.items()},
                'groups':{role:value['sid'] for role,value in groups.items()}}
        flat=list(values['users'].values())+list(values['groups'].values())
        ctx.require(len(flat)==len(set(flat)),'disposable identities do not have distinct SIDs')
        tokens={}
        for role in ('alice','bob','carol'):
            token=ctx.bridge_as(role,dict(op='windows.token'))
            ctx.equal(token['user_sid'],users[role]['sid'],'impersonated bridge has wrong user SID')
            ctx.equal(token['token_source'],'thread','impersonated bridge did not use a thread token')
            group_sids={group['sid'] for group in token['groups']}
            expected_allow=role in ('bob','carol')
            expected_deny=role=='bob'
            ctx.equal(groups['allow']['sid'] in group_sids,expected_allow,'allow-group token membership mismatch')
            ctx.equal(groups['deny']['sid'] in group_sids,expected_deny,'deny-group token membership mismatch')
            tokens[role]=token
        ctx.record('local-identities',dict(identities=values,tokens=tokens));return
    if name.endswith('_process_identity'):
        role=name.split('_',1)[0]
        token=ctx.bridge_process_as(role,dict(op='windows.token'))
        ctx.equal(token['user_sid'],users[role]['sid'],'Crystal bridge ran as the wrong local user')
        ctx.equal(token['token_source'],'process','process-launched bridge unexpectedly used a thread token')
        ctx.record('bridge-token',token);return
    if name in ('owner_implicit_read_control','owner_implicit_write_dac',
                'owner_rights_deny_read_control','owner_rights_deny_write_dac'):
        path,_=_create_as(ctx,oracle,'alice')
        owner=wire.parse_descriptor(oracle.read(path))['owner']
        ctx.equal(owner,users['alice']['sid'],'Alice did not own her created file')
        aces=[]
        if name=='owner_rights_deny_read_control':aces=['(D;;RC;;;OW)']
        if name=='owner_rights_deny_write_dac':aces=['(D;;WD;;;OW)']
        data=_set_sddl_dacl(oracle,path,aces)
        if name in ('owner_implicit_read_control','owner_rights_deny_read_control'):
            request=dict(op='windows.read',path=str(path),information=4)
        else:
            request=dict(op='windows.write',path=str(path),hex=data.hex(),information=4,inheritance='Protect')
        if name.startswith('owner_rights_'):_expect_bridge_denied(ctx,'alice',request,'OWNER RIGHTS deny was ignored')
        else:ctx.bridge_as('alice',request)
        return
    if name=='unrelated_user_denied':
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,[])
        _expect_bridge_denied(ctx,'carol',dict(op='windows.file_access',path=str(path),access=0x80000000),'unrelated user read unexpectedly succeeded');return
    if name in ('explicit_user_allow_read','explicit_user_deny_read'):
        path,_=_create_as(ctx,oracle,'alice')
        kind='A' if name=='explicit_user_allow_read' else 'D'
        _set_sddl_dacl(oracle,path,['(%s;;FR;;;%s)'%(kind,users['carol']['sid'])])
        request=dict(op='windows.file_access',path=str(path),access=0x80000000)
        if kind=='A':ctx.bridge_as('carol',request)
        else:_expect_bridge_denied(ctx,'carol',request,'explicit user deny was ignored')
        return
    if name in ('allow_group_member','allow_group_nonmember'):
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%groups['allow']['sid']])
        role='carol' if name=='allow_group_member' else 'alice'
        request=dict(op='windows.file_access',path=str(path),access=0x80000000)
        if name=='allow_group_member':ctx.bridge_as(role,request)
        else:
            # Alice owns the file and receives implicit control rights, not data read.
            _expect_bridge_denied(ctx,role,request,'nonmember received group data access')
        return
    if name in ('deny_group_overrides_user_allow','deny_group_overrides_allow_group'):
        path,_=_create_as(ctx,oracle,'alice')
        allow_sid=users['bob']['sid'] if name.endswith('user_allow') else groups['allow']['sid']
        _set_sddl_dacl(oracle,path,['(D;;FR;;;%s)'%groups['deny']['sid'],'(A;;FR;;;%s)'%allow_sid])
        _expect_bridge_denied(ctx,'bob',dict(op='windows.file_access',path=str(path),access=0x80000000),'deny-group ACE did not override allow')
        return
    if name in ('fresh_logon_membership_add','fresh_logon_membership_remove','existing_token_membership_snapshot'):
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%groups['allow']['sid']])
        manager=LocalAccountManager.attach(secret)
        request=dict(op='windows.file_access',path=str(path),access=0x80000000)
        if name=='fresh_logon_membership_add':
            _expect_bridge_denied(ctx,'alice',request,'Alice unexpectedly began in allow group')
            try:
                manager.set_member('allow','alice',True);ctx.bridge_as('alice',request)
            finally:manager.set_member('allow','alice',False)
            return
        if name=='fresh_logon_membership_remove':
            ctx.bridge_as('carol',request)
            try:
                manager.set_member('allow','carol',False)
                _expect_bridge_denied(ctx,'carol',request,'fresh Carol logon retained removed group')
            finally:manager.set_member('allow','carol',True)
            return
        with lab.logon(users['carol']) as old_token:
            old_snapshot=lab.token_snapshot(old_token)
            try:
                manager.set_member('allow','carol',False)
                with lab.impersonate_token(old_token):old_result=oracle.try_open(path,0x80000000)
                with lab.impersonate(users['carol']) as new_token:
                    new_snapshot=lab.token_snapshot(new_token);new_result=oracle.try_open(path,0x80000000)
            finally:manager.set_member('allow','carol',True)
        ctx.record('membership-snapshot',dict(old_token=old_snapshot,new_token=new_snapshot,old_result=old_result,new_result=new_result))
        ctx.require(old_result['allowed'] and not new_result['allowed'],'group membership was not snapshotted per logon token')
        return
    if name in ('delegated_write_dac_path','delegated_write_dac_borrowed'):
        path,_=_create_as(ctx,oracle,'alice')
        data=_set_sddl_dacl(oracle,path,['(A;;WD;;;%s)'%users['bob']['sid']])
        _expect_bridge_denied(ctx,'bob',dict(op='windows.read',path=str(path),information=4),'WRITE_DAC-only trustee unexpectedly read DACL')
        request=dict(op='windows.write',path=str(path),hex=data.hex(),information=4,inheritance='Protect')
        if name.endswith('borrowed'):
            request.update(borrowed=True,open_mask=0x40000)
        ctx.bridge_as('bob',request)
        return
    if name=='delegated_read_control':
        path,_=_create_as(ctx,oracle,'alice')
        data=_set_sddl_dacl(oracle,path,['(A;;RC;;;%s)'%users['bob']['sid']])
        ctx.bridge_as('bob',dict(op='windows.read',path=str(path),information=4))
        _expect_bridge_denied(ctx,'bob',dict(op='windows.write',path=str(path),hex=data.hex(),information=4),'READ_CONTROL-only trustee wrote DACL')
        return
    if name in ('deny_only_group_allow_ignored','deny_only_group_deny_applies'):
        path,_=_create_as(ctx,oracle,'alice')
        if name.endswith('allow_ignored'):
            _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%groups['allow']['sid']])
            normal=_token_try_open(ctx,oracle,lab,'bob',path,0x80000000)
            restricted=_token_try_open(ctx,oracle,lab,'bob',path,0x80000000,disable_sids=[groups['allow']['sid']])
            ctx.require(normal['result']['allowed'] and not restricted['result']['allowed'],'deny-only allow group still granted access')
            match=[g for g in restricted['token']['groups'] if g['sid']==groups['allow']['sid']]
            ctx.require(match and match[0]['deny_only'],'disabled group was not marked deny-only')
        else:
            _set_sddl_dacl(oracle,path,['(D;;FR;;;%s)'%groups['deny']['sid'],'(A;;FR;;;%s)'%users['bob']['sid']])
            restricted=_token_try_open(ctx,oracle,lab,'bob',path,0x80000000,disable_sids=[groups['deny']['sid']])
            ctx.require(not restricted['result']['allowed'],'deny-only group stopped participating in deny checks')
        return
    if name=='restricted_sid_double_check':
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%users['bob']['sid']])
        denied=_token_try_open(ctx,oracle,lab,'bob',path,0x80000000,restrict_sids=[groups['allow']['sid']])
        _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%users['bob']['sid'],'(A;;FR;;;%s)'%groups['allow']['sid']])
        allowed=_token_try_open(ctx,oracle,lab,'bob',path,0x80000000,restrict_sids=[groups['allow']['sid']])
        ctx.require(not denied['result']['allowed'] and allowed['result']['allowed'],'restricting SID did not require a second independent allow')
        return
    if name in ('parent_delete_child','child_delete_right'):
        _prepare_root(ctx,oracle,['bob'])
        parent=ctx.root/'parent';parent.mkdir();child=parent/'child';child.write_bytes(b'x')
        if name=='parent_delete_child':
            _set_sddl_dacl(oracle,parent,['(A;;FXDC;;;%s)'%users['bob']['sid']])
            _set_sddl_dacl(oracle,child,['(D;;SD;;;%s)'%users['bob']['sid'],'(A;;FR;;;%s)'%users['bob']['sid']])
        else:
            _set_sddl_dacl(oracle,parent,['(A;;FX;;;%s)'%users['bob']['sid']])
            _set_sddl_dacl(oracle,child,['(A;;SD;;;%s)'%users['bob']['sid']])
        with lab.impersonate(users['bob']):os.remove(child)
        ctx.require(not child.exists(),'authorized delete operation did not remove child')
        return
    if name in ('traverse_with_change_notify','traverse_without_change_notify'):
        _prepare_root(ctx,oracle,['bob'])
        locked=ctx.root/'locked';locked.mkdir();child=locked/'child';child.write_bytes(b'x')
        _set_sddl_dacl(oracle,locked,[])
        _set_sddl_dacl(oracle,child,['(A;;FR;;;%s)'%users['bob']['sid']])
        if name.endswith('with_change_notify'):
            result=_token_try_open(ctx,oracle,lab,'bob',child,0x80000000)
            ctx.require(result['result']['allowed'],'SeChangeNotifyPrivilege did not bypass directory traversal checks')
        else:
            result=_token_try_open(ctx,oracle,lab,'bob',child,0x80000000,delete_privileges=['SeChangeNotifyPrivilege'])
            privilege=[item for item in result['token']['privileges'] if item['name']=='SeChangeNotifyPrivilege']
            ctx.require(not privilege or not privilege[0]['enabled'],'restricted token retained enabled SeChangeNotifyPrivilege')
            ctx.require(not result['result']['allowed'],'path traversal succeeded after SeChangeNotifyPrivilege removal')
        return
    if name in ('creator_owner_inheritance','creator_group_inheritance'):
        sid='CO' if name=='creator_owner_inheritance' else 'CG'
        _set_sddl_dacl(oracle,ctx.root,['(A;;FA;;;%s)'%users['alice']['sid'],'(A;OICIIO;FA;;;%s)'%(sid)],inherit=True)
        path=ctx.root/'created'
        ctx.bridge_as('alice',dict(op='windows.create',path=str(path),directory=False))
        parsed=wire.parse_descriptor(oracle.read(path))
        entries=parsed['dacl']['entries']
        ctx.require(all(entry.get('sid') not in ('S-1-3-0','S-1-3-1') for entry in entries),'creator placeholder survived inheritance')
        if name=='creator_owner_inheritance':
            ctx.require(any(entry.get('sid')==users['alice']['sid'] and entry['flags']&0x10 for entry in entries),'CREATOR OWNER was not substituted with Alice')
        else:
            ctx.record('creator-group-result',dict(group=parsed['group'],entries=entries))
            ctx.require(parsed['group'] is not None,'created object did not expose a primary group SID')
            ctx.require(any(entry.get('sid')==parsed['group'] and entry['flags']&0x10 for entry in entries),
                        'CREATOR GROUP was not substituted with the object primary group')
        return
    if name.startswith('low_integrity_'):
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,['(A;;FA;;;%s)'%users['bob']['sid']])
        try:oracle.enable_privilege('SeSecurityPrivilege')
        except SkipCase:raise
        policy={'low_integrity_no_write_up':'NW','low_integrity_no_read_up':'NR','low_integrity_no_execute_up':'NX'}[name]
        target='ME'
        oracle.write(path,oracle.sddl('S:(ML;;%s;;;%s)'%(policy,target)),16)
        desired={'NW':0x40000000,'NR':0x80000000,'NX':0x20000000}[policy]
        normal=_token_try_open(ctx,oracle,lab,'bob',path,desired)
        low=_token_try_open(ctx,oracle,lab,'bob',path,desired,integrity_sid='S-1-16-4096')
        ctx.require(normal['result']['allowed'] and not low['result']['allowed'],'mandatory integrity policy was not enforced')
        return
    if name=='hardlink_descriptor_identity':
        path,_=_create_as(ctx,oracle,'alice');link=ctx.root/'hardlink';os.link(path,link)
        before=semantic(wire.parse_descriptor(oracle.read(path)))
        ctx.equal(semantic(wire.parse_descriptor(oracle.read(link))),before,'hard-link names returned different descriptors')
        _set_sddl_dacl(oracle,link,['(A;;FR;;;%s)'%users['carol']['sid']])
        ctx.equal(semantic(wire.parse_descriptor(oracle.read(path))),semantic(wire.parse_descriptor(oracle.read(link))),
                  'DACL update through hard link did not affect shared object')
        return
    if name=='owner_group_update_isolation':
        path,_=_create_as(ctx,oracle,'alice');before=wire.parse_descriptor(oracle.read(path))
        _set_sddl_dacl(oracle,path,['(A;;FR;;;%s)'%users['carol']['sid']])
        after=wire.parse_descriptor(oracle.read(path))
        ctx.equal(after['owner'],before['owner'],'DACL-only update changed owner')
        ctx.equal(after['group'],before['group'],'DACL-only update changed primary group')
        return
    if name=='account_cleanup_recovery':
        path,_=_create_as(ctx,oracle,'alice')
        _set_sddl_dacl(oracle,path,[])
        # The elevated collector's explicit recovery ACE must remain sufficient
        # to read and restore the fixture before account deletion.
        compare(ctx,oracle,path)
        oracle.reset_for_cleanup(path);compare(ctx,oracle,path)
        return
    raise AssertionError('unknown multiuser case '+name)

def extended_path(path):
    """Explicit spelling for an absolute scratch path, including UNC shares."""
    if path.startswith('\\\\?\\'):return path
    if path.startswith('\\\\'):return '\\\\?\\UNC\\'+path[2:]
    if not pathlib.PureWindowsPath(path).is_absolute():raise ValueError('absolute path required')
    return '\\\\?\\'+path

def long_path_evidence(root, leaf):
    """Describe the exact ordinary and extended spellings before bridge I/O."""
    relative=str(leaf)
    ordinary=str(pathlib.PureWindowsPath(str(root))/relative)
    return dict(component=len(relative),
                relative_utf16_units=len(relative.encode('utf-16-le'))//2,
                absolute_utf16_units=len(ordinary.encode('utf-16-le'))//2,
                ordinary=ordinary,
                extended=extended_path(ordinary))

def paths(ctx,oracle,name):
    names={'ascii':'file','spaces':'file with spaces','unicode':'雪-δοκιμή','decomposed':'e\u0301','emoji':'file-🧪','long_component':'x'*240}
    if name=='newline':
        try:a=ctx.fixture('line\nbreak')
        except OSError as exc:
            ctx.record('filename-rejection',dict(error=str(exc),winerror=getattr(exc,'winerror',None)))
            raise Observation('ordinary Win32 namespace rejected a control-character filename; not a shard failure')
        compare(ctx,oracle,a);return
    if name=='long_component':
        # The short relative spelling isolates component length from total length.
        leaf=pathlib.Path(names[name]);leaf.write_bytes(b'x')
        path_info=ctx.record('path-lengths-before-bridge',long_path_evidence(ctx.root,leaf))
        compare(ctx,oracle,leaf)
        ordinary=path_info['ordinary'];extended=path_info['extended']
        compare(ctx,oracle,extended)
        ctx.bridge(dict(op='windows.write',path=extended,hex=dacl(oracle,[]).hex(),information=4))
        reference=compare(ctx,oracle,leaf)
        ctx.equal(semantic(compare(ctx,oracle,extended)),semantic(reference),'relative and extended spellings disagree')
        result=ctx.bridge(dict(op='windows.read',path=ordinary),True)
        ctx.record('path-lengths',dict(component=len(str(leaf)),utf16_units=len(ordinary.encode('utf-16-le'))//2,bare=result))
        if not result['ok'] and result.get('operation')=='CreateFileW' and result.get('code') in (3,206) and len(ordinary.encode('utf-16-le'))//2>=260:
            raise Observation('bare long path rejected; short relative and extended spellings of the same file verified')
        ctx.require(result['ok'],'unexpected bare path rejection: '+str(result));ctx.equal(semantic(result['value']),semantic(reference),'bare path refers to different object');return
    if name in names:
        a=ctx.fixture(names[name]);compare(ctx,oracle,a)
        ctx.bridge(dict(op='windows.write',path=str(a),hex=dacl(oracle,[]).hex(),information=4));compare(ctx,oracle,a);return
    if name=='extended_length':
        root=extended_path(str(ctx.root.resolve()))
        for i in range(7):root+='\\'+('component-'+str(i)+'-'+'x'*35);os.mkdir(root)
        a=root+'\\file';pathlib.Path(a).write_bytes(b'x');compare(ctx,oracle,a)
        ctx.bridge(dict(op='windows.write',path=a,hex=dacl(oracle,[]).hex(),information=4));compare(ctx,oracle,a);return
    if name=='relative':
        ctx.fixture();compare(ctx,oracle,pathlib.Path('fixture'));return
    a=ctx.fixture('target',directory=name in ('directory_symlink','intermediate_symlink'))
    if name=='rename_handle':
        value=ctx.bridge(dict(op='windows.rename_handle',path=str(a)))
        ctx.equal(semantic(value),semantic(wire.parse_descriptor(oracle.read(str(a)+'.renamed'))),'renamed borrowed handle changed object');return
    link=ctx.root/'link'
    if name=='hardlink':os.link(a,link)
    else:
        try:os.symlink(str(ctx.root/'missing') if name=='dangling_symlink' else str(a),link,target_is_directory=a.is_dir())
        except OSError as exc:
            if getattr(exc,'winerror',None) in (1314,50,1):raise SkipCase('symlink creation unavailable: '+str(exc)) from exc
            raise
    if name=='intermediate_symlink':
        target=a/'inner';target.write_bytes(b'x');path=link/'inner'
        ctx.bridge(dict(op='windows.write',path=str(path),hex=dacl(oracle,[]).hex(),information=4,follow=False));compare(ctx,oracle,target);return
    follow=name in ('symlink_follow','directory_symlink','hardlink')
    before=semantic(wire.parse_descriptor(oracle.read(a)))
    data=dacl(oracle,[wire.ace(0,0,128,wire.sid_bytes(OTHER))])
    ctx.bridge(dict(op='windows.write',path=str(link),hex=data.hex(),information=4,follow=follow,inheritance='Protect'))
    compare(ctx,oracle,link,follow=follow)
    if name in ('symlink_follow','symlink_nofollow','directory_symlink','dangling_symlink'):
        try:ctx.record('named-query-diagnostic',dict(hex=oracle.read_named(link).hex()))
        except NativeFailure as exc:ctx.record('named-query-diagnostic',dict(error=exc.code))
    if not follow:ctx.equal(semantic(wire.parse_descriptor(oracle.read(a))),before,'nofollow changed symlink target')
    else:ctx.equal(semantic(wire.parse_descriptor(oracle.read(a))),semantic(wire.parse_descriptor(oracle.read(link))),'follow/hardlink identity mismatch')
