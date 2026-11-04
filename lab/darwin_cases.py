"""Darwin filesystem tests, with an independent libSystem oracle."""
import errno
import os
import pathlib
import random
import uuid
from . import wire, model_cases
from .darwin import Darwin
from .native import NativeFailure, SkipCase, Observation
from .context import BridgeFailure

# XNU kern_credential.c: kauth_wellknown_guid, 12-byte fingerprint + BE code.
NOBODY=str(uuid.UUID(bytes=bytes.fromhex('abcdefabcdefabcdefabcdef')+bytes.fromhex('fffffffe')))
EVERYONE=str(uuid.UUID(bytes=bytes.fromhex('abcdefabcdefabcdefabcdef')+bytes.fromhex('0000000c')))

def entry(principal=NOBODY,kind=1,mask=2,flags=0):
    return dict(principal=principal,raw_flags=kind|flags,raw_rights=mask)

def semantic(value):
    return {key:value.get(key) for key in ('presence','flags','entries')}

def compare(ctx,oracle,path,follow=True,borrowed=False):
    native=ctx.record('native-read',oracle.read(path,follow))
    shard=ctx.bridge(dict(op='darwin.read',path=str(path),follow=follow,borrowed=borrowed))
    ctx.equal(semantic(shard),semantic(native),'Crystal read differs from native getattrlist evidence')
    libc=ctx.record('libc-read',oracle.libc_read(path,follow))
    # libc may erase the empty ACL; never use that as the oracle for empty state.
    if native.get('entries') and libc['ok']:
        parsed=wire.parse_darwin_export(bytes.fromhex(libc['hex']))
        ctx.equal(parsed['entries'],native['entries'],'libc enumeration/export disagrees with raw attribute entries')
        ctx.equal(parsed['flags'],native['flags'],'libc export disagrees with raw attribute flags')
    return shard

def roundtrip(ctx,oracle,entries,flags=0,directory=False):
    a=ctx.fixture('crystal-target',directory);b=ctx.fixture('oracle-target',directory)
    data=wire.darwin_export(entries,flags)
    errors={}
    for name,path in [('crystal',a),('oracle',b)]:
        try:
            if name=='crystal': ctx.bridge(dict(op='darwin.write',path=str(path),hex=data.hex()))
            else: oracle.write(path,data)
        except (NativeFailure,BridgeFailure) as exc: errors[name]=dict(code=exc.code,error=str(exc))
    ctx.record('write-input-and-outcome',dict(hex=data.hex(),errors=errors))
    if errors:
        ctx.require(len(errors)==2,'only one implementation rejected the write')
        ctx.equal(errors['crystal']['code'],errors['oracle']['code'],'native write error codes disagree')
        raise Observation('both implementations rejected this input; recorded, not counted as a successful round-trip')
    first=compare(ctx,oracle,a);second=compare(ctx,oracle,b)
    ctx.equal(semantic(first),semantic(second),'Crystal/native writes produced different kernel ACLs')
    if first.get('hex')!=data.hex(): ctx.notes.append('Kernel normalized requested ACL; both implementations agree on returned state.')
    if not directory:
        compare(ctx,oracle,a,borrowed=True)
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=data.hex(),borrowed=True))
        compare(ctx,oracle,a)
    return a,first

def create_tree(root):
    paths={}
    for rel,isdir in [('file',False),('dir',True),('dir/grandfile',False),('dir/granddir',True),('dir/granddir/greatfile',False)]:
        p=root/rel
        if isdir:p.mkdir()
        else:p.write_bytes(b'inheritance fixture')
        paths[rel]=p
    return paths

def run(ctx):
    oracle=Darwin();group=ctx.case['group'];name=ctx.case['id'].split('.')[-1];p=ctx.case['params']
    if group=='model': return model_cases.run(ctx)
    if group in ('rights','ace_flags'):
        return roundtrip(ctx,oracle,[entry(kind=p['kind'],mask=p.get('mask',2),flags=p.get('flags',0))],directory=p.get('obj','dir')=='dir')
    if group=='acl_flags': return roundtrip(ctx,oracle,[entry()]*p['count'],p['flags'])
    if group=='count':
        n=p['count']
        if n==129:
            data=bytearray(wire.darwin_export([entry()]*128));data[36:40]=(129).to_bytes(4,'big');data+=bytes(24)
            result=ctx.bridge(dict(op='model.darwin',hex=data.hex()),True)
            ctx.require(not result['ok'] and result['error']=='ACL::InvalidACLError','129-entry ACL not rejected before native call')
            return
        return roundtrip(ctx,oracle,[entry(kind=1+(i%2),mask=2<<(i%3)) for i in range(n)])
    if group=='ordering':
        items=[entry(kind=1,mask=6),entry(kind=2,mask=2),entry(kind=1,mask=128)]
        return roundtrip(ctx,oracle,[items[i] for i in p['order']])
    if group=='principal':
        values=dict(current_user=oracle.principal(),current_group=oracle.principal(True),everyone=EVERYONE,zero=str(uuid.UUID(int=0)),random=str(uuid.UUID(int=random.Random(ctx.case['seed']).getrandbits(128))),unknown_user='00112233-4455-6677-8899-aabbccddeeff')
        return roundtrip(ctx,oracle,[entry(principal=values[name])])
    if group=='inheritance':
        a=ctx.fixture('crystal-parent',True);b=ctx.fixture('oracle-parent',True)
        data=wire.darwin_export([entry(kind=p['kind'],flags=p['flags'])])
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=data.hex()));oracle.write(b,data)
        trees=[create_tree(a),create_tree(b)]
        for rel in trees[0]:
            first=compare(ctx,oracle,trees[0][rel]);second=compare(ctx,oracle,trees[1][rel])
            ctx.equal(semantic(first),semantic(second),'inheritance differs between native and Crystal-created parent ACLs: '+rel)
        # Assert the ordinary FI|DI case rather than only comparing two writers.
        if p['flags']==96:
            for rel in ['file','dir','dir/grandfile']:
                value=oracle.read(trees[0][rel])
                ctx.require(any(e['principal']==NOBODY and e['raw_flags']&16 for e in value.get('entries') or []),'expected inherited marker missing: '+rel)
        return
    if group=='chmod':
        a=ctx.fixture();data=wire.darwin_export([entry(principal=oracle.principal(),mask=128)])
        oracle.write(a,data)
        try:
            os.chmod(a,p['mode']);value=compare(ctx,oracle,a)
            ctx.record('mode-interaction',dict(mode=p['mode'],acl=value))
        finally:os.chmod(a,0o600)
        return
    if group=='attr_buffer':
        a=ctx.fixture();oracle.write(a,wire.darwin_export([entry()]))
        value=ctx.record('raw-sized-attribute',oracle.raw_attribute(a,size=p['size']))
        if p['size']>=100 and not value['returncode']: compare(ctx,oracle,a)
        raise Observation('raw getattrlist size/errno evidence; small-buffer behavior is not assigned a guessed contract')
    if group=='libc':
        a=ctx.fixture()
        for label,data in [('removed',None),('empty',wire.darwin_export([],0x20000)),('one',oracle.build_using_entry_api(oracle.principal()))]:
            oracle.write(a,data)
            ctx.record(label,dict(attribute=oracle.read(a),libc=oracle.libc_read(a)))
            compare(ctx,oracle,a)
            if label=='one':ctx.equal(data,wire.darwin_export([entry(principal=oracle.principal())]),'entry API disagrees with external byte format')
        return
    if group=='stress':
        a=ctx.fixture();oracle.write(a,wire.darwin_export([entry()]))
        result=ctx.bridge(dict(op='darwin.stress',path=str(a),mode=name,iterations=ctx.case['iterations']))
        ctx.record('resource-measurements',result)
        ctx.require(result['resources_after']<=result['resources_before']+2,'FD count grew after stress loop')
        return
    if group=='access':
        if os.geteuid()==0: raise SkipCase('run this enforcement case as an ordinary user; root is not the baseline credential')
        a=ctx.fixture();fd=os.open(a,os.O_RDWR)
        try:
            mask={'read':2,'write':4,'append':32}[name]
            data=wire.darwin_export([entry(principal=oracle.principal(),kind=2,mask=mask)])
            ctx.bridge(dict(op='darwin.write',path=str(a),hex=data.hex()))
            flags={'read':os.O_RDONLY,'write':os.O_WRONLY,'append':os.O_WRONLY|os.O_APPEND}[name]
            code=0
            try:
                h=os.open(a,flags);os.close(h)
            except OSError as exc:code=exc.errno
            ctx.record('real-open',dict(operation=name,errno=code))
            ctx.require(code in (errno.EACCES,errno.EPERM),'native open did not enforce the deny ACE')
            compare(ctx,oracle,a)
        finally:oracle.write(a,None,fd=fd);os.close(fd)
        return
    if group=='path': return paths(ctx,oracle,name)
    if group=='contract': return contract(ctx,oracle,name)
    raise AssertionError('unimplemented Darwin case '+ctx.case['id'])

def contract(ctx,oracle,name):
    if name=='invalid_handle':
        result=ctx.bridge(dict(op='darwin.invalid_handle'),True)
        ctx.require(not result['ok'] and result['code']==errno.EBADF,'invalid fd did not yield EBADF');return
    if name=='invalid_paths':
        f=ctx.fixture();values=[('',errno.ENOENT),(str(ctx.root/'missing'),errno.ENOENT),(str(f/'child'),errno.ENOTDIR)]
        for path,code in values:
            result=ctx.bridge(dict(op='darwin.read',path=path),True)
            ctx.require(not result['ok'] and result['code']==code,'unexpected path error: '+str(result))
        for op in ['darwin.read','darwin.write']:
            result=ctx.bridge(dict(op=op,path=str(f)+'\0suffix',hex=None),True)
            ctx.require(not result['ok'] and result['error']=='ArgumentError','NUL path reached native API')
        return
    if name=='permission_denied_lookup':
        if os.geteuid()==0: raise SkipCase('root bypasses this path traversal permission test')
        d=ctx.fixture('locked-dir',True);f=d/'file';f.write_bytes(b'x');os.chmod(d,0)
        try:
            result=ctx.bridge(dict(op='darwin.read',path=str(f)),True)
            ctx.require(not result['ok'] and result['code'] in (errno.EACCES,errno.EPERM),'lookup denial not surfaced')
        finally:os.chmod(d,0o700)
        return
    a=ctx.fixture()
    if name=='baseline': compare(ctx,oracle,a);return
    if name=='empty':
        data=wire.darwin_export([],0x20000)
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=data.hex()))
        value=compare(ctx,oracle,a)
        ctx.require(value['presence']=='Present' and value['entries']==[] and value['flags']==0x20000,'present empty ACL/NO_INHERIT was lost');return
    if name=='null_or_remove':
        oracle.write(a,wire.darwin_export([entry()]))
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=None))
        value=compare(ctx,oracle,a)
        ctx.require(value['entries'] is None,'remove retained a present ACL');return
    if name in ('borrowed_handle','fd_or_handle_permissions'):
        oracle.write(a,wire.darwin_export([entry()]))
        compare(ctx,oracle,a,borrowed=True)
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=wire.darwin_export([entry(mask=128)]).hex(),borrowed=True))
        compare(ctx,oracle,a)
        return
    raise AssertionError('unknown contract '+name)

def paths(ctx,oracle,name):
    names={'ascii':'file','spaces':'file with spaces','unicode':'雪-δοκιμή','decomposed':'e\u0301','emoji':'file-🧪','newline':'line\nbreak','long_component':'x'*240}
    if name in names:
        a=ctx.fixture(names[name]);oracle.write(a,wire.darwin_export([entry()]))
        compare(ctx,oracle,a);ctx.bridge(dict(op='darwin.write',path=str(a),hex=wire.darwin_export([entry(mask=128)]).hex()));compare(ctx,oracle,a);return
    if name=='relative':
        a=ctx.fixture();oracle.write(a,wire.darwin_export([entry()]))
        compare(ctx,oracle,pathlib.Path('fixture'));return
    if name=='fifo_nofollow':
        a=ctx.root/'fifo';os.mkfifo(a,0o600)
        ctx.bridge(dict(op='darwin.write',path=str(a),hex=wire.darwin_export([entry(mask=128)]).hex(),follow=False))
        compare(ctx,oracle,a,False);return
    a=ctx.fixture('target',directory=name in ('directory_symlink','intermediate_symlink'))
    oracle.write(a,wire.darwin_export([entry(mask=128)]))
    if name=='rename_handle':
        value=ctx.bridge(dict(op='darwin.rename_handle',path=str(a)))
        ctx.equal(semantic(value),semantic(oracle.read(str(a)+'.renamed')),'borrowed renamed descriptor mismatch');return
    link=ctx.root/'link'
    if name=='hardlink':os.link(a,link)
    else:os.symlink(str(ctx.root/'missing') if name=='dangling_symlink' else str(a),link)
    if name=='intermediate_symlink':
        target=a/'inner';target.write_bytes(b'x');path=link/'inner'
        data=wire.darwin_export([entry()]);ctx.bridge(dict(op='darwin.write',path=str(path),hex=data.hex(),follow=False))
        compare(ctx,oracle,target);return
    follow=name in ('symlink_follow','directory_symlink','hardlink')
    before=oracle.read(a)
    ctx.bridge(dict(op='darwin.write',path=str(link),hex=wire.darwin_export([entry(mask=512)]).hex(),follow=follow))
    compare(ctx,oracle,link,follow)
    if not follow:ctx.equal(semantic(oracle.read(a)),semantic(before),'nofollow write modified the target')
    else:ctx.equal(semantic(oracle.read(a)),semantic(oracle.read(link)),'follow/hardlink identity mismatch')
