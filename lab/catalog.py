"""Deterministic named case matrix. Counts are cases, not hidden loop assertions."""
import itertools

DARWIN_RIGHTS = {'read_data':2,'write_data':4,'execute':8,'delete':16,'append':32,
    'delete_child':64,'read_attr':128,'write_attr':256,'read_xattr':512,
    'write_xattr':1024,'read_security':2048,'write_security':4096,'chown':8192,
    'synchronize':1<<20,'generic_all':1<<21,'generic_execute':1<<22,
    'generic_write':1<<23,'generic_read':1<<24}
WINDOWS_RIGHTS = {'read_data':1,'write_data':2,'append':4,'read_ea':8,'write_ea':16,
    'execute':32,'delete_child':64,'read_attr':128,'write_attr':256,'delete':0x10000,
    'read_control':0x20000,'write_dac':0x40000,'write_owner':0x80000,'synchronize':0x100000,
    'generic_all':0x10000000,'generic_execute':0x20000000,'generic_write':0x40000000,
    'generic_read':0x80000000,'zero':0,'all_file':0x1f01ff}
PATH_KINDS = ['ascii','spaces','unicode','decomposed','emoji','newline','long_component','relative',
              'symlink_follow','symlink_nofollow','dangling_symlink','directory_symlink','intermediate_symlink','hardlink','rename_handle']


def cases(platform, profile='full', seed=20261103, iterations=1000, local_accounts=False):
    if platform not in ('darwin','windows'): raise ValueError('unsupported platform')
    if profile not in ('smoke','full','stress'): raise ValueError('unknown profile')
    result=[]
    def add(group, case_name, smoke=False, privileged=False, **p):
        result.append(dict(id=platform+'.'+group+'.'+case_name, platform=platform, group=group,
                           params=p, smoke=smoke, privileged=privileged, seed=seed, iterations=iterations))
    for name in ['baseline','empty','null_or_remove','invalid_paths','invalid_handle','borrowed_handle','fd_or_handle_permissions']:
        add('contract',name,smoke=True)
    for name in PATH_KINDS:
        add('path',name,smoke=name in ('unicode','symlink_nofollow','hardlink','rename_handle'))
    add('model','seeded_valid',smoke=True)
    add('model','bounded_malformed',smoke=True)
    if platform=='darwin':
        for (name,mask),kind,obj in itertools.product(DARWIN_RIGHTS.items(),[1,2],['file','dir']):
            add('rights',f'{obj}.{kind}.{name}',smoke=name=='read_data' and kind==1 and obj=='file',mask=mask,kind=kind,obj=obj)
        for flag_bits,kind in itertools.product(range(32),[1,2]):
            flags=sum(value for bit,value in enumerate([16,32,64,128,256]) if flag_bits & (1<<bit))
            add('ace_flags',f'{kind}.{flags:03x}',flags=flags,kind=kind)
        for flags,n in itertools.product([0,1,0x10000,0x20000,0x30000,0x20001],[0,1]):
            add('acl_flags',f'{flags:x}.{n}',smoke=flags==0x20000 and n==0,flags=flags,count=n)
        for n in [0,1,2,16,64,127,128,129]: add('count',str(n),count=n)
        for perm in itertools.permutations([0,1,2]): add('ordering',''.join(map(str,perm)),order=list(perm))
        for name in ['current_user','current_group','everyone','zero','random','unknown_user']:
            add('principal',name,name=name)
        for bits,kind in itertools.product(range(16),[1,2]):
            flags=sum(value for bit,value in enumerate([32,64,128,256]) if bits & (1<<bit))
            add('inheritance',f'{kind}.{flags:03x}',smoke=flags==96 and kind==1,flags=flags,kind=kind)
        for mode in [0,0o600,0o644,0o700,0o755,0o777]: add('chmod',f'{mode:o}',mode=mode)
        for right in ['read','write','append']: add('access',right,smoke=right=='read',right=right)
        for size in [4,24,28,32,44,68,128,3148]: add('attr_buffer',str(size),size=size)
        add('libc','absent_empty_nonempty',smoke=True)
        add('path','fifo_nofollow')
        add('contract','permission_denied_lookup')
    else:
        for (name,mask),kind,obj in itertools.product(WINDOWS_RIGHTS.items(),[0,1],['file','dir']):
            add('rights',f'{obj}.{kind}.{name}',smoke=name=='read_data' and kind==0 and obj=='file',mask=mask,kind=kind,obj=obj)
        for flags,kind in itertools.product(range(32),[0,1]): add('ace_flags',f'{kind}.{flags:02x}',flags=flags,kind=kind)
        for revision,count in itertools.product([2,4],[0,1,2,16,128,512]): add('count',f'{revision}.{count}',revision=revision,count=count)
        for n in [0,1,2,8,15]:
            for authority in [0,1,5,16,4294967301,281474976710655]: add('sid',f'{authority}.{n}',authority=authority,count=n)
        for kind in [0,1,2,3,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,254]:
            add('ace_binary',str(kind),kind=kind)
        for kind, guids in itertools.product([5,6,9,10,11,12],[0,1,2,3]):
            if kind in (9,10) and guids:continue
            add('extended_ace_write',f'{kind}.{guids}',kind=kind,guids=guids)
        for size in [4096,32768,65528,65532]:add('acl_limit',str(size),size=size)
        for information in [1,2,3,4,5,6,7,16,17,20,23,32,64,128,256]:
            add('query',f'{information:x}',smoke=information==7,information=information)
        for name in ['owner','group','dacl','protect','unprotect','preserve','unqueried_guard','null_guard','audit_in_dacl','absent_dacl']:
            add('update',name,smoke=name in ('dacl','protect','null_guard'))
        for bits in range(16): add('inheritance',f'{bits:02x}',smoke=bits==3,flags=bits)
        for name in ['existing_children','protected_child','unprotect_child','grandchildren']:
            add('propagation',name,smoke=name=='protected_child')
        for order,mask in itertools.product(['allow','deny','allow_then_deny','deny_then_allow','empty','null'],[1,2,4,0x20,0x80]):
            add('access',f'{order}.{mask:x}',smoke=mask==1 and order in ('empty','null','deny_then_allow'),order=order,mask=mask)
        for name in ['basic','empty','null','owner_group','protected','inheritance','object_guid','two_guids','audit','label','conditional','invalid']:
            add('sddl',name,smoke=name in ('object_guid','empty','conditional'))
        add('update','delegated_write_only')
        add('path','extended_length')
        add('sacl','pure_read_handles',privileged=True)
        add('sacl','no_enabled_privilege',smoke=True)
        add('stress','noop')
        for flags in [0x40,0x80,0xc0]: add('sacl',f'audit_{flags:x}',privileged=True,flags=flags)
        for name in ['query_backup','label_read','label_write_low','audit_dacl_isolation']:
            add('sacl',name,privileged=name!='label_read',name=name)
        if local_accounts:
            for case_name in [
                'identities',
                'alice_process_identity',
                'bob_process_identity',
                'carol_process_identity',
                'owner_implicit_read_control',
                'owner_implicit_write_dac',
                'owner_rights_deny_read_control',
                'owner_rights_deny_write_dac',
                'unrelated_user_denied',
                'explicit_user_allow_read',
                'explicit_user_deny_read',
                'allow_group_member',
                'allow_group_nonmember',
                'deny_group_overrides_user_allow',
                'deny_group_overrides_allow_group',
                'fresh_logon_membership_add',
                'fresh_logon_membership_remove',
                'existing_token_membership_snapshot',
                'delegated_write_dac_path',
                'delegated_write_dac_borrowed',
                'delegated_read_control',
                'deny_only_group_allow_ignored',
                'deny_only_group_deny_applies',
                'restricted_sid_double_check',
                'parent_delete_child',
                'child_delete_right',
                'traverse_with_change_notify',
                'traverse_without_change_notify',
                'creator_owner_inheritance',
                'creator_group_inheritance',
                'low_integrity_no_write_up',
                'low_integrity_no_read_up',
                'low_integrity_no_execute_up',
                'hardlink_descriptor_identity',
                'owner_group_update_isolation',
                'account_cleanup_recovery',
            ]:
                add('multiuser',case_name,privileged=case_name.startswith('low_integrity_'))
                result[-1]['local_accounts'] = True
    for name in ['read_handles','read_write','invalid_handles','serialize']:
        add('stress',name,smoke=False)
    if profile=='smoke': result=[r for r in result if r['smoke']]
    if profile=='stress':
        for r in result: r['iterations']=max(iterations,10000)
    return result
