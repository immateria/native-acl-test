import unittest
from ci import lane

class LaneTests(unittest.TestCase):
    def test_push_only_three_and_no_accounts(self):
        lanes = lane.matrix('push', 'windows-lab')['include']
        self.assertEqual([row['lane'] for row in lanes], ['macos-arm64', 'windows-elevated', 'windows-filtered'])
    def test_isolated_account_dispatch(self):
        self.assertEqual(lane.matrix('workflow_dispatch', 'windows-lab')['include'], [{'lane':'windows-lab','runner':'windows-2025'}])
        with self.assertRaises(ValueError): lane.matrix('pull_request_target', 'windows-lab')
    def test_focused_selection_and_account_boundary(self):
        args, ids = lane.plan('windows-lab','smoke','','41')
        self.assertIn('--local-accounts', args)
        self.assertEqual(len(ids), 36)
        self.assertTrue(all(x.startswith('windows.multiuser.') for x in ids))
        args, ids = lane.plan('windows-filtered','full','windows.sacl.pure_read_handles','41')
        self.assertEqual(ids, ['windows.sacl.pure_read_handles'])
        self.assertNotIn('--privileged', args)
        for bad in ['foo*','../foo','windows.*;curl']:
            with self.assertRaises(ValueError): lane.plan('windows-elevated','full',bad,'1')
        with self.assertRaises(ValueError): lane.plan('windows-lab','full','windows.path.*','1')
    def test_identity_enforced(self):
        lane.check_identity('windows-filtered',{'system':'Windows','machine':'AMD64','bits':64,'elevated':False,'integrity_sid':'S-1-16-8192','admin_member':False})
        for patch in [{'elevated':True},{'integrity_sid':'S-1-16-12288'},{'admin_member':True},{'machine':'ARM64'}]:
            ident={'system':'Windows','machine':'AMD64','bits':64,'elevated':False,'integrity_sid':'S-1-16-8192','admin_member':False};ident.update(patch)
            with self.assertRaises(ValueError): lane.check_identity('windows-filtered',ident)
        with self.assertRaises(ValueError): lane.check_identity('macos-arm64',{'system':'Darwin','machine':'arm64','bits':64,'uid':0})

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.meta={'expected':['darwin.a'], 'lane':'macos-arm64','args':['--seed','1','--skip-specs']}
        self.man=[{'id':'darwin.a'}];self.results=[{'id':'darwin.a','status':'PASS'}]
        stages=[{'name':name,'status':'PASS'} for name in ['crystal-version','bridge-build','format','sdk-abi-run','sdk-abi-build','final-cleanup']]
        self.summary={'counts':{'PASS':1},'completed':1,'selected':1,'exit_code':0,'errors':[],'platform':'darwin','stages':stages}

    def test_green_is_complete_and_not_a_skip(self):
        from ci.evidence import validate
        self.assertEqual(validate(self.meta,self.man,self.results,self.summary),[])
        for s in ['FAIL','ERROR','TIMEOUT','BLOCKED','SKIP','UNKNOWN']:
            self.assertTrue(validate(self.meta,self.man,[{'id':'darwin.a','status':s}],dict(self.summary,counts={s:1})))
        self.assertEqual(validate(self.meta,self.man,[{'id':'darwin.a','status':'OBSERVE'}],dict(self.summary,counts={'OBSERVE':1})),[])

    def test_missing_duplicate_wrong_os_and_missing_sdk_are_red(self):
        from ci.evidence import validate
        self.assertTrue(validate(self.meta,self.man,[],self.summary))
        self.assertTrue(validate(self.meta,self.man,self.results*2,self.summary))
        for change in [{'platform':'windows'},{'stages':[]},{'errors':['fixture remains']},{'completed':0}]:
            self.assertTrue(validate(self.meta,self.man,self.results,dict(self.summary,**change)))

    def test_partial_run_is_packaged_but_red(self):
        from ci.evidence import finish
        from pathlib import Path
        from tempfile import TemporaryDirectory
        import contextlib,io,json,zipfile
        with TemporaryDirectory() as t:
            w=Path(t)/'work';o=Path(t)/'out';o.mkdir();r=w/'raw/acl-results-darwin-synthetic';r.mkdir(parents=True)
            (o/'run.json').write_text(json.dumps(self.meta));(r/'results.jsonl').write_text('{"id":"darwin.a","status":"PASS"}\n')
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(finish(w,o),1)
            with zipfile.ZipFile(o/'handback.zip') as z: self.assertIsNone(z.testzip())
            self.assertFalse(json.loads((o/'gate.json').read_text())['ok'])

    def test_diff_uses_selector_keys_not_attempt_id(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.compare import compare
        with TemporaryDirectory() as t:
            a,b=Path(t)/'a',Path(t)/'b';a.mkdir();b.mkdir()
            for dest,code,idx in [(a,5,1),(b,0,23)]:
                (dest/'run.json').write_text(json.dumps(dict(lane='windows-filtered',context={},args=[])))
                (dest/'windows-selectors.jsonl').write_text(json.dumps(dict(kind='selector',object='file',operation='set',selector='dacl',variant='sdk',api_code=code,attempt_id=idx))+'\n')
            c=compare(a,b);self.assertEqual(len(c['selector_changes']),1)
            change=c['selector_changes'][0];self.assertEqual((change['before']['api_code'],change['after']['api_code']),(5,0))

class MapperTests(unittest.TestCase):
    def test_matrix_completeness_and_token_are_checked(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.explore import verify_mapper
        sel = 'owner group dacl sacl label attribute scope process_trust_label access_filter basic audit_label all_defined backup'.split()
        rows = [dict(kind='token', elevated=False,integrity_sid='S-1-16-8192')]+[dict(kind='selector',selector=s,object=o,operation=m,sdk_access=0x20000,access=mask,variant=v) for mask,v in [(0,'zero'),(0x20000,'sdk')] for s in sel for o in ['file','directory'] for m in ['query','set']]
        with TemporaryDirectory() as t:
            p=Path(t)/'map';q=Path(t)/'summary'
            def write(items): p.write_text(''.join(json.dumps(x)+'\n' for x in items))
            write(rows);verify_mapper(p,'windows-filtered',False,q)
            write(rows[:-1]);
            with self.assertRaises(ValueError): verify_mapper(p,'windows-filtered',False,q)
            write(rows+[dict(kind='privilege_enable')]);
            with self.assertRaises(ValueError): verify_mapper(p,'windows-filtered',False,q)
            write([dict(kind='token',elevated=True,integrity_sid='S-1-16-12288')]+rows[1:]);
            with self.assertRaises(ValueError): verify_mapper(p,'windows-filtered',False,q)
