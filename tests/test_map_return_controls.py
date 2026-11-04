"""Portable regressions for run 41864149171. Native outcomes require a native runner."""
import json
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from lab import behavior, map_controls as ctl, wire

OWNER = 'S-1-5-21-42-43-44-45'

class ReturnEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p = Path(self.temp.name) / 'domain.jsonl'
        self.keys = ('first', 'second')
        w = behavior.RowWriter(self.p, 'windows', 'authz', self.keys)
        w.emit('first', 'ok', {})
        w.emit('second', 'error', {'native_error': 87})
        w.finish()

    def validate(self):
        return behavior.validate_jsonl(self.p, 'windows', 'authz', self.keys)

    def test_genuine_row_errors_are_counted_not_mislabeled_corrupt(self):
        d = self.validate()
        self.assertEqual((d['completed'], d['counts']['error']), (2, 1))

    def test_corruption_still_fails(self):
        rows = [json.loads(s) for s in self.p.read_text().splitlines()]
        for label, modified in [
            ('false green', rows[:-1] + [dict(rows[-1],status='ok')]),
            ('wrong counts', rows[:-1] + [dict(rows[-1],details=dict(rows[-1]['details'],counts={}))]),
            ('missing', rows[1:]), ('duplicate', [rows[0]] + rows),
            ('non-final', rows+[rows[0]]), ('no final', rows[:-1]),
            ('wrong identity', [dict(rows[0],platform='darwin')]+rows[1:]),
            ('unexpected', [dict(rows[0],key='unexpected')]+rows[1:]),
        ]:
            with self.subTest(label=label):
                self.p.write_text(''.join(json.dumps(r)+'\n' for r in modified))
                with self.assertRaises(ValueError): self.validate()

    def test_null_empty_callback_and_resource_manager_are_preserved(self):
        for dacl in (None,wire.acl([]),wire.acl([wire.ace(9,3,1,wire.sid_bytes('S-1-1-0'),payload=b'keep')])):
            data = bytearray(wire.descriptor(group=wire.sid_bytes('S-1-5-18'),dacl=dacl,sacl=wire.acl([]),control=0x4000))
            data[1] = 0x5a
            before = wire.parse_descriptor(data)
            raw = ctl.with_owner(bytes(data), OWNER); after = wire.parse_descriptor(raw)
            self.assertEqual(after['owner'], OWNER)
            self.assertEqual(bytes(data[:4])+bytes(data[8:]), raw[:4]+raw[8:len(data)])
            for name in ('group','dacl','sacl','control','resource_manager'):
                self.assertEqual(before[name],after[name])
            self.assertIs(ctl.with_owner(raw,'S-1-1-0'),raw)

    def test_absent_dacl_and_invalid_binary_do_not_go_to_authz(self):
        for raw in (b'x',wire.descriptor(owner=wire.sid_bytes(OWNER))):
            with self.assertRaises(ValueError): ctl.with_owner(raw, OWNER)

    def test_fixture_recovery_precedes_handle_close_even_on_failure(self):
        events=[]
        class Oracle:
            @contextmanager
            def handle(self,path,mask):
                events.append(('open',path,mask))
                try: yield 321
                finally: events.append('close')
            def write_handle(self,*args): events.append(('restore',args))
        with self.assertRaisesRegex(ValueError,'mutation'):
            with ctl.fixture_guard(Oracle(),'leaf',b'recovery') as handle:
                self.assertEqual(handle,321);raise ValueError('mutation')
        self.assertEqual(events,[('open','leaf',0x60000),('restore',(321,b'recovery',4,'Protect')),'close'])

    def test_recovery_error_does_not_look_like_an_expected_denial(self):
        @contextmanager
        def handle(*args): yield 4
        oracle=Mock();oracle.handle=handle;oracle.write_handle.side_effect=PermissionError(5,'denied')
        with self.assertRaisesRegex(RuntimeError,'recovery failed'):
            with ctl.fixture_guard(oracle,'leaf',b'r'): pass

    def test_createfile_controls_vary_only_flags_and_access(self):
        oracle=Mock();oracle.try_open_detailed.return_value={'ok':True}
        controls=ctl.open_controls(oracle,'fixture',1)
        self.assertEqual({(c['desired'],c['flags']) for c in controls.values()},
                         {(1,0x2000000),(0x100001,0x2000000),(1,0x42000000),(0x100001,0x42000000)})
        self.assertEqual(oracle.try_open_detailed.call_count,4)

    def test_authz_gate_rejects_uniform_api_failure(self):
        records,bad=ctl.authz_controls(Mock(),None,OWNER,lambda fn: {'ok':False,'error':{'code':87}})
        self.assertEqual(bad,['allow_read','empty_dacl'])
        self.assertTrue(records['ownerless']['matched'])
        self.assertIsNone(wire.parse_descriptor(bytes.fromhex(records['ownerless']['descriptor_hex']))['owner'])

    def test_evaluated_denial_is_not_failed_api(self):
        results=iter([{'ok':False,'error':{'code':87}}, {'ok':True,'value':{'errors':[0],'granted':[1]}},
                      {'ok':True,'value':{'errors':[5],'granted':[0]}}])
        records, failures = ctl.authz_controls(None,None,OWNER,lambda fn: next(results))
        self.assertEqual(failures,[])
        self.assertTrue(records['empty_dacl']['reply']['ok'])

class WorkerWiringTests(unittest.TestCase):
    def test_worker_respects_platform_call_signatures(self):
        from lab import behavior_worker as worker, behavior_catalog
        import sys
        from types import ModuleType
        from unittest.mock import patch
        import lab
        for platform in ('darwin','windows'):
            seen=[]; name=platform+'_behavior'; module=ModuleType('lab.'+name)
            def darwin(domain,depth,workspace,writer,privileged=False):
                seen.append('darwin');writer.emit('k','ok',{})
            def windows(domain,depth,workspace,writer,privileged=False,local_accounts=False):
                seen.append(('windows',local_accounts));writer.emit('k','ok',{})
            module.run_domain=darwin if platform=='darwin' else windows
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules,{'lab.'+name:module}), patch.object(lab,name,module,create=True), patch.object(behavior_catalog,'manifest',return_value={'test':['k']}):
                out=Path(tmp)/'rows'; args=['--platform',platform,'--domain','test','--depth','smoke','--workspace',tmp,'--output',str(out)]
                if platform=='windows':args.append('--local-accounts')
                self.assertEqual(worker.main(args),0)
                self.assertEqual(behavior.validate_jsonl(out,platform,'test',['k'])['counts']['ok'],1)
                self.assertEqual(seen,['darwin'] if platform=='darwin' else [('windows',True)])

    def test_collector_and_independent_gate_retain_an_errored_domain(self):
        from ci import behavior as collector, evidence
        from lab import behavior_catalog, core
        from unittest.mock import patch
        def child(argv,prefix,timeout,cwd):
            out=Path(argv[argv.index('--output')+1]);w=behavior.RowWriter(out,'windows','test',['k']);w.emit('k','error',{'problem':'injected'});w.finish()
            return {'returncode':0,'timed_out':False}
        with tempfile.TemporaryDirectory() as td, patch.object(behavior_catalog,'manifest',return_value={'test':['k']}), patch.object(core,'command',side_effect=child):
            root=Path(td)
            with self.assertRaisesRegex(ValueError,'1 behavior row'):
                collector.run_all('windows','smoke',root,root)
            summary=json.loads((root/'behavior'/'summary.json').read_text()); self.assertIn('test',summary['domains'])
            result,errors=evidence.validate_behavior(root/'behavior','windows','windows-filtered')
            self.assertEqual(result['rows'],1);self.assertEqual(result['domains']['test']['counts']['error'],1)
            self.assertTrue(errors);self.assertFalse(any('contradict' in e or 'do not match' in e for e in errors))
