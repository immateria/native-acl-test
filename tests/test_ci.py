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
        sel = (
            'owner group dacl sacl label attribute scope process_trust_label '
            'access_filter basic audit_label protected_dacl unprotected_dacl '
            'protected_sacl unprotected_sacl conflicting_dacl_protection '
            'conflicting_sacl_protection all_defined backup'
        ).split()
        variants = [(0,'zero'),(0x20000,'sdk'),(0x120000,'plus_synchronize'),
                    (0x02000000,'maximum_allowed')]
        rows = [dict(kind='token', elevated=False,integrity_sid='S-1-16-8192')]+[dict(kind='selector',selector=s,object=o,operation=m,sdk_access=0x20000,access=mask,variant=v) for mask,v in variants for s in sel for o in ['file','directory'] for m in ['query','set']]
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

class ExpandedRunnerMatrixTests(unittest.TestCase):
    def test_manual_all_maps_supported_hosted_runner_families(self):
        lanes = lane.matrix('workflow_dispatch', 'all')['include']
        self.assertEqual(lanes, [
            {'lane': 'macos-arm64', 'runner': 'macos-15'},
            {'lane': 'macos-x64', 'runner': 'macos-15-intel'},
            {'lane': 'windows-elevated', 'runner': 'windows-2025'},
            {'lane': 'windows-filtered', 'runner': 'windows-2025'},
            {'lane': 'windows-2022-elevated', 'runner': 'windows-2022'},
            {'lane': 'windows-2022-filtered', 'runner': 'windows-2022'},
        ])

    def test_push_remains_bounded_to_primary_three_lanes(self):
        self.assertEqual(
            [entry['lane'] for entry in lane.matrix('push', 'all')['include']],
            ['macos-arm64', 'windows-elevated', 'windows-filtered'],
        )

    def test_new_lane_identity_and_privilege_policy(self):
        lane.check_identity('macos-x64', {
            'system': 'Darwin', 'machine': 'x86_64', 'bits': 64, 'uid': 501,
        })
        lane.check_identity('windows-2022-filtered', {
            'system': 'Windows', 'machine': 'AMD64', 'bits': 64,
            'elevated': False, 'integrity_sid': 'S-1-16-8192', 'admin_member': False,
        })
        lane.check_identity('windows-2022-elevated', {
            'system': 'Windows', 'machine': 'AMD64', 'bits': 64,
            'elevated': True, 'integrity_sid': 'S-1-16-12288', 'admin_member': True,
        })
        filtered_args, _ = lane.plan('windows-2022-filtered', 'map', '', '41')
        elevated_args, _ = lane.plan('windows-2022-elevated', 'map', '', '41')
        self.assertNotIn('--privileged', filtered_args)
        self.assertIn('--privileged', elevated_args)

    def test_generated_filesystem_cleanup_verifies_partial_native_resources(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        mac = (root / 'ci/macos-volumes.sh').read_text(encoding='utf-8')
        win = (root / 'ci/windows-filesystems.ps1').read_text(encoding='utf-8')
        self.assertIn('detach_plist_devices', mac)
        self.assertIn('attach succeeded without a bounded disk device', mac)
        self.assertIn('Get-SmbShare -Name', win)
        self.assertRegex(
            win,
            r'\$state = Get-VHD -Path \$vhd[\s\S]+if \(\$state\.Attached\) \{[\s\S]+Dismount-VHD -Path \$vhd',
        )
        self.assertIn('unsafe VHD path in metadata', win)
        self.assertIn('generated filesystem root cleanup failed', win)

    def test_workflow_wires_generated_filesystems_and_cleanup(self):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/native-acl.yml').read_text(encoding='utf-8')
        for lane_name in ('macos-x64', 'windows-2022-elevated', 'windows-2022-filtered'):
            self.assertIn(lane_name, workflow)
        self.assertIn('ci/macos-volumes.sh prepare', workflow)
        self.assertIn('ci/macos-volumes.sh cleanup', workflow)
        self.assertIn('ci/windows-filesystems.ps1 -Stage Prepare', workflow)
        self.assertIn('ci/windows-filesystems.ps1 -Stage Cleanup', workflow)
        self.assertRegex(workflow, r'name: Cleanup generated native filesystems[\s\S]+if: always\(\)')
        self.assertIn('timeout-minutes: 360', workflow)

    def test_filesystem_scripts_are_scoped_and_emit_replayable_metadata(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        mac = (root / 'ci/macos-volumes.sh').read_text(encoding='utf-8')
        win = (root / 'ci/windows-filesystems.ps1').read_text(encoding='utf-8')
        for token in ('native-acl-ci/generated-filesystems', 'macos-filesystems.json',
                      'ACL_MACOS_APFSX_ROOT', 'ACL_MACOS_HFSX_ROOT', 'hdiutil detach'):
            self.assertIn(token, mac)
        for token in ('generated-filesystems', 'windows-filesystems.json',
                      'ACL_LOOPBACK_SMB_ROOT', 'ACL_WINDOWS_REFS_ROOT',
                      'New-SmbShare', 'Remove-SmbShare', 'Dismount-VHD'):
            self.assertIn(token, win)
        self.assertIn('icacls.exe $refsRoot /grant', win)
        self.assertIn('icacls.exe $refsRoot /setintegritylevel', win)
        self.assertNotIn('Remove-Item -Recurse -Force $env:RUNNER_TEMP', win)

class BehaviorComparisonTests(unittest.TestCase):
    @staticmethod
    def _artifact(root, value, path_prefix, reverse=False):
        import json
        from pathlib import Path
        root = Path(root)
        (root / 'behavior').mkdir(parents=True)
        (root / 'run.json').write_text(json.dumps({
            'lane': 'macos-arm64', 'context': {'GITHUB_SHA': str(value)}, 'args': ['--profile', 'map'],
        }), encoding='utf-8')
        (root / 'gate.json').write_text(json.dumps({'ok': True, 'problems': []}), encoding='utf-8')
        rows = [
            {'schema': 1, 'platform': 'darwin', 'domain': 'api', 'key': 'api:path-only',
             'status': 'ok', 'details': {'path': f'{path_prefix}/native-acl-ci/scratch/fixture', 'value': 7}},
            {'schema': 1, 'platform': 'darwin', 'domain': 'api', 'key': 'api:changed',
             'status': 'ok', 'details': {'value': value, 'elapsed_seconds': value * 10}},
            {'schema': 1, 'platform': 'darwin', 'domain': 'api', 'key': 'summary',
             'status': 'ok', 'details': {}},
        ]
        if reverse:
            rows[:2] = reversed(rows[:2])
        (root / 'behavior/api.jsonl').write_text(
            ''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')

    def test_behavior_diff_uses_semantic_keys_and_normalizes_runner_paths(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.compare import compare
        with TemporaryDirectory() as temporary:
            old = Path(temporary) / 'old'
            new = Path(temporary) / 'new'
            old.mkdir(); new.mkdir()
            self._artifact(old, 1, '/Users/runner/work/repo', reverse=False)
            self._artifact(new, 2, 'D:/a/repo', reverse=True)
            report = compare(old, new)
            self.assertEqual(report['behavior_coverage_changes'], [])
            self.assertEqual(len(report['behavior_changes']), 1)
            self.assertEqual(report['behavior_changes'][0]['key'], ('api', 'api:changed'))
            self.assertEqual(report['behavior_changes'][0]['before']['details'], {'value': 1})
            self.assertEqual(report['behavior_changes'][0]['after']['details'], {'value': 2})

    def test_behavior_diff_normalizes_ephemeral_identities_and_binary_layout(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.compare import compare

        def write(root, sid, principal, account, raw):
            root = Path(root)
            (root / "behavior").mkdir(parents=True)
            (root / "run.json").write_text(json.dumps({
                "lane": "windows-elevated", "context": {"GITHUB_SHA": raw},
                "args": ["--profile", "map"],
            }), encoding="utf-8")
            (root / "gate.json").write_text(json.dumps({"ok": True, "problems": []}), encoding="utf-8")
            rows = [
                {"schema": 1, "platform": "windows", "domain": "descriptor-storage",
                 "key": "descriptor-storage:identity", "status": "ok",
                 "details": {
                     "owner_sid": sid,
                     "account": {"name": account, "sid": sid},
                     "principal": principal,
                     "requested_hex": raw,
                     "descriptor": raw,
                     "bounded": {"owner": sid, "bytes": len(raw) // 2, "control": 0x8004},
                 }},
                {"schema": 1, "platform": "windows", "domain": "descriptor-storage",
                 "key": "summary", "status": "ok", "details": {}},
            ]
            (root / "behavior/descriptor-storage.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

        with TemporaryDirectory() as temporary:
            old = Path(temporary) / "old"
            new = Path(temporary) / "new"
            old.mkdir(); new.mkdir()
            write(old, "S-1-5-21-111-222-333-1001",
                  "11111111-2222-3333-4444-555555555555",
                  "aclA_deadbeef", "001122334455")
            write(new, "S-1-5-21-999-888-777-4242",
                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                  "aclA_cafebabe", "ffeeddccbbaa")
            report = compare(old, new)
            self.assertEqual(report["behavior_changes"], [])
            self.assertEqual(report["behavior_change_summary"], {})

    def test_behavior_diff_rejects_duplicate_semantic_keys(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.compare import compare
        with TemporaryDirectory() as temporary:
            old = Path(temporary) / 'old'
            new = Path(temporary) / 'new'
            old.mkdir(); new.mkdir()
            self._artifact(old, 1, '/tmp/a')
            self._artifact(new, 1, '/tmp/b')
            path = new / 'behavior/api.jsonl'
            rows = path.read_text(encoding='utf-8').splitlines()
            path.write_text('\n'.join([rows[0], rows[0], rows[1], rows[2]]) + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate behavior key'):
                compare(old, new)


class BehaviorEvidenceGateTests(unittest.TestCase):
    def _write_behavior(self, root, platform, depth, lane):
        from lab import behavior_catalog
        from lab.behavior import RowWriter, validate_jsonl
        from lab import core
        manifest = behavior_catalog.manifest(platform, depth)
        if platform == 'windows' and lane != 'windows-lab':
            manifest = {name: values for name, values in manifest.items() if name != 'multiuser-map'}
        domains = {}
        behavior_root = root / 'behavior'
        behavior_root.mkdir(parents=True)
        for domain, expected in manifest.items():
            writer = RowWriter(behavior_root / f'{domain}.jsonl', platform, domain, expected)
            for key in expected:
                writer.emit(key, 'ok', {'value': key})
            writer.finish()
            domains[domain] = validate_jsonl(behavior_root / f'{domain}.jsonl', platform, domain, expected)
        core.write_json(behavior_root / 'summary.json', {
            'platform': platform,
            'depth': depth,
            'domains': domains,
            'failures': [],
            'expected_rows': sum(map(len, manifest.values())),
        })
        return manifest

    def test_behavior_gate_revalidates_every_domain_and_row(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.evidence import validate_behavior
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self._write_behavior(root, 'darwin', 'smoke', 'macos-arm64')
            summary, errors = validate_behavior(root / 'behavior', 'darwin', 'macos-arm64')
            self.assertEqual(errors, [])
            self.assertEqual(summary['rows'], sum(map(len, manifest.values())))
            missing = next(iter(manifest))
            (root / 'behavior' / f'{missing}.jsonl').unlink()
            _, errors = validate_behavior(root / 'behavior', 'darwin', 'macos-arm64')
            self.assertTrue(any(missing in error for error in errors))

    def test_recursive_hash_manifest_includes_behavior_evidence(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from ci.evidence import write_hash_manifest
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'behavior').mkdir()
            (root / 'top.json').write_text('{}\n', encoding='utf-8')
            (root / 'behavior' / 'api.jsonl').write_text('{}\n', encoding='utf-8')
            write_hash_manifest(root)
            manifest = (root / 'SHA256SUMS').read_text(encoding='utf-8')
            self.assertIn('  top.json\n', manifest)
            self.assertIn('  behavior/api.jsonl\n', manifest)
