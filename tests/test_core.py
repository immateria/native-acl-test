import json
import pathlib
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from lab import wire, catalog, core

class WireTests(unittest.TestCase):
    def test_sid_endian_and_limits(self):
        b=wire.sid_bytes('S-1-5-21-4294967295')
        self.assertEqual(b.hex(),'010200000000000515000000ffffffff')
        self.assertEqual(wire.sid_text(b),'S-1-5-21-4294967295')
        for s in ['S-2-5-1','S-1-281474976710656-1','S-1-5--1','S-1-5-4294967296']:
            with self.assertRaises(ValueError): wire.sid_bytes(s)
    def test_windows_descriptor_and_empty_null(self):
        sid=wire.sid_bytes('S-1-1-0')
        ace=wire.ace(0,0x12,0x12345678,sid)
        acl=wire.acl([ace])
        sd=wire.descriptor(owner=sid,group=sid,dacl=acl)
        p=wire.parse_descriptor(sd)
        self.assertEqual(p['owner'],'S-1-1-0')
        self.assertEqual(p['dacl']['entries'][0]['mask'],0x12345678)
        self.assertEqual(wire.parse_descriptor(wire.descriptor())['dacl']['presence'],'Absent')
        self.assertEqual(wire.parse_descriptor(wire.descriptor(dacl=None))['dacl']['presence'],'Null')
        self.assertEqual(wire.parse_descriptor(wire.descriptor(dacl=wire.acl([])))['dacl']['presence'],'Present')
    def test_object_guid_and_payload(self):
        a=wire.ace(11,0,1,wire.sid_bytes('S-1-1-0'),object_guid='00112233-4455-6677-8899-aabbccddeeff',payload=b'artx')
        self.assertEqual(a[12:28].hex(),'33221100554477668899aabbccddeeff')
        p=wire.parse_acl(wire.acl([a],revision=4))['entries'][0]
        self.assertEqual(p['object_type'],'00112233-4455-6677-8899-aabbccddeeff')
        self.assertEqual(p['application_data'],'61727478')
    def test_darwin_export(self):
        b=wire.darwin_export([dict(principal='00112233-4455-6677-8899-aabbccddeeff',raw_flags=1,raw_rights=2)],0x20000)
        self.assertEqual(len(b),68)
        self.assertEqual(b[:4].hex(),'012cc16d')
        self.assertEqual(struct.unpack_from('>II',b,36),(1,0x20000))
        self.assertEqual(wire.parse_darwin_export(b)['entries'][0]['raw_rights'],2)
    def test_bound_checks(self):
        for b in [b'',b'\0'*19, b'\1\0\0\x80'+b'\xff'*16]:
            with self.assertRaises(ValueError): wire.parse_descriptor(b)
        with self.assertRaises(ValueError): wire.parse_darwin_export(b'\0'*44)

class CatalogTests(unittest.TestCase):
    def test_unique_stable_cases(self):
        for osname in ['darwin','windows']:
            a=catalog.cases(osname,'full',1234,1000)
            self.assertGreater(len(a),150)
            self.assertEqual(len(a),len({x['id'] for x in a}))
            self.assertEqual(a,catalog.cases(osname,'full',1234,1000))
            self.assertTrue(all(x['platform']==osname for x in a))
    def test_smoke_is_subset_and_privilege_optin(self):
        full=catalog.cases('windows','full',1,500)
        smoke=catalog.cases('windows','smoke',1,500)
        self.assertLess(len(smoke),len(full))
        self.assertTrue(any(x.get('privileged') for x in full))
        self.assertTrue(set(x['id'] for x in smoke)<=set(x['id'] for x in full))

class CoreTests(unittest.TestCase):
    def test_process_failure_and_timeout(self):
        with tempfile.TemporaryDirectory() as t:
            out=core.command([sys.executable,'-c','import sys; print("evidence"); sys.exit(7)'],pathlib.Path(t)/'fail',5)
            self.assertEqual(out['returncode'],7)
            self.assertIn('evidence',pathlib.Path(out['stdout']).read_text())
            out=core.command([sys.executable,'-c','import time; time.sleep(30)'],pathlib.Path(t)/'timeout',.1)
            self.assertTrue(out['timed_out'])
    def test_archive_contains_integrity_and_no_symlink_follow(self):
        import zipfile
        with tempfile.TemporaryDirectory() as t:
            r=pathlib.Path(t)/'results';r.mkdir();(r/'x.json').write_text('{}')
            external=pathlib.Path(t)/'private';external.write_text('DO NOT SHIP')
            try: (r/'link').symlink_to(external)
            except OSError: pass
            target=core.archive(r)
            with zipfile.ZipFile(target) as z:
                self.assertTrue(any(n.endswith('manifest.sha256') for n in z.namelist()))
                self.assertFalse(any(n.endswith('/link') for n in z.namelist()))
    def test_scratch_creation_never_reuses_directory(self):
        with tempfile.TemporaryDirectory() as t:
            a=core.new_workspace(pathlib.Path(t));b=core.new_workspace(pathlib.Path(t))
            self.assertNotEqual(a,b)
            self.assertTrue((a/'.acl-lab-owned').is_file())


class AdditionalSafetyTests(unittest.TestCase):
    def test_delete_does_not_follow_external_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            parent=pathlib.Path(t)
            external=parent/'external';external.mkdir();(external/'keep').write_text('safe')
            root=parent/'owned';root.mkdir()
            try:(root/'link').symlink_to(external,target_is_directory=True)
            except OSError:self.skipTest('symlink creation unavailable')
            core.safe_remove_tree(root)
            self.assertEqual((external/'keep').read_text(),'safe')
    def test_native_struct_sizes_match_64_bit_sdk_expectations(self):
        import ctypes
        from lab.darwin import Attributes
        from lab.windows import LUID,Privileges,Mapping
        self.assertEqual(ctypes.sizeof(Attributes),24)
        self.assertEqual(ctypes.sizeof(LUID),8)
        self.assertEqual(ctypes.sizeof(Privileges),16)
        self.assertEqual(ctypes.sizeof(Mapping),16)
    def test_window_acl_size_boundaries(self):
        sid=wire.sid_bytes('S-1-1-0')
        for size in [4096,32768,65528,65532]:
            a=wire.ace(0,0,1,sid);count=(size-8)//len(a)
            data=wire.acl([a]*count,padding=b'\0'*(size-8-count*len(a)))
            parsed=wire.parse_acl(data)
            self.assertEqual(parsed['size'],size)
            self.assertEqual(len(parsed['entries']),count)
    def test_profile_selection_does_not_enable_privileges(self):
        from run import parser, selected
        args=parser().parse_args(['--profile','full'])
        self.assertFalse(args.privileged)
        self.assertEqual(len(selected(args,'windows')),357)
        self.assertEqual(len(selected(args,'darwin')),248)
    def test_portable_worker_writes_result_and_cleans_on_blocked_build(self):
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            t=pathlib.Path(t);workspace=core.new_workspace(t);root=workspace/'test';root.mkdir()
            evidence=t/'evidence';evidence.mkdir()
            cfg=dict(case=dict(id='darwin.model.seeded_valid',platform='darwin',group='model',seed=1,iterations=128),
                     root=str(root),evidence=str(evidence),workspace_name=workspace.name,bridge=None,model_only=True)
            config=evidence/'config.json';core.write_json(config,cfg)
            kit=pathlib.Path(__file__).resolve().parents[1]
            result=subprocess.run([sys.executable,'-m','lab.worker',str(config)],cwd=kit,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            data=json.loads((evidence/'result.json').read_text())
            self.assertEqual(data['status'],'BLOCKED')
            self.assertFalse(root.exists())

@unittest.skipUnless(sys.platform.startswith('linux'), 'POSIX process-tree regression is verified on Linux')
class ProcessTreeTests(unittest.TestCase):
    def test_outer_timeout_terminates_nested_bridge(self):
        import os
        with tempfile.TemporaryDirectory() as t:
            parent=pathlib.Path(t)
            kit=pathlib.Path(__file__).resolve().parents[1]
            child="import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
            worker="from lab.core import command; import sys; command([sys.executable,'-c',sys.argv[1],sys.argv[2]],sys.argv[3],30,isolate=False)"
            result=core.command([sys.executable,'-c',worker,child,str(parent/'pid'),str(parent/'nested')],parent/'outer',3,cwd=kit)
            self.assertTrue(result['timed_out'])
            pid=int((parent/'pid').read_text())
            status=pathlib.Path('/proc')/str(pid)/'stat'
            import time, signal
            deadline=time.monotonic()+2
            try:
                while status.exists() and status.read_text().split(') ',1)[1].split()[0]!='Z' and time.monotonic()<deadline:
                    time.sleep(.01)
                if status.exists():
                    self.assertEqual(status.read_text().split(') ',1)[1].split()[0],'Z','bridge survived worker timeout')
            finally:
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass


class ReturnRegressionTests(unittest.TestCase):
    def test_extended_scratch_names_handle_local_and_unc_prefixes(self):
        from lab.windows_cases import extended_path
        for ordinary, extended in [(r'C:\dir\f',r'\\?\C:\dir\f'), (r'\\server\share\f',r'\\?\UNC\server\share\f')]:
            self.assertEqual(extended_path(ordinary),extended)
            self.assertEqual(extended_path(extended),extended)
        with self.assertRaises(ValueError):extended_path(r'dir\relative')

    def test_privileged_positive_control_and_ordinary_negative_control_are_distinct(self):
        cases={c['id']:c for c in catalog.cases('windows')}
        self.assertTrue(cases['windows.sacl.pure_read_handles']['privileged'])
        self.assertFalse(cases['windows.sacl.no_enabled_privilege']['privileged'])
        self.assertFalse(cases['windows.stress.noop']['privileged'])

class LocalAccountLabTests(unittest.TestCase):
    def test_local_account_catalog_is_opt_in_and_named(self):
        ordinary=catalog.cases('windows','full',1,100)
        expanded=catalog.cases('windows','full',1,100,local_accounts=True)
        self.assertEqual(len(ordinary),357)
        self.assertGreaterEqual(len(expanded)-len(ordinary),30)
        added=[case for case in expanded if case.get('local_accounts')]
        self.assertEqual(len(added),len(expanded)-len(ordinary))
        self.assertTrue(all(case['id'].startswith('windows.multiuser.') for case in added))
        self.assertEqual(len(added),len({case['id'] for case in added}))

    def test_parser_requires_explicit_local_account_opt_in(self):
        from run import parser, selected
        ordinary=parser().parse_args(['--profile','full'])
        enabled=parser().parse_args(['--profile','full','--local-accounts'])
        self.assertFalse(ordinary.local_accounts)
        self.assertTrue(enabled.local_accounts)
        self.assertEqual(len(selected(ordinary,'windows')),357)
        self.assertGreater(len(selected(enabled,'windows')),357)

    def test_account_names_are_unique_bounded_and_portable(self):
        from lab.windows_accounts import account_names
        names=account_names('acl-results-windows-20261103T010203Z-01234567')
        values=list(names['users'].values())+list(names['groups'].values())
        self.assertEqual(len(values),len(set(values)))
        self.assertTrue(all(1 <= len(name) <= 20 for name in values))
        self.assertTrue(all(name.replace('_','').isalnum() for name in values))

    def test_local_account_membership_uses_qualified_local_name(self):
        from lab.windows_accounts import qualified_account_name
        self.assertEqual(qualified_account_name('DESKTOP42','alice'),'DESKTOP42\\alice')
        self.assertEqual(qualified_account_name('.','alice'),'.\\alice')

    def test_public_account_description_redacts_passwords(self):
        from lab.windows_accounts import public_account_description
        secret={'users':{'alice':{'name':'aclA_123','password':'TopSecret!1','sid':'S-1-5-21-1'}},
                'groups':{'allow':{'name':'aclG_123','sid':'S-1-5-21-2','members':['alice']}}}
        public=public_account_description(secret)
        encoded=json.dumps(public)
        self.assertNotIn('TopSecret',encoded)
        self.assertNotIn('password',encoded.lower())
        self.assertEqual(public['users']['alice']['sid'],'S-1-5-21-1')

    def test_secret_file_is_protected_before_workspace_is_opened_to_lab_users(self):
        source=(pathlib.Path(__file__).resolve().parents[1]/'run.py').read_text(encoding='utf-8')
        self.assertLess(source.index('write_secret_file(account_secret_path,account_secret)'),
                        source.index("access_sids=[value['sid']"))

    def test_multiuser_launcher_explicitly_opts_into_privilege_cases(self):
        script=(pathlib.Path(__file__).resolve().parents[1]/'run-windows-multiuser.ps1').read_text(encoding='utf-8')
        self.assertIn("'-Privileged'",script)

    def test_emergency_cleanup_script_requires_public_metadata_and_validates_names(self):
        script=(pathlib.Path(__file__).resolve().parents[1]/'scripts'/'cleanup-local-accounts.ps1').read_text(encoding='utf-8')
        self.assertIn('local-accounts.json',script)
        self.assertIn('Validate-LabName',script)
        self.assertIn('Translate([Security.Principal.SecurityIdentifier])',script)
        self.assertIn('expected_sid',script)
        self.assertNotIn('.password',script.lower())
        self.assertNotIn('["password"]',script.lower())
        self.assertNotIn("['password']",script.lower())


class ExecutableResolutionTests(unittest.TestCase):
    def test_relative_executable_path_is_resolved_before_cwd_changes(self):
        import os
        from unittest import mock
        import run
        with tempfile.TemporaryDirectory() as t:
            root=pathlib.Path(t)
            previous=os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(run.shutil,'which',return_value='./tool'):
                    resolved=run.resolve_executable('./tool')
                with mock.patch.object(run.shutil,'which',return_value=None):
                    missing=run.resolve_executable('./missing')
            finally:
                os.chdir(previous)
            self.assertEqual(resolved,str((root/'tool').resolve()))
            self.assertIsNone(missing)


class WindowsNativeMapTests(unittest.TestCase):
    def test_compile_command_is_strict_and_links_only_sdk_libraries(self):
        from lab.windows_native_map import compile_command
        command=compile_command(r'C:\VS\cl.exe',pathlib.Path('probe.c'),pathlib.Path('map.exe'),pathlib.Path('map.obj'))
        self.assertEqual(command[0],r'C:\VS\cl.exe')
        for value in ['/nologo','/std:c11','/W4','/WX','/Fe:map.exe','/Fo:map.obj','advapi32.lib','kernel32.lib']:
            self.assertIn(value,command)
        self.assertNotIn('shell=True',' '.join(command))

    def test_jsonl_loader_rejects_nonobjects_and_summarizes_outcomes(self):
        from lab.windows_native_map import load_jsonl, summarize
        with tempfile.TemporaryDirectory() as t:
            path=pathlib.Path(t)/'map.jsonl'
            path.write_text(
                '{"kind":"environment","ok":true}\n'
                '{"kind":"selector","fixture_code":0,"open_code":0,"api_code":5,"cleanup_code":0}\n'
                '{"kind":"selector","fixture_code":3,"open_code":null,"api_code":null,"cleanup_code":null}\n'
                '{"kind":"selector","fixture_code":0,"open_code":0,"api_code":0,"cleanup_code":32}\n',
                encoding='utf-8',
            )
            records=load_jsonl(path)
            self.assertEqual(len(records),4)
            self.assertEqual(summarize(records),{'records':4,'kinds':{'environment':1,'selector':3},'nonzero_outcomes':3})
            path.write_text('[]\n',encoding='utf-8')
            with self.assertRaises(ValueError):load_jsonl(path)

    def test_collector_builds_runs_and_parses_the_native_mapper(self):
        source=(pathlib.Path(__file__).resolve().parents[1]/'run.py').read_text(encoding='utf-8')
        self.assertIn('windows-native-map-build',source)
        self.assertIn('windows-native-map-run',source)
        self.assertIn('windows-native-map-summary.json',source)
        self.assertIn('windows_native_map.compile_command',source)
        self.assertIn('if map_output.is_file():',source)
        self.assertNotIn("if map_run['status']=='PASS':\n                            try:",source)


    def test_native_mapper_isolates_every_selector_variant_on_a_fresh_fixture(self):
        source=(pathlib.Path(__file__).resolve().parents[1]/'probes'/'windows_acl_map.c').read_text(encoding='utf-8')
        self.assertIn('create_attempt_fixture',source)
        self.assertIn('cleanup_attempt_fixture',source)
        self.assertIn(r'\"attempt_id\"',source)
        self.assertIn(r'\"fixture_code\"',source)
        self.assertIn(r'\"cleanup_code\"',source)
        emit_start=source.index('static void emit_selector_attempt')
        map_start=source.index('static void map_selector')
        emit_source=source[emit_start:map_start]
        self.assertIn('create_attempt_fixture(',emit_source)
        self.assertIn('cleanup_attempt_fixture(',emit_source)

    def test_native_mapper_only_requests_token_adjustment_for_privileged_runs(self):
        source=(pathlib.Path(__file__).resolve().parents[1]/'probes'/'windows_acl_map.c').read_text(encoding='utf-8')
        self.assertIn('TOKEN_QUERY | (privileged ? TOKEN_ADJUST_PRIVILEGES : 0U)',source)
        self.assertNotIn('OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES',source)


if __name__=='__main__':
    unittest.main()
