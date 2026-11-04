#!/usr/bin/env python3
"""Run the native ACL evidence suite and always package results.

Python 3.9+ standard library. No network access or automatic installation.
Use --list to preview the exact test manifest without changing any ACLs.
"""
import argparse
import collections
import datetime
import fnmatch
import hashlib
import json
import os
import pathlib
import platform
import shutil
import sys
import tempfile
import traceback
import uuid
from lab import catalog,core,windows_native_map

ROOT=pathlib.Path(__file__).resolve().parent

def resolve_executable(value):
    """Resolve an executable before later stages change working directory."""
    found=shutil.which(value)
    return str(pathlib.Path(found).resolve()) if found else None

def parser():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--profile',choices=['smoke','full','stress'],default='full')
    p.add_argument('--privileged',action='store_true',help='opt into process-scoped privilege cases; never auto-elevates')
    p.add_argument('--local-accounts',action='store_true',help='create disposable local users/groups for multi-token Windows cases; requires an elevated shell')
    p.add_argument('--seed',type=int,default=20261103)
    p.add_argument('--iterations',type=int,default=1000,help='stress iterations and seeded model fixtures, bounded at 10000 for model cases')
    p.add_argument('--only',action='append',default=[],help='case ID glob; repeatable, e.g. windows.inheritance.*')
    p.add_argument('--case-timeout',type=float,default=180)
    p.add_argument('--build-timeout',type=float,default=600)
    p.add_argument('--scratch-parent',type=pathlib.Path,default=pathlib.Path(tempfile.gettempdir()),help='existing parent on the filesystem to test; a NEW private subdirectory is created')
    p.add_argument('--results-parent',type=pathlib.Path,default=ROOT/'results')
    p.add_argument('--crystal',default='crystal',help='compiler executable/path (not a command string)')
    p.add_argument('--list',action='store_true',help='print JSON case catalog and exit without creating files')
    p.add_argument('--platform',choices=['darwin','windows'],help='catalog target for --list only')
    p.add_argument('--model-only',action='store_true',help='bounded binary tests only; also usable on Linux')
    p.add_argument('--skip-specs',action='store_true',help='skip checkpoint specs for a targeted rerun; recorded as SKIP')
    p.add_argument('--skip-sdk',action='store_true',help='skip C SDK probe for a targeted rerun; recorded as SKIP')
    return p

def selected(args,osname):
    platforms=['darwin','windows'] if args.model_only else [osname]
    result=[]
    for name in platforms:result+=catalog.cases(name,args.profile,args.seed,args.iterations,local_accounts=args.local_accounts and name=='windows')
    if args.model_only:result=[r for r in result if r['group']=='model']
    if args.only:result=[r for r in result if any(fnmatch.fnmatchcase(r['id'],pattern) for pattern in args.only)]
    return result

def hash_sources():
    out={}
    for directory in ['acl','lab','probes']:
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                out[path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ['run.py','run-macos.sh','run-windows.ps1','run-windows-multiuser.ps1','scripts/cleanup-local-accounts.ps1']:
        path=ROOT/name
        if path.exists():out[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    return out

def main(argv=None):
    args=parser().parse_args(argv)
    if sys.version_info < (3,9):parser().error('Python 3.9+ required')
    osname='windows' if sys.platform=='win32' else 'darwin' if sys.platform=='darwin' else 'linux'
    if args.platform and not args.list:parser().error('--platform is only for previewing --list; native OS may not be spoofed')
    if args.iterations<1 or args.iterations>1000000:parser().error('--iterations must be 1..1000000')
    if args.case_timeout<1 or args.build_timeout<1:parser().error('timeouts must be positive')
    if args.list:
        chosen=args.platform or osname
        if chosen=='linux' and not args.model_only:parser().error('--list on Linux needs --platform or --model-only')
        print(json.dumps(selected(args,chosen),indent=2));return 0
    if osname=='linux' and not args.model_only:parser().error('native suites require macOS/Windows; --model-only is available here')
    if args.local_accounts and (osname!='windows' or args.model_only):
        parser().error('--local-accounts requires a native Windows run')
    case_list=selected(args,osname)
    if not case_list:parser().error('selection matches no cases')
    args.results_parent.mkdir(parents=True,exist_ok=True)
    run_id='acl-results-'+osname+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    results=args.results_parent.resolve()/run_id;results.mkdir()
    (results/'stages').mkdir();(results/'cases').mkdir();build=results/'build';build.mkdir()
    workspace=None;stages=[];case_results=[];errors=[];exit_code=1;archive_path=None
    account_manager=None;account_secret_path=None;account_public=None;account_bridge=None
    def stage(name,argv,cwd=ROOT,timeout=None,env=None):
        r=core.command(argv,results/'stages'/name,timeout or args.build_timeout,cwd=cwd,env=env)
        r.update(name=name,status='PASS' if r['returncode']==0 and not r['timed_out'] else 'FAIL')
        stages.append(r);print('STAGE '+name+': '+r['status'],flush=True);return r
    def skipped(name,reason):stages.append(dict(name=name,status='SKIP',reason=reason))
    try:
        core.write_json(results/'case-manifest.json',case_list)
        core.write_json(results/'source-hashes.json',hash_sources())
        core.write_json(results/'invocation.json',dict(arguments=vars_to_json(args),suite='acl-checkpoint-5',checkpoint='acl 0.0.5'))
        workspace=core.new_workspace(args.scratch_parent)
        core.write_json(results/'scratch-location.json',dict(path=str(workspace),ownership_marker='.acl-lab-owned'))
        metadata=dict(system=platform.system(),release=platform.release(),version=platform.version(),machine=platform.machine(),
                      python=sys.version,python_executable=sys.executable,pointer_bits=__import__('struct').calcsize('P')*8,cpu_count=os.cpu_count(),
                      privileged_requested=args.privileged,model_only=args.model_only)
        if osname=='windows' and not args.model_only:
            from lab.windows import Windows
            native=Windows();metadata['native']=native.environment(workspace)
            core.write_json(results/'environment.json',metadata)
            if not metadata['native']['persistent_acls']:raise RuntimeError('Selected filesystem does not advertise persistent ACLs; mutation suite not started')
            native.secure_directory(workspace)
            metadata['windows_version']=list(sys.getwindowsversion())
            if args.local_accounts:
                if not metadata['native']['elevated']:
                    raise RuntimeError('--local-accounts requires an elevated Windows shell')
                from lab.windows_accounts import LocalAccountManager, public_account_description, write_secret_file
                account_manager=LocalAccountManager(run_id)
                try:
                    account_secret=account_manager.provision()
                    account_public=public_account_description(account_secret)
                    core.write_json(results/'local-accounts.json',account_public)
                    stages.append(dict(name='local-account-provision',status='PASS',
                        users=len(account_public['users']),groups=len(account_public['groups'])))
                    # Write and protect credentials while the workspace still has
                    # its original collector/SYSTEM-only DACL. Protecting the child first
                    # prevents the later inheritable lab-user ACEs from reaching it.
                    account_secret_path=workspace/'.acl-local-account-secrets.json'
                    write_secret_file(account_secret_path,account_secret)
                    secret_sddl='D:P(A;;FA;;;'+native.current_sid()+')(A;;FA;;;SY)'
                    native.write(account_secret_path,native.sddl(secret_sddl),4,'Protect')
                    # Lab users need traverse/execute access to their per-case roots and
                    # the copied bridge. Individual cases replace their root DACL with a
                    # protected test-specific DACL.
                    access_sids=[value['sid'] for value in account_public['users'].values()]
                    sddl='D:P(A;OICI;FA;;;'+native.current_sid()+')(A;OICI;FA;;;SY)'
                    sddl+=''.join('(A;OICI;RX;;;'+sid+')' for sid in access_sids)
                    native.write(workspace,native.sddl(sddl),4,'Protect')
                except BaseException:
                    failures=account_manager.cleanup()
                    stages.append(dict(name='local-account-provision',status='FAIL',cleanup_failures=failures))
                    raise
        elif osname=='darwin' and not args.model_only:
            from lab.darwin import Darwin
            native=Darwin();metadata['native']=native.environment(workspace)
            core.write_json(results/'environment.json',metadata)
            # Clear inherited ACLs only on this newly-created private root.
            native.write(workspace,None)
            stage('sw-vers',['/usr/bin/sw_vers'],timeout=20)
            stage('filesystem',['/bin/df',str(workspace)],timeout=20)
            # Optional Rosetta evidence; missing key on native machines is not a failed test.
            r=core.command(['/usr/sbin/sysctl','-n','sysctl.proc_translated'],results/'stages'/'rosetta',20)
            metadata['rosetta_probe']=r
        core.write_json(results/'environment.json',metadata)
        compiler=resolve_executable(args.crystal)
        bridge=build/('acl-bridge.exe' if osname=='windows' else 'acl-bridge')
        env=os.environ.copy();env['TMPDIR']=str(workspace);env['TMP']=str(workspace);env['TEMP']=str(workspace)
        # No user-supplied global SACL spec opt-in leaks into the ordinary spec process.
        env.pop('ACL_NATIVE_SACL_TESTS',None)
        if compiler:
            stage('crystal-version',[compiler,'--version'],timeout=30)
            shards=shutil.which('shards')
            if shards:stage('shards-check',[shards,'check'],cwd=ROOT/'acl',timeout=30)
            else:skipped('shards-check','Shards executable missing; no dependencies need downloading')
            stage('format',[compiler,'tool','format','--check','src','spec','examples'],cwd=ROOT/'acl',timeout=60)
            compiled=stage('bridge-build',[compiler,'build',str(ROOT/'probes'/'bridge.cr'),'--error-trace','-o',str(bridge)],env=env)
            if compiled['status']!='PASS':bridge=None
            elif osname=='windows':
                # A missing manifest is diagnostic, not a compiler failure. Keep
                # SDK output and status even when resource #1 is not present.
                mt=shutil.which('mt.exe')
                manifest=results/'stages'/'bridge-manifest.xml'
                if mt:
                    r=core.command([mt,'-nologo','-inputresource:'+str(bridge)+';#1','-out:'+str(manifest)],results/'stages'/'manifest-extract',20)
                    core.write_json(results/'stages'/'manifest-status.json',dict(returncode=r['returncode'],extracted=manifest.is_file()))
                else:core.write_json(results/'stages'/'manifest-status.json',dict(extracted=False,reason='mt.exe unavailable'))
            if osname=='windows' and bridge and args.local_accounts:
                shared_bin=workspace/'shared-bin'
                shared_bin.mkdir()
                account_bridge=shared_bin/'acl-bridge.exe'
                shutil.copy2(bridge,account_bridge)
                core.write_json(results/'stages'/'account-bridge.json',dict(path=str(account_bridge),
                    sha256=hashlib.sha256(account_bridge.read_bytes()).hexdigest()))
                stages.append(dict(name='account-bridge-prepare',status='PASS'))
            if args.skip_specs:skipped('checkpoint-specs','--skip-specs requested')
            else:
                spec_paths=['spec/acl/posix','spec/acl/darwin','spec/acl/windows'] if args.model_only else []
                for order in [args.seed,args.seed+1]:
                    stage('checkpoint-specs-'+str(order),[compiler,'spec']+spec_paths+['--error-trace','--order',str(order)],cwd=ROOT/'acl',env=env)
                stage('checkpoint-release-specs',[compiler,'spec']+spec_paths+['--release','--error-trace','--order',str(args.seed)],cwd=ROOT/'acl',env=env)
        else:
            bridge=None;stages.append(dict(name='bridge-build',status='FAIL',reason='Crystal executable not found: '+args.crystal))
        if args.skip_sdk or args.model_only:
            skipped('sdk-abi','disabled by --skip-sdk or --model-only')
            if osname=='windows':skipped('windows-native-map','disabled by --skip-sdk or --model-only')
        else:
            exe=build/('sdk-abi.exe' if osname=='windows' else 'sdk-abi')
            if osname=='darwin':
                cc=shutil.which('cc')
                cmd=[cc,'-std=c11','-Wall','-Wextra','-Werror',str(ROOT/'probes'/'darwin_acl_abi.c'),'-o',str(exe)] if cc else None
            else:
                cc=shutil.which('cl.exe') or shutil.which('clang-cl.exe')
                cmd=[cc,'/nologo','/std:c11','/W4','/WX',str(ROOT/'probes'/'windows_acl_abi.c'),'/Fe:'+str(exe),'/Fo:'+str(build/'sdk-abi.obj'),'/link','advapi32.lib'] if cc else None
            if cmd:
                built=stage('sdk-abi-build',cmd,cwd=build,env=env)
                if built['status']=='PASS':stage('sdk-abi-run',[str(exe),str(workspace)],cwd=workspace,timeout=30)
            else:
                skipped('sdk-abi','C compiler/SDK not found. On Windows use the SDK developer shell; on macOS install Command Line Tools.')

            if osname=='windows':
                if cc:
                    map_exe=build/'windows-acl-map.exe'
                    map_output=results/'stages'/'windows-native-map.jsonl'
                    map_cmd=windows_native_map.compile_command(cc,ROOT/'probes'/'windows_acl_map.c',map_exe,build/'windows-acl-map.obj')
                    map_built=stage('windows-native-map-build',map_cmd,cwd=build,env=env)
                    if map_built['status']=='PASS':
                        map_run=stage('windows-native-map-run',[str(map_exe),str(workspace),str(map_output),'1' if args.privileged else '0'],cwd=workspace,timeout=180)
                        if map_output.is_file():
                            try:
                                map_records=windows_native_map.load_jsonl(map_output)
                                summary=windows_native_map.summarize(map_records)
                                summary['run_status']=map_run['status']
                                core.write_json(results/'stages'/'windows-native-map-summary.json',summary)
                                stages.append(dict(name='windows-native-map-parse',status='PASS',records=len(map_records),partial=map_run['status']!='PASS'))
                            except Exception as exc:
                                stages.append(dict(name='windows-native-map-parse',status='FAIL',error=repr(exc)))
                        else:
                            stages.append(dict(name='windows-native-map-parse',status='FAIL',error='mapper produced no JSONL output'))
                else:
                    skipped('windows-native-map','C compiler/SDK not found. Use a Windows SDK developer shell.')
        if not bridge:
            # Still collect independently runnable oracle-only cases and full blocked-case inventory.
            print('Bridge unavailable; native diagnostics continue and dependent cases are BLOCKED.',flush=True)
        for index,case in enumerate(case_list,1):
            case_root=workspace/case['id'];case_root.mkdir()
            if osname!='windows':case_root.chmod(0o700)
            evidence=results/'cases'/case['id'];evidence.mkdir()
            config=dict(case=case,root=str(case_root),evidence=str(evidence),workspace_name=workspace.name,
                        bridge=str(bridge) if bridge else None,privileged=args.privileged,
                        inner_timeout=max(1,args.case_timeout*.7),model_only=args.model_only,
                        account_secrets=str(account_secret_path) if account_secret_path else None,
                        account_bridge=str(account_bridge) if account_bridge else None,
                        account_public=account_public)
            config_path=evidence/'config.json';core.write_json(config_path,config)
            # -m needs the kit on sys.path, while the child changes cwd to its own fixtures.
            childenv=env.copy();childenv['PYTHONPATH']=str(ROOT)
            r=core.command([sys.executable,'-m','lab.worker',str(config_path)],evidence/'worker',args.case_timeout,cwd=ROOT,env=childenv)
            rp=evidence/'result.json'
            if rp.exists():record=json.loads(rp.read_text(encoding='utf-8'))
            else:record=dict(id=case['id'],group=case['group'],status='TIMEOUT' if r['timed_out'] else 'ERROR',reason='worker did not write a result',worker=r)
            if r['timed_out']:record['status']='TIMEOUT'
            if r['returncode'] not in (0,None) and record['status']=='PASS':record.update(status='ERROR',reason='worker exited nonzero after result')
            if record.get('cleanup_warnings'):
                record['assertion_status']=record['status'];record['status']='ERROR'
                record['reason']='Fixture cleanup needs review; original assertion status retained'
            core.write_json(rp,record)
            case_results.append(record)
            with (results/'results.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(record,ensure_ascii=True)+'\n');f.flush()
            print(f'[{index}/{len(case_list)}] {record["status"]:7} {case["id"]}',flush=True)
        failures=[r for r in case_results if r['status'] in ('FAIL','ERROR','TIMEOUT','BLOCKED')]
        stage_failures=[r for r in stages if r['status']=='FAIL']
        exit_code=1 if failures or stage_failures else 0
    except KeyboardInterrupt:
        errors.append('Interrupted by user; completed evidence retained.');exit_code=130
    except Exception:
        errors.append(traceback.format_exc());exit_code=1
    finally:
        if workspace:
            # Cleanup is itself bounded. A hung filesystem must not prevent
            # packaging the logs already collected on the results filesystem.
            try:
                cleanup_env=os.environ.copy();cleanup_env['PYTHONPATH']=str(ROOT)
                cleanup_platform='portable' if args.model_only else osname
                r=core.command([sys.executable,'-m','lab.cleanup',str(workspace),cleanup_platform],
                               results/'stages'/'final-cleanup',60,cwd=ROOT,env=cleanup_env)
                r.update(name='final-cleanup',status='PASS' if r['returncode']==0 and not r['timed_out'] else 'FAIL')
                stages.append(r)
                if r['status']!='PASS':errors.append(dict(cleanup_incomplete=True,scratch_root=str(workspace)));exit_code=1
            except KeyboardInterrupt:
                errors.append(dict(cleanup_interrupted=True,scratch_root=str(workspace)));exit_code=130
            except Exception as exc:errors.append(dict(cleanup_error=repr(exc),scratch_root=str(workspace)));exit_code=1
        if account_manager:
            try:
                failures=account_manager.cleanup()
                stages.append(dict(name='local-account-cleanup',status='PASS' if not failures else 'FAIL',failures=failures))
                if failures:
                    errors.append(dict(local_account_cleanup_failures=failures));exit_code=1
            except Exception as exc:
                stages.append(dict(name='local-account-cleanup',status='FAIL',error=repr(exc)))
                errors.append(dict(local_account_cleanup_error=repr(exc)));exit_code=1
        counts=dict(collections.Counter(r['status'] for r in case_results))
        summary=dict(suite='acl-checkpoint-5',checkpoint='acl 0.0.5',platform=osname,profile=args.profile,
                     selected=len(case_list),completed=len(case_results),counts=counts,stages=stages,errors=errors,
                     exit_code=exit_code,certification=False,notice='PASS is only the named assertion; SKIP, OBSERVE and BLOCKED are not passes.')
        core.write_json(results/'summary.json',summary)
        report=['# ACL native test results','',f'Platform: {osname}. Profile: {args.profile}. Selected: {len(case_list)}; completed: {len(case_results)}.',
                '', 'Counts: `'+json.dumps(counts,sort_keys=True)+'`', '', 'SKIP / OBSERVE / BLOCKED are not passes. This is not release certification.', '', '## Failed or blocked cases','']
        for r in case_results:
            if r['status'] in ('FAIL','ERROR','TIMEOUT','BLOCKED'):
                report.append('- `'+r['id']+'`: '+r['status']+' — '+r.get('reason','Inspect case evidence.'))
        report+=['','## Stage outcomes','']
        for r in stages:report.append('- `'+r['name']+'`: '+r['status'])
        if errors:report+=['','## Collector/cleanup errors','', '```json',json.dumps(errors,indent=2),'```']
        (results/'REPORT.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
        # Build products are not needed in a returned report; source hashes and compiler diagnostics are.
        if build.exists():shutil.rmtree(build)
        try:archive_path=core.archive(results)
        except Exception as exc:print('Packaging failed; return directory '+str(results)+': '+repr(exc),file=sys.stderr);exit_code=1
        print('\nCOUNTS '+json.dumps(counts,sort_keys=True),flush=True)
        print('RESULT_DIRECTORY '+str(results),flush=True)
        if archive_path:print('UPLOAD '+str(archive_path),flush=True)
    return exit_code

def vars_to_json(args):
    return {k:str(v) if isinstance(v,pathlib.Path) else v for k,v in vars(args).items()}

if __name__=='__main__':sys.exit(main())
