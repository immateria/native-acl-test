"""Probe native behavior independently of the Crystal build and test assertions."""
import json
import os
import pathlib
import shutil
import tempfile

from ci import behavior
from lab import core, windows_native_map, wire
from lab.native import NativeFailure


def explore(lane, work, out):
    profile = os.environ.get('ACL_PROFILE', 'smoke')
    behavior_timeout = 3600 if profile == 'map' else 900
    if lane.startswith('macos-'):
        from lab.darwin import Darwin
        native = Darwin()
        with tempfile.TemporaryDirectory(dir=work/'scratch') as td, (out/'darwin-presence.jsonl').open('w', encoding='utf-8') as log:
            path = pathlib.Path(td)/'fixture'
            path.touch(mode=0o600)
            for name, data in [('removed',None),('empty-flagged',wire.darwin_export([],0x20000)),
                               ('one-ace',native.build_using_entry_api(native.principal()))]:
                row = {'case':name}
                try:
                    native.write(path, data)
                    with path.open('rb') as f:
                        row.update(path=native.read(path), fd=native.read(path,fd=f.fileno()), libc=native.libc_read(path))
                except NativeFailure as exc:
                    row['native_error'] = {'operation':exc.operation,'code':exc.code}
                print(json.dumps(row), file=log, flush=True)
        behavior.run_all('darwin', profile, work, out, privileged=False,
                         timeout=behavior_timeout)
        return 0
    build = work/'explore-build'
    exe = build/'aclmap.exe'
    cc = shutil.which('cl.exe') or shutil.which('clang-cl.exe')
    if not cc: raise RuntimeError('MSVC/Windows SDK compiler unavailable')
    cmd = windows_native_map.compile_command(cc,pathlib.Path(__file__).resolve().parents[1]/'probes/windows_acl_map.c',exe,build/'aclmap.obj')
    r = core.command(cmd, out/'mapper-build', 180, cwd=build)
    if r['returncode'] != 0 or r['timed_out']: return 1
    # Do not confound UAC filtering with enabling extra privileges. Every Windows lane
    # maps its untouched token first. The opt-in repeat is a *fresh process*.
    filtered = lane.endswith('-filtered')
    modes = [('', False)] if filtered else [('', False), ('-privileged', True)]
    failures=[]
    for suffix, enable in modes:
        dest=out/f'windows-selectors{suffix}.jsonl'
        result=core.command([exe,work/'scratch',dest,str(int(enable))],out/f'mapper-run{suffix}',180,cwd=build)
        try:
            if result['returncode']!=0 or result['timed_out']: raise ValueError('mapper process failed')
            verify_mapper(dest,lane,enable,out/f'windows-selectors{suffix}-summary.json')
        except (ValueError,OSError,KeyError) as exc:
            failures.append(f'{dest.name}: {exc}')
    if failures: raise ValueError('; '.join(failures))

    from lab.windows_behavior import implemented_domains
    domains = tuple(implemented_domains())
    local_accounts = lane == 'windows-lab'
    if not local_accounts:
        domains = tuple(name for name in domains if name != 'multiuser-map')
    behavior.run_all(
        'windows', profile, work, out,
        privileged=not filtered,
        timeout=behavior_timeout, domains=domains,
        local_accounts=local_accounts,
    )
    return 0


def verify_mapper(dest,lane,enable,summary_path):
    rows=windows_native_map.load_jsonl(dest)
    required={
        'owner','group','dacl','sacl','label','attribute','scope',
        'process_trust_label','access_filter','basic','audit_label',
        'protected_dacl','unprotected_dacl','protected_sacl','unprotected_sacl',
        'conflicting_dacl_protection','conflicting_sacl_protection',
        'all_defined','backup',
    }
    expected={(s,o,m) for s in required for o in ('file','directory') for m in ('query','set')}
    actual={(r['selector'],r['object'],r['operation']) for r in rows if r['kind']=='selector'}
    core.write_json(summary_path,windows_native_map.summarize(rows))
    if expected!=actual or any(r['kind']=='fatal' for r in rows): raise ValueError('incomplete Windows mapper output')
    # A truncated file may still contain all 52 tuples when the last tuple lost a variant.
    groups={}
    for row in rows:
        if row['kind']=='selector':
            groups.setdefault((row['selector'],row['object'],row['operation']),[]).append(row)
    for key, attempts in groups.items():
        sdk=attempts[0]['sdk_access']
        candidates=[('zero',0),('sdk',sdk),('plus_read_control',sdk|0x20000)]
        if sdk & 0x20000: candidates.append(('minus_read_control',sdk & ~0x20000))
        candidates.extend((('plus_synchronize', sdk | 0x100000),
                           ('maximum_allowed', 0x02000000)))
        distinct={}
        for variant,mask in candidates: distinct.setdefault(mask,variant)
        if (any(r['sdk_access']!=sdk for r in attempts) or len(attempts)!=len(distinct)
                or {(r['access'],r['variant']) for r in attempts}!=set(distinct.items())):
            raise ValueError(f'incomplete or duplicate access-mask variants: {key}')
    tokens=[r for r in rows if r['kind']=='token']
    filtered = lane.endswith('-filtered')
    if len(tokens)!=1 or tokens[0]['elevated'] is not (not filtered):
        raise ValueError('mapper did not confirm the expected token')
    attempts=[r for r in rows if r['kind']=='privilege_enable']
    if len(attempts)!=(4 if enable else 0): raise ValueError('privilege mode mismatch')
    if filtered and tokens[0].get('integrity_sid')!='S-1-16-8192':
        raise ValueError('filtered mapper did not run at medium integrity')
