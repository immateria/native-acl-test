"""Entry points shared by the hosted jobs. Never substitute another OS or token."""
import ctypes
import fnmatch
import json
import os
import platform
import re
import struct
import sys
from pathlib import Path

from lab import catalog, core

ROOT = Path(__file__).resolve().parents[1]
RUNNERS = {'macos-arm64': 'macos-15', 'windows-elevated': 'windows-2025',
           'windows-filtered': 'windows-2025', 'windows-lab': 'windows-2025'}
NORMAL = tuple(RUNNERS)[:3]
OUT = ROOT / 'ci-out'
WORK = Path(os.environ.get('RUNNER_TEMP', ROOT / '.ci-local')).resolve() / 'native-acl-ci'
REFERENCE = '7ad681568e1ef18ce9f429d6a4962496ddd64d11'


def matrix(event, choice):
    if event not in ('push', 'workflow_dispatch'):
        raise ValueError('only push and workflow_dispatch are supported')
    lanes = NORMAL if event == 'push' or choice in ('', 'all') else (choice,)
    if any(x not in RUNNERS for x in lanes):
        raise ValueError('unknown runner lane')
    return {'include': [{'lane': x, 'runner': RUNNERS[x]} for x in lanes]}


def plan(lane, profile, pattern, seed_text):
    if lane not in RUNNERS or profile not in ('smoke', 'full', 'stress'):
        raise ValueError('unknown lane or profile')
    if not re.fullmatch(r'[0-9]{1,10}', seed_text) or int(seed_text) >= 2**31 - 1:
        raise ValueError('seed must be in 0..2147483646 (the second order uses seed+1)')
    if pattern and not re.fullmatch(r'[a-zA-Z0-9_.?*\-]{1,140}', pattern):
        raise ValueError('invalid case filter; use a case ID or a * / ? glob')
    is_lab = lane == 'windows-lab'
    if is_lab:
        profile = 'full'  # these cases are intentionally not part of smoke
        pattern = pattern or 'windows.multiuser.*'
    osname = 'darwin' if lane == 'macos-arm64' else 'windows'
    cases = catalog.cases(osname, profile, int(seed_text), 1000, local_accounts=is_lab)
    ids = [c['id'] for c in cases if fnmatch.fnmatchcase(c['id'], pattern or '*')]
    if not ids or (is_lab and any(not i.startswith('windows.multiuser.') for i in ids)):
        raise ValueError(f'{lane}: select at least one matching case from this lane (lab: multiuser only)')
    args = ['--profile', profile, '--seed', seed_text]
    if pattern: args += ['--only', pattern, '--skip-specs']
    if lane in ('windows-elevated', 'windows-lab'): args.append('--privileged')
    if is_lab: args.append('--local-accounts')
    return args, ids


def check_identity(lane, data):
    if lane == 'macos-arm64':
        valid = (data['system'] == 'Darwin' and data['machine'].lower() == 'arm64'
                 and data['bits'] == 64 and data['uid'] != 0)
    else:
        expected = lane != 'windows-filtered'
        valid = (lane in RUNNERS and data['system'] == 'Windows' and data['bits'] == 64
                 and data['machine'].lower() in ('amd64', 'x86_64')
                 and data['elevated'] is expected and data['admin_member'] is expected
                 and (expected or data['integrity_sid'] == 'S-1-16-8192'))
    if not valid: raise ValueError(f'{lane}: wrong execution identity/architecture: {data}')


def identity(lane, stage):
    data = {'system': platform.system(), 'machine': platform.machine(), 'bits': 8 * struct.calcsize('P'),
            'release': platform.release(), 'version': platform.version(), 'python': sys.version}
    if sys.platform == 'win32':
        from lab.windows import Windows
        data.update(Windows().environment(WORK / 'scratch'))
        data['admin_member'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    elif sys.platform == 'darwin':
        data['uid'] = os.geteuid()
    core.write_json(OUT / f'identity-{stage}.json', data)
    check_identity(lane, data)


def requested():
    lane = os.environ['ACL_LANE']
    args, ids = plan(lane, os.environ.get('ACL_PROFILE') or 'smoke', os.environ.get('ACL_ONLY', ''),
                     os.environ.get('ACL_SEED') or '20261103')
    return lane, args, ids


def initialize():
    OUT.mkdir(exist_ok=True)
    if (OUT/'run.json').exists(): raise ValueError('refusing to mix runs in ci-out')
    lane, args, ids = requested()
    names = ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT',
             'GITHUB_EVENT_NAME','RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion')
    core.write_json(OUT / 'run.json', dict(schema=1, lane=lane, reference_commit=REFERENCE,
                    runner=RUNNERS[lane], context={k: os.getenv(k) for k in names},
                    args=args, expected=ids, crystal_version='1.21.1'))
    WORK.mkdir(parents=True, exist_ok=False)
    for name in ('scratch','raw','tmp','cache','explore-build'): (WORK / name).mkdir()


def execute(stage):
    lane, args, ids = requested()
    if lane == 'windows-lab' and (os.getenv('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                                   or os.getenv('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('account provisioning requires manual dispatch on a GitHub-hosted VM')
    identity(lane, stage)
    os.environ.update(TMP=str(WORK/'tmp'), TEMP=str(WORK/'tmp'), TMPDIR=str(WORK/'tmp'),
                      CRYSTAL_CACHE_DIR=str(WORK/'cache'))
    if stage == 'explore':
        from ci.explore import explore
        return explore(lane, WORK, OUT)
    import run
    print(f'{lane}: {len(ids)} selected cases', flush=True)
    return run.main(args + ['--results-parent',str(WORK/'raw'),'--scratch-parent',str(WORK/'scratch')])


def main():
    cmd = sys.argv[1]
    if cmd == 'matrix':
        print(json.dumps(matrix(os.environ['GITHUB_EVENT_NAME'], os.getenv('ACL_CHOICE','')), separators=(',',':')))
    elif cmd == 'init': initialize()
    elif cmd in ('explore','collect'): return execute(cmd)
    elif cmd == 'finish':
        from ci.evidence import finish
        return finish(WORK, OUT)
    else: raise ValueError('unknown subcommand')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
