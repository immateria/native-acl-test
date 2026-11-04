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
RUNNERS = {
    'macos-arm64': 'macos-15',
    'macos-x64': 'macos-15-intel',
    'windows-elevated': 'windows-2025',
    'windows-filtered': 'windows-2025',
    'windows-2022-elevated': 'windows-2022',
    'windows-2022-filtered': 'windows-2022',
    'windows-lab': 'windows-2025',
}
PUSH_LANES = ('macos-arm64', 'windows-elevated', 'windows-filtered')
MANUAL_LANES = tuple(name for name in RUNNERS if name != 'windows-lab')
OUT = ROOT / 'ci-out'
WORK = Path(os.environ.get('RUNNER_TEMP', ROOT / '.ci-local')).resolve() / 'native-acl-ci'
REFERENCE = '7ad681568e1ef18ce9f429d6a4962496ddd64d11'


def matrix(event, choice):
    if event not in ('push', 'workflow_dispatch'):
        raise ValueError('only push and workflow_dispatch are supported')
    if event == 'push':
        lanes = PUSH_LANES
    elif choice in ('', 'all'):
        lanes = MANUAL_LANES
    else:
        lanes = (choice,)
    if any(x not in RUNNERS for x in lanes):
        raise ValueError('unknown runner lane')
    return {'include': [{'lane': x, 'runner': RUNNERS[x]} for x in lanes]}


def is_macos_lane(lane):
    return lane.startswith('macos-')


def is_windows_lane(lane):
    return lane.startswith('windows-')


def is_filtered_lane(lane):
    return is_windows_lane(lane) and lane.endswith('-filtered')


def is_privileged_lane(lane):
    return is_windows_lane(lane) and not is_filtered_lane(lane)


def plan(lane, profile, pattern, seed_text):
    if lane not in RUNNERS or profile not in ('smoke', 'full', 'map', 'stress'):
        raise ValueError('unknown lane or profile')
    if not re.fullmatch(r'[0-9]{1,10}', seed_text) or int(seed_text) >= 2**31 - 1:
        raise ValueError('seed must be in 0..2147483646 (the second order uses seed+1)')
    if pattern and not re.fullmatch(r'[a-zA-Z0-9_.?*\-]{1,140}', pattern):
        raise ValueError('invalid case filter; use a case ID or a * / ? glob')
    is_lab = lane == 'windows-lab'
    if is_lab:
        profile = 'full'  # these cases are intentionally not part of smoke
        pattern = pattern or 'windows.multiuser.*'
    osname = 'darwin' if is_macos_lane(lane) else 'windows'
    cases = catalog.cases(osname, profile, int(seed_text), 1000, local_accounts=is_lab)
    ids = [c['id'] for c in cases if fnmatch.fnmatchcase(c['id'], pattern or '*')]
    if not ids or (is_lab and any(not i.startswith('windows.multiuser.') for i in ids)):
        raise ValueError(f'{lane}: select at least one matching case from this lane (lab: multiuser only)')
    args = ['--profile', profile, '--seed', seed_text]
    if pattern: args += ['--only', pattern, '--skip-specs']
    if is_privileged_lane(lane): args.append('--privileged')
    if is_lab: args.append('--local-accounts')
    return args, ids


def check_identity(lane, data):
    if lane not in RUNNERS:
        raise ValueError(f'{lane}: unknown lane')
    if is_macos_lane(lane):
        expected_machine = {'macos-arm64': 'arm64', 'macos-x64': 'x86_64'}[lane]
        valid = (data['system'] == 'Darwin' and data['machine'].lower() == expected_machine
                 and data['bits'] == 64 and data['uid'] != 0)
    else:
        expected = not is_filtered_lane(lane)
        valid = (data['system'] == 'Windows' and data['bits'] == 64
                 and data['machine'].lower() in ('amd64', 'x86_64')
                 and data['elevated'] is expected and data['admin_member'] is expected
                 and (expected or data['integrity_sid'] == 'S-1-16-8192'))
    if not valid:
        raise ValueError(f'{lane}: wrong execution identity/architecture: {data}')


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
                    args=args, expected=ids, crystal_version='1.21.1',
                    behavior_profile=os.environ.get('ACL_PROFILE') or 'smoke'))
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
