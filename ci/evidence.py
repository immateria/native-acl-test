"""Validate a native handback independently of the collector's process exit."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import zipfile
from lab import core

BAD = {'FAIL', 'ERROR', 'BLOCKED', 'TIMEOUT'}
STATUSES = BAD | {'PASS', 'OBSERVE', 'SKIP'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def validate(meta, manifest, records, summary):
    """Missing, duplicate, out-of-contract, and unexecuted cases must not go green."""
    errors = []
    expected = meta['expected']
    named = [r['id'] for r in records]
    planned = [r['id'] for r in manifest]
    counts = Counter(r['status'] for r in records)
    if not expected or len(expected)!=len(set(expected)) or planned!=expected or named!=expected:
        errors.append('case IDs do not match the ordered plan exactly')
    if set(counts)-STATUSES or dict(counts)!=summary['counts']:
        errors.append('invalid statuses or inconsistent status totals')
    if summary['completed']!=len(named) or summary['selected']!=len(expected): errors.append('incomplete run')
    if summary['errors'] or summary['exit_code']!=0 or BAD.intersection(counts): errors.append('native collector reported failures')
    if not counts['PASS'] and not counts['OBSERVE']: errors.append('no assertion or observation executed')
    osname = 'darwin' if meta['lane']=='macos-arm64' else 'windows'
    if summary['platform']!=osname: errors.append('collector reported the wrong OS')
    stages={s['name']:s['status'] for s in summary['stages']}
    required={'crystal-version','format','bridge-build','sdk-abi-build','sdk-abi-run','final-cleanup'}
    if osname=='windows': required.update(['windows-native-map-build','windows-native-map-run','windows-native-map-parse'])
    if meta['lane']=='windows-lab': required.update(['local-account-provision','local-account-cleanup','account-bridge-prepare'])
    args=meta['args']
    if '--skip-specs' not in args:
        seed=int(args[args.index('--seed')+1]);required.update([f'checkpoint-specs-{seed}',f'checkpoint-specs-{seed+1}','checkpoint-release-specs'])
    for stage in sorted(required):
        if stages.get(stage)!='PASS': errors.append(f'required stage {stage}: {stages.get(stage,"MISSING")}')
    if 'FAIL' in stages.values(): errors.append('a recorded stage failed')
    return errors


def finish(work, out):
    """Keep available diagnostics even when compilation, collection or validation fails."""
    out.mkdir(exist_ok=True)
    problems=[]; records=[]; counts={}; lane=os.getenv('ACL_LANE','unknown')
    try:
        meta = read(out/'run.json'); lane=meta['lane']
        from ci.lane import check_identity
        for stage in ('explore','collect'):
            try: check_identity(lane, read(out/f'identity-{stage}.json'))
            except (ValueError, KeyError, OSError) as e: problems.append(f'{stage} identity: {e}')
        dirs=[p for p in (work/'raw').glob('acl-results-*') if p.is_dir() and not p.is_symlink()]
        if len(dirs)!=1: raise ValueError(f'expected one native result directory; found {len(dirs)}')
        root=dirs[0]
        for name in ('summary.json','case-manifest.json','environment.json','results.jsonl','REPORT.md'):
            if (root/name).is_file(): shutil.copyfile(root/name,out/name)
        archive=root.with_suffix('.zip')
        if not archive.is_file():
            problems.append('collector did not finalize the ZIP; salvaging partial evidence')
            archive=core.archive(root)
        with zipfile.ZipFile(archive) as z:
            if z.testzip() is not None: raise ValueError('collector archive CRC failure')
        shutil.copyfile(archive,out/'handback.zip')
        records=rows(out/'results.jsonl'); counts=dict(Counter(r['status'] for r in records))
        problems+=validate(meta,read(out/'case-manifest.json'),records,read(out/'summary.json'))
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e:
        problems.append(str(e))
    for step in ('setup','explore','collect'):
        outcome=os.getenv('ACL_'+step.upper()+'_OUTCOME')
        if outcome and outcome!='success': problems.append(f'Actions step {step}: {outcome}')
    core.write_json(out/'gate.json',{'lane':lane,'counts':counts,'problems':problems,'ok':not problems})
    lines=[f'## Native ACL: {lane}', '', f'Case outcomes: `{json.dumps(counts,sort_keys=True)}`',
           '', 'Evidence gate: '+('FAIL' if problems else 'PASS')]
    lines += ['- '+str(p).replace('\n',' ')[:500] for p in problems]
    bad=[r for r in records if r['status'] in BAD]
    if bad:
        lines+=['','First failing case IDs:']+[f"- `{r['id']}`: {r['status']}" for r in bad[:30]]
    lines+=['','See `handback.zip` for individual requests, native responses and compiler diagnostics.']
    markdown='\n'.join(lines)+'\n'; (out/'LANE.md').write_text(markdown,encoding='utf-8')
    if os.getenv('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a',encoding='utf-8') as f: f.write(markdown)
    # Only this expressly staged directory is uploaded. No checkout, scratch or build cache.
    files=sorted(p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files),encoding='utf-8')
    print(markdown)
    return int(bool(problems))
