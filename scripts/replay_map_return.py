#!/usr/bin/env python3
"""Recount a map handback ZIP without unpacking it or trusting its aggregate counts.

Returns 0 for an internally consistent replay, not a native qualification pass.
Use on trusted runner artifacts. Volatile paths, SIDs and raw tokens are not emitted.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

STATUSES = ('ok','observe','skip','error')


def analyze(path):
    report = {'lanes': {}, 'source': Path(path).name, 'integrity_files': 0}
    with ZipFile(path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)): raise ValueError('duplicate archive member')
        for marker in sorted(x for x in names if x.endswith('/gate.json') and '/artifacts/' in x):
            base=marker[:-len('gate.json')]
            get=lambda name: json.loads(z.read(base+name))
            run=get('run.json'); lane=run['lane']; gate=get('gate.json')
            if lane in report['lanes']: raise ValueError('duplicate lane: '+lane)
            manifest=z.read(base+'SHA256SUMS').decode().splitlines()
            for line in manifest:
                digest, name=line.split('  ',1)
                if '..' in PurePosixPath(name).parts or name.startswith('/'): raise ValueError(name)
                h=hashlib.sha256()
                with z.open(base+name) as f:
                    for b in iter(lambda:f.read(1048576),b''):h.update(b)
                if h.hexdigest()!=digest:raise ValueError('hash mismatch '+base+name)
            report['integrity_files']+=len(manifest)
            case_ids=[];counts=Counter()
            with z.open(base+'results.jsonl') as f:
                for r in map(json.loads,f):case_ids.append(r['id']);counts[r['status']]+=1
            if case_ids!=run['expected'] or counts!=get('summary.json')['counts']:raise ValueError('named plan mismatch')
            a=report['lanes'][lane]={'commit':run['context']['GITHUB_SHA'],'run':run['context']['GITHUB_RUN_ID'],
                'image':run['context']['ImageVersion'],'named':dict(counts),'gate_rows':gate['behavior']['rows'],
                'gate_ok':gate['ok'],'recorded':0,'domains':{},'error_keys':[], 'findings':{}}
            metrics={}
            def count(group,key):metrics.setdefault(group,Counter())[str(key)]+=1
            for name in sorted(n for n in names if n.startswith(base+'behavior/') and n.endswith('.jsonl')):
                keys=set(); counts=Counter(); final=None; domain=PurePosixPath(name).stem
                with z.open(name) as f:
                    for r in map(json.loads,f):
                        k=r['key'];d=r['details'];st=r['status']
                        if final is not None:raise ValueError('nonfinal summary')
                        if r['domain']!=domain or r['schema']!=1 or r['platform']!=('windows' if lane.startswith('windows') else 'darwin'):raise ValueError('row identity mismatch')
                        if k=='summary': final=r;continue
                        if k in keys or st not in STATUSES:raise ValueError('invalid key/status')
                        keys.add(k);counts[st]+=1
                        if st=='error':a['error_keys'].append(k)
                        if d.get('cleanup_error'):count('cleanup_errors',domain)
                        if domain=='authz':
                            if 'access_check' in d:
                                q=d['access_check'];count('authz_call', 'reply' if q['ok'] else q['error'].get('code'))
                                count('authz_called_owner_absent', d['descriptor']['owner'] is None)
                            else:count('authz_not_called',d['case'])
                        if domain=='descriptor-storage' and 'candidate_ace_hex' in d:
                            q=d['write']; count('ace_write',d['placement']+':'+('success' if q['ok'] else str(q['error'].get('code'))))
                            if q['ok']:
                                read=d.get('read',{}); placement=d['placement']
                                if read.get('ok'):
                                    acl=read['value']['descriptor'][placement]
                                    stored=any(entry.get('hex')==d['candidate_ace_hex'] for entry in acl.get('entries',[]))
                                    count('ace_after_success',placement+(' exact' if stored else ' not byte-identical or absent'))
                                else:count('ace_after_success',placement+' readback unavailable')
                        if domain=='access-evaluation':
                            x=d.get('access_check',{});y=d.get('create_file',{})
                            count('requested_acl_check_vs_open',str(x.get('value',{}).get('allowed'))+'/'+str(y.get('allowed')))
                            q=d.get('installed',{});count('post_write_path_read','success' if q.get('ok') else q.get('error',{}).get('code'))
                        if domain=='inheritance-events' and st=='observe': count('inheritance_observations', ':'.join(k.split(':')[1:3]+k.split(':')[-2:]))
                complete=False
                if final:
                    t=final['details']; digest=hashlib.sha256(('\n'.join(sorted(keys))+'\n').encode()).hexdigest()
                    if (digest!=t['catalog_sha256'] or t['counts']!={s:counts[s] for s in STATUSES} or
                        t['completed']!=len(keys) or t['expected']!=len(keys) or t['missing'] or
                        final['status']!=('error' if counts['error'] else 'ok')):raise ValueError('inconsistent terminal record: '+name)
                    complete=True
                a['domains'][domain]={'rows':len(keys),'counts':dict(counts),'terminal_record_consistent':complete}
                a['recorded']+=len(keys)
            a['findings']={k:dict(v) for k,v in metrics.items()}
            if base+'darwin-presence.jsonl' in names:
                a['darwin_presence']=[{'case':r['case'],**{k:{f:r[k].get(f) for f in ('presence','flags','entries')} for k in ('path','fd')}} for r in map(json.loads,z.read(base+'darwin-presence.jsonl').splitlines())]
        if not report['lanes']:raise ValueError('no lane gates in archive')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('zip');p.add_argument('--output',type=Path);args=p.parse_args()
    text=json.dumps(analyze(args.zip),indent=2,sort_keys=True)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
