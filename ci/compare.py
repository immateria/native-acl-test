"""Compare two extracted lane artifacts by case ID and native selector tuple."""
import argparse
import json
from pathlib import Path


def index(path, key, value):
    result = {}
    if not path.is_file(): return result
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip(): continue
        row = json.loads(line); ident = key(row)
        if ident is None: continue
        if ident in result: raise ValueError(f'duplicate key {ident} in {path}')
        result[ident] = value(row)
    return result


def changes(a,b):
    return [{'key':k,'before':a.get(k),'after':b.get(k)} for k in sorted(a.keys()|b.keys()) if a.get(k)!=b.get(k)]


def compare(old,new):
    def get(root):
        if not (root/'run.json').is_file(): raise ValueError(f'{root}: select an extracted lane artifact, not the parent directory')
        def key(r):
            if r['kind']=='selector': return (r['object'],r['operation'],r['selector'],r['variant'])
        cols=('sdk_access','access','fixture_code','open_code','source_code','api_code','cleanup_code','granted_access','ntstatus')
        def darwin(r):  # UUIDs and filesec identity fields vary across runner hosts
            if 'native_error' in r: return {'native_error':r['native_error']}
            return {k:(r[k]['presence'], r[k]['flags'], len(r[k]['entries'] or [])) for k in ('path','fd')} | {'libc_ok':r['libc']['ok'],'libc_errno':r['libc'].get('errno')}
        meta=json.loads((root/'run.json').read_text(encoding='utf-8'))
        gate=json.loads((root/'gate.json').read_text(encoding='utf-8')) if (root/'gate.json').exists() else {'ok':False,'problems':['missing gate']}
        return (dict(lane=meta['lane'],sha=meta['context'].get('GITHUB_SHA'),args=meta['args'],gate=gate),
                index(root/'results.jsonl',lambda r:r['id'],lambda r:r['status']),
                index(root/'windows-selectors.jsonl',key,lambda r:{k:r.get(k) for k in cols}),
                index(root/'darwin-presence.jsonl',lambda r:r['case'],darwin),
                index(root/'windows-selectors-privileged.jsonl',key,lambda r:{k:r.get(k) for k in cols}))
    x,y=get(old),get(new)
    return dict(before=x[0],after=y[0],case_changes=changes(x[1],y[1]),selector_changes=changes(x[2],y[2]),darwin_changes=changes(x[3],y[3]),privileged_selector_changes=changes(x[4],y[4]))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('old',type=Path);parser.add_argument('new',type=Path)
    a=parser.parse_args();print(json.dumps(compare(a.old,a.new),indent=2))
