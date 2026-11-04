"""Check (default) or intentionally update the reviewed case inventory."""
import argparse
import json
from pathlib import Path
from lab.catalog import cases

LOCK = Path(__file__).with_name('coverage.json')


def inventory():
    return {platform: {c['id']: {'smoke': c['smoke'], 'privileged': c['privileged'],
                                'accounts': bool(c.get('local_accounts'))}
                       for c in cases(platform, 'full', local_accounts=platform=='windows')}
            for platform in ('darwin','windows')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true')
    args=parser.parse_args(); current=inventory()
    if args.write:
        LOCK.write_text(json.dumps(current,sort_keys=True,indent=2)+'\n',encoding='utf-8');return 0
    if json.loads(LOCK.read_text(encoding='utf-8'))!=current:
        print('Catalog drift: review the difference from python -m ci.catalog_lock --write.');return 1
    print('Verified case inventory:', {p:len(cs) for p,cs in current.items()});return 0

if __name__=='__main__': raise SystemExit(main())
