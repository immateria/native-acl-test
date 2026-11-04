"""Bounded final-cleanup subprocess, restricted to a generated lab workspace."""
import json
import pathlib
import sys
from . import core
from .worker import cleanup

def main():
    root=pathlib.Path(sys.argv[1]).absolute()
    platform=sys.argv[2]
    if not root.name.startswith('acl-lab-') or not (root/'.acl-lab-owned').is_file():
        raise RuntimeError('refusing to clean an unmarked workspace')
    if platform=='portable':
        core.safe_remove_tree(root);warnings=[]
    else:
        warnings=cleanup(root,platform)
    print(json.dumps(dict(cleanup_warnings=warnings),ensure_ascii=True))
    return 1 if warnings else 0

if __name__=='__main__':sys.exit(main())
