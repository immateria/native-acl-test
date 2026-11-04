"""One case per process. Never launched directly by a user."""
import json
import os
import pathlib
import sys
import time
import traceback
from . import core
from .context import Context, BlockedCase
from .native import SkipCase, Observation

def cleanup(root,platform):
    """Restore our generated tree before deletion; never follow reparse points."""
    warnings=[]
    if platform=='windows':
        from .windows import Windows
        oracle=Windows()
    else:
        from .darwin import Darwin
        oracle=Darwin()
    def visit(path):
        if path.is_symlink() or core.is_reparse(path):return
        try:
            if platform=='windows':oracle.reset_for_cleanup(path)
            else:
                oracle.write(path,None)
                os.chmod(path,0o700 if path.is_dir() else 0o600)
        except (OSError,ValueError) as exc:warnings.append(dict(path=str(path),error=repr(exc)))
        if path.is_dir():
            try:
                for child in path.iterdir():visit(child)
            except OSError as exc:warnings.append(dict(path=str(path),error=repr(exc)))
    visit(root)
    try:core.safe_remove_tree(root)
    except OSError as exc:warnings.append(dict(path=str(root),error=repr(exc)))
    return warnings

def main(config_path):
    config=json.loads(pathlib.Path(config_path).read_text(encoding='utf-8'))
    ctx=Context(config)
    root=ctx.root.resolve(strict=True)
    if root.parent.name!=config['workspace_name'] or not (root.parent/'.acl-lab-owned').is_file():
        raise RuntimeError('worker refused non-owned scratch root')
    os.chdir(root)
    started=time.monotonic()
    result=dict(id=ctx.case['id'],group=ctx.case['group'],status='ERROR',notes=ctx.notes)
    try:
        if ctx.case.get('privileged') and not config.get('privileged'):
            raise SkipCase('opt-in privilege case; rerun with --privileged from an elevated shell')
        if config.get('model_only'):
            from .model_cases import run
        elif ctx.case['platform']=='darwin':
            from .darwin_cases import run
        else:
            from .windows_cases import run
        run(ctx)
        result['status']='PASS'
    except BlockedCase as exc:result.update(status='BLOCKED',reason=str(exc))
    except SkipCase as exc:result.update(status='SKIP',reason=str(exc))
    except Observation as exc:result.update(status='OBSERVE',reason=str(exc))
    except AssertionError as exc:result.update(status='FAIL',reason=str(exc),traceback=traceback.format_exc())
    except Exception as exc:result.update(status='ERROR',reason=str(exc),exception=type(exc).__name__,traceback=traceback.format_exc())
    finally:
        result['elapsed_seconds']=round(time.monotonic()-started,6)
        os.chdir(root.parent)
        try:
            if config.get('model_only'):
                core.safe_remove_tree(root); result['cleanup_warnings']=[]
            else:result['cleanup_warnings']=cleanup(root,ctx.case['platform'])
        except Exception as exc:result['cleanup_warnings']=[dict(error=repr(exc))]
        core.write_json(ctx.evidence/'result.json',result)
    return 0

if __name__=='__main__':sys.exit(main(sys.argv[1]))
