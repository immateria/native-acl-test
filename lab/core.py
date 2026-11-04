"""Process isolation, crash-tolerant recording and bounded artifact packaging."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import zipfile


def write_json(path, value):
    """Atomically replace one JSON document; never leave half a result."""
    path = pathlib.Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def command(argv, prefix, timeout, cwd=None, env=None, stdin=None, isolate=True):
    """Run argv without a shell, capture streams, terminate on timeout.

    Top-level workers/compilers own process groups. A nested bridge uses
    isolate=False so killing its worker group also kills the bridge. It has
    no subprocess children of its own; its inner timeout kills that process.
    """
    prefix = pathlib.Path(prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    stdout, stderr = prefix.with_suffix('.stdout.txt'), prefix.with_suffix('.stderr.txt')
    started = time.monotonic()
    result = dict(argv=[str(a) for a in argv], cwd=str(cwd) if cwd else None,
                  stdout=str(stdout), stderr=str(stderr), timed_out=False, returncode=None)
    try:
        with stdout.open('wb') as out, stderr.open('wb') as err:
            options = {'start_new_session': isolate} if os.name != 'nt' else {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP if isolate else 0}
            process = subprocess.Popen(result['argv'], cwd=cwd, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                       stdout=out, stderr=err, **options)
            def stop_tree():
                if os.name == 'nt':
                    try:
                        subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=20)
                    except (OSError, subprocess.SubprocessError):
                        pass
                elif isolate:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                if process.poll() is None: process.kill()
                process.communicate(timeout=20)
            try:
                process.communicate(stdin, timeout=timeout)
            except subprocess.TimeoutExpired:
                result['timed_out'] = True
                stop_tree()
            except BaseException:
                # Do not let Ctrl-C leave a test alive while the parent cleans its fixture.
                stop_tree()
                raise
            result['returncode'] = process.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        result['launch_error'] = repr(exc)
    result['elapsed_seconds'] = round(time.monotonic() - started, 6)
    write_json(prefix.with_suffix('.command.json'), result)
    return result


def new_workspace(parent):
    """Create a fresh owner-private root; never adopt a pre-existing directory."""
    parent = pathlib.Path(parent).resolve(strict=True)
    if not parent.is_dir(): raise ValueError('scratch parent must be a directory')
    path = pathlib.Path(tempfile.mkdtemp(prefix='acl-lab-', dir=str(parent)))
    if os.name != 'nt': path.chmod(0o700)
    (path / '.acl-lab-owned').write_text('ACL LAB GENERATED FIXTURES ONLY\n', encoding='ascii')
    return path


def archive(root):
    """Archive only result files, never fixtures or symlink/reparse targets."""
    root = pathlib.Path(root).resolve()
    files = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != 'build' and not pathlib.Path(directory, d).is_symlink() and not is_reparse(pathlib.Path(directory, d)))
        for name in sorted(names):
            p = pathlib.Path(directory, name)
            if p.name == 'manifest.sha256' or p.is_symlink() or is_reparse(p): continue
            if p.is_file(): files.append(p)
    manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(root).as_posix() + '\n' for p in files)
    (root / 'manifest.sha256').write_text(manifest, encoding='utf-8')
    target = root.with_suffix('.zip')
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in files + [root / 'manifest.sha256']:
            z.write(p, (pathlib.Path(root.name) / p.relative_to(root)).as_posix())
    return target


def is_reparse(path):
    try: return bool(getattr(path.lstat(), 'st_file_attributes', 0) & 0x400)
    except OSError: return True


def safe_remove_tree(path):
    """Delete generated descendants only, without following symbolic links.

    Caller supplies a freshly-created fixture directory and invokes this only
    after its child process has exited. Never use for a user-selected tree.
    """
    path = pathlib.Path(path)
    if path.is_symlink():
        path.unlink(); return
    if is_reparse(path):
        if path.is_dir(): path.rmdir()
        else: path.unlink()
        return
    if path.is_dir():
        # Experiments may leave the directory itself unsearchable (mode 0).
        # Restore owner access so the fixture can be torn down; a failure to
        # do so still raises below.
        try: os.chmod(path, 0o700)
        except OSError: pass
        for child in path.iterdir(): safe_remove_tree(child)
        path.rmdir()
    else:
        path.unlink()
