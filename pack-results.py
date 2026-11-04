#!/usr/bin/env python3
"""Package a stopped/interrupted run's evidence without touching its fixtures."""
import argparse
import pathlib
from lab import core
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('directory',type=pathlib.Path)
a=p.parse_args()
root=a.directory.resolve(strict=True)
if not (root/'invocation.json').is_file() or not (root/'case-manifest.json').is_file():
    p.error('directory is not an ACL lab result directory')
print('UPLOAD '+str(core.archive(root)))
