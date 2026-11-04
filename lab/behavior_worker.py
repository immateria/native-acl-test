"""One-process-per-domain native behavior mapping worker."""
import argparse
import pathlib
import platform as host_platform
import sys

from . import behavior, behavior_catalog


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--platform", choices=("darwin", "windows"), required=True)
    value.add_argument("--domain", required=True)
    value.add_argument("--depth", choices=behavior_catalog.DEPTHS, required=True)
    value.add_argument("--workspace", type=pathlib.Path, required=True)
    value.add_argument("--output", type=pathlib.Path, required=True)
    value.add_argument("--privileged", action="store_true")
    value.add_argument("--local-accounts", action="store_true")
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    expected = behavior_catalog.manifest(args.platform, args.depth).get(args.domain)
    if expected is None:
        raise ValueError("unknown behavior domain")
    writer = behavior.RowWriter(args.output, args.platform, args.domain, expected)
    if args.platform == "darwin":
        from . import darwin_behavior as implementation
    else:
        from . import windows_behavior as implementation
    implementation.run_domain(args.domain, args.depth, args.workspace, writer,
                              args.privileged, local_accounts=args.local_accounts)
    writer.finish(dict(python=sys.version, system=host_platform.system(), machine=host_platform.machine()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
