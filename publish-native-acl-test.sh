#!/usr/bin/env bash
# Publish the prepared native-acl-test source tree without launching OAuth/device login.
# Supports an empty remote, the exact known temporary-bootstrap history, or ordinary updates.
set -euo pipefail

REPOSITORY_URL='git@github.com:immateria/native-acl-test.git'
INITIAL_BOOTSTRAP='208cf6dd60e58162951e082ab02ddea6c14c0ac8'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DRY_RUN=0

usage()
{
    cat <<'HELP'
Usage: ./publish-native-acl-test.sh [--remote GIT_URL] [--dry-run]

Run from the extracted native-acl-test directory (or execute this script in
that directory). Uses existing noninteractive SSH credentials by default;
NEVER invokes gh auth login, a web browser, or GitHub's device activation.

Remote outcomes:
  Empty main:               create one initial commit and push normally.
  Known bootstrap-only main: replace its temporary chunk history using an
                             exact-SHA force-with-lease. No unrelated history
                             is overwritten.
  Normal main:              require an existing local Git checkout whose HEAD
                             is a fast-forward descendant of the remote main.
  Unknown remote contents:  refuse to publish; do not force push.

--remote GIT_URL  Override the default SSH remote (also useful for local tests).
--dry-run         Check prerequisites and classify remote, but change nothing.
HELP
}

die()
{
    printf 'error: %s\n' "$*" >&2
    exit 1
}

forbidden_remote_option()
{
    case "$1" in
        -*) return 0 ;;
        *) return 1 ;;
    esac
}

while (($#)); do
    case "$1" in
        --remote)
            (($# >= 2)) || die '--remote requires a value'
            REPOSITORY_URL="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ -n "$REPOSITORY_URL" ]] || die 'empty remote'
if forbidden_remote_option "$REPOSITORY_URL"; then
    die 'remote URLs must not begin with a dash'
fi
command -v git >/dev/null 2>&1 || die 'git is required'
[[ -f "$SCRIPT_DIR/.github/workflows/native-acl.yml" ]] || die 'workflow missing: run from native-acl-test source directory'
[[ -f "$SCRIPT_DIR/acl/shard.yml" ]] || die 'acl/shard.yml missing: wrong source directory'
[[ -f "$SCRIPT_DIR/run.py" ]] || die 'run.py missing: wrong source directory'

# Prevent credential prompts or helpers that launch a device-code/browser flow.
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/usr/bin/false
export SSH_ASKPASS=/usr/bin/false
export GCM_INTERACTIVE=Never
export GCM_GUI_PROMPT=0
export GIT_SSH_COMMAND='ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=yes'

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/native-acl-publish.XXXXXXXX")"
cleanup()
{
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

printf 'Source: %s\nRemote: %s\n' "$SCRIPT_DIR" "$REPOSITORY_URL"
if ! remote_heads="$(git ls-remote --heads "$REPOSITORY_URL" refs/heads/main 2>"$tmp_dir/ls-remote.err")"; then
    cat "$tmp_dir/ls-remote.err" >&2
    die 'could not query the Git remote using pre-existing credentials (no login attempted)'
fi
remote_sha="$(printf '%s\n' "$remote_heads" | awk '$2 == "refs/heads/main" {print $1}')"
if [[ -n "$remote_sha" && ! "$remote_sha" =~ ^[0-9a-f]{40}$ ]]; then
    die 'unexpected remote main SHA'
fi

# Inspection happens in a throwaway repository so dry-run never changes the source.
bootstrap_only=0
if [[ -n "$remote_sha" ]]; then
    git -C "$tmp_dir" init -q
    git -C "$tmp_dir" -c protocol.file.allow=always fetch -q --no-tags "$REPOSITORY_URL" refs/heads/main
    fetched_sha="$(git -C "$tmp_dir" rev-parse FETCH_HEAD)"
    [[ "$fetched_sha" == "$remote_sha" ]] || die 'remote main changed while checking; retry'

    roots="$(git -C "$tmp_dir" rev-list --max-parents=0 "$fetched_sha")"
    count="$(git -C "$tmp_dir" rev-list --count "$fetched_sha")"
    if [[ "$roots" == "$INITIAL_BOOTSTRAP" && "$count" -le 256 ]]; then
        bootstrap_only=1
        while IFS= read -r sha; do
            subject="$(git -C "$tmp_dir" show -s --format=%s "$sha")"
            case "$subject" in
                'Initialize native ACL test repository'|'Stage native ACL test payload '*|'Stage compressed native ACL payload '*) ;;
                *) bootstrap_only=0 ;;
            esac
            while IFS= read -r path; do
                case "$path" in
                    '.bootstrap'|.bootstrap-payload/chunk-[0-9]*|.bootstrap-xz/chunk-[0-9]*) ;;
                    *) bootstrap_only=0 ;;
                esac
            done < <(git -C "$tmp_dir" ls-tree -r --name-only "$sha")
        done < <(git -C "$tmp_dir" rev-list "$fetched_sha")
    fi
fi

has_local_git=0
if [[ -d "$SCRIPT_DIR/.git" ]]; then
    has_local_git=1
    [[ "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)" == "$SCRIPT_DIR" ]] || die 'unexpected nested Git checkout'
    existing_url="$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
    if [[ -n "$existing_url" && "$existing_url" != "$REPOSITORY_URL" ]]; then
        die "existing origin is '$existing_url'; refusing to change it automatically"
    fi
fi

if [[ -z "$remote_sha" ]]; then
    action='create initial main'
elif [[ "$bootstrap_only" -eq 1 ]]; then
    action='replace known bootstrap history (exact-SHA lease)'
elif [[ "$has_local_git" -eq 1 ]]; then
    action='fast-forward existing checkout only'
else
    die 'remote contains non-bootstrap history and source has no Git history; clone the remote and merge deliberately'
fi

printf 'Remote main: %s\nOperation: %s\n' "${remote_sha:-<absent>}" "$action"
if ((DRY_RUN)); then
    printf 'DRY RUN: no source files, commits, or remote references changed.\n'
    exit 0
fi

if ((has_local_git == 0)); then
    git -C "$SCRIPT_DIR" init -q -b main
fi
if ! git -C "$SCRIPT_DIR" remote get-url origin >/dev/null 2>&1; then
    git -C "$SCRIPT_DIR" remote add origin "$REPOSITORY_URL"
fi

git -C "$SCRIPT_DIR" add -A
if ! git -C "$SCRIPT_DIR" diff --cached --quiet; then
    git -C "$SCRIPT_DIR" -c commit.gpgsign=false commit -m 'Import native ACL qualification harness'
fi

if [[ -n "$remote_sha" && "$bootstrap_only" -eq 0 ]]; then
    git -C "$SCRIPT_DIR" fetch -q --no-tags origin refs/heads/main:refs/remotes/origin/main
    latest_sha="$(git -C "$SCRIPT_DIR" rev-parse refs/remotes/origin/main)"
    [[ "$latest_sha" == "$remote_sha" ]] || die 'remote main advanced during import; retry after merging'
    git -C "$SCRIPT_DIR" merge-base --is-ancestor "$remote_sha" HEAD || die 'local branch is not a fast-forward of remote main; no force push attempted'
    git -C "$SCRIPT_DIR" push -u origin HEAD:refs/heads/main
elif [[ -n "$remote_sha" ]]; then
    # The only force operation: known temporary commits, exact expected tip.
    git -C "$SCRIPT_DIR" push -u "--force-with-lease=refs/heads/main:$remote_sha" origin HEAD:refs/heads/main
else
    git -C "$SCRIPT_DIR" push -u origin HEAD:refs/heads/main
fi

printf '\nPublished: %s\nCommit: %s\n' "$REPOSITORY_URL" "$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
printf 'GitHub Actions: https://github.com/immateria/native-acl-test/actions\n'
