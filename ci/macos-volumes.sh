#!/usr/bin/env bash
# Create disposable native filesystems below the owned GitHub runner scratch tree.
set -euo pipefail

stage=${1:-}
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
root="$RUNNER_TEMP/native-acl-ci/generated-filesystems"
out="$GITHUB_WORKSPACE/ci-out"
metadata="$out/macos-filesystems.json"
cleanup_metadata="$out/macos-filesystems-cleanup.json"
records="$root/records.jsonl"
devices="$root/devices.tsv"

case "$root" in
  "$RUNNER_TEMP"/native-acl-ci/generated-filesystems) ;;
  *) printf 'refusing unsafe generated-filesystem root: %s\n' "$root" >&2; exit 64 ;;
esac

json_record() {
  local kind=$1 supported=$2 filesystem=$3 image=$4 mount=$5 device=$6 error=$7
  KIND=$kind SUPPORTED=$supported FILESYSTEM=$filesystem IMAGE=$image MOUNT=$mount DEVICE=$device ERROR_TEXT=$error \
    python3 - <<'PY' >>"$records"
import json, os
print(json.dumps({
    "kind": os.environ["KIND"],
    "supported": os.environ["SUPPORTED"] == "true",
    "filesystem": os.environ["FILESYSTEM"],
    "image": os.environ["IMAGE"],
    "root": os.environ["MOUNT"],
    "device": os.environ["DEVICE"] or None,
    "error": os.environ["ERROR_TEXT"] or None,
}, sort_keys=True))
PY
}


plist_devices() {
  local plist=$1
  python3 - "$plist" <<'PYDEV'
import plistlib, re, sys
with open(sys.argv[1], "rb") as stream:
    payload = plistlib.load(stream)
seen = set()
for entity in payload.get("system-entities", []):
    device = entity.get("dev-entry", "")
    if re.fullmatch(r"/dev/disk[0-9]+s?[0-9]*", device) and device not in seen:
        seen.add(device)
        print(device)
PYDEV
}

detach_plist_devices() {
  local plist=$1 mount=$2 image=$3 parsed device failures=0
  [[ -f $plist ]] || return 0
  if ! parsed=$(plist_devices "$plist"); then
    return 1
  fi
  while IFS= read -r device; do
    [[ -n $device ]] || continue
    if hdiutil detach "$device" >/dev/null 2>&1 || hdiutil detach -force "$device" >/dev/null 2>&1; then
      continue
    fi
    # Preserve the exact device for the final cleanup stage rather than leaking
    # an attached image after a malformed/unexpected attach plist.
    printf '%s\t%s\t%s\n' "$device" "$mount" "$image" >>"$devices"
    failures=1
  done <<<"$parsed"
  return "$failures"
}

prepare_volume() {
  local kind=$1 filesystem=$2 variable=$3 label=$4
  local image="$root/$kind.dmg" mount="$root/$kind" plist="$root/$kind-attach.plist" error_file="$root/$kind-error.txt"
  mkdir -p "$mount"
  if ! hdiutil create -quiet -size 128m -type UDIF -fs "$filesystem" -volname "$label" "$image" 2>"$error_file"; then
    json_record "$kind" false "$filesystem" "$image" "$mount" "" "$(tr '\n' ' ' <"$error_file" | head -c 2000)"
    return 0
  fi
  if ! hdiutil attach -plist -nobrowse -noautoopen -mountpoint "$mount" "$image" >"$plist" 2>"$error_file"; then
    json_record "$kind" false "$filesystem" "$image" "$mount" "" "$(tr '\n' ' ' <"$error_file" | head -c 2000)"
    return 0
  fi
  local device parse_error=""
  if ! device=$(MOUNT_POINT="$mount" python3 - "$plist" <<'PY'
import os, plistlib, sys
with open(sys.argv[1], "rb") as stream:
    payload = plistlib.load(stream)
for entity in payload.get("system-entities", []):
    if entity.get("mount-point") == os.environ["MOUNT_POINT"]:
        print(entity.get("dev-entry", ""))
        break
PY
  ); then
    parse_error="attach plist could not be parsed"
    device=""
  fi
  if [[ ! $device =~ ^/dev/disk[0-9]+s?[0-9]*$ ]]; then
    detach_plist_devices "$plist" "$mount" "$image" || true
    json_record "$kind" false "$filesystem" "$image" "$mount" "$device" \
      "${parse_error:-attach succeeded without a bounded disk device}"
    return 0
  fi
  printf '%s\t%s\t%s\n' "$device" "$mount" "$image" >>"$devices"
  printf '%s=%s\n' "$variable" "$mount" >>"${GITHUB_ENV:-$root/github-env}"
  json_record "$kind" true "$filesystem" "$image" "$mount" "$device" ""
}

write_summary() {
  local destination=$1 status=$2
  ROOT_PATH="$root" STATUS_TEXT="$status" python3 - "$records" "$destination" <<'PY'
import json, os, platform, sys
source, destination = sys.argv[1:]
rows = []
try:
    with open(source, encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
except FileNotFoundError:
    pass
payload = {
    "schema": 1,
    "platform": "darwin",
    "root": os.environ["ROOT_PATH"],
    "status": os.environ["STATUS_TEXT"],
    "machine": platform.machine(),
    "volumes": rows,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

case "$stage" in
  prepare)
    [[ $(uname -s) == Darwin ]] || { printf 'macOS volume preparation requires Darwin\n' >&2; exit 64; }
    mkdir -p "$root" "$out"
    : >"$records"
    : >"$devices"
    # APFSX and HFSX are the case-sensitive variants accepted by hdiutil.
    prepare_volume apfs-case-sensitive APFSX ACL_MACOS_APFSX_ROOT ACLMapAPFSX
    prepare_volume hfs-plus HFSX ACL_MACOS_HFSX_ROOT ACLMapHFSX
    write_summary "$metadata" prepared
    ;;
  cleanup)
    mkdir -p "$root" "$out"
    : >"$records.cleanup"
    failures=0
    if [[ -f $devices ]]; then
      while IFS=$'\t' read -r device mount image; do
        [[ $device =~ ^/dev/disk[0-9]+s?[0-9]*$ ]] || { printf 'unsafe device in metadata: %s\n' "$device" >&2; failures=1; continue; }
        if hdiutil detach "$device" >"$root/detach.out" 2>"$root/detach.err"; then
          code=0
        elif hdiutil detach -force "$device" >>"$root/detach.out" 2>>"$root/detach.err"; then
          code=0
        else
          code=$?
          failures=1
        fi
        DEVICE=$device MOUNT=$mount IMAGE=$image CODE=$code python3 - <<'PY' >>"$records.cleanup"
import json, os
print(json.dumps({"device": os.environ["DEVICE"], "root": os.environ["MOUNT"],
                  "image": os.environ["IMAGE"], "detach_code": int(os.environ["CODE"])}, sort_keys=True))
PY
      done < <(tail -r "$devices" 2>/dev/null || tac "$devices")
    fi
    ROOT_PATH="$root" FAILURES=$failures python3 - "$records.cleanup" "$cleanup_metadata" <<'PY'
import json, os, sys
source, destination = sys.argv[1:]
rows = []
try:
    with open(source, encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
except FileNotFoundError:
    pass
with open(destination, "w", encoding="utf-8") as stream:
    json.dump({"schema": 1, "platform": "darwin", "root": os.environ["ROOT_PATH"],
               "ok": os.environ["FAILURES"] == "0", "detaches": rows}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY
    if [[ $failures -eq 0 ]]; then rm -rf -- "$root"; fi
    exit "$failures"
    ;;
  *)
    printf 'usage: %s prepare|cleanup\n' "$0" >&2
    exit 64
    ;;
esac
