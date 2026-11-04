# native-acl-test

Run the same ACL shard against real Darwin and Windows kernels and bring back enough evidence to explain disagreements. This is a **test repository**, not a new release of the `acl` shard. `acl/`, `lab/`, `probes/` and the original entry points come from checkpoint 5 (`acl` 0.0.5). No desktop registration, repository secrets, self-hosted runner, or manual upload is needed for hosted runs.

## First push

Extract the ZIP and run its included `publish-native-acl-test.sh` from the
`native-acl-test/` directory:

```sh
unzip native-acl-test-ready.zip
cd native-acl-test
bash ./publish-native-acl-test.sh --dry-run
bash ./publish-native-acl-test.sh
```

The script defaults to `git@github.com:immateria/native-acl-test.git` and uses
**existing noninteractive SSH authentication only**. It never calls `gh auth
login`, opens a browser, or requests a device code. An SSH key and a trusted
GitHub host key must already be configured. If not, it stops without changing
the remote.

The remote may have a known incomplete bootstrap history (`.bootstrap`,
`.bootstrap-payload/`, `.bootstrap-xz/`) from the first import attempt. The
script validates the exact initial bootstrap commit and all descendant commit
messages and file paths, then replaces that staging-only history with one clean
source commit using an exact-SHA `--force-with-lease`. It **refuses** to rewrite
any other remote history. Empty remotes get a normal initial push; future
updates from the same local Git checkout use normal fast-forward pushes.

After publication, the first push containing the workflow starts the native
smoke matrix. The workflow must be on the default branch for manual dispatch.
The in-repo files are authoritative; the ZIP only seeds the repository.


## Choose the right lane

| Lane | Runner and actual identity | Smoke / full named cases | Additional evidence |
|---|---|---:|---|
| `macos-arm64` | `macos-15`, Apple Silicon, not root | 18 / 248 | Three-state ACL experiment: native libc vs raw path and descriptor reads |
| `windows-elevated` | `windows-2025`, x64, elevated; verifies active admin membership | 27 / 357 | C selector map twice: untouched token, then requested privileges in a fresh process |
| `windows-filtered` | Same image, same user SID within that job, UAC-style restricted token, medium integrity, no enabled admin membership | 27 / 357 | Same C mapper on the untouched filtered token |
| `windows-lab` | **Manual only**, separate elevated `windows-2025` VM | 36 multiuser cases | Provision/cleanup evidence for three disposable local users and two groups; never targets your desktop |

`all` means the first three lanes. Native matrix jobs do not fail fast. Pushes touching code, tests, runner scripts or the workflow use smoke. Manual runs default to full. Docs-only pushes do not trigger native jobs. An Ubuntu job runs the Python harness tests and checks the reviewed case inventory; it does **not** claim native Windows or Darwin coverage. Only the compiled binaries and live kernel results from the designated runner count as native evidence.

## Iterate with `gh`

Run commands from this repository's clone. The web alternative is **Actions → native-acl → Run workflow**.

```sh
# Full baseline on all three ordinary lanes
gh workflow run native-acl.yml --ref main -f lane=all -f profile=full

# Reproduce just the audit-SACL question, with the same seed after a patch
gh workflow run native-acl.yml --ref main -f lane=windows-elevated \
  -f profile=full -f 'only=windows.sacl.*' -f seed=20261103

# Real Windows identities. Only this dispatch enables account creation.
gh workflow run native-acl.yml --ref main -f lane=windows-lab

# Pick the run for the right commit and event; do not assume latest means yours.
gh run list --workflow native-acl.yml --limit 10 \
  --json databaseId,headSha,event,displayTitle,status,conclusion
# Replace 123456 with the chosen databaseId. A red run still has handbacks.
gh run watch 123456 --exit-status
gh run download 123456 --dir handbacks/123456
```

`only` is a data argument, not shell code. Use a single matching lane and a case ID or `*` / `?` glob. Filtering runs the full native bridge/SDK setup but skips the three broad shard-spec builds. `windows-lab` forces the full multiuser catalog; a filter may narrow it. No matching cases is a failure, not a green no-op. A filtered run where *every* selected case skips is also not green. Push each code change, then dispatch a focused run for the affected OS. For example, `macos-arm64` + `full` + `darwin.acl_flags.*` isolates flag preservation.

Each artifact is named `acl-<lane>-<run-id>-<attempt>`, so a GitHub **Re-run failed jobs** does not overwrite attempt 1. To compare two extracted artifacts:

```sh
python -m ci.compare handbacks/123456/acl-windows-elevated-123456-1 \
                     handbacks/123457/acl-windows-elevated-123457-1
```

The comparison reports status changes by case ID and native `open_code`/`api_code`/`granted_access` etc. by `(object, operation, selector, variant)`, not by ephemeral SID, timing or attempt number. Untouched and privilege-enabled maps are separate. Darwin comparisons suppress random filesec identity bytes; raw values remain available. The report includes both commit SHAs, lane, arguments and gate state. Added/removed cases on different profiles are coverage changes, not regressions. Unchanged status does not imply unchanged ACL bytes: compare the case's recorded requests/responses for that question.

## Read a handback

Start with the GitHub job summary or `LANE.md`, then `gate.json`. `run.json` records commit, image, attempt, lane, requested flags and the exact case list. `identity-collect.json` and `identity-explore.json` are written by the **test processes**, not by their elevated parent. A mismatch blocks execution; there is no elevated fallback for the filtered lane.

`handback.zip` is the original collector archive (or explicitly marked partial salvage). It contains per-case evidence, native bytes, compiler/SDK logs, `REPORT.md`, `environment.json`, and a SHA-256 manifest. `results.jsonl` and `summary.json` are also exposed directly. `windows-selectors*.jsonl` or `darwin-presence.jsonl` are the independent experiments. A Windows attempt can fail to open its handle, fail a later API call, or succeed; these are **different observations**, not three names for a failed assertion. A null code means that stage was not attempted.

Qualification matches exact case IDs, counts, statuses, required build/SDK/cleanup stages and identity. `FAIL`, `ERROR`, `TIMEOUT`, `BLOCKED`, collection errors, and missing required evidence fail the job. `SKIP` and `OBSERVE` remain visible, never counted as assertion passes. Normal assertion failures do not suppress the independent experiment or the artifact upload. A setup failure may yield only provenance and a failed gate. A lost VM, hard cancellation or failed upload cannot guarantee an artifact. Retention requested: 30 days.

The upload scope is **only `ci-out/`**. Account credentials live outside it, in the collector's temporary fixture area. Hosted artifacts do include paths, the VM's SIDs/UUIDs and privilege metadata. Old desktop handbacks and historical source archives were deliberately not imported. No Actions jobs run from `pull_request_target` or on a self-hosted desktop. Local launchers still work; see [native test instructions](docs/NATIVE-TESTING.md) and [coverage](docs/COVERAGE.md).

## Relationship to native-test

Reference: [`immateria/native-test` at `7ad6815`](https://github.com/immateria/native-test/tree/7ad681568e1ef18ce9f429d6a4962496ddd64d11), branch `native-probes-ci`. Its [workflow](https://github.com/immateria/native-test/blob/7ad681568e1ef18ce9f429d6a4962496ddd64d11/.github/workflows/native-probes.yml) separates qualification from native experiments and uploads results on failure. In run `41774705060` the elevated qualification failed, but exploration and artifact upload succeeded. That is the behavior this repository reproduces, not just its runner labels.

**One intentional external dependency:** Windows jobs sparse-check out two inputs from that exact public commit: `.github/actions/setup-crystal-windows/` and `explore/windows/job_explore.cr`. Only the bootstrap and `launch-unelevated` command are used; no process-supervision tests are run. This reuses your proven launcher and hash-checked Crystal 1.21.1/MSVC setup. Keeping `native-test` public at that commit is required for this seed; to sever the dependency, vendor these two inputs and update the workflow before making it private. macOS uses the same pinned universal release and SHA-256 as the reference workflow.

One important difference: in the reference kit the wrapper remains elevated and only its executable is filtered. Here **Python calls Advapi32 itself**, so filtering just `acl-bridge.exe` would mix two identities in a single comparison. Instead, the bootstrap and launcher compilation remain elevated; the launcher runs `python.exe` directly. Each experiment and the entire collector (including its workers, compiler and native bridge) inherit the filtered token. This is not a second real user or a normal interactive logon; use `windows-lab` for the latter tests.

## Local verification and intentional catalog changes

```sh
python -m ci.catalog_lock
python -m unittest discover -s tests -v
python run.py --list --platform windows --profile full
# With Crystal already installed, portable model checks also work on Linux:
python run.py --model-only --profile smoke --skip-specs
```

`ci/coverage.json` freezes case IDs and privilege/account/smoke classification. When adding an experiment, update `lab/catalog.py`, implement it, then run `python -m ci.catalog_lock --write` and review the diff. To change shard behavior, edit `acl/src/`, add a regression in `acl/spec/`, and compare artifacts from the same runner lane, profile and seed. Do not change expected results simply because an OS returned something different.
