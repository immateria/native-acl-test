# On GitHub's disposable runner only. Never modify the checkout or its parents' ACLs.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Requires a hosted runner.' }
$bin = (Get-Command crystal.exe -ErrorAction Stop).Source
& $bin --version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-Command cl.exe,link.exe -ErrorAction Stop | Select-Object Name,Source
if ($env:ACL_LANE -notlike 'windows*-filtered') { exit 0 }
$work = Join-Path $env:RUNNER_TEMP 'native-acl-ci'
$out = Join-Path $env:GITHUB_WORKSPACE 'ci-out'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# The downgraded identity has the same user SID but Administrators is deny-only.
# Set both DACL and integrity. /T reaches the empty subdirs made at init.
foreach ($dir in @($work, $out)) {
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Not initialized: $dir" }
  & icacls.exe $dir /grant "*${sid}:(OI)(CI)M" /T /Q
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & icacls.exe $dir /setintegritylevel '(OI)(CI)M' /T /Q
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$exe = Join-Path $env:RUNNER_TEMP 'acl-filter.exe'
& $bin build --no-color .ci-reference/explore/windows/job_explore.cr -o $exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
