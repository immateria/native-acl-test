[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('explore','collect')][string] $Stage)
$ErrorActionPreference = 'Stop'
$py = (Get-Command python.exe -ErrorAction Stop).Source
if ($env:ACL_LANE -eq 'windows-filtered') {
  # Launch python.exe directly. PowerShell does not run under the restricted token.
  # The child probes its own token before allowing either exploration or fixture writes.
  $launcher = Join-Path $env:RUNNER_TEMP 'acl-filter.exe'
  & $launcher launch-unelevated -- $py -u -m ci.lane $Stage
} else {
  & $py -u -m ci.lane $Stage
}
exit $LASTEXITCODE
