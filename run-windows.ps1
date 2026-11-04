# Use an SDK/MSVC developer PowerShell with Crystal and Python 3.9+ on PATH.
# No installation, elevation, or permanent execution-policy changes are made.
[CmdletBinding()]
param(
    [ValidateSet('smoke','full','stress')][string]$Profile = 'full',
    [switch]$Privileged,
    [switch]$LocalAccounts,
    [int]$Seed = 20261103,
    [int]$Iterations = 1000,
    [double]$CaseTimeout = 180,
    [double]$BuildTimeout = 600,
    [string]$ScratchParent,
    [string]$ResultsParent,
    [string]$Crystal = 'crystal',
    [string]$Python,
    [string[]]$Only = @(),
    [switch]$List,
    [switch]$ModelOnly,
    [switch]$SkipSpecs,
    [switch]$SkipSdk
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'This launcher requires native Windows.'
}
$PythonPrefix = @()
if (-not $Python) {
    $Launcher = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    if ($Launcher) {
        $Python = $Launcher.Source
        $PythonPrefix = @('-3')
    } else {
        foreach ($Candidate in @('python3.exe','python.exe')) {
            $Command = Get-Command $Candidate -ErrorAction SilentlyContinue
            if ($Command -and $Command.Source -notmatch '\\WindowsApps\\') {
                $Python = $Command.Source
                break
            }
        }
    }
}
if (-not $Python) { throw 'Install Python 3.9+ first, or pass -Python C:\path\python.exe. Nothing is downloaded by this kit.' }
& $Python @PythonPrefix -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 2)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.9+ is required.' }
$Invocation = @((Join-Path $PSScriptRoot 'run.py'), '--profile', $Profile, '--seed', "$Seed", '--iterations', "$Iterations",
    '--case-timeout', "$CaseTimeout", '--build-timeout', "$BuildTimeout", '--crystal', $Crystal)
if ($Privileged) { $Invocation += '--privileged' }
if ($LocalAccounts) { $Invocation += '--local-accounts' }
if ($ScratchParent) { $Invocation += @('--scratch-parent', $ScratchParent) }
if ($ResultsParent) { $Invocation += @('--results-parent', $ResultsParent) }
foreach ($Pattern in $Only) { $Invocation += @('--only', $Pattern) }
if ($List) { $Invocation += '--list' }
if ($ModelOnly) { $Invocation += '--model-only' }
if ($SkipSpecs) { $Invocation += '--skip-specs' }
if ($SkipSdk) { $Invocation += '--skip-sdk' }
& $Python @PythonPrefix @Invocation
exit $LASTEXITCODE
