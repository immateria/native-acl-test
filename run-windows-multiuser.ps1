# Run the disposable local-user/group authorization matrix only.
# Launch from an elevated SDK/MSVC Developer PowerShell.
[CmdletBinding()]
param(
    [int]$Seed = 20261103,
    [double]$CaseTimeout = 240,
    [double]$BuildTimeout = 600,
    [string]$ScratchParent,
    [string]$ResultsParent,
    [string]$Crystal = 'crystal',
    [string]$Python,
    [switch]$SkipSpecs,
    [switch]$SkipSdk
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The multi-user ACL suite must run from an elevated PowerShell. It creates and removes disposable local users and groups.'
}
$Arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'run-windows.ps1'),
    '-Profile','full','-LocalAccounts','-Privileged','-Seed',"$Seed",'-CaseTimeout',"$CaseTimeout",'-BuildTimeout',"$BuildTimeout",
    '-Crystal',$Crystal,'-Only','windows.multiuser.*')
if ($ScratchParent) { $Arguments += @('-ScratchParent',$ScratchParent) }
if ($ResultsParent) { $Arguments += @('-ResultsParent',$ResultsParent) }
if ($Python) { $Arguments += @('-Python',$Python) }
if ($SkipSpecs) { $Arguments += '-SkipSpecs' }
if ($SkipSdk) { $Arguments += '-SkipSdk' }
& powershell.exe @Arguments
exit $LASTEXITCODE
