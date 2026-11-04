# Emergency cleanup for a run interrupted before its normal account teardown.
# The input is the public local-accounts.json emitted in the result directory;
# it contains names and SIDs, never passwords.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$MetadataPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this cleanup script from an elevated PowerShell.'
}

function Validate-LabName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -notmatch '^acl(?:A|B|C|GA|GD)_[a-z0-9]{1,8}$') {
        throw "Refusing non-lab account/group name: $Name"
    }
    return $Name
}

function Validate-LabSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    if ($Sid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') {
        throw "Refusing non-local-SAM SID: $Sid"
    }
    return $Sid
}

function Resolve-LocalSid {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $account = [Security.Principal.NTAccount]::new($env:COMPUTERNAME, $Name)
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch [Security.Principal.IdentityNotMappedException] {
        return $null
    }
}

$metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$users = @('alice', 'bob', 'carol') | ForEach-Object {
    $role = $_
    $entry = $metadata.users.PSObject.Properties[$role].Value
    [pscustomobject]@{
        kind = 'user'
        name = (Validate-LabName ([string]$entry.name))
        expected_sid = (Validate-LabSid ([string]$entry.sid))
    }
}
$groups = @('allow', 'deny') | ForEach-Object {
    $role = $_
    $entry = $metadata.groups.PSObject.Properties[$role].Value
    [pscustomobject]@{
        kind = 'group'
        name = (Validate-LabName ([string]$entry.name))
        expected_sid = (Validate-LabSid ([string]$entry.sid))
    }
}

$failures = [System.Collections.Generic.List[object]]::new()
foreach ($entry in @($users) + @($groups)) {
    $actualSid = Resolve-LocalSid $entry.name
    if ($null -eq $actualSid) {
        Write-Host "$($entry.kind) $($entry.name) is already absent."
        continue
    }
    if ($actualSid -ne $entry.expected_sid) {
        throw "Refusing to delete $($entry.name): current SID $actualSid does not match recorded SID $($entry.expected_sid)"
    }
    if ($PSCmdlet.ShouldProcess("local $($entry.kind) $($entry.name) [$actualSid]", 'Delete')) {
        if ($entry.kind -eq 'user') {
            & "$env:SystemRoot\System32\net.exe" user $entry.name /delete | Out-Host
        }
        else {
            & "$env:SystemRoot\System32\net.exe" localgroup $entry.name /delete | Out-Host
        }
        if ($LASTEXITCODE -notin @(0, 2)) {
            $failures.Add([pscustomobject]@{
                kind = $entry.kind
                name = $entry.name
                expected_sid = $entry.expected_sid
                exit_code = $LASTEXITCODE
            })
        }
    }
}

if ($failures.Count -ne 0) {
    $failures | ConvertTo-Json -Depth 4 | Write-Error
    exit 1
}
Write-Host 'Disposable ACL lab accounts/groups are absent.'
