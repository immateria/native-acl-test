[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Prepare', 'Cleanup')][string] $Stage)
$ErrorActionPreference = 'Stop'
if (-not $env:RUNNER_TEMP -or -not $env:GITHUB_WORKSPACE) { throw 'RUNNER_TEMP and GITHUB_WORKSPACE are required.' }

$workRoot = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'native-acl-ci'))
$root = [IO.Path]::GetFullPath((Join-Path $workRoot 'generated-filesystems'))
$out = [IO.Path]::GetFullPath((Join-Path $env:GITHUB_WORKSPACE 'ci-out'))
$metadataPath = Join-Path $out 'windows-filesystems.json'
$cleanupPath = Join-Path $out 'windows-filesystems-cleanup.json'
if (-not $root.StartsWith($workRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing unsafe generated-filesystem root: $root"
}

function Write-EnvironmentValue([string] $Name, [string] $Value) {
  $target = if ($env:GITHUB_ENV) { $env:GITHUB_ENV } else { Join-Path $root 'github-env.txt' }
  Add-Content -LiteralPath $target -Value "$Name=$Value" -Encoding utf8
}

function Save-Json([string] $Path, [object] $Value) {
  $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8
}

function New-Result([string] $Kind) {
  [ordered]@{ kind = $Kind; supported = $false; root = $null; error = $null }
}

function Get-GeneratedShareName {
  $name = ('aclmap-{0}-{1}' -f $env:GITHUB_RUN_ID, $env:GITHUB_RUN_ATTEMPT) -replace '[^A-Za-z0-9_-]', '-'
  if ($name.Length -gt 60) { $name = $name.Substring(0, 60) }
  return $name
}

function Test-ChildPath([string] $Candidate, [string] $Parent) {
  $candidatePath = [IO.Path]::GetFullPath($Candidate)
  $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar)
  return $candidatePath.StartsWith($parentPath + [IO.Path]::DirectorySeparatorChar,
                                   [StringComparison]::OrdinalIgnoreCase)
}

if ($Stage -eq 'Prepare') {
  New-Item -ItemType Directory -Force -Path $root, $out | Out-Null
  $results = @()
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $currentName = $currentIdentity.Name
  $currentSid = $currentIdentity.User.Value

  $smb = New-Result 'loopback-smb'
  $shareRoot = Join-Path $root 'smb-root'
  $shareName = Get-GeneratedShareName
  try {
    New-Item -ItemType Directory -Force -Path $shareRoot | Out-Null
    New-SmbShare -Name $shareName -Path $shareRoot -FullAccess $currentName -Temporary -ErrorAction Stop | Out-Null
    $unc = "\\localhost\$shareName"
    $smb.supported = $true
    $smb.root = $unc
    $smb.share_name = $shareName
    $smb.local_path = $shareRoot
    Write-EnvironmentValue 'ACL_LOOPBACK_SMB_ROOT' $unc
  } catch {
    $smb.error = $_.Exception.Message
    $smb.share_name = $shareName
    $smb.local_path = $shareRoot
  }
  $results += [pscustomobject]$smb

  $refs = New-Result 'refs-vhdx'
  $vhdPath = Join-Path $root 'refs.vhdx'
  try {
    Import-Module Hyper-V -ErrorAction Stop
    New-VHD -Path $vhdPath -Dynamic -SizeBytes 2GB -ErrorAction Stop | Out-Null
    $disk = Mount-VHD -Path $vhdPath -Passthru -ErrorAction Stop | Get-Disk -ErrorAction Stop
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop | Out-Null
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
    $volume = Format-Volume -Partition $partition -FileSystem ReFS -NewFileSystemLabel ACLMapReFS -Confirm:$false -Force -ErrorAction Stop
    $refsRoot = "$($volume.DriveLetter):\acl-map"
    New-Item -ItemType Directory -Force -Path $refsRoot | Out-Null
    & icacls.exe $refsRoot /grant "*${currentSid}:(OI)(CI)F" /T /Q
    if ($LASTEXITCODE -ne 0) { throw "failed to grant the runner user access to ReFS root: $LASTEXITCODE" }
    & icacls.exe $refsRoot /setintegritylevel '(OI)(CI)M' /T /Q
    if ($LASTEXITCODE -ne 0) { throw "failed to set medium integrity on ReFS root: $LASTEXITCODE" }
    $refs.supported = $true
    $refs.root = $refsRoot
    $refs.vhd_path = $vhdPath
    $refs.disk_number = [int]$disk.Number
    Write-EnvironmentValue 'ACL_WINDOWS_REFS_ROOT' $refsRoot
  } catch {
    $refs.error = $_.Exception.Message
    $refs.vhd_path = $vhdPath
    try { Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue } catch {}
  }
  $results += [pscustomobject]$refs

  Save-Json $metadataPath ([ordered]@{
    schema = 1
    platform = 'windows'
    root = $root
    lane = $env:ACL_LANE
    filesystems = $results
  })
  exit 0
}

New-Item -ItemType Directory -Force -Path $out | Out-Null
$cleanup = @()
$failed = $false
$entries = @()
if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
  $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
  $entries = @($metadata.filesystems)
} else {
  # Recover resources even when Prepare was interrupted after native creation
  # but before its summary JSON was written.
  $entries = @(
    [pscustomobject]@{ kind = 'loopback-smb'; share_name = (Get-GeneratedShareName); vhd_path = $null },
    [pscustomobject]@{ kind = 'refs-vhdx'; share_name = $null; vhd_path = (Join-Path $root 'refs.vhdx') }
  )
}
foreach ($entry in $entries) {
  $row = [ordered]@{ kind = $entry.kind; ok = $true; error = $null }
  try {
    if ($entry.kind -eq 'loopback-smb' -and $entry.share_name) {
      $share = [string]$entry.share_name
      if ($share -notmatch '^aclmap-[A-Za-z0-9_-]+$') { throw "unsafe share name in metadata: $share" }
      if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $share -Force -Confirm:$false -ErrorAction Stop
      }
      if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {
        throw "generated SMB share still exists after cleanup: $share"
      }
    }
    if ($entry.kind -eq 'refs-vhdx' -and $entry.vhd_path) {
      $vhd = [IO.Path]::GetFullPath([string]$entry.vhd_path)
      if (-not (Test-ChildPath $vhd $root)) { throw "unsafe VHD path in metadata: $vhd" }
      if ((Test-Path -LiteralPath $vhd) -and (Get-Command Dismount-VHD -ErrorAction SilentlyContinue)) {
        $state = Get-VHD -Path $vhd -ErrorAction Stop
        if ($state.Attached) {
          Dismount-VHD -Path $vhd -ErrorAction Stop
          $state = Get-VHD -Path $vhd -ErrorAction Stop
        }
        if ($state.Attached) { throw "generated VHD remains attached after cleanup: $vhd" }
      }
    }
  } catch {
    $row.ok = $false
    $row.error = $_.Exception.Message
    $failed = $true
  }
  $cleanup += [pscustomobject]$row
}
if (-not $failed -and (Test-Path -LiteralPath $root)) {
  try {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
  } catch {
    $cleanup += [pscustomobject]@{
      kind = 'root'
      ok = $false
      error = "generated filesystem root cleanup failed: $($_.Exception.Message)"
    }
    $failed = $true
  }
}
Save-Json $cleanupPath ([ordered]@{
  schema = 1
  platform = 'windows'
  root = $root
  ok = -not $failed
  cleanup = $cleanup
})
if ($failed) { exit 1 }
