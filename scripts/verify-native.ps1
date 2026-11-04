# Run in a Windows SDK/MSVC developer shell with Crystal >= 1.18 and Shards.
# Optional: ACL_NATIVE_SACL_TESTS=1 with required privileges already enabled.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
function Check-Exit([string] $Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed: exit $LASTEXITCODE" }
}
New-Item -ItemType Directory -Force (Join-Path $Root 'build') | Out-Null
& crystal --version; Check-Exit 'Crystal version'
& shards --version; Check-Exit 'Shards version'
Push-Location (Join-Path $Root 'build')
try {
    & cl.exe /nologo /std:c11 /W4 /WX (Join-Path $Root 'scripts/probes/windows_acl_abi.c') /Fe:windows-acl-abi.exe /link advapi32.lib
    Check-Exit 'Windows SDK probe compile'
    & .\windows-acl-abi.exe; Check-Exit 'Windows SDK probe run'
    & cl.exe /nologo /std:c11 /W4 /WX (Join-Path $Root 'probes/windows_acl_map.c') /Fe:windows-acl-map.exe /Fo:windows-acl-map.obj /link advapi32.lib kernel32.lib
    Check-Exit 'Windows native mapper compile'
    $MapOutput = Join-Path $Root 'build/windows-native-map.jsonl'
    & .\windows-acl-map.exe $env:TEMP $MapOutput 0; Check-Exit 'Windows native mapper run'
    $MapRecords = @(Get-Content -LiteralPath $MapOutput | ForEach-Object { $_ | ConvertFrom-Json })
    if ($MapRecords.Count -lt 100) { throw "Windows native mapper produced only $($MapRecords.Count) records" }
} finally { Pop-Location }
Push-Location (Join-Path $Root 'acl')
try {
    & shards check; Check-Exit 'Shards manifest'
    & crystal tool format --check src spec examples; Check-Exit 'Formatting'
    & crystal spec --error-trace --error-on-warnings; Check-Exit 'Specs'
    & crystal build spec/compile/windows_api.cr --error-on-warnings -o (Join-Path $Root 'build/windows-api.exe')
    Check-Exit 'Native Windows API link'
} finally { Pop-Location }
