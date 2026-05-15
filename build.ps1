#requires -Version 7
<#
    Builds Winternal end-to-end.

    The driver requires VS 2022's MSBuild because the WDK 10.0.26100.0 ships
    `Microsoft.DriverKit.Build.Tasks.17.0.dll` (toolset 17.0 = VS 2022). The
    user-mode pieces are built with VS 2026's MSBuild for v145 toolset
    parity. If only VS 2022 is installed, everything is built with it.

    Usage: ./build.ps1 [-Config Release|Debug] [-Platform x64|ARM64]
                       [-Skip cli|core|driver]
#>

[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')]
    [string]$Config = 'Release',
    [ValidateSet('x64','ARM64')]
    [string]$Platform = 'x64',
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Stop'

$msbuild2026 = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
$msbuild2022 = 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
if (-not (Test-Path $msbuild2026)) { $msbuild2026 = $msbuild2022 }
if (-not (Test-Path $msbuild2022)) { throw "VS 2022 MSBuild not found at $msbuild2022 — required for driver build (WDK 17.0 tasks)." }

$root = $PSScriptRoot

# All projects emit their final binaries here. MSBuild requires OutDir to
# have a trailing backslash. Intermediate (.obj/.pdb) files still go to a
# per-project IntDir so they don't collide.
$outDir = Join-Path $root "$Platform\$Config"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Build-Project([string]$ms, [string]$proj, [string]$label) {
    Write-Host ">> Building $label ($Config|$Platform) -> $outDir" -ForegroundColor Cyan
    $projDir = Split-Path -Parent (Join-Path $root $proj)
    $intDir  = Join-Path $projDir "$Platform\$Config\"
    & $ms (Join-Path $root $proj) `
        /p:Configuration=$Config `
        /p:Platform=$Platform `
        /p:OutDir="$outDir\" `
        /p:IntDir="$intDir" `
        /v:m /nologo /m
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $label (exit $LASTEXITCODE)" }
}

if ($Skip -notcontains 'core')   { Build-Project $msbuild2026 'WinternalCore\WinternalCore.vcxproj' 'WinternalCore' }
if ($Skip -notcontains 'cli')    {
    # CLI embeds Lua. Vendor the sources on first build.
    & (Join-Path $root 'tools\fetch-lua.ps1')
    # Regenerate the SDK-derived status-name database (writes only if changed,
    # so this is idempotent — no rebuilds when the SDK hasn't moved).
    & (Join-Path $root 'tools\generate-status-db.ps1')
    # Shield DLL — loaded into every GUI process by `win protect` / `win rule`
    # via SetWindowsHookEx. Built before the CLI so it's present in OutDir
    # alongside Winternal.exe when the install command copies binaries out.
    Build-Project $msbuild2026 'WinternalCLI\WinternalWinShield.vcxproj' 'WinternalWinShield'
    Build-Project $msbuild2026 'WinternalCLI\WinternalCLI.vcxproj'   'WinternalCLI'
}
if ($Skip -notcontains 'driver') { Build-Project $msbuild2022 'Winternal\Winternal.vcxproj'        'Winternal (driver, VS2022 MSBuild)' }

Write-Host "`nArtifacts:" -ForegroundColor Green
Write-Host "  CLI:    $outDir\Winternal.exe"
Write-Host "  Core:   $outDir\WinternalCore.lib"
# The KMDF Driver ConfigurationType packages the .sys into a subfolder named
# after the target. With OutDir overridden, that nests one level inside.
Write-Host "  Driver: $outDir\Winternal\Winternal.sys"
