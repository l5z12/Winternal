#requires -Version 7
<#
    Downloads Lua 5.4.7 source into WinternalCLI/lua/ on first build.
    Idempotent: if WinternalCLI/lua/src/lua.h already exists, exits silently.

    The Lua project is MIT-licensed; we keep the upstream archive's LICENSE
    file alongside the sources. No code is modified — the CLI vcxproj just
    compiles src\*.c minus lua.c (interpreter main) and luac.c (compiler main),
    which we replace with our own entry that exposes the Winternal bindings.
#>

[CmdletBinding()]
param(
    [string]$Version = '5.4.7',
    [string]$DestDir = (Join-Path $PSScriptRoot '..\WinternalCLI\lua')
)

$ErrorActionPreference = 'Stop'

$DestDir = [IO.Path]::GetFullPath($DestDir)
$marker  = Join-Path $DestDir 'src\lua.h'
if (Test-Path $marker) {
    Write-Host ">> Lua $Version already present at $DestDir" -ForegroundColor DarkGray
    return
}

$url  = "https://www.lua.org/ftp/lua-$Version.tar.gz"
$tmp  = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ("lua-" + [Guid]::NewGuid())) -Force
$gz   = Join-Path $tmp.FullName "lua-$Version.tar.gz"

Write-Host ">> Downloading $url" -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $gz -UseBasicParsing

Write-Host ">> Extracting" -ForegroundColor Cyan
# tar is built-in on Win10+.
& tar.exe -xzf $gz -C $tmp.FullName
if ($LASTEXITCODE -ne 0) { throw "tar extraction failed (exit $LASTEXITCODE)" }

$extracted = Join-Path $tmp.FullName "lua-$Version"
if (-not (Test-Path $extracted)) { throw "Expected $extracted after extraction" }

if (-not (Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir | Out-Null }

# Copy src/ and doc license verbatim.
Copy-Item (Join-Path $extracted 'src') -Destination $DestDir -Recurse -Force
$readme = Join-Path $extracted 'README'
if (Test-Path $readme) { Copy-Item $readme (Join-Path $DestDir 'README') -Force }
$doc = Join-Path $extracted 'doc'
if (Test-Path $doc) {
    $licDest = Join-Path $DestDir 'doc'
    if (-not (Test-Path $licDest)) { New-Item -ItemType Directory -Path $licDest | Out-Null }
    Get-ChildItem $doc -Filter 'readme.html' -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $licDest $_.Name) -Force }
}

Remove-Item $tmp.FullName -Recurse -Force
Write-Host ">> Lua $Version installed at $DestDir" -ForegroundColor Green
