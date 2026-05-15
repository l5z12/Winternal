#requires -Version 7
<#
    Parses ntstatus.h and winerror.h from the Windows SDK and emits
    WinternalCLI/StatusDb.gen.h with two static tables:

        kNtStatusNames[]    -- every STATUS_* macro -> 32-bit NTSTATUS value
        kWin32ErrorNames[]  -- every ERROR_* macro  -> Win32 decimal code

    The CLI builds a Win32->canonical-NTSTATUS reverse map at startup via
    RtlNtStatusToDosError, so ERROR_* lookups still land on the kernel's
    canonical NTSTATUS rather than the FACILITY_WIN32-encoded form
    HRESULT_FROM_WIN32 would produce.

    Why static at all: there's no Windows API for name -> value lookup
    (these are preprocessor macros, never reified at runtime). The SDK
    headers are the only authoritative source. Regenerate when the SDK
    moves, or when a new status code becomes interesting.

    Usage: tools/generate-status-db.ps1
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $root 'WinternalCLI\StatusDb.gen.h'

function Find-SdkIncludeRoot {
    # Prefer the env var the WDK installer sets. Fall back to the standard
    # install layout and pick the newest 10.0.* SDK present.
    if ($env:WindowsSdkDir -and $env:WindowsSdkVersion) {
        $p = Join-Path $env:WindowsSdkDir "Include\$($env:WindowsSdkVersion.TrimEnd('\'))"
        if (Test-Path $p) { return $p }
    }
    $base = 'C:\Program Files (x86)\Windows Kits\10\Include'
    if (-not (Test-Path $base)) { throw "Windows SDK include root not found at $base" }
    $latest = Get-ChildItem $base -Directory `
        | Where-Object { $_.Name -match '^10\.0\.\d+\.\d+$' } `
        | Sort-Object Name -Descending `
        | Select-Object -First 1
    if (-not $latest) { throw "No 10.0.* SDK under $base" }
    return $latest.FullName
}

$sdkInc = Find-SdkIncludeRoot
Write-Host ">> SDK include root: $sdkInc"

$ntstatusPath = Join-Path $sdkInc 'shared\ntstatus.h'
# winerror.h moved between shared/ and um/ across SDK versions; pick whichever exists.
$winerrorPath = $null
foreach ($cand in @('shared\winerror.h', 'um\winerror.h')) {
    $p = Join-Path $sdkInc $cand
    if (Test-Path $p) { $winerrorPath = $p; break }
}
if (-not (Test-Path $ntstatusPath)) { throw "Missing $ntstatusPath" }
if (-not $winerrorPath) { throw "winerror.h not found under $sdkInc (looked in shared\ and um\)" }

# --- ntstatus.h: lines like
#     #define STATUS_FOO ((NTSTATUS)0xC0000022L)
# or  #define STATUS_FOO ((NTSTATUS)0xC0000022)
# or  #define STATUS_FOO 0xC0000022
$ntStatus = @{}
$ntRe = [regex]'^\s*#define\s+(STATUS_[A-Z0-9_]+)\s+(?:\(\(NTSTATUS\))?0x([0-9A-Fa-f]+)L?\)?\s*(?://.*)?$'
foreach ($line in Get-Content $ntstatusPath) {
    $m = $ntRe.Match($line)
    if ($m.Success) {
        $name  = $m.Groups[1].Value
        $value = [Convert]::ToUInt32($m.Groups[2].Value, 16)
        # ntstatus.h has historical duplicates (severity-class aliases).
        # First spelling wins; SDK orders by canonical name.
        if (-not $ntStatus.ContainsKey($name)) {
            $ntStatus[$name] = $value
        }
    }
}
Write-Host ">> STATUS_*  entries: $($ntStatus.Count)"

# --- winerror.h: lines like
#     #define ERROR_FOO  N[L]
# where N is decimal. Some entries are hex (#define ERROR_FOO 0x...L)
# but the vast majority are decimal Win32 codes.
$win32Err = @{}
$decRe = [regex]'^\s*#define\s+(ERROR_[A-Z0-9_]+)\s+([0-9]+)L?\s*(?://.*)?$'
$hexRe = [regex]'^\s*#define\s+(ERROR_[A-Z0-9_]+)\s+0x([0-9A-Fa-f]+)L?\s*(?://.*)?$'
foreach ($line in Get-Content $winerrorPath) {
    $m = $decRe.Match($line)
    if ($m.Success) {
        $name  = $m.Groups[1].Value
        $value = [Convert]::ToUInt32($m.Groups[2].Value, 10)
        if (-not $win32Err.ContainsKey($name)) { $win32Err[$name] = $value }
        continue
    }
    $m = $hexRe.Match($line)
    if ($m.Success) {
        $name  = $m.Groups[1].Value
        $value = [Convert]::ToUInt32($m.Groups[2].Value, 16)
        if (-not $win32Err.ContainsKey($name)) { $win32Err[$name] = $value }
    }
}
Write-Host ">> ERROR_*   entries: $($win32Err.Count)"

# --- Emit StatusDb.gen.h
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('// AUTO-GENERATED. Do not edit by hand.')
[void]$sb.AppendLine('// Regenerate via tools/generate-status-db.ps1.')
[void]$sb.AppendLine('//')
[void]$sb.AppendLine('// Source: <SDK>/shared/ntstatus.h and <SDK>/um/winerror.h')
[void]$sb.AppendLine("// SDK include root used: $sdkInc")
[void]$sb.AppendLine('#pragma once')
[void]$sb.AppendLine('#include <cstdint>')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('namespace winternal_status_db {')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('struct NamedCode { const wchar_t* name; uint32_t value; };')
[void]$sb.AppendLine('')

[void]$sb.AppendLine('// NTSTATUS -- value is the 32-bit NTSTATUS verbatim.')
[void]$sb.AppendLine('inline constexpr NamedCode kNtStatusNames[] = {')
foreach ($k in ($ntStatus.Keys | Sort-Object)) {
    [void]$sb.AppendFormat("    {{ L""{0}"", 0x{1:X8}u }},`n", $k, $ntStatus[$k])
}
[void]$sb.AppendLine('};')
[void]$sb.AppendLine("inline constexpr size_t kNtStatusNamesCount = sizeof(kNtStatusNames)/sizeof(kNtStatusNames[0]);")
[void]$sb.AppendLine('')

[void]$sb.AppendLine('// Win32 ERROR_* -- value is the decimal Win32 code. At runtime the CLI')
[void]$sb.AppendLine('// runs each STATUS through RtlNtStatusToDosError to build a Win32->NTSTATUS')
[void]$sb.AppendLine('// reverse map, so ERROR_* lookups resolve to the kernel-canonical NTSTATUS.')
[void]$sb.AppendLine('inline constexpr NamedCode kWin32ErrorNames[] = {')
foreach ($k in ($win32Err.Keys | Sort-Object)) {
    [void]$sb.AppendFormat("    {{ L""{0}"", {1}u }},`n", $k, $win32Err[$k])
}
[void]$sb.AppendLine('};')
[void]$sb.AppendLine("inline constexpr size_t kWin32ErrorNamesCount = sizeof(kWin32ErrorNames)/sizeof(kWin32ErrorNames[0]);")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('} // namespace winternal_status_db')

# Write only if changed so MSBuild doesn't rebuild WinternalCLI every time.
$new = $sb.ToString()
$writeIt = $true
if (Test-Path $outPath) {
    $old = Get-Content $outPath -Raw
    if ($old -eq $new) { $writeIt = $false }
}
if ($writeIt) {
    [System.IO.File]::WriteAllText($outPath, $new, [System.Text.UTF8Encoding]::new($false))
    Write-Host ">> Wrote $outPath"
} else {
    Write-Host ">> $outPath up-to-date"
}
