#requires -Version 7
<#
    Creates a self-signed code-signing certificate named "WinternalTestCert"
    and installs it in CurrentUser\My. The WDK driver build picks it up
    automatically when SignMode=TestSign. Idempotent: rerunning re-uses the
    existing cert if it's still valid.

    Run from an elevated prompt only if you want the cert in LocalMachine
    stores (TrustedPublisher / Root). Regular use only needs CurrentUser\My.
#>

[CmdletBinding()]
param(
    [string]$Subject = 'CN=WinternalTestCert',
    [int]$YearsValid = 3,
    [switch]$InstallTrusted
)

$ErrorActionPreference = 'Stop'

$existing = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($existing) {
    Write-Host ">> Reusing existing cert $($existing.Thumbprint) (valid until $($existing.NotAfter))" -ForegroundColor DarkGray
    $cert = $existing
} else {
    Write-Host ">> Creating new self-signed code-signing cert $Subject" -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -Type CodeSigningCert `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears($YearsValid)
}

Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Subject:    $($cert.Subject)"
Write-Host "NotAfter:   $($cert.NotAfter)"

if ($InstallTrusted) {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-InstallTrusted requires an elevated prompt."
    }
    Write-Host ">> Installing into TrustedPublisher + Root (LocalMachine)" -ForegroundColor Cyan
    $exportPath = Join-Path $env:TEMP "$($cert.Thumbprint).cer"
    Export-Certificate -Cert $cert -FilePath $exportPath -Type CERT | Out-Null
    Import-Certificate -FilePath $exportPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    Import-Certificate -FilePath $exportPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Remove-Item $exportPath -Force
    Write-Host ">> Installed. The driver will load on this machine under bcdedit /set testsigning on." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "To make the driver load on this machine, run this script once from an" -ForegroundColor Yellow
    Write-Host "elevated prompt with -InstallTrusted. Then enable test signing:" -ForegroundColor Yellow
    Write-Host "    bcdedit /set testsigning on  (reboot required)" -ForegroundColor Yellow
}
