#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stop, remove, and uninstall the SystemFileKiller helper service.
#>
[CmdletBinding()]
param(
    [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"
$serviceName = "SystemFileKiller"
$installDir  = Join-Path $env:ProgramFiles "SFK"

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Write-Host "[*] Stopping $serviceName"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[*] Deleting service $serviceName"
    & sc.exe delete $serviceName | Out-Null
} else {
    Write-Host "[!] Service '$serviceName' not installed — nothing to remove"
}

if (-not $KeepFiles -and (Test-Path $installDir)) {
    Write-Host "[*] Removing $installDir"
    Remove-Item -Recurse -Force $installDir
}

Write-Host "[+] Uninstall complete."
