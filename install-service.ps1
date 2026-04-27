#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Build, publish, and install the SystemFileKiller LocalSystem helper service.

.DESCRIPTION
    Publishes SystemFileKiller.Service to "$env:ProgramFiles\SFK" and registers it
    with the SCM as a LocalSystem service. The service listens on \\.\pipe\sfk and
    handles privileged kill / service-stop requests forwarded by the MCP host
    (Stage 4 of the kill ladder).

.PARAMETER StartType
    "Manual" (default) — service is created with start=demand. Flip to "Automatic"
    to start it on boot.

.EXAMPLE
    PS> ./install-service.ps1
    PS> ./install-service.ps1 -StartType Automatic
#>
[CmdletBinding()]
param(
    [ValidateSet("Manual", "Automatic")]
    [string]$StartType = "Manual"
)

$ErrorActionPreference = "Stop"

$root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj        = Join-Path $root "SystemFileKiller.Service\SystemFileKiller.Service.csproj"
$installDir  = Join-Path $env:ProgramFiles "SFK"
$exeName     = "SystemFileKiller.Service.exe"
$serviceName = "SystemFileKiller"
$displayName = "System File Killer Helper"

if (-not (Test-Path $proj)) {
    throw "Project not found: $proj"
}

Write-Host "[*] Publishing $proj -> $installDir"
& dotnet publish $proj -c Release -r win-x64 --self-contained false -o $installDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }

$exePath = Join-Path $installDir $exeName
if (-not (Test-Path $exePath)) {
    throw "Built exe not found at $exePath"
}

# Stop & remove any existing service
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Existing service found ($($existing.Status)) — removing"
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

$scStart = if ($StartType -eq "Automatic") { "auto" } else { "demand" }

Write-Host "[*] Creating service: $serviceName (start=$scStart, account=LocalSystem)"
& sc.exe create $serviceName binPath= "`"$exePath`"" obj= LocalSystem start= $scStart DisplayName= "$displayName" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed (exit $LASTEXITCODE)" }

& sc.exe description $serviceName "LocalSystem helper for SFK privileged kill escalation. Listens on \\.\pipe\sfk." | Out-Null

Write-Host ""
Write-Host "[+] Installed."
Write-Host ""
Write-Host "    Start now:    sc.exe start $serviceName"
Write-Host "    Status:       Get-Service $serviceName"
if ($StartType -eq "Manual") {
    Write-Host "    Auto on boot: ./install-service.ps1 -StartType Automatic"
}
