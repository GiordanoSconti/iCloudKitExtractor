# Attach Frida validation capture to several iOS processes in sequence.
# Usage:
#   .\fetch_ids_validation_multi.ps1 -Host 192.168.1.217:27042
param(
    [Parameter(Mandatory = $true)][string]$Host,
    [int]$Timeout = 120
)

$names = @("identityservicesd", "imagent", "IMTransferAgent", "CommCenter")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

foreach ($n in $names) {
    Write-Host "======== trying -n $n ($Timeout s) ========" -ForegroundColor Cyan
    Write-Host "Toggle iMessage NOW on the phone..." -ForegroundColor Yellow
    python fetch_ids_validation.py -H $Host -n $n --timeout $Timeout
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK captured via $n" -ForegroundColor Green
        exit 0
    }
}

Write-Host "No capture from: $($names -join ', ')" -ForegroundColor Red
exit 1
