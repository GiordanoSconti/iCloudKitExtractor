# Avvia stack akd emulato: ADI worker (6973) + AnisetteServer (6971).
# Nessun CoreADI64.dll, nessun Mac remoto.
param(
    [int]$AnisettePort = 6971,
    [int]$AdiWorkerPort = 6973,
    [string]$HostName = '127.0.0.1',
    # iphone-coherent (default, cpd minimale + Client-Info iPhone) | provision (Mac/Xcode) | akd (EPB pieno)
    [ValidateSet('akd', 'provision', 'iphone-coherent')]
    [string]$IdentityMode = 'iphone-coherent'
)

$ErrorActionPreference = 'Stop'
$env:AKD_IDENTITY_MODE = $IdentityMode
$repoRoot = Split-Path -Parent $PSScriptRoot
$workerScript = Join-Path $repoRoot 'scripts\akd-adi-worker\akd_adi_worker.py'
$serverProject = Join-Path $repoRoot 'src\AnisetteServer\AnisetteServer.csproj'

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error 'Python richiesto (pip install -r scripts\akd-adi-worker\requirements.txt)'
}

$reqFile = Join-Path $repoRoot 'scripts\akd-adi-worker\requirements.txt'
if (Test-Path $reqFile) {
    # pip scrive notice/upgrade su stderr: con $ErrorActionPreference=Stop
    # PowerShell lo tratta come NativeCommandError anche se exit code=0.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & python -m pip install -q -r $reqFile 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "pip install fallito (exit $LASTEXITCODE): $reqFile"
        }
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
}

Write-Host '=== akd emulato (split C# MidService + worker ADI) ===' -ForegroundColor Cyan
Write-Host 'Vedi docs/EMULATED_AKD.md'
Write-Host ('Identity mode: {0}' -f $IdentityMode) -ForegroundColor Cyan
if ($IdentityMode -ne 'akd') {
    Write-Host ('TEST: identita {0} + ADI Android.' -f $IdentityMode) -ForegroundColor Yellow
    Write-Host ('Ricorda: nella shell della GUI esegui  $env:AKD_IDENTITY_MODE=''{0}''' -f $IdentityMode) -ForegroundColor Yellow
}
Write-Host ''
Write-Host ('Avvio ADI worker su :{0} ...' -f $AdiWorkerPort)
# EPB RealMobile: MD trailer u32be=3 (Android nativo=4). Override: AKD_FORCE_OTP_TRAILER=native
if (-not $env:AKD_FORCE_OTP_TRAILER) {
    $env:AKD_FORCE_OTP_TRAILER = '3'
}
Write-Host ('OTP trailer: {0} (EPB align)' -f $env:AKD_FORCE_OTP_TRAILER) -ForegroundColor Cyan
$workerJob = Start-Job -ScriptBlock {
    param($script, $port, $identityMode, $otpTrailer)
    $env:AKD_IDENTITY_MODE = $identityMode
    $env:AKD_FORCE_OTP_TRAILER = $otpTrailer
    python $script --port $port --backend android
} -ArgumentList $workerScript, $AdiWorkerPort, $IdentityMode, $env:AKD_FORCE_OTP_TRAILER

Start-Sleep -Seconds 2
$workerHealthy = $false
try {
    $healthUrl = 'http://{0}:{1}/health' -f $HostName, $AdiWorkerPort
    Invoke-RestMethod $healthUrl -TimeoutSec 5 | Out-Null
    $workerHealthy = $true
    Write-Host 'ADI worker OK' -ForegroundColor Green
}
catch {
    Write-Host 'ADI worker non risponde - controlla: python -m pip install anisette' -ForegroundColor Yellow
}

if ($workerHealthy) {
    try {
        $bridgeUrl = 'http://{0}:{1}/v1/bridge' -f $HostName, $AdiWorkerPort
        $probe = '{"command":"is-provisioned","adi_id":"probe","dsid":"-2"}'
        Invoke-RestMethod $bridgeUrl -Method POST -Body $probe -ContentType 'application/json' -TimeoutSec 30 | Out-Null
    }
    catch {
        Write-Host 'Bridge ADI fallito - reset libs worker...' -ForegroundColor Yellow
        try {
            $provisionUrl = 'http://{0}:{1}/provision' -f $HostName, $AdiWorkerPort
            Invoke-RestMethod $provisionUrl -Method POST -TimeoutSec 10 | Out-Null
        }
        catch {
            # worker spento o gia resettato
        }
    }
}

$env:AKD_ADI_WORKER_URL = 'http://{0}:{1}' -f $HostName, $AdiWorkerPort
$env:ANISETTE_SERVER_BACKEND = 'akd-emulated'
$env:ANISETTE_SERVER_PORT = [string]$AnisettePort

Write-Host ('Avvio AnisetteServer akd-emulated su :{0} ...' -f $AnisettePort)
Write-Host ('Configura: .\scripts\configure-emulated-ios-anisette.ps1 -Port {0}' -f $AnisettePort)
Write-Host ''

try {
    dotnet run --project $serverProject -c Release -- --port $AnisettePort
}
finally {
    Stop-Job $workerJob -ErrorAction SilentlyContinue
    Remove-Job $workerJob -ErrorAction SilentlyContinue
}
