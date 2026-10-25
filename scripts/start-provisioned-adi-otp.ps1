# Avvia worker ADI + AnisetteServer akd-emulated usando l'ADI già provisionata
# (device-iphone-coherent.json + libs.bin). OTP fresco = GET / → request-otp.
# MidService solo se non provisionata, o POST /provision?forceMid=1.
param(
    [int]$AnisettePort = 6971,
    [int]$AdiWorkerPort = 6973
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$env:AKD_IDENTITY_MODE = 'iphone-coherent'
$env:ANISETTE_SERVER_BACKEND = 'akd-emulated'
$env:AKD_ADI_WORKER_URL = "http://127.0.0.1:$AdiWorkerPort"
$env:ANISETTE_SERVER_PORT = "$AnisettePort"
$env:ICLOUD_AUTH_MODE = 'iphone'
$env:ANISETTE_SERVER_URL = "http://127.0.0.1:$AnisettePort"
if (-not $env:AKD_FORCE_OTP_TRAILER) { $env:AKD_FORCE_OTP_TRAILER = '3' }
# MidService HTTP in C# (default). Non forzare AKD_OWNS_MIDSERVICE qui.

$adiId = (Get-Content "$env:APPDATA\iCloudKitExtractor\device-iphone-coherent.json" -Raw | ConvertFrom-Json).AdiIdentifier
Write-Host "ADI provisionata: $adiId" -ForegroundColor Cyan
Write-Host "OTP: GET http://127.0.0.1:$AnisettePort/  (request-otp, stesso MD-M)"
Write-Host "MidService soft: POST http://127.0.0.1:$AnisettePort/provision?forceMid=1"

# Libera porte se occupate da sessioni precedenti
foreach ($port in @($AnisettePort, $AdiWorkerPort)) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
    }
}
Start-Sleep -Seconds 1

$workerScript = Join-Path $repoRoot 'scripts\akd-adi-worker\akd_adi_worker.py'
$workerJob = Start-Job -ScriptBlock {
    param($script, $port, $mode, $trailer)
    $env:AKD_IDENTITY_MODE = $mode
    $env:AKD_FORCE_OTP_TRAILER = $trailer
    python $script --port $port --backend android
} -ArgumentList $workerScript, $AdiWorkerPort, $env:AKD_IDENTITY_MODE, $env:AKD_FORCE_OTP_TRAILER

$ok = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    try {
        Invoke-RestMethod "http://127.0.0.1:$AdiWorkerPort/health" -TimeoutSec 2 | Out-Null
        $ok = $true
        break
    } catch {}
}
if (-not $ok) {
    Receive-Job $workerJob
    throw "ADI worker non risponde su :$AdiWorkerPort"
}
Write-Host "ADI worker OK :$AdiWorkerPort" -ForegroundColor Green

# Probe is-provisioned
$probe = @{ command = 'is-provisioned'; adi_id = $adiId; dsid = '-2' } | ConvertTo-Json
try {
    $r = Invoke-RestMethod "http://127.0.0.1:$AdiWorkerPort/v1/bridge" -Method POST -Body $probe -ContentType 'application/json' -TimeoutSec 30
    Write-Host ("is-provisioned: {0}" -f ($r | ConvertTo-Json -Compress))
} catch {
    Write-Host "is-provisioned probe: $($_.Exception.Message)" -ForegroundColor Yellow
}

dotnet build (Join-Path $repoRoot 'src\AnisetteServer\AnisetteServer.csproj') -c Release
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

try {
    dotnet run --project (Join-Path $repoRoot 'src\AnisetteServer\AnisetteServer.csproj') -c Release --no-build -- --port $AnisettePort
}
finally {
    Stop-Job $workerJob -ErrorAction SilentlyContinue
    Remove-Job $workerJob -ErrorAction SilentlyContinue
}
