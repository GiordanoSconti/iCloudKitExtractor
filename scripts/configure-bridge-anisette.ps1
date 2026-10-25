param(
    [int]$HttpPort = 6970,

    [ValidateSet("iphone", "hybrid")]
    [string]$AuthMode = "iphone",

    [switch]$TestOnly
)

$ErrorActionPreference = "Stop"
$url = "http://127.0.0.1:${HttpPort}/"
$settingsPath = Join-Path $env:APPDATA "iCloudKitExtractor\anisette.json"

Write-Host "Test bridge HTTP: $url"
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:${HttpPort}/health" -TimeoutSec 10
    if (-not $health.clientConnected) {
        throw "Bridge attivo ma nessun client Mac connesso. Avvia il client sul Mac."
    }
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 35
    $json = $response.Content | ConvertFrom-Json
    $mdM = $json.'X-Apple-I-MD-M'
    if (-not $mdM) { throw "Risposta senza X-Apple-I-MD-M" }
    $preview = $mdM.Substring(0, [Math]::Min(20, $mdM.Length))
    Write-Host "OK - client Mac connesso, MD-M: ${preview}..."
}
catch {
    Write-Host ""
    Write-Host "Bridge non pronto: $_" -ForegroundColor Red
    Write-Host "1. Avvia: .\scripts\start-anisette-bridge-server.ps1"
    Write-Host "2. Port-forward TCP 6971 sul router"
    Write-Host "3. Sul Mac: ./start-anisette-bridge-client.sh"
    exit 1
}

if ($TestOnly) { return }

$dir = Split-Path $settingsPath -Parent
New-Item -ItemType Directory -Force -Path $dir | Out-Null
@{
    serverUrl = $url.TrimEnd('/')
    authMode  = $AuthMode
} | ConvertTo-Json | Set-Content -Path $settingsPath -Encoding UTF8

Write-Host ""
Write-Host "Scritto: $settingsPath"
Write-Host "authMode=$AuthMode - avvia iCloudKitExtractor (nessun Anisette su Windows)."
