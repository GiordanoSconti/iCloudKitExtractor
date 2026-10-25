param(
    [int]$TcpPort = 6971,
    [int]$HttpPort = 6970,
    [string]$TcpBind = "0.0.0.0",
    [string]$HttpBind = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root "src\AnisetteBridge.Server\AnisetteBridge.Server.csproj"
$tokenFile = Join-Path $env:APPDATA "iCloudKitExtractor\bridge-token.txt"

if (-not (Test-Path $tokenFile)) {
    $token = [guid]::NewGuid().ToString("N")
    $dir = Split-Path $tokenFile -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path $tokenFile -Value $token -NoNewline -Encoding ASCII
    Write-Host "Token bridge creato: $tokenFile"
    Write-Host "Copia lo stesso token sul Mac (ANISETTE_BRIDGE_TOKEN)."
}

$token = Get-Content $tokenFile -Raw
$env:ANISETTE_BRIDGE_TOKEN = $token.Trim()
$env:ANISETTE_BRIDGE_TCP_PORT = "$TcpPort"
$env:ANISETTE_BRIDGE_HTTP_PORT = "$HttpPort"
$env:ANISETTE_BRIDGE_TCP_BIND = $TcpBind
$env:ANISETTE_BRIDGE_HTTP_BIND = $HttpBind

Write-Host ""
Write-Host "=== AnisetteBridge SERVER ==="
Write-Host "  Port-forward router: TCP $TcpPort -> questo PC"
Write-Host "  Client Mac -> IP_PUBBLICO:$TcpPort"
Write-Host "  App locale: http://${HttpBind}:$HttpPort/"
Write-Host "  Token: $($token.Substring(0, [Math]::Min(8, $token.Length)))..."
Write-Host ""

dotnet run --project $project -c Release
