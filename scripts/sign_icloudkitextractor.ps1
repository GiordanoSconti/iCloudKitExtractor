# Signs iCloudKitExtractor Release output with a local ForensisLab code-signing certificate.
# Self-signed: after -TrustLocally once (Root + TrustedPublisher), Smart App Control / CI
# can accept local lab builds. Does NOT replace EV/OV Authenticode for public releases
# (use scripts/sign-release.ps1 + Azure Trusted Signing for that).
param(
    [string]$OutputDir = "",
    [string]$ExePath = "",
    [switch]$TrustLocally
)

$ErrorActionPreference = "Stop"
$CertSubject = "CN=ForensisLab iCloudKitExtractor"
$CertFriendly = "ForensisLab-IKE-CodeSign"

function Get-OrCreateCert {
    $existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
    if ($existing) { return $existing }

    Write-Host "Creating local code-signing certificate: $CertSubject"
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertSubject `
        -FriendlyName $CertFriendly `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(5)
}

function Trust-Cert([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
    foreach ($storeName in @("TrustedPublisher", "Root")) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
        $store.Open("ReadWrite")
        try {
            $have = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            if (-not $have) {
                $store.Add($cert)
                Write-Host "Trusted in CurrentUser\$storeName ($($cert.Thumbprint))"
            }
        }
        finally {
            $store.Close()
        }
    }
}

function Sign-File([string]$path, $cert) {
    if (-not (Test-Path $path)) { return }
    # Skip already valid signatures from the same cert
    $cur = Get-AuthenticodeSignature -FilePath $path
    if ($cur.Status -eq "Valid" -and $cur.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
        Write-Host ("{0}: already Valid" -f (Split-Path $path -Leaf))
        return
    }

    $sig = Set-AuthenticodeSignature -FilePath $path -Certificate $cert `
        -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256
    Write-Host ("{0}: {1}" -f (Split-Path $path -Leaf), $sig.Status)
    if ($sig.Status -notin @("Valid", "UnknownError")) {
        $sig2 = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256
        Write-Host ("{0} (no timestamp): {1}" -f (Split-Path $path -Leaf), $sig2.Status)
    }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDir -and $ExePath) {
    $OutputDir = Split-Path $ExePath -Parent
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "src\iCloudKitExtractor\bin\Release\net10.0-windows"
}

if (-not (Test-Path $OutputDir)) {
    throw "OutputDir not found: $OutputDir (build Release first)"
}

$cert = Get-OrCreateCert
if ($TrustLocally) { Trust-Cert $cert }

# Firmare TUTTI gli .exe/.dll dell'output: SAC/App Control blocca spesso
# dipendenze non firmate (BouncyCastle.Cryptography, SQLite, PhotosViewer, …).
$toSign = @(Get-ChildItem $OutputDir -Recurse -File -Include *.exe,*.dll -ErrorAction SilentlyContinue)
$toSign = $toSign | Where-Object { $_ -ne $null } | Sort-Object FullName -Unique
if ($toSign.Count -eq 0) {
    throw "No iCloudKitExtractor binaries to sign in $OutputDir"
}

foreach ($f in $toSign) {
    Sign-File $f.FullName $cert
}

Write-Host ""
Write-Host "Signed with: $CertSubject"
Write-Host "Thumbprint:  $($cert.Thumbprint)"
Write-Host "OutputDir:   $OutputDir"
Write-Host "First run: ensure -TrustLocally (csproj does this on Release builds)."
