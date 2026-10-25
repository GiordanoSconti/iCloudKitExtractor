#Requires -Version 5.1
<#
.SYNOPSIS
  Authenticode-sign a publish folder with Forensis-Lab Azure Trusted Signing (PublicTrust).

.DESCRIPTION
  Uses the local Azure CLI login (az login) + Artifact Signing dlib.
  Default metadata matches Desktop\TOOL FIRMA APPLICAZIONI\metadata.json
  (account Forensis-Lab-Sviluppo / profile PublicCertificateForensis-Lab).

.PARAMETER PublishDir
  Folder containing the published .exe/.dll to sign.

.PARAMETER MetadataPath
  Path to Trusted Signing metadata.json.
#>
param(
  [Parameter(Mandatory = $true)]
  [string] $PublishDir,

  [string] $MetadataPath = (Join-Path $env:USERPROFILE "Desktop\TOOL FIRMA APPLICAZIONI\metadata.json"),

  [string] $DlibPath = (Join-Path $env:USERPROFILE ".nuget\packages\microsoft.artifactsigning.client\1.0.128\bin\x64\Azure.CodeSigning.Dlib.dll"),

  [string] $SignTool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",

  [string] $TimestampUrl = "http://timestamp.acs.microsoft.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PublishDir)) { throw "PublishDir not found: $PublishDir" }
if (-not (Test-Path $MetadataPath)) { throw "Metadata not found: $MetadataPath" }
if (-not (Test-Path $DlibPath)) { throw "Dlib not found: $DlibPath (install NuGet Microsoft.ArtifactSigning.Client)" }
if (-not (Test-Path $SignTool)) { throw "signtool not found: $SignTool" }

$who = az account show --query user.name -o tsv 2>$null
if (-not $who) { throw "Azure CLI is not logged in. Run: az login" }
Write-Host "Trusted Signing as $who"

Get-ChildItem $PublishDir -Recurse -Include *.exe, *.dll | ForEach-Object {
  Write-Host "SIGN $($_.Name)"
  & $SignTool sign /fd SHA256 /tr $TimestampUrl /td SHA256 /dlib $DlibPath /dmdf $MetadataPath $_.FullName
  if ($LASTEXITCODE -ne 0) { throw "Sign failed: $($_.FullName)" }
}

Write-Host "Verify:"
Get-ChildItem $PublishDir -Recurse -Include *.exe | ForEach-Object {
  & $SignTool verify /pa $_.FullName
}
