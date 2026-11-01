#Requires -Version 5.1
<#
.SYNOPSIS
  Append SHA-256 checksums to GitHub release notes (and upload HASHES.sha256).

.DESCRIPTION
  Uses `gh` + asset digests from the GitHub API (no re-download needed when
  digests are present). Skips releases that already have a "### SHA-256" section
  unless -Force is set.

.PARAMETER Repo
  owner/name (default: current gh repo).

.PARAMETER Tag
  Optional single tag. Default: all releases.

.PARAMETER Force
  Rewrite the SHA-256 section even if already present.

.PARAMETER UploadSums
  Also upload / replace HASHES.sha256 as a release asset.
#>
param(
  [string] $Repo = "",
  [string] $Tag = "",
  [switch] $Force,
  [switch] $UploadSums
)

$ErrorActionPreference = "Stop"

$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) {
  $candidate = Join-Path ${env:ProgramFiles} "GitHub CLI\gh.exe"
  if (Test-Path $candidate) {
    $env:Path = "$(Split-Path $candidate);$env:Path"
  }
  else {
    throw "gh CLI not found. Install GitHub CLI and run: gh auth login"
  }
}

if (-not $Repo) {
  $resolved = & gh repo view --json nameWithOwner -q .nameWithOwner 2>$null
  if ($resolved) { $Repo = $resolved.Trim() }
  if (-not $Repo) {
    $Repo = "GiordanoSconti/iCloudKitExtractor"
    Write-Host "Using default repo: $Repo"
  }
}

Write-Host "Repo: $Repo"

$releasesJson = & gh api "repos/$Repo/releases?per_page=100"
$releases = $releasesJson | ConvertFrom-Json
if ($Tag) {
  $releases = @($releases | Where-Object { $_.tag_name -eq $Tag })
  if ($releases.Count -eq 0) { throw "Release not found: $Tag" }
}

function Build-Sha256Section([object[]] $assets) {
  $rows = New-Object System.Collections.Generic.List[string]
  $gnu = New-Object System.Collections.Generic.List[string]
  foreach ($a in ($assets | Sort-Object name)) {
    if ($a.name -eq "HASHES.sha256") { continue }
    $digest = [string]$a.digest
    if (-not $digest -or -not $digest.StartsWith("sha256:")) {
      throw "Missing sha256 digest for asset $($a.name) (tag asset may predate digests)."
    }
    $hex = $digest.Substring(7).ToLowerInvariant()
    $rows.Add("| ``$($a.name)`` | ``$hex`` |")
    $gnu.Add("$hex  $($a.name)")
  }
  if ($rows.Count -eq 0) { throw "No hashable assets." }

  $md = @"
### SHA-256

| File | SHA-256 |
|------|--------|
$($rows -join "`n")
"@
  return @{
    Markdown = $md.TrimEnd() + "`n"
    Gnu      = (($gnu -join "`n") + "`n")
  }
}

function Strip-Sha256Section([string] $body) {
  if (-not $body) { return "" }
  # Remove prior ### SHA-256 section through next ### heading or EOF
  return [regex]::Replace(
    $body,
    "(?ms)^### SHA-256\s*\r?\n.*?(?=^### |\z)",
    "").TrimEnd() + "`n"
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ike-release-sha256-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpRoot | Out-Null

try {
  foreach ($r in $releases) {
    $tag = $r.tag_name
    Write-Host ""
    Write-Host "==> $tag"

    $built = Build-Sha256Section @($r.assets)
    $body = [string]$r.body
    if (-not $Force -and $body -match '(?m)^### SHA-256\s*$') {
      Write-Host "  skip (already has ### SHA-256); use -Force to rewrite"
    }
    else {
      $clean = Strip-Sha256Section $body
      $newBody = ($clean.TrimEnd() + "`n`n" + $built.Markdown).TrimEnd() + "`n"
      $notesFile = Join-Path $tmpRoot ("notes-" + ($tag -replace '[^\w\.-]', '_') + ".md")
      [System.IO.File]::WriteAllText($notesFile, $newBody, [System.Text.UTF8Encoding]::new($false))
      & gh release edit $tag --repo $Repo --notes-file $notesFile
      if ($LASTEXITCODE -ne 0) { throw "gh release edit failed for $tag" }
      Write-Host "  notes updated"
    }

    if ($UploadSums) {
      $sumDir = Join-Path $tmpRoot ($tag -replace '[^\w\.-]', '_')
      New-Item -ItemType Directory -Force -Path $sumDir | Out-Null
      $sumFile = Join-Path $sumDir "HASHES.sha256"
      [System.IO.File]::WriteAllText($sumFile, $built.Gnu, [System.Text.UTF8Encoding]::new($false))
      # clobber if re-running (asset name = basename)
      & gh release upload $tag $sumFile --repo $Repo --clobber
      if ($LASTEXITCODE -ne 0) { throw "gh release upload failed for $tag" }
      Write-Host "  uploaded HASHES.sha256"
    }
  }
}
finally {
  Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Done."
