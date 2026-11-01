#Requires -Version 5.1
<#
.SYNOPSIS
  Write SHA-256 checksums for release zip archives (GNU coreutils style).

.DESCRIPTION
  For each file in -Path (or each *.zip in -Dir), writes:
    - HASHES.sha256 next to the first file / in -Dir
    - prints a Markdown "### SHA-256" table suitable for GitHub release notes

.PARAMETER Path
  One or more archive/file paths to hash.

.PARAMETER Dir
  Directory of *.zip archives (ignored if -Path is set).

.PARAMETER OutFile
  Optional explicit path for HASHES.sha256 (default: next to inputs).
#>
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $Path,

  [string] $Dir,

  [string] $OutFile
)

$ErrorActionPreference = "Stop"

$files = @()
if ($Path -and $Path.Count -gt 0) {
  foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
      throw "File not found: $p"
    }
    $files += (Get-Item -LiteralPath $p)
  }
}
elseif ($Dir) {
  if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
    throw "Dir not found: $Dir"
  }
  $files = @(Get-ChildItem -LiteralPath $Dir -Filter *.zip -File | Sort-Object Name)
}
else {
  throw "Specify -Path <files...> or -Dir <folder>"
}

if ($files.Count -eq 0) { throw "No files to hash." }

$lines = New-Object System.Collections.Generic.List[string]
$mdRows = New-Object System.Collections.Generic.List[string]

foreach ($f in $files) {
  $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  $lines.Add("$hash  $($f.Name)")
  $mdRows.Add("| ``$($f.Name)`` | ``$hash`` |")
  Write-Host ("{0}  {1}" -f $hash, $f.Name)
}

if (-not $OutFile) {
  $OutFile = Join-Path $files[0].DirectoryName "HASHES.sha256"
}

[System.IO.File]::WriteAllText(
  $OutFile,
  (($lines -join "`n") + "`n"),
  [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Wrote $OutFile"
Write-Host ""
Write-Host "### SHA-256"
Write-Host ""
Write-Host "| File | SHA-256 |"
Write-Host "|------|--------|"
foreach ($row in $mdRows) { Write-Host $row }
