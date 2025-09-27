<#
.SYNOPSIS
  Scan for postmark-mcp occurrences and optionally uninstall them.

.DESCRIPTION
  - Searches recursively for occurrences of "postmark-mcp" in package*.json and lockfiles.
  - Finds installed copies under node_modules (*/node_modules/postmark-mcp).
  - Reports paths and discovered versions (if package.json present).
  - If -AutoUninstall is used, attempts to run `npm uninstall postmark-mcp` in the project directory and `npm uninstall -g postmark-mcp` for global installs.
  - If -AutoUninstall is not used, prompts for confirmation before uninstalling each hit.

.PARAMETER Path
  Root path to scan. Defaults to current directory.

.PARAMETER AutoUninstall
  If present, performs uninstall operations automatically (no per-item prompt).

.EXAMPLE
  .\scan_postmark_mcp.ps1 -Path C:\Projects
  .\scan_postmark_mcp.ps1 -AutoUninstall
#>

param(
  [string]$Path = ".",
  [switch]$AutoUninstall
)

function Ensure-Npm {
  try {
    $npm = & npm --version 2>$null
    if ($LASTEXITCODE -ne 0) { throw "npm not found or not in PATH." }
    return $true
  } catch {
    Write-Warning "npm is not available in PATH. Install Node.js / npm or run this from a machine with npm."
    return $false
  }
}

function Report-And-Uninstall($projectDir, $foundPath, $version) {
  $rel = (Resolve-Path $projectDir).Path
  Write-Host "FOUND: $foundPath  (project root: $rel)  version: $version" -ForegroundColor Yellow

  if (-not (Ensure-Npm)) { return }

  $doIt = $AutoUninstall.IsPresent
  if (-not $doIt) {
    $answer = Read-Host "Uninstall postmark-mcp from $rel? (y/N)"
    $doIt = $answer -match '^(y|yes)$'
  }

  if ($doIt) {
    Write-Host " -> Running: npm uninstall postmark-mcp (in $rel)"
    try {
      Push-Location $rel
      & npm uninstall postmark-mcp 2>&1 | Write-Host
      Pop-Location
      # also attempt to remove node_modules/postmark-mcp folder if it still exists
      $nmPath = Join-Path $rel "node_modules\postmark-mcp"
      if (Test-Path $nmPath) {
        Write-Host " -> Removing leftover folder: $nmPath"
        Remove-Item -Recurse -Force $nmPath -ErrorAction SilentlyContinue
      }
      Write-Host " -> Uninstall attempt finished for $rel" -ForegroundColor Green
    } catch {
      Write-Warning "Uninstall failed for $rel. Error: $_"
      if (Test-Path $rel) { Pop-Location 2>$null }
    }
  } else {
    Write-Host " -> Skipping uninstall for $rel (user chose no)." -ForegroundColor Cyan
  }
}

Write-Host "Scanning for postmark-mcp under: $Path" -ForegroundColor Cyan

# 1) Search package*.json and lockfiles for literal mentions
$packageFiles = Get-ChildItem -Path $Path -Recurse -Include package.json, package*.json, package-lock.json, npm-shrinkwrap.json -File -ErrorAction SilentlyContinue

$hits = @()
foreach ($f in $packageFiles) {
  try {
    $content = Get-Content -Raw -Encoding UTF8 $f.FullName -ErrorAction SilentlyContinue
    if ($content -match "postmark-mcp") {
      # try to extract version if present in JSON
      $version = "unknown"
      try {
        $json = $null
        $json = $content | ConvertFrom-Json -ErrorAction Stop
        if ($json -ne $null) {
          foreach ($k in "dependencies","devDependencies","peerDependencies","optionalDependencies") {
            if ($json.PSObject.Properties.Name -contains $k) {
              $deps = $json.$k
              if ($deps -and $deps["postmark-mcp"]) { $version = $deps["postmark-mcp"] }
            }
          }
        }
      } catch { $version = "unknown" }
      $hits += [PSCustomObject]@{ Path = $f.FullName; Type = "manifest/lockfile"; Version = $version }
    }
  } catch { }
}

# 2) Check node_modules folders for installed copies
$nmDirs = Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue |
          Where-Object { $_.FullName -like "*\node_modules\postmark-mcp" -or $_.FullName -like "*/node_modules/postmark-mcp" }

foreach ($d in $nmDirs) {
  $pkg = Join-Path $d.FullName "package.json"
  $ver = "unknown"
  if (Test-Path $pkg) {
    try {
      $pj = Get-Content $pkg -Raw | ConvertFrom-Json
      $ver = $pj.version
    } catch { $ver = "unknown" }
  }
  $projectRoot = ($d.FullName -replace "(.*)(\\|/)node_modules\\postmark-mcp$",'$1')
  $hits += [PSCustomObject]@{ Path = $d.FullName; Type = "node_modules"; Version = $ver; ProjectRoot = $projectRoot }
}

# 3) Print findings
if ($hits.Count -eq 0) {
  Write-Host "No occurrences of postmark-mcp found under: $Path" -ForegroundColor Green
} else {
  Write-Host "Occurrences found:" -ForegroundColor Yellow
  foreach ($h in $hits) {
    if ($h.Type -eq "node_modules") {
      Write-Host " - [node_modules] $($h.Path)  version: $($h.Version)"
    } else {
      Write-Host " - [$($h.Type)] $($h.Path)  version: $($h.Version)"
    }
  }

  # Offer uninstall per project for node_modules hits and manifest hits within a project
  # Collect unique project roots to run npm uninstall inside
  $projectRoots = @()
  foreach ($h in $hits) {
    if ($h.ProjectRoot) { $projectRoots += $h.ProjectRoot }
    else { $projectRoots += (Split-Path $h.Path -Parent) }
  }
  $projectRoots = $projectRoots | Sort-Object -Unique

  foreach ($proj in $projectRoots) {
    $ver = ($hits | Where-Object { ($_.ProjectRoot -eq $proj) -or (Split-Path $_.Path -Parent -eq $proj) } | Select-Object -First 1).Version
    Report-And-Uninstall -projectDir $proj -foundPath $proj -version $ver
  }

  # Also check and uninstall global copy if present
  if (Ensure-Npm) {
    try {
      $globalCheck = & npm ls -g postmark-mcp --depth=0 2>$null
      if ($globalCheck -and $globalCheck -match "postmark-mcp@") {
        Write-Host "`nGlobal postmark-mcp appears installed. Attempt global uninstall?" -ForegroundColor Yellow
        $doGlobal = $AutoUninstall.IsPresent
        if (-not $doGlobal) {
          $ans = Read-Host "Uninstall global postmark-mcp? (y/N)"
          $doGlobal = $ans -match '^(y|yes)$'
        }
        if ($doGlobal) {
          Write-Host " -> Running: npm uninstall -g postmark-mcp"
          & npm uninstall -g postmark-mcp 2>&1 | Write-Host
          Write-Host " -> Global uninstall attempt complete." -ForegroundColor Green
        } else {
          Write-Host " -> Skipping global uninstall." -ForegroundColor Cyan
        }
      } else {
        Write-Host "No global installation of postmark-mcp detected."
      }
    } catch { Write-Warning "Failed to check global npm packages." }
  }
}

Write-Host "`nScan complete." -ForegroundColor Cyan
