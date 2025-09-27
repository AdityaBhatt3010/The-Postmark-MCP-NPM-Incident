# The Postmark-MCP NPM Incident: What Happened, Why It Matters, and How to Hunt It Down 🧐📧

**TL;DR status:** If `postmark-mcp@1.0.16` shows up in your environment, treat it as compromised and follow remediation immediately. 🚨

![PostMark-MCP_Cover](https://github.com/user-attachments/assets/992ec22c-b84e-440f-90a4-1099468cb1df) <br/>

---

## Executive summary

On a recent disclosure, a malicious npm package published under the name `postmark-mcp` (an MCP connector for Postmark) contained a backdoor in release **1.0.16** that silently BCC’ed outgoing emails to an attacker-controlled address. The package was removed from the registry after discovery, but installations that already pulled that release can still be exfiltrating data. This is a textbook supply-chain compromise affecting connector tooling — high impact because these libraries handle email (tokens, password resets, invoices). 😬

---

## Quick facts & impact statistics

* **Weekly downloads (npm):** ~**1.5K+** — meaning it was in active developer workflows and could be transitively included in many projects. 📥
* **Estimated impact:** conservative calculations suggest **3,000–15,000 emails** could have been exfiltrated **daily**, originating from roughly **300 organizations** (estimate based on observed integrations and download footprint). These numbers show a potentially large data bleed even from a package with modest download counts. 📈📨
* **Nature of compromise:** silent BCC to attacker-controlled mailbox and exfiltration to attacker domain.
* **Why this is dangerous:** email often carries tokens, credentials, password resets, PII — exfiltrating mail means broad access to sensitive artifacts.

---

## Indicators of Compromise (IOCs)

* **Package:** `postmark-mcp` (npm)
* **Malicious versions:** `1.0.16` **and later (malicious release)**
* **Backdoor email (destination):** `phan@giftshop[.]club`
* **Domain:** `giftshop[.]club`

> If you see traffic to `giftshop.club` or mails forwarded to `phan@giftshop.club`, treat it as highly suspicious. 🔍

---

## Why this attack matters (technical elevator)

MCP connectors are trusted components used by AI/email tooling. They:

1. Handle sensitive mail content (tokens, invoices, internal messages).
2. Are often accepted into projects without deep review.
3. Can exfiltrate large volumes with minimal code changes (one line can BCC everything).
   Result: moderate-download packages can still cause severe breaches.

---

## Defender playbook — what to run now

Below are two practical scanners (Python & PowerShell) to discover `postmark-mcp` occurrences in your codebase or environment. Run them from a workspace root (e.g., `~/Projects`) to identify direct installs, lockfile references, or literal mentions.

> **If you detect version `1.0.16`**: follow remediation checklist below immediately.

---

## Python scanner (save as `scan_postmark_mcp.py`)

Scans recursively for:

* `package-lock.json` / `npm-shrinkwrap.json` dependency trees
* `package.json` entries
* `node_modules/postmark-mcp/package.json` (installed copy)
* Raw file text matches in `.json`, `.js`, `.ts`, `.lock`, `.md`, `.txt`

```python
#!/usr/bin/env python3
"""
scan_postmark_mcp.py
Usage:
  python3 scan_postmark_mcp.py [start_path]

Scans recursively for evidence of "postmark-mcp" and flags version 1.0.16 as compromised.
"""
import sys, os, json, re

START = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
TARGET = "postmark-mcp"
COMPROMISED_VERSION = "1.0.16"
findings = []

def check_package_json_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict) and TARGET in deps:
            version = deps.get(TARGET, "unknown")
            findings.append((path, "package.json-deps", version))

def walk_package_lock(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return
    def walk_deps(deps, trail):
        if not isinstance(deps, dict):
            return
        for name, info in deps.items():
            if name == TARGET:
                version = info.get("version") or info.get("resolved") or "unknown"
                findings.append((path + " -> " + " > ".join(trail + [name]), "package-lock", version))
            if isinstance(info, dict):
                nested = info.get("dependencies") or info.get("requires")
                if nested:
                    walk_deps(nested, trail + [name])
    deps = data.get("dependencies") or {}
    walk_deps(deps, [])

def check_node_module_dir(start_dir):
    nm_path = os.path.join(start_dir, "node_modules", TARGET, "package.json")
    if os.path.exists(nm_path):
        try:
            with open(nm_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            version = data.get("version", "unknown")
        except Exception:
            version = "unknown"
        findings.append((nm_path, "node_modules", version))

def raw_text_check(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception:
        return
    if TARGET in txt:
        m = re.search(r"postmark-mcp[\"']?\s*[:@]?\s*([0-9]+\.[0-9]+\.[0-9]+)", txt)
        version = m.group(1) if m else "unknown"
        findings.append((path, "raw-text", version))

for root, dirs, files in os.walk(START):
    lower_files = set(files)
    if "package-lock.json" in lower_files:
        walk_package_lock(os.path.join(root, "package-lock.json"))
    if "npm-shrinkwrap.json" in lower_files:
        walk_package_lock(os.path.join(root, "npm-shrinkwrap.json"))
    if "package.json" in lower_files:
        check_package_json_file(os.path.join(root, "package.json"))
    check_node_module_dir(root)
    for fname in files:
        if fname.endswith((".json",".js",".ts",".lock",".txt",".md")):
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) <= 1024*1024:
                    raw_text_check(fpath)
            except Exception:
                pass

if not findings:
    print("✅ No evidence of postmark-mcp found under:", START)
else:
    print("⚠️ Findings for postmark-mcp under:", START)
    for path, kind, version in findings:
        compromised = (version == COMPROMISED_VERSION)
        flag = "🚨 COMPROMISED (1.0.16)" if compromised else ""
        print(f" - [{kind}] {path}  — version: {version} {flag}")

if findings:
    print("\nSuggested next steps:")
    print("  1) For each project, npm uninstall postmark-mcp")
    print("  2) For 1.0.16: remove node_modules + package-lock.json and npm install fresh")
    print("  3) Rotate relevant secrets and audit mail logs")
```

**How to run:**

```bash
python3 scan_postmark_mcp.py /path/to/start   # default is current dir
```

OR

```bash
python scan_postmark_mcp.py /path/to/start   # default is current dir
```

<img width="1120" height="188" alt="Python_Screenshot" src="https://github.com/user-attachments/assets/d43ebc13-5ec1-45a5-a9e7-fc4dd32949bf" /> <br/>

---

### Save as `scan_postmark_mcp.ps1`

```powershell
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
```

---

### How to run

**Scan current folder:**

```powershell
.\scan_postmark_mcp.ps1
```

**Scan a specific folder:**

```powershell
.\scan_postmark_mcp.ps1 -Path "C:\Users\Adi\Projects"
```

**Automatically uninstall detected copies without prompts:**

```powershell
.\scan_postmark_mcp.ps1 -Path "C:\Users\Adi\Projects" -AutoUninstall
```

**If execution is blocked:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scan_postmark_mcp.ps1
```

<img width="1119" height="243" alt="Ps1_Screenshot" src="https://github.com/user-attachments/assets/27ca3097-040a-4d23-9413-91b4f7af5afc" />

---

## Remediation checklist (if `1.0.16` is found)

1. **Uninstall**: `npm uninstall postmark-mcp` (for each affected project).
2. **Clean install**: delete `node_modules` + `package-lock.json` and run `npm install` from a trusted lockfile.
3. **Rotate secrets**: Postmark API keys, SMTP credentials, any tokens that might have been sent over email - assume compromise. 🔑
4. **Audit logs**: outbound mail logs (look for unknown BCCs), network logs (connections to `giftshop.club`), and system logs.
5. **Global check**: `npm ls -g postmark-mcp --depth=0` and uninstall global copies.
6. **Incident response**: document, escalate internally, and treat this as a supply-chain security incident. 📝

<img width="3174" height="1662" alt="PostMark-MCP_WorkFlow" src="https://github.com/user-attachments/assets/544bdb34-d17e-4772-8c46-56063ee92056" /> <br/>

---

## Final Thoughts (Attacker + Defender Mental Model)

Small packages that act as connectors are high-value targets. One line of malicious code in an email connector can leak thousands of messages per day across many organizations. The key defense is automated dependency scanning, lockfile hygiene, and rapid incident response. Stay paranoid about anything that handles email. 🛡️🗡️

---
