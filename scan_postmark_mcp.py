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
