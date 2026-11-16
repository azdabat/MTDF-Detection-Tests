<#
  lab.ps1 - the whole local pipeline in one command, against Kustainer on localhost:8080.

      powershell -ExecutionPolicy Bypass -File lab.ps1            # check, lint, compile, test, docs
      powershell -ExecutionPolicy Bypass -File lab.ps1 -Load      # also load the Empire telemetry into your tables

  -Load  puts every recorded attack from detections\*\*\fixtures* into the real Device* tables,
         so you can paste any rule into the ADX web UI and see it fire. Safe to run more than once
         only if you add -Fresh (drops and reloads those tables), otherwise rows are added twice.
#>
param(
    [switch]$Load,
    [switch]$Fresh
)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$cluster = "http://localhost:8080"

function Step($n, $text) { Write-Host "`n[$n] $text" -ForegroundColor Cyan }

Step 1 "Is the Kusto engine (Docker) answering on $cluster ?"
try {
    $body = '{"db":"NetDefaultDB","csl":"print ready=1"}'
    Invoke-RestMethod -Uri "$cluster/v1/rest/query" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 15 | Out-Null
    Write-Host "    yes" -ForegroundColor Green
} catch {
    Write-Host "    NO. Open Docker Desktop, wait for 'Engine running', then:  docker start amazing_goldstine" -ForegroundColor Red
    exit 1
}

Step "1a" "Make the database Defender-shaped (adds missing Defender columns, keeps your rows)"
python tools\tenant_setup.py

if ($Load) {
    Step "1b" "Loading the Empire / Covenant / native-tool telemetry into your Device* tables"
    if ($Fresh) { python tools\ingest_to_adx.py --all-detections --fresh } else { python tools\ingest_to_adx.py --all-detections }
}

Step 2 "Lint: known MTDF bug classes (ERROR = must fix)"
python tools\lint_kql.py detections --no-port
$lint = $LASTEXITCODE

Step 3 "Compile check with Microsoft's Kusto language service"
if (Get-Command node -ErrorAction SilentlyContinue) {
    if (-not (Test-Path tools\semantic\node_modules)) { npm install --prefix tools\semantic --no-audit --no-fund --silent }
    python tools\semantic_check.py
    $compile = $LASTEXITCODE
} else {
    Write-Host "    skipped: Node.js is not installed (https://nodejs.org, LTS). CI still runs it." -ForegroundColor Yellow
    $compile = 0
}

Step 4 "Run every test: each rule against the real attack it must catch"
python tools\run_tests.py --json docs\results.json
$tests = $LASTEXITCODE

Step 5 "Regenerate README coverage, detection pages and the ATT&CK Navigator layer"
python tools\build_docs.py

Step 6 "Tenant mode: every rule, unchanged, hunting over everything in your tables"
python tools\hunt_all.py

Write-Host ""
if ($lint -eq 0 -and $compile -eq 0 -and $tests -eq 0) {
    Write-Host "PIPELINE GREEN. Next: powershell -ExecutionPolicy Bypass -File publish.ps1 -Promote -Message 'Lab run'" -ForegroundColor Green
} else {
    Write-Host "Something needs a look - scroll up for ERROR / FAIL lines and send them to Claude." -ForegroundColor Yellow
}
