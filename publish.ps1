<#
  publish.ps1 - lint locally, then commit and push. GitHub Actions runs the
  detection tests on a real Kusto engine and regenerates the docs.

  No local Kusto engine is needed. Run from anywhere:

      powershell -ExecutionPolicy Bypass -File publish.ps1 -Message "Add run-keys detection"
      powershell -ExecutionPolicy Bypass -File publish.ps1 -Promote -Message "Promote passing tests"

  -Promote  first promotes experimental tests that passed the last CI run to stable
  -Test     also runs the tests locally (needs Kustainer on http://localhost:8080)
#>
param(
    [string]$Message = "Update detections",
    [switch]$Promote,
    [switch]$Test
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Syncing with GitHub (CI may have committed updated docs)..." -ForegroundColor Cyan
git pull --rebase --autostash
if ($LASTEXITCODE -ne 0) { Write-Host "git pull failed - resolve it, then run again." -ForegroundColor Red; exit 1 }

if ($Promote) {
    python tools\promote.py --apply
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "Linting rules..." -ForegroundColor Cyan
python tools\lint_kql.py detections --no-port
if ($LASTEXITCODE -ne 0) { Write-Host "Lint ERRORs above - nothing pushed." -ForegroundColor Red; exit 1 }

if ($Test) {
    python tools\run_tests.py
    if ($LASTEXITCODE -ne 0) { Write-Host "Blocking test failures - nothing pushed." -ForegroundColor Red; exit 1 }
}

git add -A
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) { Write-Host "Nothing changed - nothing to push." -ForegroundColor Yellow; exit 0 }

git commit -m $Message
git push
if ($LASTEXITCODE -ne 0) { Write-Host "git push failed (check your GitHub sign-in)." -ForegroundColor Red; exit 1 }

Write-Host "Pushed. Watch the run in the repo's Actions tab - it tests every detection and updates the docs." -ForegroundColor Green
