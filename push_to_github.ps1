<#
  push_to_github.ps1 - first upload of this repository to GitHub, in one command.

  1. On github.com create an EMPTY repository (no README, no .gitignore, no licence).
  2. Run, from this folder:
       powershell -ExecutionPolicy Bypass -File push_to_github.ps1 -User <your GitHub username>
  Later changes go up with publish.ps1.
#>
param(
    [Parameter(Mandatory = $true)][string]$User,
    [string]$Repo = "MTDF-Detection-Tests"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git is not installed: https://git-scm.com/download/win (defaults are fine), then run this again." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path .git)) { git init -b main | Out-Null }
if (-not (git config user.name)) { git config user.name $User }
if (-not (git config user.email)) { git config user.email "$User@users.noreply.github.com" }
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) { git commit -m "MTDF detection-as-code: 12 detections, 25 tests on recorded adversary telemetry" | Out-Null }
git remote remove origin 2>$null
git remote add origin "https://github.com/$User/$Repo.git"
Write-Host "Pushing to https://github.com/$User/$Repo (a GitHub sign-in window may open)..." -ForegroundColor Cyan
git push -u origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "Done. Open https://github.com/$User/$Repo/actions to watch the first pipeline run." -ForegroundColor Green
}
