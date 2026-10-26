# AutoTrack release pipeline - the regression gate made mechanical.
# The two shipped launch failures (v2026.10.26.2 parse-time event,
# v2026.10.26.4 deleted resource key) both compiled clean; this script
# refuses to let such a build reach GitHub Releases:
#   1. static audit   - resource keys + parse-time-event lint (audit.py)
#   2. smoke launch   - SMOKE build variant (asInvoker, auto-self-test);
#                       the release is BLOCKED unless the app actually boots
#                       and its UI self-test passes
#   3. publish + zip  - the real (requireAdministrator) build
#   4. -Release       - commit, push, gh release create with the zip
# Usage:  powershell tools/release.ps1 -Version 2026.10.27 [-Release]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$Release,
    [string]$Title = "AutoTrack v$Version"
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# -- 1. static audit ----------------------------------------------------
Write-Host "== audit =="
python tools/audit.py
if ($LASTEXITCODE -ne 0) { throw "AUDIT FAILED - fix findings before releasing." }

# -- 2. smoke gate ------------------------------------------------------
Write-Host "== smoke build (asInvoker, auto self-test) =="
dotnet publish App/AutoTrack.csproj -c Release -r win-x64 --self-contained -p:Smoke=true -o publish_smoke --ignore-failed-sources
if ($LASTEXITCODE -ne 0) { throw "smoke publish failed" }

$smokeDir = Join-Path $root "publish_smoke"
$result = Join-Path $smokeDir "selftest-result.txt"
Remove-Item $result -ErrorAction SilentlyContinue
Remove-Item (Join-Path $smokeDir "crash.log") -ErrorAction SilentlyContinue

Write-Host "== smoke launch =="
$p = Start-Process -FilePath (Join-Path $smokeDir "AutoTrack.exe") -WorkingDirectory $smokeDir -PassThru
$deadline = (Get-Date).AddSeconds(90)
while (-not (Test-Path $result) -and -not $p.HasExited -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
if ($p.HasExited -and -not (Test-Path $result)) {
    # window died before the self-test wrote its verdict - the exact
    # regression class this gate exists for
    $crash = Join-Path $smokeDir "crash.log"
    if (Test-Path $crash) { Get-Content $crash | Select-Object -Last 12 | Write-Host }
    throw "SMOKE FAILED - app exited before self-test (startup crash)."
}
if (-not (Test-Path $result)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    throw "SMOKE FAILED - no selftest-result.txt within 90s."
}
$verdict = (Get-Content $result -Raw).Trim()
Write-Host "selftest: $verdict"
if (-not $verdict.StartsWith("PASS")) {
    $crash = Join-Path $smokeDir "crash.log"
    if (Test-Path $crash) { Get-Content $crash | Select-Object -Last 12 | Write-Host }
    throw "SMOKE FAILED - $verdict"
}
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Write-Host "SMOKE GATE: PASS" -ForegroundColor Green

# -- 3. real build + zip ------------------------------------------------
Write-Host "== publish $Version =="
$projFiles = @(Get-ChildItem App -Recurse -Filter *.csproj) + @(Get-ChildItem Engines -Recurse -Filter *.fsproj)
foreach ($f in $projFiles) {
    $t = Get-Content $f.FullName -Raw
    $t = $t -replace '<Version>[^<]*</Version>', "<Version>$Version</Version>"
    Set-Content -Path $f.FullName -Value $t -NoNewline
}
dotnet publish App/AutoTrack.csproj -c Release -r win-x64 --self-contained -o publish_out --ignore-failed-sources
if ($LASTEXITCODE -ne 0) { throw "publish failed" }
$zip = "AutoTrack-v$Version-win-x64.zip"
Compress-Archive -Path publish_out/* -DestinationPath $zip -Force
Write-Host "built $zip"

# -- 4. optional release ------------------------------------------------
if ($Release) {
    git add -A
    git -c user.name="Dan Park" -c user.email="dan@magicpoint.ai" commit -m "release: v$Version"
    git push origin master
    $notes = "release_notes_v$Version.md"
    if (-not (Test-Path $notes)) {
        "# AutoTrack v$Version`n`n(Summary pending - see commit history.)" | Set-Content $notes
    }
    gh release create "v$Version" --title $Title --notes-file $notes $zip --latest
    Write-Host "released v$Version"
} else {
    Write-Host "gate passed; zip ready at $zip (rerun with -Release to publish)"
}
