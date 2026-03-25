# release.ps1 - Build a Linux binary locally and upload it to GitHub Releases.
#
# Run this on your Windows machine BEFORE deploying to the VPS.
# The deploy.sh script will then download this binary instead of compiling on the server.
#
# Usage (from the vps/ directory):
#   cd C:\...\simson\vps
#   .\deploy\release.ps1 -Tag v1.0.0 -Repo nitish-mp3/simson-vps
#
# Prerequisites:
#   - Go installed locally
#   - GitHub CLI (gh) installed: https://cli.github.com/
#   - Run: gh auth login
#
param(
    [Parameter(Mandatory=$true)]
    [string]$Tag,             # e.g. "v1.0.0"

    [Parameter(Mandatory=$true)]
    [string]$Repo,            # e.g. "nitish-mp3/simson-vps"

    [string]$BinaryName = "simson-server-linux-amd64",

    [switch]$DraftRelease     # Create as draft first (recommended)
)

$ErrorActionPreference = "Stop"

# Run a native command, capture all output (stdout+stderr merged), return exit code.
# Temporarily suspends Stop preference so stderr doesn't throw.
function Invoke-Native {
    param([scriptblock]$Cmd)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = & $Cmd 2>&1
    $ec  = $LASTEXITCODE
    $ErrorActionPreference = $prev
    return [PSCustomObject]@{ Out = ($out -join "`n"); ExitCode = $ec }
}

$VpsDir   = $PSScriptRoot | Split-Path -Parent
$OutBin   = Join-Path $VpsDir $BinaryName

Write-Host "=== Simson Release Builder ===" -ForegroundColor Cyan
Write-Host "Tag:    $Tag"
Write-Host "Repo:   $Repo"
Write-Host "Binary: $OutBin"
Write-Host ""

# Build cross-compiled Linux/amd64 binary
Write-Host "[1/3] Cross-compiling for linux/amd64..." -ForegroundColor Yellow
Push-Location $VpsDir
try {
    $env:GOOS   = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    go build -ldflags "-X main.Version=$Tag" -o $OutBin ./cmd/simson-server/
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
    Remove-Item Env:\GOOS   -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH  -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

$size = (Get-Item $OutBin).Length / 1MB
Write-Host "  Built: $BinaryName ($([math]::Round($size,1)) MB)" -ForegroundColor Green

# Tag the commit
Write-Host "[2/3] Creating git tag $Tag..." -ForegroundColor Yellow
$r = Invoke-Native { git -C $VpsDir tag $Tag }
if ($r.ExitCode -ne 0 -and $r.Out -notmatch "already exists") { throw "git tag failed: $($r.Out)" }
if ($r.Out -match "already exists") { Write-Warning "Tag $Tag already exists locally, re-using it." }

$r = Invoke-Native { git -C $VpsDir push origin $Tag }
if ($r.ExitCode -ne 0 -and $r.Out -notmatch "already exists") { throw "git push tag failed: $($r.Out)" }

# Create GitHub Release and upload the binary
Write-Host "[3/3] Creating GitHub Release $Tag and uploading binary..." -ForegroundColor Yellow
$releaseArgs = @(
    "release", "create", $Tag,
    $OutBin,
    "--repo", $Repo,
    "--title", "Simson VPS $Tag",
    "--notes", "Control plane release $Tag.`n`nDeploy:`n``````bash`n./deploy.sh simson-vps.niti.life `"`" https://github.com/$Repo.git $Tag`n``````"
)
if ($DraftRelease) {
    $releaseArgs += "--draft"
}
gh @releaseArgs

Write-Host ""
Write-Host "=== Release complete! ===" -ForegroundColor Green
Write-Host ""
Write-Host "Deploy to VPS:" -ForegroundColor Cyan
Write-Host "  ./deploy.sh simson-vps.niti.life `"`" https://github.com/$Repo.git $Tag"
Write-Host ""
Write-Host "The deploy script will download the binary directly - no compilation on VPS."
