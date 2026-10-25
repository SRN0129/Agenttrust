<#
.SYNOPSIS
    Installs and builds AgentTrust on Windows environments.
.DESCRIPTION
    Validates Node.js runtime, installs dependencies, builds TypeScript project,
    and sets up default local state directories.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Verifying host runtime prerequisites..." -ForegroundColor Cyan

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js 18+ is required but not found in PATH. Please install Node.js."
    exit 1
}

$nodeVersion = (node -v).TrimStart('v')
$nodeMajor = [int]($nodeVersion.Split('.')[0])
if ($nodeMajor -lt 18) {
    Write-Error "Node.js version must be >= 18 (detected v$nodeVersion)."
    exit 1
}

Write-Host "Found Node.js v$nodeVersion and npm $((npm -v))." -ForegroundColor Green

$rootDir = Split-Path -Parent $PSScriptRoot
Set-Location $rootDir

Write-Host "Creating local state directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "data", "logs", "certs" | Out-Null

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Write-Host "Copying .env.example to .env..." -ForegroundColor Cyan
        Copy-Item ".env.example" ".env"
    } else {
        Write-Host "Generating initial .env configuration..." -ForegroundColor Cyan
        @"
PORT=3000
DATABASE_PATH=./data/agent_trust.db
LOG_LEVEL=info
"@ | Set-Content -Path ".env" -Encoding UTF8
    }
}

Write-Host "Installing dependencies..." -ForegroundColor Cyan
npm install

Write-Host "Compiling TypeScript bundles..." -ForegroundColor Cyan
npm run build

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "AgentTrust Enterprise Gateway successfully built on Windows!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "To start the gateway:" -ForegroundColor Yellow
Write-Host "  npm start"
Write-Host "To run test suites:" -ForegroundColor Yellow
Write-Host "  npm test"
Write-Host "========================================================================"
