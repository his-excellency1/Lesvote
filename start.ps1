#!/usr/bin/env pwsh

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     LESVOTE - Starting Application" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if Node.js is installed
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCheck) {
    Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
    Write-Host "Download from: https://nodejs.org"
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host "`nStarting server...`n" -ForegroundColor Yellow

Write-Host "========================================" -ForegroundColor Green
Write-Host "   LESVOTE Server Running" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Open in browser: " -NoNewline
Write-Host "http://localhost:3000" -ForegroundColor Cyan

Write-Host "`nSuper Admin Login:" -ForegroundColor Yellow
Write-Host "  Username: " -NoNewline
Write-Host "admin" -ForegroundColor Cyan
Write-Host "  Password: " -NoNewline
Write-Host "awards2025" -ForegroundColor Cyan

Write-Host "`nPress Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Green

npm start
