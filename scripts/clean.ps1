#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Safe cleanup utility for generated data files
    
.DESCRIPTION
    Removes only generated data:
    - .jsonl files (labels, events)
    - ml_results.json
    - Log files in zeek/ and suricata/ subdirectories
    
    Preserves:
    - .gitkeep files (so directories remain in git)
    - Source code and configurations
    - docker-compose.yml and Dockerfiles

.EXAMPLE
    powershell -File .\scripts\clean.ps1

.EXAMPLE
    .\scripts\clean.ps1

.NOTES
    Safe to run multiple times. Does not remove containers or images.
    For full cleanup including Docker artifacts, use:
        docker compose down -v
#>

param(
    [switch]$Confirm = $false
)

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "Data Cleanup Utility" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $Confirm) {
    Write-Host "This will delete:" -ForegroundColor Yellow
    Write-Host "  • *.jsonl files (labels, events)" -ForegroundColor White
    Write-Host "  • ml_results.json" -ForegroundColor White
    Write-Host "  • data/zeek/* (except .gitkeep)" -ForegroundColor White
    Write-Host "  • data/suricata/* (except .gitkeep)" -ForegroundColor White
    Write-Host ""
    Write-Host "Preserved:" -ForegroundColor Gray
    Write-Host "  • .gitkeep files (keep directories in git)" -ForegroundColor Gray
    Write-Host "  • Source code and configs" -ForegroundColor Gray
    Write-Host "  • Docker images and containers" -ForegroundColor Gray
    Write-Host ""
    
    $response = Read-Host "Continue? [y/N]"
    if ($response -ne "y" -and $response -ne "Y") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "Cleaning..." -ForegroundColor Yellow
Write-Host ""

# Patterns to clean
$patterns = @(
    "data/*.jsonl",
    "data/ml_results.json",
    "data/zeek/*.log",
    "data/zeek/*.json",
    "data/suricata/eve.json",
    "data/suricata/*.json"
)

$deletedCount = 0

foreach ($pattern in $patterns) {
    $items = Get-Item $pattern -ErrorAction SilentlyContinue
    if ($items) {
        foreach ($item in $items) {
            if ($item.Name -ne ".gitkeep") {
                Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "  ✓ Deleted: $($item.FullName)" -ForegroundColor Green
                $deletedCount++
            }
        }
    }
}

Write-Host ""
Write-Host "✅ Cleanup complete. $deletedCount files deleted." -ForegroundColor Green
