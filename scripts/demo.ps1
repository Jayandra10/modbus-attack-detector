<#
.SYNOPSIS
    End-to-end demo runner for Modbus Recon + Manipulation Detector (Phase 1 + Phase 2)

.DESCRIPTION
    Automates the full workflow:
    1. Navigate to repo root
    2. Clean up old generated files
    3. Build and start all services
    4. Generate 3-phase synthetic traffic
    5. Train ML classifier
    6. Display results and PASS/FAIL checklist

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1

.NOTES
    Requires: Docker Desktop with Docker Compose v2.x
    Duration: ~5-6 minutes
#>

# Navigate to repo root
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
Write-Host ""
Write-Host "=== Modbus Recon + Manipulation Detector - Full Demo ===" -ForegroundColor Cyan
Write-Host ""

# Ensure data directories exist
@("data", "data/zeek", "data/suricata") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Step 1: Clean up old artifacts
Write-Host "[1/6] Cleaning up old artifacts..." -ForegroundColor Yellow
docker compose down --remove-orphans 2>&1 | Out-Null

$cleanPatterns = @(
    "data\labels.jsonl",
    "data\generator_events.jsonl",
    "data\ml_results.json",
    "data\zeek\conn.log",
    "data\zeek\*.json",
    "data\suricata\eve.json",
    "data\suricata\*.json"
)

foreach ($pattern in $cleanPatterns) {
    Get-Item $pattern -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Force -ErrorAction SilentlyContinue
}
Write-Host "   Cleaned." -ForegroundColor Green
Write-Host ""

# Step 2: Build and start services
Write-Host "[2/6] Building and starting services..." -ForegroundColor Yellow
Write-Host "   (This may take 1-2 minutes on first run)" -ForegroundColor Gray

$buildStart = Get-Date
docker compose up -d --build | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ERROR: docker compose up failed" -ForegroundColor Red
    exit 1
}
$buildElapsed = ((Get-Date) - $buildStart).TotalSeconds
Write-Host "   Started in $([Math]::Round($buildElapsed, 1))s" -ForegroundColor Green
docker compose ps
Write-Host ""

# Step 3: Generate 3-phase traffic
Write-Host "[3/6] Generating 3-phase synthetic traffic..." -ForegroundColor Yellow
Write-Host "   Phase 1: Normal (120s) | Phase 2: Recon (60s) | Phase 3: Manipulation (60s)" -ForegroundColor Gray
Write-Host "   This takes approximately 4 minutes..." -ForegroundColor Gray

$trafficStart = Get-Date
docker compose run --rm traffic-gen 2>&1 | Select-String "generation complete|error|Error" | ForEach-Object { Write-Host "   $_" -ForegroundColor Cyan }
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ERROR: traffic-gen failed" -ForegroundColor Red
}
$trafficElapsed = ((Get-Date) - $trafficStart).TotalSeconds
Write-Host "   Completed in $([Math]::Round($trafficElapsed, 1))s" -ForegroundColor Green
Write-Host ""

# Step 4: Wait for files and verify data generation
Write-Host "[4/6] Waiting for files to be written..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

$fileReady = $false
for ($i = 0; $i -lt 10; $i++) {
    if ((Test-Path "data\labels.jsonl") -and (Get-Item "data\labels.jsonl").Length -gt 100 -and
        (Test-Path "data\generator_events.jsonl") -and (Get-Item "data\generator_events.jsonl").Length -gt 100) {
        $fileReady = $true
        Write-Host "   Files ready." -ForegroundColor Green
        break
    }
    Write-Host "   Waiting... ($($i+1)/10)" -ForegroundColor Gray
    Start-Sleep -Seconds 2
}

if (-not $fileReady) {
    Write-Host "   WARNING: Data files not ready, but proceeding anyway" -ForegroundColor Yellow
}
Write-Host ""

# Step 5: Train ML model
Write-Host "[5/6] Training ML classifier..." -ForegroundColor Yellow

$mlStart = Get-Date
# Run ML training in a fresh container (won't re-trigger traffic-gen since we removed that dependency)
$mlOutput = docker compose run --rm ml 2>&1
$mlExitCode = $LASTEXITCODE
$mlElapsed = ((Get-Date) - $mlStart).TotalSeconds

if ($mlExitCode -ne 0) {
    Write-Host "   ERROR: ML training failed with exit code $mlExitCode" -ForegroundColor Red
    Write-Host "   Showing full output:" -ForegroundColor Yellow
    $mlOutput | ForEach-Object { Write-Host "   $_" -ForegroundColor Cyan }
} else {
    Write-Host "   Completed in $([Math]::Round($mlElapsed, 1))s" -ForegroundColor Green
}

# Extract and print ML metrics
Write-Host ""
Write-Host "   ML Output:" -ForegroundColor White
$mlOutput | Select-String "Classification Report|accuracy|precision|recall|Confusion Matrix|TN=|TP=|Feature matrix|Label distribution" | ForEach-Object {
    Write-Host "   $_" -ForegroundColor Cyan
}
Write-Host ""

# Step 6: Verify outputs
Write-Host "[6/6] PASS/FAIL Checklist:" -ForegroundColor Yellow

$checks = @(
    @{ name = "labels.jsonl"; path = "data\labels.jsonl"; size_min = 1 },
    @{ name = "generator_events.jsonl"; path = "data\generator_events.jsonl"; size_min = 1 },
    @{ name = "data/zeek/conn.log"; path = "data\zeek\conn.log"; size_min = 1 },
    @{ name = "data/suricata/eve.json"; path = "data\suricata\eve.json"; size_min = 1 },
    @{ name = "ml_results.json"; path = "data\ml_results.json"; size_min = 1 }
)

$passCount = 0
$failCount = 0

foreach ($check in $checks) {
    if (Test-Path $check.path) {
        $size = (Get-Item $check.path).Length
        if ($size -ge $check.size_min) {
            Write-Host "   [PASS] $($check.name) - $([Math]::Round($size / 1MB, 2))MB" -ForegroundColor Green
            $passCount++
        } else {
            Write-Host "   [FAIL] $($check.name) - Empty" -ForegroundColor Red
            $failCount++
        }
    } else {
        Write-Host "   [FAIL] $($check.name) - Not found" -ForegroundColor Red
        $failCount++
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "   PASS: $passCount / 5" -ForegroundColor Green
Write-Host "   FAIL: $failCount / 5" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($failCount -gt 0) {
    Write-Host "Diagnostics (copy and run if needed):" -ForegroundColor Yellow
    Write-Host "   docker compose ps" -ForegroundColor White
    Write-Host "   docker logs modbus-server --tail 50" -ForegroundColor White
    Write-Host "   docker logs suricata --tail 80" -ForegroundColor White
    Write-Host "   docker logs zeek --tail 80" -ForegroundColor White
    Write-Host ""
}

Write-Host "Generated files:" -ForegroundColor Yellow
@("data\labels.jsonl", "data\generator_events.jsonl", "data\zeek\conn.log", "data\suricata\eve.json", "data\ml_results.json") | ForEach-Object {
    if (Test-Path $_) {
        $size = (Get-Item $_).Length
        Write-Host "   $_ : $([Math]::Round($size / 1KB, 2))KB" -ForegroundColor White
    }
}

Write-Host ""
if ($failCount -eq 0) {
    Write-Host "✅ ALL CHECKS PASSED!" -ForegroundColor Green
    Write-Host ""
    
    # Step 7: Generate visualizations
    Write-Host "[7/6] Generating visualizations..." -ForegroundColor Yellow
    
    $vizStart = Get-Date
    $vizOutput = docker compose run --rm viz 2>&1
    $vizExitCode = $LASTEXITCODE
    $vizElapsed = ((Get-Date) - $vizStart).TotalSeconds
    
    if ($vizExitCode -eq 0) {
        Write-Host "   Completed in $([Math]::Round($vizElapsed, 1))s" -ForegroundColor Green
        Write-Host ""
        Write-Host "Generated visualizations in reports/:" -ForegroundColor Yellow
        @("phase_timeline.png", "ops_per_phase.png", "suricata_alerts_over_time.png", "feature_correlation.png", "model_coefficients.png") | ForEach-Object {
            if (Test-Path "reports\$_") {
                Write-Host "   ✅ $_" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "   Warning: Visualization failed with exit code $vizExitCode" -ForegroundColor Yellow
        Write-Host "   (This is optional; data generation still succeeded)" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠️  Some checks failed. See diagnostics above." -ForegroundColor Yellow
}
Write-Host ""
