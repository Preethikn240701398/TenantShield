# ==============================================================================
# TenantShield - Run Layer-Kill Matrix Script (PowerShell)
# ==============================================================================
# Runs Level 8 Layer-Kill Matrix against 'tenantshield_lab' database.
# Usage:
#   .\scripts\run_matrix.ps1
# ==============================================================================

Write-Host "================================================================="
Write-Host " TenantShield Level 8 - Layer-Kill Matrix Runner"
Write-Host " Target Database: tenantshield_lab"
Write-Host "================================================================="

$PythonExe = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $PythonExe scripts\run_matrix.py
