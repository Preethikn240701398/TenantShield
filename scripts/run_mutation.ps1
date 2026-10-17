# ==============================================================================
# TenantShield - Run Isolation Mutation Testing Script (PowerShell)
# ==============================================================================
# Runs Isolation Mutation Testing against 'tenantshield_lab' database.
# Usage:
#   .\scripts\run_mutation.ps1
# ==============================================================================

Write-Host "================================================================="
Write-Host " TenantShield - Isolation Mutation Testing Suite"
Write-Host " Target Database: tenantshield_lab"
Write-Host "================================================================="

$PythonExe = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $PythonExe scripts\run_mutation.py
