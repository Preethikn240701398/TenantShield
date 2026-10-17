# ==============================================================================
# TenantShield - Reset Lab Database Script (PowerShell)
# ==============================================================================
# Single-command runner to reset and reseed 'tenantshield_lab' database.
# Usage:
#   .\scripts\reset_lab_db.ps1
# ==============================================================================

Write-Host "================================================================="
Write-Host " TenantShield - Resetting Lab Database"
Write-Host "================================================================="

$PythonExe = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $PythonExe scripts\reset_lab_db.py
