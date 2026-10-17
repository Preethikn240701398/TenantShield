# ==============================================================================
# TenantShield - Dedicated Lab Database Setup Script (PowerShell)
# ==============================================================================
# Sets up or resets 'tenantshield_lab' database without modifying 'tenantshield_db'.
# Usage:
#   .\scripts\setup_lab_db.ps1 -Action "setup"
#   .\scripts\setup_lab_db.ps1 -Action "reset"
#   .\scripts\setup_lab_db.ps1 -Action "disable-rls"
#   .\scripts\setup_lab_db.ps1 -Action "enable-rls"
# ==============================================================================

param (
    [string]$Action = "setup",
    [string]$AdminUrl = ""
)

Write-Host "================================================================="
Write-Host " TenantShield - Isolated Lab Database Runner"
Write-Host " Action: $Action"
Write-Host "================================================================="

$PythonExe = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }

if ($AdminUrl -ne "") {
    & $PythonExe scripts\setup_lab_db.py --admin-url $AdminUrl --action $Action
} else {
    & $PythonExe scripts\setup_lab_db.py --action $Action
}
