# ==============================================================================
# TenantShield - Dedicated Lab Database Setup Script (PowerShell)
# ==============================================================================
# Sets up 'tenantshield_lab' database without modifying 'tenantshield_db'.
# Usage:
#   .\scripts\setup_lab_db.ps1 -AdminUrl "postgresql://postgres:password@localhost:5432/postgres" -Action "setup"
# ==============================================================================

param (
    [string]$AdminUrl = "postgresql://postgres:postgres@localhost:5432/postgres",
    [string]$Action = "setup"
)

Write-Host "================================================================="
Write-Host " TenantShield Level 4 - Isolated Lab Database Runner"
Write-Host " Action: $Action"
Write-Host "================================================================="

py -3.10 scripts\setup_lab_db.py --admin-url $AdminUrl --action $Action
