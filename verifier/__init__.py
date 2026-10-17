"""
TenantShield - Verification & Cross-Tenant Attack Verification Package
======================================================================
Automated security verification harness that inspects OpenAPI schemas,
dynamically generates cross-tenant attack vectors, executes integrity checks,
evaluates isolation boundaries, and executes layer-kill resilience matrices.
"""

from verifier.generator import AttackGenerator, AttackSpec
from verifier.runner import VerificationRunner
from verifier.matrix_runner import LayerKillMatrixRunner

__all__ = ["AttackGenerator", "AttackSpec", "VerificationRunner", "LayerKillMatrixRunner"]
