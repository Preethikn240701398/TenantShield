"""
TenantShield - Dynamic OpenAPI Attack Generator
================================================
Parses the application's OpenAPI schema dynamically to discover attackable endpoints
without relying on hardcoded routes:
1. Discovers path parameters representing resource IDs (e.g. {document_id}, {id}, {tenant_id}).
2. Builds cross-tenant attack definitions for read (GET), update (PUT/PATCH), and delete (DELETE).
3. Identifies resource creation endpoints capable of accepting foreign tenant references.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional


@dataclass
class AttackSpec:
    name: str
    category: str  # "read", "update", "delete", "create_injection", "action"
    method: str
    path_template: str
    path_param_name: Optional[str] = None
    path_param_type: Optional[str] = None  # "resource_id" or "tenant_id"
    payload_template: Optional[Dict[str, Any]] = None
    query_template: Optional[Dict[str, Any]] = None
    headers_template: Optional[Dict[str, Any]] = None
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackGenerator:
    """
    Analyzes an OpenAPI 3.x schema and dynamically generates attack specifications
    targeting multi-tenant isolation boundaries.
    """

    ID_PARAM_PATTERN = re.compile(r"\{([a-zA-Z0-9_]*(?:id|key|doc|resource|tenant)[a-zA-Z0-9_]*)\}", re.IGNORECASE)

    def __init__(self, openapi_schema: Dict[str, Any]):
        self.schema = openapi_schema
        self.paths = self.schema.get("paths", {})

    @classmethod
    def from_app(cls, app: Any) -> "AttackGenerator":
        """Factory creating a generator directly from a FastAPI application."""
        return cls(app.openapi())

    def discover_resource_endpoints(self) -> List[Dict[str, Any]]:
        """
        Discovers all path templates that contain resource or identifier parameters.
        """
        discovered = []
        for path_pattern, path_item in self.paths.items():
            matches = self.ID_PARAM_PATTERN.findall(path_pattern)
            if matches:
                discovered.append({
                    "path": path_pattern,
                    "params": matches,
                    "methods": [
                        m.upper() for m in path_item.keys()
                        if m.lower() in ("get", "post", "put", "patch", "delete")
                    ],
                })
        return discovered

    def generate_attacks(self) -> List[AttackSpec]:
        """
        Generates full list of dynamic cross-tenant attack specifications.
        """
        attacks: List[AttackSpec] = []

        for path_pattern, path_item in self.paths.items():
            matches = self.ID_PARAM_PATTERN.findall(path_pattern)

            # 1. Path-parameterized endpoints (e.g. /documents/{document_id}, /admin/keys/{tenant_id}/...)
            if matches:
                param_name = matches[0]
                param_lower = param_name.lower()
                param_type = "tenant_id" if "tenant" in param_lower else "resource_id"

                for method_str, op_details in path_item.items():
                    method = method_str.upper()
                    if method not in ("GET", "PUT", "PATCH", "DELETE", "POST"):
                        continue

                    summary = op_details.get("summary", "")

                    if method == "GET":
                        attacks.append(
                            AttackSpec(
                                name=f"Cross-Tenant Read: {method} {path_pattern}",
                                category="read",
                                method=method,
                                path_template=path_pattern,
                                path_param_name=param_name,
                                path_param_type=param_type,
                                description=(
                                    f"Tenant A attempts unauthorized GET on Tenant B's {param_name} "
                                    f"via {path_pattern} ({summary})."
                                ),
                            )
                        )
                    elif method in ("PUT", "PATCH"):
                        malicious_payload = {
                            "title": "HACKED_BY_TENANT_A",
                            "content": "MALICIOUS_OVERWRITE_DATA_UNAUTHORIZED",
                        }
                        attacks.append(
                            AttackSpec(
                                name=f"Cross-Tenant Update: {method} {path_pattern}",
                                category="update",
                                method=method,
                                path_template=path_pattern,
                                path_param_name=param_name,
                                path_param_type=param_type,
                                payload_template=malicious_payload,
                                description=(
                                    f"Tenant A attempts unauthorized {method} tampering with Tenant B's "
                                    f"{param_name} via {path_pattern}."
                                ),
                            )
                        )
                    elif method == "DELETE":
                        attacks.append(
                            AttackSpec(
                                name=f"Cross-Tenant Delete: DELETE {path_pattern}",
                                category="delete",
                                method="DELETE",
                                path_template=path_pattern,
                                path_param_name=param_name,
                                path_param_type=param_type,
                                description=(
                                    f"Tenant A attempts unauthorized destruction of Tenant B's "
                                    f"{param_name} via {path_pattern}."
                                ),
                            )
                        )
                    elif method == "POST":
                        # e.g. key rotation/shredding actions
                        attacks.append(
                            AttackSpec(
                                name=f"Cross-Tenant Action: POST {path_pattern}",
                                category="action",
                                method="POST",
                                path_template=path_pattern,
                                path_param_name=param_name,
                                path_param_type=param_type,
                                description=(
                                    f"Tenant A attempts unauthorized management action on Tenant B's "
                                    f"{param_name} via {path_pattern}."
                                ),
                            )
                        )

            # 2. Resource creation endpoints capable of accepting foreign tenant references
            for method_str, op_details in path_item.items():
                if method_str.upper() == "POST" and not matches:
                    params = op_details.get("parameters", [])
                    has_tenant_query_or_header = any(
                        p.get("name", "").lower() in ("tenant_id", "x-tenant-id")
                        for p in params
                    )
                    request_body = op_details.get("requestBody", {})
                    content_schema = (
                        request_body.get("content", {})
                        .get("application/json", {})
                        .get("schema", {})
                    )

                    # Filter out unauthenticated auth routes (e.g. /auth/login)
                    is_resource_creation = (
                        not path_pattern.startswith("/auth/login")
                        and (has_tenant_query_or_header or op_details.get("security"))
                    )

                    # Check if body or parameters allow tenant reference injection
                    if is_resource_creation and (has_tenant_query_or_header or content_schema):
                        attacks.append(
                            AttackSpec(
                                name=f"Cross-Tenant Create Injection: POST {path_pattern} (Body Reference)",
                                category="create_injection",
                                method="POST",
                                path_template=path_pattern,
                                payload_template={
                                    "title": "Injected Document for Tenant B",
                                    "content": "Malicious payload planted in foreign workspace",
                                    "tenant_id": "{target_tenant_id}",
                                },
                                query_template={"tenant_id": "{target_tenant_id}"},
                                headers_template={"X-Tenant-ID": "{target_tenant_id}"},
                                description=(
                                    f"Tenant A attempts to inject a resource directly into Tenant B's workspace "
                                    f"via {path_pattern} by spoofing tenant_id in payload, query, and headers."
                                ),
                            )
                        )

        return attacks
