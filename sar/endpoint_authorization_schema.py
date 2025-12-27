"""
Pydantic schema for endpoint-centric authorization analysis

This schema focuses on ENDPOINTS rather than authorization "behaviors",
making it easier to understand what protects each endpoint.
"""

from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from enum import Enum


class EnforcementPoint(str, Enum):
    """Where authorization is enforced in the request lifecycle"""
    ROUTE_GUARD = "route_guard"  # HTTP layer (e.g., SecurityFilterChain, route config)
    MIDDLEWARE_GUARD = "middleware_guard"  # Request middleware/interceptors
    ENDPOINT_GUARD = "endpoint_guard"  # Method-level (e.g., @PreAuthorize)
    CONTROLLER_GUARD = "controller_guard"  # Class-level annotations
    INLINE_GUARD = "inline_guard"  # Manual checks in code (if/throw)
    SERVICE_GUARD = "service_guard"  # Service layer authorization
    DATA_GUARD = "data_guard"  # Data/ORM level (out of scope for endpoint_authorization)
    UNKNOWN = "unknown"


class Scope(str, Enum):
    """Scope of authorization rule application"""
    GLOBAL = "global"  # Applies to all routes
    CONTROLLER = "controller"  # Applies to all endpoints in a controller
    ENDPOINT = "endpoint"  # Applies to specific endpoint only
    UNKNOWN = "unknown"


class AuthorizationType(str, Enum):
    """Type of authorization mechanism"""
    RBAC = "RBAC"  # Role-Based Access Control
    PUBLIC = "PUBLIC"  # Explicitly configured as public/permitAll (no authorization required)
    OTHER = "OTHER"  # Other mechanisms (described in 'rule' field)
    UNKNOWN = "UNKNOWN"


class Authorization(BaseModel):
    """Authorization rule specification"""
    type: AuthorizationType
    roles_any_of: Optional[List[str]] = Field(
        None,
        description="List of roles, any of which grants access (RBAC only)"
    )
    rule: Optional[str] = Field(
        None,
        description="English description of the authorization rule (OTHER only)"
    )

    class Config:
        use_enum_values = True

    def model_dump(self, **kwargs):
        """Override to exclude None values by default"""
        kwargs.setdefault('exclude_none', True)
        return super().model_dump(**kwargs)


class Evidence(BaseModel):
    """Evidence of where authorization was discovered"""
    ref: str = Field(
        ...,
        description="Source reference: file:line or config key/path"
    )
    mechanism_name: str = Field(
        ...,
        description="Mechanism observed (e.g., @PreAuthorize, HttpSecurity, middleware X)"
    )
    config_snippet: Optional[str] = Field(
        None,
        description="(Deprecated) Actual configuration code snippet showing the authorization. Use config_source_id and sources section instead to avoid duplication."
    )
    config_source_id: Optional[str] = Field(
        None,
        description="ID referencing entry in evidence.sources section. Use this instead of config_snippet to avoid duplication."
    )


class EndpointAuthorization(BaseModel):
    """Single authorization applied to an endpoint"""
    enforcement_point: EnforcementPoint
    scope: Scope
    authorization: Authorization
    description: str = Field(
        ...,
        description="English description of who can access via this authorization"
    )
    evidence: Evidence

    class Config:
        use_enum_values = True


class EffectiveAuthorization(BaseModel):
    """Net result of all authorizations for this endpoint"""
    type: AuthorizationType
    roles_any_of: Optional[List[str]] = Field(
        None,
        description="Combined list of roles that grant access (RBAC only)"
    )
    description: str = Field(
        ...,
        description="English summary of effective access requirement"
    )

    class Config:
        use_enum_values = True

    def model_dump(self, **kwargs):
        """Override to exclude None values by default"""
        kwargs.setdefault('exclude_none', True)
        return super().model_dump(**kwargs)


class Endpoint(BaseModel):
    """HTTP endpoint with its authorizations"""
    id: str = Field(
        ...,
        description="Unique identifier (e.g., GET_/owners/{ownerId})"
    )
    method: str = Field(
        ...,
        description="HTTP method: GET|POST|PUT|DELETE|PATCH|* if unknown"
    )
    path: str = Field(
        ...,
        description="Normalized route pattern (e.g., /owners/{ownerId})"
    )
    handler: str = Field(
        ...,
        description="Human-readable handler identifier (e.g., OwnerController.updateOwner)"
    )
    authorizations: List[EndpointAuthorization] = Field(
        default_factory=list,
        description="All authorizations applied to this endpoint (ordered by precedence)"
    )
    effective_authorization: EffectiveAuthorization = Field(
        ...,
        description="Net result of all authorizations"
    )


class EndpointAuthorizationReport(BaseModel):
    """Complete report of endpoint authorizations"""
    endpoints: List[Endpoint]
    summary: dict = Field(
        default_factory=dict,
        description="Summary statistics"
    )
