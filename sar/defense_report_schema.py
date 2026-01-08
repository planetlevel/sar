"""
Pydantic models for defense analysis reports.

This is the single source of truth for the defense report schema.
Ensures consistent report structure across all agents.
"""

from typing import List, Dict, Optional, Any, Union, Literal
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# ============================================================================
# Common Models
# ============================================================================

class Tool(BaseModel):
    """Tool metadata"""
    vendor: str
    name: str
    version: str


class Property(BaseModel):
    """Key-value property"""
    name: str
    value: str


class Component(BaseModel):
    """Component being analyzed"""
    type: str = "application"
    name: str
    version: str
    properties: Optional[List[Property]] = None


class Metadata(BaseModel):
    """Report metadata"""
    timestamp: str
    tools: List[Tool]
    component: Component


# ============================================================================
# Defense-Specific Models
# ============================================================================

class Framework(BaseModel):
    """Framework with version information"""
    name: str
    version: Optional[str] = None


class Behavior(BaseModel):
    """A specific instance of a defense mechanism"""
    framework: str
    category: str
    type: str
    mechanism: str
    method: str
    class_: Optional[str] = Field(None, alias="class")
    file: str
    line: int
    location: str
    location_type: str
    roles: Optional[List[str]] = None
    httpMethod: Optional[str] = None
    route: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class Mechanism(BaseModel):
    """Defense mechanism with its behaviors"""
    framework: str
    category: str
    type: str
    patterns: List[str] = Field(default_factory=list)
    behaviors: List[Behavior]
    count: Optional[int] = None
    pattern_group_target: Optional[str] = None
    pattern_group_search_type: Optional[str] = None
    pattern_group_description: Optional[str] = None
    discovery_method: Optional[str] = None


class DefenseUsageMatrix(BaseModel):
    """Matrix showing exposure vs defense coverage"""
    rows: List[str]  # Exposures (endpoints, methods, etc.)
    columns: List[str]  # Defense options (roles, validation types, etc.)
    matrix: List[List[bool]]  # [row][col] = True if exposure i has defense j
    row_protected: List[bool]  # Which rows have any protection


class RoleStructure(BaseModel):
    """Proposed role structure for authorization"""
    current_roles: List[str]
    proposed_roles: List[str]
    role_mapping: Dict[str, str]
    rationale: str


class EndpointClassification(BaseModel):
    """Classification of a single endpoint"""
    endpoint: str
    current_auth: Optional[str]
    suggested_auth: Literal["PUBLIC", "AUTHENTICATED", "ROLE_SPECIFIC"]
    suggested_role: Optional[Union[str, List[str]]]  # Single role or multiple roles
    rationale: str


class ProposedAccessMatrix(BaseModel):
    """Complete proposed access control matrix"""
    role_structure: RoleStructure
    endpoint_classifications: List[EndpointClassification]
    total_endpoints: int
    currently_protected: int
    suggested_public: int
    suggested_authenticated: int
    suggested_role_specific: int


class Roles(BaseModel):
    """Role analysis"""
    used: List[str]
    generic: List[str]
    domain_specific: List[str]
    generic_count: int
    domain_specific_count: int


class AuthPattern(BaseModel):
    """Authorization architecture pattern"""
    pattern: str
    confidence: float
    primary_layer: str
    evidence_summary: str
    coverage_approach: str
    architecture_description: str


class CoverageMetrics(BaseModel):
    """Coverage metrics with two dimensions:
    - policy_coverage: does this defense make a decision? (permitAll = yes)
    - restrictiveness: does it restrict access? (permitAll = no)
    """
    metric_type: str
    dimension: Optional[Literal["policy_coverage", "restrictiveness"]] = None
    exposures: int
    protected: int  # For policy_coverage: has decision | For restrictiveness: requires auth/denies
    unprotected: int
    coverage: float
    explanation: str


class MechanismTest(BaseModel):
    """Record of a protection mechanism that was tested during verification"""
    type: str
    description: str
    checked: bool
    found: int
    query: str


class AdditionalProtection(BaseModel):
    """A protection mechanism found during verification"""
    method: str
    class_: Optional[str] = Field(None, alias="class")
    mechanism: str
    file: str
    protection_type: str
    note: str

    model_config = ConfigDict(populate_by_name=True)


class UpdatedCoverage(BaseModel):
    """Updated coverage metrics after verification"""
    exposures: int
    protected: int
    unprotected: int
    coverage: float


class VerificationReport(BaseModel):
    """AI-driven verification of unprotected routes"""
    mechanisms_tested: List[MechanismTest]
    additional_protections_found: List[AdditionalProtection]
    verified_unprotected_count: int
    updated_coverage: Optional[UpdatedCoverage] = None


class Evidence(BaseModel):
    """Evidence supporting the recommendation"""
    # Core evidence fields
    mechanisms: Optional[List[Mechanism]] = None
    defense_usage_matrix: Optional[DefenseUsageMatrix] = None
    roles: Optional[Roles] = None
    auth_pattern: Optional[AuthPattern] = None
    coverage_metrics: Optional[CoverageMetrics] = None
    proposed_access_matrix: Optional[ProposedAccessMatrix] = None
    verification: Optional[VerificationReport] = None

    # Agent-specific evidence fields
    endpoints: Optional[List[Dict[str, Any]]] = None  # List of discovered endpoints with authorization details
    sources: Optional[Dict[str, Dict[str, Any]]] = None  # Configuration source code snippets
    frameworks: Optional[List[Framework]] = None  # List of detected frameworks with versions
    authorizations: Optional[Dict[str, Dict[str, Any]]] = None  # Dictionary of authorization definitions by ID
    test_discovery: Optional[Dict[str, Any]] = None  # Test file discovery results

    # Allow extra fields for future agent-specific evidence
    model_config = ConfigDict(extra="allow")


class Recommendation(BaseModel):
    """Recommendation structure"""
    title: str
    summary: str
    design_recommendation: str
    implementation_recommendation: str
    rationale: str


class DefenseMetadata(BaseModel):
    """Defense mechanism metadata"""
    defense_id: str  # Machine ID: "spring_security_http"
    defense_mechanism: str  # Technical mechanism: "route_guard"
    defense_name: str  # Human label: "Spring Security HTTP Security"
    defense_type: str
    defense_patterns: List[Union[str, Dict[str, Any]]]
    description: Optional[str] = None  # AI-generated description of what this defense does


class DefenseSection(BaseModel):
    """FACTUAL description of a single defense mechanism (no evaluation/judgement)"""
    defense_metadata: DefenseMetadata
    evidence: Optional[Evidence] = None  # Code snippets, configs showing this defense
    metrics: Optional[List[CoverageMetrics]] = None  # Coverage metrics with policy_coverage and restrictiveness dimensions
    defense_matrix: Optional['DefenseMatrix'] = None  # How this defense applies to each endpoint


class DefenseMatrix(BaseModel):
    """Matrix showing how all defenses apply to each endpoint"""
    endpoints: List[Dict[str, Any]]  # Each endpoint with all its defense layers
    summary: Optional[Dict[str, Any]] = None  # Overall matrix summary


class AgentRecommendation(BaseModel):
    """Single agent's recommendation"""
    agent_id: str
    agent_name: str
    ran: bool
    reason: Optional[str] = None  # If not run

    # === FACTUAL SECTIONS (descriptive, no evaluation) ===

    # Individual defense sections (each with its own defense matrix)
    defenses: Optional[List[DefenseSection]] = None

    # Shared data across all defenses
    frameworks: Optional[List[Framework]] = None

    # === EVALUATION SECTION (prescriptive, spans defenses) ===

    # Overall recommendation (may reference multiple defenses)
    recommendation: Optional[Recommendation] = None


class Summary(BaseModel):
    """Report summary"""
    agents_ran: int
    agents_skipped: int
    total_recommendations: int
    overall_coverage: float


# ============================================================================
# Top-Level Report Model
# ============================================================================

class DefenseReport(BaseModel):
    """
    Complete defense analysis report.

    This follows the CompassDefenseReport format inspired by CycloneDX BOM.
    """
    bomFormat: Literal["CompassDefenseReport"] = "CompassDefenseReport"
    specVersion: str = "1.0"
    version: int = 1
    serialNumber: str
    metadata: Metadata
    recommendations: List[AgentRecommendation]
    summary: Summary

    model_config = ConfigDict(extra="allow")


# ============================================================================
# Helper Functions
# ============================================================================

def load_report(filepath: str) -> DefenseReport:
    """
    Load and validate a defense report JSON file.

    Raises ValidationError if the file doesn't match the schema.
    """
    import json

    with open(filepath) as f:
        data = json.load(f)

    return DefenseReport(**data)


def validate_report_dict(report_dict: dict) -> DefenseReport:
    """
    Validate a report dictionary against the schema.

    Useful for validating before saving to disk.
    """
    return DefenseReport(**report_dict)


def generate_json_schema(output_file: str = "schema/defense-report-schema.json"):
    """
    Generate JSON schema file from Pydantic models.

    Run this after updating the Pydantic models to regenerate the JSON schema.
    """
    import json
    from pathlib import Path

    schema = DefenseReport.model_json_schema()

    # Add custom metadata
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"
    schema["$id"] = "https://compass.defense-report.schema.json"

    output_path = Path(output_file)
    output_path.parent.mkdir(exist_ok=True, parents=True)

    with open(output_path, 'w') as f:
        json.dump(schema, f, indent=2)

    print(f"Generated JSON schema: {output_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "generate-schema":
            generate_json_schema()
        elif sys.argv[1] == "validate":
            # Validate a specific report file
            if len(sys.argv) > 2:
                report = load_report(sys.argv[2])
                print(f"✓ Valid defense report")
                print(f"  Agents ran: {report.summary.agents_ran}")
                print(f"  Recommendations: {len(report.recommendations)}")
                print(f"  Overall coverage: {report.summary.overall_coverage}%")
            else:
                print("Usage: python3 defense_report_schema.py validate <report.json>")
        else:
            # Validate specific file
            report = load_report(sys.argv[1])
            print(f"✓ Valid: {report.bomFormat} v{report.specVersion}")
    else:
        print("Usage:")
        print("  python3 defense_report_schema.py generate-schema")
        print("  python3 defense_report_schema.py validate <report.json>")
        print("  python3 defense_report_schema.py <report.json>")
