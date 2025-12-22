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
    suggested_role: Optional[str]
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


class ArchitectureEvaluation(BaseModel):
    """Architecture quality evaluation"""
    consistency: Dict[str, Any]
    centralization: Dict[str, Any]
    boundaries: Dict[str, Any]
    maintainability: Dict[str, Any]


class CoverageMetrics(BaseModel):
    """Coverage metrics"""
    metric_type: str
    exposures: int
    protected: int
    unprotected: int
    coverage: float
    explanation: str


class Evidence(BaseModel):
    """Evidence supporting the recommendation"""
    mechanisms: Optional[List[Mechanism]] = None
    defense_usage_matrix: Optional[DefenseUsageMatrix] = None
    roles: Optional[Roles] = None
    auth_pattern: Optional[AuthPattern] = None
    evaluation: Optional[ArchitectureEvaluation] = None  # DEPRECATED: Replaced by AI-based architecture evaluation in recommendation
    coverage_metrics: Optional[CoverageMetrics] = None
    proposed_access_matrix: Optional[ProposedAccessMatrix] = None

    # Allow extra fields for agent-specific evidence
    model_config = ConfigDict(extra="allow")


class Metrics(BaseModel):
    """Standardized metrics"""
    exposures: int
    protected: int
    unprotected: int
    coverage: float


class Recommendation(BaseModel):
    """Recommendation structure"""
    title: str
    summary: str
    design_recommendation: str
    implementation_recommendation: str
    rationale: str


class DefenseMetadata(BaseModel):
    """Defense mechanism metadata"""
    defense_name: str
    defense_type: str
    defense_mechanism: str
    defense_patterns: List[Union[str, Dict[str, Any]]]


class AgentRecommendation(BaseModel):
    """Single agent's recommendation"""
    agent_id: str
    agent_name: str
    ran: bool
    reason: Optional[str] = None  # If not run
    defense_metadata: Optional[DefenseMetadata] = None
    evidence: Optional[Evidence] = None
    metrics: Optional[Metrics] = None
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
