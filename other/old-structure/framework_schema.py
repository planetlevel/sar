"""
Pydantic models for framework definitions.

This is the single source of truth for the framework schema.
The JSON schema file is generated from these models.
"""

from typing import List, Dict, Optional, Union, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator


# ============================================================================
# Pattern Group Models
# ============================================================================

class PatternGroup(BaseModel):
    """
    A pattern group defines what to search for and how to search.

    Examples:
        # Annotation search
        PatternGroup(
            target="joern",
            search_type="annotation_name",
            pattern=["PreAuthorize", "Secured"],
            description="Authorization annotations"
        )

        # Method signature search
        PatternGroup(
            target="joern",
            search_type="method_signature",
            signature="java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
            description="Process execution"
        )
    """
    target: Optional[Literal["filename", "filecontent", "joern"]] = Field(
        None,
        description="What to search (the target of the search)"
    )

    search_type: Optional[Literal[
        "method_signature",
        "method_name_regex",
        "class_name_regex",
        "annotation_name",
        "annotation_name_regex",
        "import",
        "regex",
        "xml_element",
        "xpath",
        "yaml_path",
        "json_value"
    ]] = Field(
        None,
        description="The specific search method to use"
    )

    pattern: Optional[Union[str, List[str], Dict[str, str]]] = Field(
        None,
        description="Pattern(s) to search for (annotation names, class names, etc.). Can be string, list of strings, or dict of named patterns"
    )

    signature: Optional[Union[str, List[str]]] = Field(
        None,
        description="Method signature(s) for method_signature search_type"
    )

    description: Optional[str] = Field(
        None,
        description="Human-readable description of what this pattern detects"
    )

    # Allow extra fields for detection section flexibility (like "levels" for package_hierarchy)
    model_config = ConfigDict(extra="allow")

    @model_validator(mode='after')
    def validate_pattern_signature_consistency(self):
        """Ensure pattern/signature fields are used consistently with search_type"""
        if self.search_type == 'method_signature':
            if not self.signature and not self.pattern:
                raise ValueError("method_signature search_type requires 'signature' field")
        else:
            if self.signature and not self.pattern:
                raise ValueError(f"'signature' field should only be used with method_signature search_type, not {self.search_type}")

        if not self.pattern and not self.signature:
            # Allow empty pattern groups for flexibility (may be filled in later)
            pass

        return self


# ============================================================================
# Detection Models
# ============================================================================

class FileContentPattern(BaseModel):
    """Pattern for searching within specific files"""
    target: Literal["filecontent"] = "filecontent"
    search_type: Literal["regex", "xml_element", "xpath", "yaml_path", "json_value"]
    files: Optional[List[str]] = None
    pattern: Optional[str] = None
    query: Optional[str] = None  # For xpath
    path: Optional[str] = None   # For yaml_path, json_value
    value: Optional[str] = None
    group: Optional[int] = None  # Regex capture group
    library: Optional[str] = None  # For dependency detection


class DependencyPattern(BaseModel):
    """Pattern for detecting dependencies in package files"""
    pattern: Optional[str] = None  # For build.gradle
    artifact: Optional[str] = None  # For pom.xml
    library: str


class Detection(BaseModel):
    """Framework detection patterns"""
    binaries: Optional[PatternGroup] = None
    files: Optional[PatternGroup] = None
    dependencies: Optional[Dict[str, List[DependencyPattern]]] = None  # filename -> patterns
    imports: Optional[PatternGroup] = None
    annotations: Optional[PatternGroup] = None
    code_patterns: Optional[PatternGroup] = None
    package_hierarchy: Optional[Dict] = None  # Complex structure, keep as dict for now


# ============================================================================
# Architecture Models
# ============================================================================

class RoutingArchitecture(BaseModel):
    """HTTP routing patterns"""
    handler_classes: Optional[List[PatternGroup]] = Field(default_factory=list)
    route_definitions: Optional[List[PatternGroup]] = Field(default_factory=list)
    parameters: Optional[List[PatternGroup]] = Field(default_factory=list)


class DatabaseArchitecture(BaseModel):
    """Database operation patterns"""
    sql_queries: Optional[List[PatternGroup]] = Field(default_factory=list)
    orm_operations: Optional[List[PatternGroup]] = Field(default_factory=list)
    jpa_operations: Optional[List[PatternGroup]] = Field(default_factory=list)
    repository_pattern: Optional[List[PatternGroup]] = Field(default_factory=list)
    nosql_operations: Optional[List[PatternGroup]] = Field(default_factory=list)
    ldap_queries: Optional[List[PatternGroup]] = Field(default_factory=list)
    xpath_queries: Optional[List[PatternGroup]] = Field(default_factory=list)


class ExecutionArchitecture(BaseModel):
    """Code and command execution patterns"""
    native: Optional[List[PatternGroup]] = Field(default_factory=list)
    expression: Optional[List[PatternGroup]] = Field(default_factory=list)
    reflection: Optional[List[PatternGroup]] = Field(default_factory=list)
    deserialization: Optional[List[PatternGroup]] = Field(default_factory=list)
    script: Optional[List[PatternGroup]] = Field(default_factory=list)


class CommunicationArchitecture(BaseModel):
    """Network communication patterns"""
    http: Optional[List[PatternGroup]] = Field(default_factory=list)
    socket: Optional[List[PatternGroup]] = Field(default_factory=list)
    rest: Optional[List[PatternGroup]] = Field(default_factory=list)
    messaging: Optional[List[PatternGroup]] = Field(default_factory=list)


class DataFlowArchitecture(BaseModel):
    """Data flow and transformation patterns"""
    sources: Optional[List[PatternGroup]] = Field(default_factory=list)
    serialization: Optional[List[PatternGroup]] = Field(default_factory=list)
    xml_parsing: Optional[List[PatternGroup]] = Field(default_factory=list)
    propagators: Optional[List[PatternGroup]] = Field(default_factory=list)


class SecurityArchitecture(BaseModel):
    """Security control patterns"""
    authentication: Optional[List[PatternGroup]] = Field(default_factory=list)
    authorization: Optional[List[PatternGroup]] = Field(default_factory=list)
    cryptography: Optional[List[PatternGroup]] = Field(default_factory=list)
    input_validation: Optional[List[PatternGroup]] = Field(default_factory=list)
    sanitization: Optional[List[PatternGroup]] = Field(default_factory=list)
    output_encoding: Optional[List[PatternGroup]] = Field(default_factory=list)
    cookie_security: Optional[List[PatternGroup]] = Field(default_factory=list)
    logging: Optional[List[PatternGroup]] = Field(default_factory=list)
    secrets: Optional[List[PatternGroup]] = Field(default_factory=list)
    privacy: Optional[List[PatternGroup]] = Field(default_factory=list)


class PresentationArchitecture(BaseModel):
    """Response generation and rendering patterns"""
    template_rendering: Optional[List[PatternGroup]] = Field(default_factory=list)
    response_output: Optional[List[PatternGroup]] = Field(default_factory=list)
    redirects: Optional[List[PatternGroup]] = Field(default_factory=list)
    cookies: Optional[List[PatternGroup]] = Field(default_factory=list)
    headers: Optional[List[PatternGroup]] = Field(default_factory=list)


class IntegrationArchitecture(BaseModel):
    """External system integration patterns"""
    filesystem: Optional[List[PatternGroup]] = Field(default_factory=list)
    email: Optional[List[PatternGroup]] = Field(default_factory=list)
    http_clients: Optional[List[PatternGroup]] = Field(default_factory=list)
    external_services: Optional[List[PatternGroup]] = Field(default_factory=list)


class AIArchitecture(BaseModel):
    """AI and LLM operation patterns"""
    chat: Optional[List[PatternGroup]] = Field(default_factory=list)
    completion: Optional[List[PatternGroup]] = Field(default_factory=list)
    embedding: Optional[List[PatternGroup]] = Field(default_factory=list)
    image: Optional[List[PatternGroup]] = Field(default_factory=list)
    audio: Optional[List[PatternGroup]] = Field(default_factory=list)
    vision: Optional[List[PatternGroup]] = Field(default_factory=list)
    function_calling: Optional[List[PatternGroup]] = Field(default_factory=list)
    streaming: Optional[List[PatternGroup]] = Field(default_factory=list)
    agents: Optional[List[PatternGroup]] = Field(default_factory=list)
    fine_tuning: Optional[List[PatternGroup]] = Field(default_factory=list)


class Architecture(BaseModel):
    """All architecture analysis patterns"""
    routing: Optional[RoutingArchitecture] = None
    database: Optional[DatabaseArchitecture] = None
    execution: Optional[ExecutionArchitecture] = None
    communication: Optional[CommunicationArchitecture] = None
    data_flow: Optional[DataFlowArchitecture] = None
    security: Optional[SecurityArchitecture] = None
    presentation: Optional[PresentationArchitecture] = None
    integration: Optional[IntegrationArchitecture] = None
    ai: Optional[AIArchitecture] = None


# ============================================================================
# Top-Level Framework Model
# ============================================================================

class RepositoryInfo(BaseModel):
    """Source repository metadata"""
    url: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None
    tag: Optional[str] = None
    date: Optional[str] = None


class FrameworkDefinition(BaseModel):
    """
    Complete framework definition.

    This is the root model - load JSON files into this.
    """
    schema_: Optional[str] = Field(None, alias="$schema", description="JSON schema reference")
    name: str = Field(..., description="Framework name")
    extends: Optional[str] = Field(None, description="Base framework/language this extends")
    languages: List[str] = Field(..., min_length=1, description="Supported languages")
    repository: Optional[RepositoryInfo] = None
    detection: Optional[Detection] = None
    metadata: Optional[Dict] = None  # Keep flexible for now
    architecture: Optional[Architecture] = None

    model_config = ConfigDict(
        extra="allow",  # Allow unknown fields for flexibility
        populate_by_name=True  # Allow both "schema_" and "$schema"
    )


# ============================================================================
# Helper Functions
# ============================================================================

def load_framework(filepath: str) -> FrameworkDefinition:
    """
    Load and validate a framework JSON file.

    Raises ValidationError if the file doesn't match the schema.
    """
    import json
    from pathlib import Path

    with open(filepath) as f:
        data = json.load(f)

    return FrameworkDefinition(**data)


def load_all_frameworks(frameworks_dir: str = "frameworks") -> Dict[str, FrameworkDefinition]:
    """
    Load all framework files from a directory.

    Returns dict of framework_name -> FrameworkDefinition
    Skips invalid files and prints warnings.
    """
    from pathlib import Path

    frameworks = {}
    frameworks_path = Path(frameworks_dir)

    for json_file in frameworks_path.glob("*.json"):
        try:
            framework = load_framework(json_file)
            frameworks[framework.name] = framework
        except Exception as e:
            print(f"WARNING: Failed to load {json_file.name}: {e}")

    return frameworks


def generate_json_schema(output_file: str = "schema/framework-schema.json"):
    """
    Generate JSON schema file from Pydantic models.

    Run this after updating the Pydantic models to regenerate the JSON schema.
    """
    import json
    from pathlib import Path

    schema = FrameworkDefinition.model_json_schema()

    # Add custom metadata
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"
    schema["$id"] = "https://compass.schema.json"

    output_path = Path(output_file)
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(schema, f, indent=2)

    print(f"Generated JSON schema: {output_path}")


if __name__ == "__main__":
    # Example usage and testing
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "generate-schema":
            generate_json_schema()
        elif sys.argv[1] == "validate":
            # Validate all framework files
            frameworks = load_all_frameworks()
            print(f"✓ Loaded {len(frameworks)} valid framework definitions")
            for name, fw in list(frameworks.items())[:5]:
                auth_count = len(fw.architecture.security.authorization) if fw.architecture and fw.architecture.security and fw.architecture.security.authorization else 0
                print(f"  - {name}: {auth_count} authorization patterns")
        else:
            # Validate specific file
            framework = load_framework(sys.argv[1])
            print(f"✓ Valid: {framework.name}")
    else:
        print("Usage:")
        print("  python3 framework_schema.py generate-schema")
        print("  python3 framework_schema.py validate")
        print("  python3 framework_schema.py frameworks/spring-security.json")
