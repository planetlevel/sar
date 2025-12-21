# Endpoint Authorization Agent Improvements (Framework-Agnostic)

**CRITICAL PRINCIPLE**: The authorization agent MUST be framework-agnostic. All framework-specific knowledge (annotations, role conventions, config patterns) must come from:
1. Framework definition files (`frameworks/*.json`)
2. AI analysis of the specific codebase
3. NOT hardcoded in the agent

## Priority 1: Framework-Agnostic Critical Fixes

### 1. AI-Driven Role Convention Detection
**Problem**: Mixed role expression conventions cause implementation errors

**Framework-Agnostic Solution**:
- Let AI analyze existing authorization expressions from discovered mechanisms
- AI identifies convention patterns in THIS codebase
- AI generates examples using detected convention
- AI warns if multiple conventions found

**Implementation**:
```python
def _detect_role_convention_via_ai(self, standard_mechanisms: List[Dict]) -> Dict:
    """
    Use AI to analyze authorization expressions and detect conventions

    Gives AI:
    - Sample of 50 authorization expressions from discovered mechanisms
    - Ask: "What role/authority convention is used? Detect pattern."

    Returns:
    - Detected convention description
    - Example expressions following convention
    - Inconsistencies found
    - Recommendation for consistency
    """

    # Collect sample authorization expressions
    expressions = []
    for mechanism in standard_mechanisms[:50]:
        for behavior in mechanism['behaviors']:
            if 'authorization_expression' in behavior:
                expressions.append(behavior['authorization_expression'])

    prompt = f"""
    Analyze these authorization expressions from the codebase:
    {json.dumps(expressions[:50], indent=2)}

    Identify:
    1. Role/authority convention used (e.g., "ROLE_" prefix or not)
    2. Expression syntax (hasRole, hasAuthority, etc.)
    3. Any inconsistencies
    4. Recommendation for standardization

    Return JSON with detected patterns and examples.
    """

    # AI analyzes and returns convention
```

### 2. AI-Powered "Public Endpoint" Guidance
**Problem**: Generic "PUBLIC role" guidance doesn't match framework patterns

**Framework-Agnostic Solution**:
- AI analyzes framework definitions to understand public endpoint patterns
- For Spring: `permitAll()`, `@PermitAll`
- For Express: middleware-less routes
- For Django: `@permission_classes([AllowAny])`
- AI generates framework-appropriate guidance

**Implementation**:
```python
def _generate_public_endpoint_guidance(self, framework_name: str, framework_config: Dict) -> str:
    """
    Use framework definition + AI to generate appropriate public endpoint guidance

    Looks at:
    - Framework's public access patterns from framework JSON
    - Existing public endpoints in codebase
    - Asks AI: "How should public endpoints be marked in {framework}?"
    """

    # Extract public access patterns from framework definition
    public_patterns = framework_config.get('architecture', {}) \
                                     .get('authorization', {}) \
                                     .get('public_access_patterns', [])

    # If not in framework definition, ask AI
    if not public_patterns:
        prompt = f"""
        Framework: {framework_name}

        How are public (unauthenticated) endpoints typically marked?
        - Configuration approach?
        - Annotation/decorator approach?
        - Best practices?

        Provide framework-specific guidance.
        """
        # AI returns framework-appropriate pattern
```

### 3. AI Defines "Protected" Standard for This App
**Problem**: "Protected" definition varies by framework and architecture

**Framework-Agnostic Solution**:
- AI analyzes discovered mechanisms to understand THIS app's protection model
- AI determines: annotation-based? config-based? both?
- AI generates protection standard for THIS specific application

**Implementation**:
```python
def _ai_define_protected_standard(self, evidence: Dict) -> Dict:
    """
    Let AI define what "protected" means for THIS application

    Gives AI:
    - Discovered mechanisms and where they're applied
    - Framework detection results
    - Architecture pattern (endpoint vs service layer)

    AI returns:
    - Definition of "protected" for this app
    - Classification categories (public/authenticated/role-based)
    - How to verify protection for new endpoints
    """

    prompt = f"""
    This application uses {framework} with {len(mechanisms)} authorization mechanisms.

    Mechanisms found:
    {json.dumps(mechanism_summary, indent=2)}

    Architecture: {architecture_pattern}

    Define:
    1. What "protected" means in this application
    2. Classification categories for endpoints
    3. How protection is verified
    4. Framework-specific best practices
    """
```

## Priority 2: AI-Enhanced Actionability

### 4. AI-Generated Route Classification Table
**Problem**: Generic table doesn't use framework-specific patterns

**Framework-Agnostic Solution**:
- Give AI: framework name, detected patterns, sample routes
- AI classifies each route using framework conventions
- AI suggests framework-appropriate protection

**Implementation**:
```python
def _ai_classify_routes(self, unprotected_routes: List[Dict],
                        framework_info: Dict) -> List[Dict]:
    """
    AI classifies each unprotected route with framework-appropriate suggestions

    For each route:
    - Path pattern (e.g., /health, /api/admin/*, /api/users/{id})
    - HTTP method
    - Controller/handler name

    AI returns:
    - Classification: public / authenticated / role-based
    - Suggested protection mechanism (framework-specific)
    - Rationale
    """

    # Batch routes for AI classification
    batch_size = 50
    for i in range(0, len(routes), batch_size):
        batch = routes[i:i+batch_size]

        prompt = f"""
        Framework: {framework_name}
        Detected patterns: {detected_patterns}

        Classify these routes:
        {json.dumps(batch, indent=2)}

        For each route provide:
        - classification: public | authenticated | role-based
        - suggested_mechanism: framework-specific annotation/config
        - rationale: why this classification
        """
```

### 5. Framework-Agnostic "Default Deny" Guidance
**Problem**: Default deny varies by framework

**Framework-Agnostic Solution**:
- AI generates framework-specific default deny statement
- Uses framework patterns from definitions
- Explains how to implement in THIS framework

**Implementation**:
```python
def _generate_default_deny_guidance(self, framework_name: str) -> str:
    """
    AI generates framework-appropriate default deny guidance

    For Spring: "anyRequest().authenticated()"
    For Express: Default middleware requiring auth
    For Django: DEFAULT_PERMISSION_CLASSES
    """

    prompt = f"""
    Framework: {framework_name}

    How should default-deny be implemented?
    - What configuration enforces "require auth by default"?
    - What's the idiomatic approach?
    - Code example?
    """
```

### 6. AI-Generated Definition of Done
**Problem**: Done criteria are framework-specific

**Framework-Agnostic Solution**:
- AI generates measurable criteria based on framework capabilities
- Includes framework-specific enforcement mechanisms
- Uses detected patterns and architecture

**Implementation**:
```python
def _ai_generate_done_criteria(self, framework_info: Dict,
                                architecture: Dict) -> List[str]:
    """
    AI generates framework-specific done criteria

    Returns checklist like:
    - [ ] All {total_routes} routes explicitly classified
    - [ ] Public endpoints documented in {framework_config_location}
    - [ ] CI enforces {framework_specific_check}
    - [ ] Authorization tests cover {coverage_target}%
    """
```

### 7. AI-Generated Test/Guardrail Code
**Problem**: Test code is framework-specific

**Framework-Agnostic Solution**:
- Framework JSON includes test patterns (new section)
- AI generates tests using framework testing conventions
- Uses actual routes and patterns from THIS codebase

**Implementation in framework JSON**:
```json
{
  "architecture": {
    "authorization": {
      "test_patterns": {
        "endpoint_enumeration": "// Spring Boot test pattern",
        "assertion_pattern": "// How to assert auth required",
        "public_allowlist": "// Where public endpoints listed"
      }
    }
  }
}
```

**Agent uses AI**:
```python
def _generate_test_code(self, framework_info: Dict,
                        unprotected_routes: List[Dict]) -> str:
    """
    AI generates framework-specific test code

    Gives AI:
    - Framework test patterns (from JSON)
    - Actual routes from this codebase
    - Detected authorization patterns

    AI returns:
    - Complete, runnable test code
    - Using framework test conventions
    - Covering discovered routes
    """
```

## Priority 3: Framework-Aware Technical Accuracy

### 8. Version-Aware Recommendations via AI
**Problem**: Framework version determines best practices

**Framework-Agnostic Solution**:
- Detect framework version (from dependencies)
- Store in framework_info
- AI generates version-appropriate recommendations

**Implementation**:
```python
def _ai_generate_config_examples(self, framework_name: str,
                                  version: str,
                                  patterns: Dict) -> str:
    """
    AI generates configuration examples for detected version

    For Spring 5.7+: SecurityFilterChain
    For Spring 5.3-5.6: WebSecurityConfigurerAdapter (note deprecation)
    For Express 5.x: Different middleware API
    """

    prompt = f"""
    Framework: {framework_name} version {version}
    Detected patterns: {patterns}

    Generate configuration example:
    - Use version-appropriate API
    - Note any deprecations
    - Show recommended approach for this version
    """
```

### 9. Scope Discipline via AI Prompt Engineering
**Problem**: AI mentions out-of-scope concerns (service layer, etc.)

**Framework-Agnostic Solution**:
- Clearly define scope in AI prompts
- Explicitly tell AI what NOT to mention
- Filter AI responses for scope violations

**Implementation**:
```python
def _build_recommendation_prompt(self, context: Dict, evidence: Dict) -> str:
    """
    Prompt explicitly defines scope boundaries
    """

    scope_boundaries = """
    CRITICAL SCOPE LIMITATIONS:
    - ONLY discuss endpoint/route-level authorization
    - DO NOT mention service-layer authorization
    - DO NOT mention data-level authorization (IDOR)
    - DO NOT mention authentication mechanisms
    - Focus purely on: "Can role X access route Y?"
    """

    return f"""
    {scope_boundaries}

    Your task: Analyze endpoint authorization coverage...
    """
```

## Priority 4: Evidence Utilization (Framework-Agnostic)

### 10. AI Explains Protection Mechanisms
**Problem**: Users don't understand WHY routes are protected/unprotected

**Framework-Agnostic Solution**:
- AI analyzes discovered mechanisms and explains them
- AI shows how mechanisms map to routes
- AI uses framework terminology

**Implementation**:
```python
def _ai_explain_protection(self, route: Dict,
                           mechanisms: List[Dict]) -> Dict:
    """
    AI explains how (or why not) a route is protected

    Returns:
    {
      "route": "GET /api/users",
      "protected": true,
      "mechanism": "@PreAuthorize annotation on method",
      "expression": "hasRole('ADMIN')",
      "source_location": "UserController:45",
      "explanation": "This route requires ADMIN role via method annotation"
    }
    """
```

## Implementation Architecture

### Framework Definition Enhancement
Add to `frameworks/*.json`:

```json
{
  "architecture": {
    "authorization": {
      "role_conventions": {
        "description": "How roles/authorities are typically expressed",
        "examples": ["hasRole('ROLE_X')", "hasAuthority('SCOPE')"]
      },
      "public_access_patterns": {
        "config": ["permitAll()", "authorize: false"],
        "annotations": ["@PermitAll", "@AllowAny"],
        "description": "How public endpoints are marked"
      },
      "default_deny": {
        "config_location": "SecurityConfig.java",
        "pattern": ".anyRequest().authenticated()",
        "description": "How to enforce default-deny"
      },
      "test_patterns": {
        "endpoint_enumeration": "How to get all routes in test",
        "assertion": "How to assert auth required",
        "examples": ["Test code patterns"]
      }
    }
  }
}
```

### Agent Flow (All via AI)

1. **Discovery Phase**: Query CPG, load framework definitions
2. **Convention Detection**: AI analyzes discovered mechanisms → identifies patterns
3. **Classification**: AI classifies routes using detected patterns
4. **Recommendation Generation**: AI generates using:
   - Framework-specific patterns (from JSON)
   - Detected conventions (from Phase 2)
   - Actual routes (from Phase 1)
   - Version info (from dependencies)

### AI Prompt Strategy

Every framework-specific detail comes from AI given:
- Framework name and version
- Framework definition JSON
- Discovered mechanisms/patterns
- Sample code from codebase

**Example Prompt Pattern**:
```
Framework: {detected_framework} version {detected_version}
Framework patterns: {from_framework_json}
Discovered in codebase: {actual_mechanisms}

Generate recommendation that:
- Uses framework conventions
- Is version-appropriate
- Matches detected patterns
- Provides concrete examples
```

## Success Criteria (Framework-Agnostic)

✅ Agent code has ZERO framework-specific logic
✅ All conventions detected via AI analysis
✅ All code examples generated by AI (not templated)
✅ Framework definitions provide patterns, not logic
✅ Works for Spring, Express, Django, Rails, etc. without code changes
✅ AI explanations use framework-appropriate terminology

## What Moves to Framework Definitions

Add to each `frameworks/*.json`:
- Role/authority conventions (examples, not logic)
- Public access patterns (how it's done)
- Default-deny patterns (typical configuration)
- Test patterns (how to enumerate routes)
- Version-specific deprecations (notes)

## What Stays in Agent (Framework-Agnostic)

- Query CPG for authorization behaviors
- Call AI with framework context
- Parse AI responses
- Build evidence structures
- Calculate metrics (coverage %)
- Generate reports

## Migration Path

1. **Phase 1**: Enhance framework JSONs with authorization patterns
2. **Phase 2**: Migrate hardcoded logic to AI prompts
3. **Phase 3**: Add convention detection via AI
4. **Phase 4**: Test on multiple frameworks (Spring, Express, Django)
