# Defense Analysis System - Design

## Problem Statement

Traditional framework-based security analysis fails when applications use custom security controls:

### Example: Teamserver Authorization
- **Standard analysis**: Found 8 "authorization" behaviors (0.66% coverage)
  - False positives: `allowedvalues()` method calls (NOT authorization)
  - Missed patterns: Custom `@Superadmin`, `@SystemAdminNoServerAdmin` annotations
- **Reality**: 99%+ of endpoints protected by custom meta-annotations
  - `@Superadmin` wraps `@PreAuthorize("isSuperadmin()")`
  - `@SystemAdminNoServerAdmin` wraps `@PreAuthorize("isSystemAdmin() and isMaxNoServerAdmin()")`
  - Every superadmin controller method has authorization

### Why Standard Analysis Fails

1. **Meta-annotations invisible**: Joern CPG sees `@Superadmin`, not the underlying `@PreAuthorize`
2. **Limited patterns**: Framework definitions only check standard Spring Security annotations
3. **False positives**: Keyword matching catches unrelated code
4. **No adaptation**: Can't learn project-specific patterns

## Solution: AI-Guided Defense Discovery

### Core Approach

```
Standard Analysis:
  Framework Config → Joern Query → Extract Behaviors
  ❌ Only finds pre-configured patterns
  ❌ Misses custom implementations

AI-Guided Discovery:
  Low Coverage Signal → AI Hypothesis Generation → Targeted Queries → Validation → Extract All
  ✅ Discovers custom patterns
  ✅ Adapts to project
  ✅ Validates findings
```

### Three-Phase Discovery

#### Phase 1: Signal Detection
Determine if custom discovery is needed:
```python
def should_run(self) -> Dict[str, Any]:
    # Count standard patterns found
    standard_coverage = self._calculate_standard_coverage()

    # Look for indicators that custom patterns exist
    has_indicators = self._check_indicators()

    # Run discovery if low coverage + strong indicators
    return {
        'should_run': (standard_coverage < 10% and has_indicators),
        'confidence': 0.0-1.0,
        'signals': {...}
    }
```

**Example signals:**
- **Authorization**: Low coverage + admin routes + Spring Security dependency
- **DOR**: Many ID-based endpoints + low ownership checks
- **Input Validation**: Large API surface + few standard validators

#### Phase 2: AI Hypothesis Generation
Ask AI to theorize about custom patterns:
```python
def generate_hypotheses(self) -> List[Dict]:
    # Sample relevant code (controllers, security classes, etc.)
    samples = self._sample_code()

    # Get indicators (annotations, imports, method signatures)
    indicators = self._get_indicators()

    # Ask AI to generate theories
    prompt = f"""
    Application has {len(endpoints)} endpoints with {standard_coverage}%
    standard pattern coverage, but strong indicators of custom security:

    Sample code:
    {samples}

    Indicators:
    {indicators}

    Generate 3-5 hypotheses about custom {defense_type} mechanisms.
    For each hypothesis, provide:
    - pattern_type: What kind of pattern
    - description: How it works
    - detection_query: Joern query to find instances
    - confidence: How likely this exists
    """

    return ai.query(prompt)
```

**AI analyzes:**
- Imports (security frameworks, custom packages)
- Annotations (custom, meta, standard)
- Method patterns (naming, signatures)
- Class structures (interceptors, aspects, filters)

#### Phase 3: Hypothesis Testing & Extraction
Test each hypothesis and extract all instances:
```python
def test_hypothesis(self, hypothesis: Dict) -> Optional[Dict]:
    # 1. Run detection query
    evidence = cpg_tool.execute_query(hypothesis['detection_query'])

    if len(evidence) < threshold:
        return None  # Not enough evidence

    # 2. Validate with AI (avoid false positives)
    validation = ai.query(f"""
        Hypothesis: {hypothesis['description']}
        Evidence: {evidence[:10]}

        Is this REALLY {defense_type}?
        - Does it enforce security?
        - Applied consistently?
        - What's the enforcement mechanism?

        Return: {{confirmed: bool, reasoning: str}}
    """)

    if not validation['confirmed']:
        return None

    # 3. Extract ALL instances
    all_instances = cpg_tool.execute_query(hypothesis['extraction_query'])

    return {
        'pattern': hypothesis,
        'instances': all_instances,
        'coverage': calculate_coverage(all_instances)
    }
```

### Granular Plugin Architecture

Each plugin focuses on ONE security control:

```
Access Control:
├─ url_authorization         ← Framework-level route protection
├─ method_authorization       ← Method-level annotations
└─ dor_protection            ← Resource ownership validation

Authentication:
├─ authentication_mechanism   ← Login flows, session management
└─ credential_validation      ← Password checks, MFA

Input Defense:
├─ injection_prevention       ← Parameterized queries, ORM
├─ input_validation          ← Bean validation, custom validators
└─ sanitization              ← Input sanitization

...
```

**Why granular?**
- **Precise AI prompts**: "Find URL-level auth" vs "Find authorization"
- **Better signals**: URL auth indicators ≠ DOR indicators
- **Actionable output**: "87% DOR coverage, 12 unprotected endpoints" vs "low authorization"
- **Focused queries**: Each plugin optimizes for its control type

## Pipeline Design

### Minimal Input Requirements

Only 2 inputs needed:

```python
1. CPG (Code Property Graph)
   ├─ Generated by Joern from source code
   ├─ Enables Joern query execution
   └─ Required for ALL defense analysis

2. Endpoints (List[Dict])
   ├─ [{route, httpMethod, controller}, ...]
   ├─ Used for coverage calculations
   └─ Simple extraction from CPG
```

**Eliminated steps:**
- ❌ Framework detection (plugins do their own)
- ❌ Project info (not used by plugins)
- ❌ Controller analysis (redundant with endpoints)
- ❌ Standard behavior extraction (incomplete/wrong)

### Execution Flow

```
DefensePluginEngine
    │
    ├─> Load Plugins
    │   └─> Each plugin registers itself
    │
    ├─> For Each Plugin:
    │   │
    │   ├─> should_run()
    │   │   ├─> Check standard coverage
    │   │   ├─> Look for indicators
    │   │   └─> Decide: run or skip
    │   │
    │   ├─> analyze() [if should_run]
    │   │   ├─> generate_hypotheses()
    │   │   │   └─> AI analyzes sample code
    │   │   │
    │   │   ├─> test_hypothesis() [for each]
    │   │   │   ├─> Run detection query
    │   │   │   ├─> Validate with AI
    │   │   │   └─> Extract all instances
    │   │   │
    │   │   └─> assess_quality()
    │   │       └─> Evaluate coverage + gaps
    │   │
    │   └─> Return Results
    │       ├─ patterns_found: [...]
    │       ├─ coverage: float
    │       ├─ behaviors: [...]
    │       └─ assessment: {...}
    │
    └─> Consolidate Results
        ├─> Group by category
        ├─> Merge behaviors
        └─> Generate summary
```

## Data Structures

### Plugin Result

```python
{
    'plugin_id': 'url_authorization',
    'plugin_name': 'URL-Based Authorization',
    'category': 'access_control',
    'ran': True,
    'control_found': True,
    'coverage': 99.9,
    'patterns': [
        {
            'pattern_type': 'meta_annotation',
            'pattern_name': '@Superadmin',
            'description': 'Meta-annotation protecting controller classes',
            'underlying_mechanism': '@PreAuthorize("isSuperadmin()")',
            'detection_query': '...',
            'extraction_query': '...',
            'confidence': 0.95,
            'instances_found': 450
        }
    ],
    'behaviors': [
        {
            'type': 'defense',
            'category': 'authorization',
            'subcategory': 'url_authorization',
            'route': '/ng/superadmin/ac/groups',
            'httpMethod': 'GET',
            'controller': 'NgSuperadminAccessGroupsRestController',
            'location': 'NgSuperadminAccessGroupsRestController.java:158',
            'code': '@SystemAdminNoServerAdmin',
            'snippet': 'Method protected by @SystemAdminNoServerAdmin',
            'discovery_source': 'ai_url_auth_plugin'
        }
    ],
    'assessment': {
        'status': 'present|partial|absent',
        'quality': 'strong|adequate|weak|none',
        'gaps': [
            '12 endpoints lack URL-level protection',
            'Public endpoints not explicitly marked'
        ]
    },
    'at_risk_endpoints': [...]  # Plugin-specific
}
```

### Consolidated Results

```python
{
    'plugins_ran': 5,
    'plugins_skipped': 6,
    'results_by_plugin': {
        'url_authorization': {...},
        'dor_protection': {...},
        ...
    },
    'all_new_behaviors': [...],  # All behaviors from all plugins
    'summary_by_category': {
        'access_control': {
            'plugins': [
                {'id': 'url_authorization', 'found': True},
                {'id': 'method_authorization', 'found': True},
                {'id': 'dor_protection', 'found': True}
            ],
            'controls_found': 3,
            'total_behaviors': 1450
        },
        'input_defense': {...},
        ...
    }
}
```

## AI Integration

### Prompt Design Principles

1. **Specific Context**: Give AI exact information about what to look for
   ```
   Bad:  "Find authorization patterns"
   Good: "Find URL-level authorization (controller annotations, SecurityFilterChain)"
   ```

2. **Examples**: Show AI what kinds of patterns exist
   ```
   Common patterns:
   - Meta-annotations wrapping @PreAuthorize
   - AOP interceptors on URL patterns
   - Custom security filters
   ```

3. **Anti-patterns**: Tell AI what to EXCLUDE
   ```
   EXCLUDE:
   - Method-level annotations (different plugin)
   - Parameter validation (not authorization)
   - allowedvalues() methods (false positive)
   ```

4. **Output Format**: Request structured, parseable responses
   ```json
   Return JSON array of hypotheses:
   [{"pattern_type": "...", "detection_query": "...", ...}]
   ```

### AI Query Optimization

- **Cache responses**: Same sample code → same hypotheses
- **Batch validation**: Validate multiple patterns in one call
- **Progressive depth**: Start with simple queries, go deeper only if needed
- **Cost awareness**: Haiku for simple checks, Sonnet for complex reasoning

## Quality Assessment

Each plugin evaluates control quality:

### Coverage Metrics
```python
coverage = protected_endpoints / total_endpoints * 100

if coverage < 50:
    status = 'absent' (< 10%) or 'partial' (10-50%)
    quality = 'weak'
elif coverage < 95:
    status = 'partial'
    quality = 'adequate'
else:
    status = 'present'
    quality = 'strong'
```

### Gap Identification
```python
gaps = []

# Missing coverage
if coverage < 100:
    unprotected = identify_unprotected_endpoints()
    gaps.append(f"{len(unprotected)} endpoints lack {control_type}")

# Pattern inconsistencies
if multiple_patterns:
    gaps.append("Inconsistent protection mechanisms")

# Weak patterns
if using_weak_crypto:
    gaps.append("Uses deprecated algorithm (MD5)")

return gaps
```

## Design Decisions

### Why Eliminate Framework Detection?
- **Problem**: Framework detection uses broad patterns, misses specifics
- **Solution**: Each plugin detects what IT needs
- **Example**: URL auth plugin checks for Spring Security classes directly

### Why Skip Standard Behavior Extraction?
- **Problem**: Pre-configured patterns miss custom implementations, generate false positives
- **Solution**: Plugins do their own extraction after AI discovery
- **Result**: Only accurate behaviors included

### Why Granular Plugins?
- **Problem**: "Authorization" is too broad - URL auth ≠ DOR protection
- **Solution**: One plugin per control type
- **Result**: Precise analysis, actionable findings

### Why AI-First?
- **Problem**: Can't predict every custom pattern
- **Solution**: Let AI reason about code and discover patterns
- **Result**: Adapts to any project's approach

## Integration with Compass

The defense system can be used standalone or integrated with Compass:

### Standalone
```python
from defenses import DefensePluginEngine

engine = DefensePluginEngine(cpg_tool, project_dir, endpoints)
results = engine.run_all_plugins()
```

### Integrated
```python
# In orchestrator.py
def analyze_full(self):
    # ... existing Compass analysis ...

    # Run defense discovery
    from defenses import DefensePluginEngine

    defense_engine = DefensePluginEngine(
        cpg_tool=self.agent.cpg_tool,
        project_dir=self.project_dir,
        endpoints=results['endpoints']
    )

    defense_results = defense_engine.run_all_plugins()
    results['defense_discovery'] = defense_results

    # Merge behaviors
    results['behaviors'].extend(defense_results['all_new_behaviors'])

    return results
```

## Future Enhancements

### Learning System
- Cache discovered patterns per project
- Build pattern library across projects
- Suggest similar patterns from other projects

### Interactive Mode
- Show AI reasoning to user
- Let user confirm/reject patterns
- Refine queries based on feedback

### Pattern Sharing
- Export discovered patterns as framework definitions
- Import community-contributed patterns
- Version control for pattern evolution

### Performance Optimization
- Parallel plugin execution
- Query result caching
- Incremental analysis (only changed code)
