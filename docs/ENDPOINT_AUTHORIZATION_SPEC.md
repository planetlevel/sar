# Endpoint Authorization Agent Specification

**Agent ID:** `endpoint_authorization`
**Agent Name:** Endpoint Authorization (Route-Level Access Control)
**Category:** Authorization Defense
**Version:** 1.0

---

## Purpose

Analyzes **route-level access control** to determine if endpoints have appropriate authorization checks. Discovers both standard framework patterns (Spring Security, Django, etc.) and custom authorization mechanisms (meta-annotations, custom methods, interceptors).

### In Scope
- ✅ Can role X access endpoint Y?
- ✅ Which endpoints require which roles?
- ✅ Are authorization checks present and consistent?
- ✅ Framework-based authorization (annotations, middleware, filters)
- ✅ Custom authorization (meta-annotations, custom methods)
- ✅ Role analysis (generic vs domain-specific)

### Out of Scope
- ❌ Data-level authorization / IDOR (separate agent: `data_authorization`)
- ❌ Authentication mechanisms (separate agent: `authentication`)
- ❌ Session management (separate agent: `session_management`)
- ❌ Resource ownership validation (#userId == user.id patterns)

---

## Agent Architecture

### Three-Phase Analysis

```
Phase 1: Mechanism Discovery
    │
    ├─> Standard Pattern Detection
    │   └─> Load patterns from frameworks/*.json (algorithmic)
    │
    ├─> Custom Pattern Discovery (AI-Powered - if needed)
    │   ├─> Detect signals (low coverage + significant endpoints)
    │   ├─> Agentic investigation (multi-turn)
    │   ├─> Test patterns with Joern queries
    │   └─> Validate findings
    │
    └─> Consolidate All Mechanisms

Phase 2: Architecture Evaluation
    │
    └─> Evaluate Authorization Architecture
        ├─> Is authorization applied consistently across the application?
        ├─> Is the authorization approach centralized or fragmented?
        ├─> Are authorization decisions made at appropriate boundaries?
        ├─> Is the architecture maintainable and testable?

Phase 3: Finding Generation
    │
    ├─> Build Evidence
    │   ├─> Access Control Matrix (endpoints × authorization status)
    │   ├─> Role usage analysis
    │   ├─> Pattern consistency analysis
    │   └─> Coverage metrics
    │
    └─> Generate Recommendation (AI-Powered)
        ├─> Analyze gaps (unprotected endpoints, generic roles)
        ├─> Design recommendation (architecture-level guidance)
        ├─> Implementation recommendation (framework-specific steps)
        └─> Rationale (why this approach fits)
```

---

## Phase 1: Mechanism Discovery

### Standard Pattern Detection

**Algorithmic Approach: Load patterns from `frameworks/*.json`**

The agent does NOT hardcode any authorization patterns. Instead:

1. **Search frameworks directory** for matching framework JSON files
2. **Extract authorization patterns** from matched frameworks
3. **Execute queries** for each pattern found
4. **Calculate coverage** based on results

```python
def discover_standard_mechanisms(self) -> List[Dict]:
    """
    Algorithmic discovery: Load patterns from framework definitions
    NO hardcoded patterns - everything comes from frameworks/*.json
    """

    # 1. Load ALL framework definitions
    frameworks_dir = Path(__file__).parent.parent.parent / 'frameworks'
    all_frameworks = self._load_all_frameworks(frameworks_dir)

    # 2. Extract authorization patterns from each framework
    standard_mechanisms = []

    for framework_file, framework_config in all_frameworks.items():
        # Navigate to security.authorization section if it exists
        auth_patterns = self._extract_authorization_patterns(framework_config)

        if not auth_patterns:
            continue  # Framework has no authorization patterns defined

        # 3. Execute queries for this framework's patterns
        for pattern_category, pattern_config in auth_patterns.items():
            behaviors = self._execute_pattern_queries(
                framework=framework_file.stem,
                category=pattern_category,
                config=pattern_config
            )

            if behaviors:
                standard_mechanisms.append({
                    'framework': framework_file.stem,
                    'category': pattern_category,
                    'patterns': pattern_config.get('patterns', []),
                    'behaviors': behaviors,
                    'count': len(behaviors)
                })

    return standard_mechanisms

def _extract_authorization_patterns(self, framework_config: Dict) -> Dict:
    """
    Extract authorization patterns from framework definition

    Looks for: framework_config['architecture']['security']['authorization']
    Returns: Dict of pattern categories and their configs
    """
    try:
        return framework_config.get('architecture', {}) \
                              .get('security', {}) \
                              .get('authorization', {})
    except (KeyError, AttributeError):
        return {}
```

**Key Points:**
- ✅ NO hardcoded patterns anywhere
- ✅ Framework definitions are the source of truth
- ✅ May find 0 standard patterns (app uses completely custom authorization)
- ✅ May find patterns from multiple frameworks (Spring + custom annotations)
- ✅ Framework matching data can be shared with AI for context

### Custom Pattern Discovery (Agentic AI Exploration)

When standard patterns provide low coverage, use **agentic AI exploration** to iteratively discover authorization mechanisms.

#### Agentic Approach: Multi-Turn Investigation

**Instead of single-shot prompts, the AI agent:**
- Has access to **tools** (Joern queries, file reads, grep)
- Formulates and tests **hypotheses** iteratively
- **Refines** understanding based on results
- **Decides when done** (high confidence or exhausted paths)

This is a **conversation** where the AI drives the investigation.

**See:** [AGENTIC_DISCOVERY.md](AGENTIC_DISCOVERY.md) for complete implementation details.

**Two Investigation Types:**

#### 1. Custom Authorization Investigation

**Goal:** Find ANY authorization mechanisms not in frameworks/*.json

**The AI explores to discover:**
- Custom annotations protecting any endpoints
- Meta-annotations wrapping framework patterns
- Custom methods checking permissions
- Interceptors/filters performing authorization
- Works with any roles (USER, MANAGER, ADMIN, etc.)

**Key:** These are general authorization mechanisms, not admin-specific.

#### 2. Admin Authorization Investigation

**Goal:** Find SEPARATE authorization for administrative functions

**The AI explores to discover:**
- Admin authorization DIFFERENT from normal user auth
- Admin role isolation strategies
- Admin portal separation patterns
- Security boundaries preventing privilege escalation

**Key:** This is about **isolation as a defense strategy**, not just "authorization on admin routes"

---

#### Signal Detection

##### Custom Authorization Discovery

Run when standard patterns show low coverage:

```python
def should_run_custom_discovery(self) -> Dict[str, Any]:
    """
    Check signals that indicate custom authorization patterns exist

    IMPORTANT: Share framework matching results with AI for context
    """

    # Calculate coverage from standard framework patterns
    standard_coverage = len(self.standard_behaviors) / len(self.endpoints) * 100 if self.endpoints else 0

    # Gather framework context (what frameworks were checked)
    frameworks_checked = [f.stem for f in self.frameworks_dir.glob('*.json')]
    frameworks_matched = [m['framework'] for m in self.standard_mechanisms]

    signals = {
        'standard_coverage': standard_coverage,
        'total_endpoints': len(self.endpoints),
        'frameworks_checked': len(frameworks_checked),
        'frameworks_matched': frameworks_matched,
        'standard_mechanisms_found': len(self.standard_mechanisms)
    }

    # Run custom discovery if:
    # - Low standard coverage (< 10%) AND
    # - Significant endpoint count (> 20)
    # This suggests custom authorization may exist
    should_run = (
        signals['standard_coverage'] < 10.0 and
        signals['total_endpoints'] > 20
    )

    return {
        'should_run': should_run,
        'reason': f"Standard coverage {signals['standard_coverage']}% suggests custom patterns may exist",
        'confidence': 0.9 if should_run else 0.0,
        'signals': signals,
        'framework_context': {
            'frameworks_checked': frameworks_checked[:10],  # Share with AI
            'frameworks_matched': frameworks_matched,
            'standard_patterns': self._get_standard_pattern_summary()
        }
    }
```

##### Admin Authorization Discovery

Run when admin routes/controllers detected:

```python
def should_run_admin_discovery(self) -> Dict[str, Any]:
    """Check signals that indicate separate admin authorization exists"""

    signals = {
        'admin_route_count': len([ep for ep in self.endpoints if self._is_admin_route(ep)]),
        'admin_controller_count': len([c for c in self.controllers if 'admin' in c.lower()]),
        'has_superadmin_role': self._check_for_superadmin_patterns(),
        'total_endpoints': len(self.endpoints)
    }

    # Run admin discovery if:
    # - Significant admin routes/controllers exist
    # - OR superadmin patterns detected
    should_run = (
        signals['admin_route_count'] > 10 or
        signals['admin_controller_count'] > 3 or
        signals['has_superadmin_role']
    )

    return {
        'should_run': should_run,
        'reason': f"Found {signals['admin_route_count']} admin routes, {signals['admin_controller_count']} admin controllers",
        'confidence': 0.8 if should_run else 0.0,
        'signals': signals
    }

def _is_admin_route(self, endpoint: Dict) -> bool:
    """Check if endpoint appears to be administrative"""
    route = endpoint['route'].lower()
    controller = endpoint.get('controller', '').lower()

    admin_keywords = ['admin', 'superadmin', 'management', 'console', 'dashboard', 'sysadmin']

    return any(keyword in route or keyword in controller for keyword in admin_keywords)
```

#### Agentic Discovery Process

**Multi-Turn Investigation with Tool Access**

The AI agent explores the codebase iteratively, formulating and testing hypotheses until confident.

**Available Tools:**
- `joern_query(query)` - Execute Joern CPG queries
- `read_file(path)` - Read source files
- `grep_code(pattern)` - Search codebase for patterns
- `list_controllers()` - Get controller classes
- `sample_endpoint(route)` - Get detailed endpoint info

**Investigation Loop:**

```
Turn 1: Initial Survey
   AI: Asks broad questions, gets sample data
   → Queries for annotations, methods, classes
   → Forms initial hypotheses

Turn 2-N: Hypothesis Testing
   AI: Tests each hypothesis with targeted queries
   → Validates patterns exist
   → Extracts usage examples
   → Refines understanding

Final Turn: Confidence Assessment
   AI: Decides if confident or needs more investigation
   → Returns discovered patterns
   → OR requests additional probing
```

**Example Investigation Session:**

```python
def discover_authorization_mechanisms_agentic(self, investigation_type: str) -> List[Dict]:
    """
    Agentic exploration: AI probes codebase iteratively to find authorization mechanisms

    investigation_type: 'custom_auth' or 'admin_auth'
    """

    # Initialize investigation context
    context = {
        'investigation_type': investigation_type,
        'framework': self.framework,
        'total_endpoints': len(self.endpoints),
        'standard_coverage': self.standard_coverage,
        'conversation_history': [],
        'discovered_patterns': [],
        'confidence': 0.0
    }

    # Multi-turn investigation loop
    max_turns = 10
    for turn in range(max_turns):
        if context['confidence'] >= 0.9:
            break  # AI is confident it found everything

        # AI decides what to investigate next
        investigation_result = self._agentic_turn(context, turn)

    # Get all class and method-level annotations
    annotations = self.cpg_tool.query(
        'cpg.annotation.name.dedup.l'
    )

    # Get all method names containing auth-related keywords
    auth_methods = self.cpg_tool.query('''
        cpg.method.name("(?i).*(auth|permission|access|role|check).*")
            .whereNot(_.isExternal)
            .fullName
            .dedup
            .l
    ''')

    prompt = f"""
You are analyzing authorization patterns in a {self.framework} application with {len(self.endpoints)} endpoints.

**Problem:** Standard framework patterns show only {self.standard_coverage}% coverage, suggesting custom authorization mechanisms exist.

**Sample Controllers:**
```
{controller_samples}
```

**Annotations Found:**
{annotations[:30]}

**Authorization-Related Methods:**
{auth_methods[:20]}

**Your Task:**
Identify CUSTOM AUTHORIZATION MECHANISMS (not in frameworks/*.json) that could protect ANY endpoints.

Look for:
1. **Custom Annotations:** Not standard framework (@RequiresPermission, @CheckAccess)
2. **Meta-Annotations:** Custom annotations wrapping standard patterns (@Authorized → @PreAuthorize)
3. **Custom Methods:** Authorization check methods (AuthService.checkAccess, PermissionValidator.validate)
4. **Interceptors/Filters:** AOP aspects or filters performing authorization

**IMPORTANT:** These patterns protect ANY endpoints with ANY roles (USER, MANAGER, ADMIN, etc.). Don't focus only on admin.

Return JSON array:
[
  {{
    "pattern_type": "custom_annotation|meta_annotation|custom_method|interceptor",
    "pattern_name": "@RequiresPermission or AuthService.checkAccess",
    "description": "What it does and which roles it handles",
    "applies_to": "all_endpoints|specific_controller|specific_routes",
    "test_query": "Joern query to find this pattern",
    "confidence": 0.0-1.0
  }}
]
"""

    response = self.ai.call_claude(prompt)
    return json.loads(response)

def generate_admin_auth_hypotheses(self) -> List[Dict]:
    """Ask AI to identify separate admin authorization mechanisms"""

    # Sample admin controllers
    admin_controllers = self._sample_admin_controllers(limit=5)

    # Sample non-admin controllers for comparison
    normal_controllers = self._sample_non_admin_controllers(limit=3)

    # Get roles that look like admin roles
    admin_role_patterns = self.cpg_tool.query('''
        cpg.literal.code("(?i).*(ADMIN|SUPER|ROOT|SYSTEM).*")
            .dedup.l
    ''')

    prompt = f"""
You are analyzing ADMIN-SPECIFIC authorization in a {self.framework} application.

**Goal:** Find authorization mechanisms that SPECIFICALLY protect administrative functions and keep them separate from normal user authorization.

**Admin Controllers:**
```
{admin_controllers}
```

**Normal Controllers (for comparison):**
```
{normal_controllers}
```

**Admin-Looking Roles:**
{admin_role_patterns[:20]}

**Your Task:**
Identify SEPARATE ADMIN AUTHORIZATION as a defense strategy.

Look for:
1. **Admin-Specific Annotations:** @AdminOnly, @SuperuserRequired (different from normal auth)
2. **Admin-Specific Roles:** SUPERADMIN, SYSTEM_ADMIN (checked separately from USER/MANAGER)
3. **Admin-Specific Methods:** isAdminPortalUser(), requiresSuperadmin() (not used for normal endpoints)
4. **Admin Portal Separation:** /admin/* routes with different auth mechanism

**Key Questions:**
- Do admin routes use DIFFERENT authorization than normal routes?
- Are admin roles checked SEPARATELY from normal user roles?
- Is there a clear SEPARATION between admin and user authorization?

Return JSON array:
[
  {{
    "pattern_type": "admin_annotation|admin_role|admin_method|admin_portal",
    "pattern_name": "@AdminOnly or SUPERADMIN role",
    "description": "How admin authorization is separated from normal authorization",
    "admin_routes_count": "estimated number of admin routes using this",
    "isolation_strategy": "separate_mechanism|separate_roles|separate_portal",
    "test_query": "Joern query to find this pattern",
    "confidence": 0.0-1.0
  }}
]
"""

    response = self.ai.call_claude(prompt)
    return json.loads(response)
```

**Step 2: Pattern Testing**

Test each hypothesis with Joern queries:

```python
def test_hypothesis(self, hypothesis: Dict) -> Optional[Dict]:
    """Test if hypothesis is valid using Joern queries"""

    pattern_type = hypothesis['pattern_type']
    pattern_name = hypothesis['pattern_name']
    test_query = hypothesis['test_query']

    if pattern_type == 'meta_annotation':
        # Validate: Does annotation wrap @PreAuthorize?
        annotation_name = pattern_name.replace('@', '')

        validation_query = f'''
            cpg.annotation
              .name("{annotation_name}")
              .annotation.name("PreAuthorize")
              .nonEmpty
        '''

        is_valid = self.cpg_tool.query(validation_query)
        if not is_valid:
            return None  # Not a real meta-annotation

        # Extract usage count
        usage_query = f'''
            cpg.method
              .where(_.annotation.name("{annotation_name}"))
              .fullName
              .l
        '''

        usages = self.cpg_tool.query(usage_query)

        return {
            'type': 'meta_annotation',
            'pattern': f'@{annotation_name}',
            'framework': 'custom',
            'usage_count': len(usages),
            'underlying_mechanism': self._extract_underlying_mechanism(annotation_name),
            'examples': usages[:5]
        }

    elif pattern_type == 'custom_method':
        # Test if method exists and is called
        usages = self.cpg_tool.query(test_query)

        if len(usages) > 5:  # Threshold: at least 5 usages
            return {
                'type': 'custom_method',
                'pattern': pattern_name,
                'framework': 'custom',
                'usage_count': len(usages),
                'examples': usages[:5]
            }

    elif pattern_type == 'interceptor':
        # Validate interceptor/filter exists
        interceptor_exists = self.cpg_tool.query(test_query)

        if interceptor_exists:
            return {
                'type': 'interceptor',
                'pattern': pattern_name,
                'framework': 'custom',
                'usage_count': 1,  # Applies globally
                'coverage_estimate': 'global'
            }

    return None
```

**Step 3: Pattern Validation**

For each discovered pattern, extract behaviors and calculate coverage:

```python
def extract_pattern_behaviors(self, pattern: Dict) -> List[Dict]:
    """Extract all endpoints protected by this pattern"""

    if pattern['type'] == 'meta_annotation':
        annotation = pattern['pattern'].replace('@', '')

        # Get all methods with this annotation
        query = f'''
            cpg.method
              .where(_.annotation.name("{annotation}"))
              .map {{ m =>
                Map(
                  "controller" -> m.typeDecl.fullName,
                  "method" -> m.name,
                  "route" -> extractRoute(m),
                  "httpMethod" -> extractHttpMethod(m),
                  "authorization" -> "protected",
                  "mechanism" -> "{pattern['pattern']}"
                )
              }}.toJson
        '''

        behaviors = self.cpg_tool.query(query)
        return behaviors

    elif pattern['type'] == 'custom_method':
        # Find all call sites of the custom method
        # ... similar logic
        pass

    return []
```

### Mechanism Consolidation

Combine standard and custom mechanisms:

```python
def consolidate_mechanisms(self) -> Dict:
    """Combine standard and custom patterns into unified view"""

    all_mechanisms = []
    all_mechanisms.extend(self.standard_mechanisms)
    all_mechanisms.extend(self.custom_mechanisms)

    # Calculate overall coverage
    protected_endpoints = set()
    for mechanism in all_mechanisms:
        for behavior in mechanism.get('behaviors', []):
            endpoint_key = f"{behavior['httpMethod']} {behavior['route']}"
            protected_endpoints.add(endpoint_key)

    total_endpoints = len(self.endpoints)
    coverage = len(protected_endpoints) / total_endpoints * 100

    return {
        'mechanisms': all_mechanisms,
        'total_mechanisms': len(all_mechanisms),
        'protected_endpoints': len(protected_endpoints),
        'total_endpoints': total_endpoints,
        'coverage': round(coverage, 1)
    }
```

---

## Phase 2: Architecture Evaluation

### Evaluate Authorization Architecture

After discovering authorization mechanisms in Phase 1, evaluate how well-architected the authorization approach is:

```python
def evaluate_architecture(self, mechanisms: List[Dict], endpoints: List[Dict]) -> Dict:
    """
    Evaluate authorization architecture across four dimensions

    Focus: Is the authorization ARCHITECTURE sound, not just "are mechanisms good"

    Returns evaluation results that feed into Phase 3 recommendation generation
    """

    evaluation = {
        'consistency': self._evaluate_consistency(mechanisms, endpoints),
        'centralization': self._evaluate_centralization(mechanisms),
        'boundaries': self._evaluate_boundaries(mechanisms, endpoints),
        'maintainability': self._evaluate_maintainability(mechanisms)
    }

    return evaluation
```

#### 1. Consistency: Is authorization applied consistently?

```python
def _evaluate_consistency(self, mechanisms: List[Dict], endpoints: List[Dict]) -> Dict:
    """
    Evaluate if authorization is applied consistently across the application

    Architecture question: Does the application follow a consistent authorization pattern,
    or is it ad-hoc and inconsistent?
    """

    # Map endpoints to their authorization patterns
    endpoint_patterns = {}
    for endpoint in endpoints:
        endpoint_key = f"{endpoint['httpMethod']} {endpoint['route']}"
        patterns = []

        for mechanism in mechanisms:
            for behavior in mechanism.get('behaviors', []):
                if f"{behavior['httpMethod']} {behavior['route']}" == endpoint_key:
                    patterns.append(mechanism.get('pattern', mechanism.get('type')))

        endpoint_patterns[endpoint_key] = patterns

    # Analyze consistency
    protected = sum(1 for patterns in endpoint_patterns.values() if patterns)
    unprotected = len(endpoint_patterns) - protected
    multiple_patterns = sum(1 for patterns in endpoint_patterns.values() if len(patterns) > 1)

    # Check coverage consistency
    coverage_pct = (protected / len(endpoints)) * 100 if endpoints else 0

    return {
        'coverage_percentage': round(coverage_pct, 1),
        'protected_count': protected,
        'unprotected_count': unprotected,
        'multiple_patterns_count': multiple_patterns,
        'unprotected_endpoints': [k for k, v in endpoint_patterns.items() if not v][:20],
        'assessment': 'consistent' if coverage_pct >= 90 and multiple_patterns == 0
                     else 'mostly_consistent' if coverage_pct >= 70
                     else 'inconsistent'
    }
```

#### 2. Centralization: Is the authorization approach centralized or fragmented?

```python
def _evaluate_centralization(self, mechanisms: List[Dict]) -> Dict:
    """
    Evaluate if authorization architecture is centralized or fragmented

    Architecture question: Does the app use a single coherent authorization approach,
    or multiple competing/overlapping approaches?
    """

    # Group mechanisms by type
    mechanism_types = {}
    for mech in mechanisms:
        mech_type = mech.get('type', 'unknown')
        if mech_type not in mechanism_types:
            mechanism_types[mech_type] = []
        mechanism_types[mech_type].append(mech)

    # Count distinct authorization approaches
    approach_count = len(mechanism_types)

    # Check for fragmentation
    is_centralized = approach_count <= 2  # At most 2 approaches (e.g., annotation + config)

    return {
        'approach_count': approach_count,
        'mechanism_types': list(mechanism_types.keys()),
        'mechanisms_per_type': {k: len(v) for k, v in mechanism_types.items()},
        'is_centralized': is_centralized,
        'assessment': 'centralized' if is_centralized
                     else 'somewhat_fragmented' if approach_count <= 4
                     else 'highly_fragmented'
    }
```

#### 3. Boundaries: Are authorization decisions made at appropriate boundaries?

```python
def _evaluate_boundaries(self, mechanisms: List[Dict], endpoints: List[Dict]) -> Dict:
    """
    Evaluate if authorization checks happen at appropriate architectural boundaries

    Architecture question: Is authorization enforced at entry points (controllers, routes)
    or scattered throughout the codebase?
    """

    # Categorize where authorization happens
    boundary_locations = {
        'controller_level': 0,    # Annotations on controllers/routes
        'method_level': 0,        # Annotations on individual methods
        'gateway_level': 0,       # Gateway/filter/middleware
        'embedded': 0             # Custom methods called within business logic
    }

    for mechanism in mechanisms:
        mech_type = mechanism.get('type', 'unknown')

        if mech_type in ['annotation', 'meta_annotation', 'decorator']:
            # Check if applied at controller or method level
            # (simplified - real implementation would parse behavior locations)
            boundary_locations['method_level'] += len(mechanism.get('behaviors', []))
        elif mech_type in ['filter', 'interceptor', 'middleware']:
            boundary_locations['gateway_level'] += 1
        elif mech_type in ['custom_method']:
            boundary_locations['embedded'] += len(mechanism.get('behaviors', []))

    # Appropriate boundaries: gateway or method-level (not embedded)
    appropriate = boundary_locations['gateway_level'] + boundary_locations['method_level']
    total = sum(boundary_locations.values())

    boundary_score = appropriate / total if total > 0 else 0

    return {
        'boundary_locations': boundary_locations,
        'boundary_score': round(boundary_score, 2),
        'assessment': 'appropriate' if boundary_score >= 0.9
                     else 'mostly_appropriate' if boundary_score >= 0.7
                     else 'scattered'
    }
```

#### 4. Maintainability: Is the architecture maintainable and testable?

```python
def _evaluate_maintainability(self, mechanisms: List[Dict]) -> Dict:
    """
    Evaluate if authorization architecture is maintainable and testable

    Architecture question: Can developers easily understand, modify, and test
    the authorization approach?
    """

    # Check for declarative vs imperative approaches
    declarative = [m for m in mechanisms if m.get('type') in ['annotation', 'meta_annotation', 'decorator']]
    imperative = [m for m in mechanisms if m.get('type') in ['custom_method', 'interceptor']]

    # Declarative approaches are generally more maintainable
    declarative_ratio = len(declarative) / len(mechanisms) if mechanisms else 0

    # Check for complexity indicators
    total_patterns = sum(len(m.get('behaviors', [])) for m in mechanisms)
    avg_complexity = total_patterns / len(mechanisms) if mechanisms else 0

    return {
        'declarative_count': len(declarative),
        'imperative_count': len(imperative),
        'declarative_ratio': round(declarative_ratio, 2),
        'average_complexity': round(avg_complexity, 1),
        'assessment': 'maintainable' if declarative_ratio >= 0.7
                     else 'moderate' if declarative_ratio >= 0.4
                     else 'complex'
    }
```

### Architecture Evaluation vs Mechanism Quality

**Key Distinction:**

- ❌ **NOT "Are these mechanisms good?"** - Looking at individual patterns in isolation
- ✅ **"Is authorization well-architected?"** - Looking at the overall approach

**What we evaluate:**
- Is authorization **consistently applied** across the entire application?
- Is the approach **centralized** (single pattern) or **fragmented** (many competing approaches)?
- Are checks made at appropriate **architectural boundaries** (entry points)?
- Is the architecture **maintainable** and **testable**?

**Example:**
- Spring Security `@PreAuthorize` is a good mechanism
- But if only 30% of endpoints use it, and the rest use ad-hoc custom checks scattered throughout business logic, **the architecture is poor**

### Evaluation Results Feed Phase 3

The architecture evaluation results are included in the evidence passed to Phase 3 for recommendation generation. The AI uses these assessments to prioritize architectural improvements.

---

## Phase 3: Finding Generation

### Evidence Building

Build comprehensive evidence for AI analysis:

```python
def build_evidence(self) -> Dict:
    """Build evidence from mechanism discovery and evaluation"""

    # Access Control Matrix
    acm = self._build_access_control_matrix()

    # Role analysis
    roles = self._analyze_roles()

    # Pattern consistency
    consistency = self._analyze_pattern_consistency()

    # Phase 2 architecture evaluation results
    evaluation = self.evaluate_architecture(self.mechanisms, self.endpoints)

    return {
        'mechanisms': self.mechanisms,
        'access_control_matrix': acm,
        'roles': roles,
        'pattern_consistency': consistency,
        'evaluation': evaluation,  # Phase 2 results
        'coverage_metrics': {
            'total_endpoints': len(self.endpoints),
            'protected': acm['protected_count'],
            'unprotected': acm['unprotected_count'],
            'coverage': acm['coverage_percentage']
        }
    }
```

#### Access Control Matrix

```python
def _build_access_control_matrix(self) -> Dict:
    """Build matrix of endpoints × authorization status"""

    matrix = []

    for endpoint in self.endpoints:
        # Find authorization for this endpoint
        auth_info = self._find_endpoint_authorization(endpoint)

        matrix.append({
            'route': endpoint['route'],
            'method': endpoint['httpMethod'],
            'controller': endpoint['controller'],
            'authorization': auth_info['status'],  # 'protected' or 'unprotected'
            'roles': auth_info.get('roles', []),
            'mechanism': auth_info.get('mechanism', None)
        })

    protected = len([e for e in matrix if e['authorization'] == 'protected'])
    unprotected = len([e for e in matrix if e['authorization'] == 'unprotected'])

    return {
        'endpoints': matrix,
        'protected_count': protected,
        'unprotected_count': unprotected,
        'coverage_percentage': round(protected / len(matrix) * 100, 1)
    }
```

#### Role Analysis

```python
def _analyze_roles(self) -> Dict:
    """Analyze role usage patterns"""

    # Extract all roles from authorization checks
    roles_used = set()
    role_usage = {}

    for mechanism in self.mechanisms:
        for behavior in mechanism.get('behaviors', []):
            for role in behavior.get('roles', []):
                roles_used.add(role)

                if role not in role_usage:
                    role_usage[role] = {
                        'role': role,
                        'usage_count': 0,
                        'endpoints': []
                    }

                role_usage[role]['usage_count'] += 1
                role_usage[role]['endpoints'].append(
                    f"{behavior['httpMethod']} {behavior['route']}"
                )

    # Classify roles
    generic_roles = ['USER', 'ADMIN', 'GUEST', 'ANONYMOUS']

    generic = [r for r in roles_used if r.upper() in generic_roles]
    domain_specific = [r for r in roles_used if r.upper() not in generic_roles]

    return {
        'used': sorted(list(roles_used)),
        'generic': generic,
        'domain_specific': domain_specific,
        'generic_count': len(generic),
        'domain_specific_count': len(domain_specific),
        'usage_details': list(role_usage.values())
    }
```

### Recommendation Generation (AI-Powered)

Generate strategic recommendation based on evidence:

```python
def generate_recommendation(self, evidence: Dict) -> Dict:
    """Use AI to generate strategic authorization recommendation"""

    # Build context about the application
    context = self._build_application_context()

    prompt = f"""
You are a security architect analyzing route-level authorization in the {context['name']} application.

**Application Context:**
- Name: {context['name']} (v{context['version']})
- Framework: {context['framework']}
- Language: {context['language']}
- Endpoints: {len(self.endpoints)}
- Description: {context['description']}

**Authorization State:**
- Coverage: {evidence['coverage_metrics']['coverage']}%
- Protected: {evidence['coverage_metrics']['protected']} endpoints
- Unprotected: {evidence['coverage_metrics']['unprotected']} endpoints
- Mechanisms found: {len(evidence['mechanisms'])}
- Roles in use: {', '.join(evidence['roles']['used'])}

**Mechanisms Discovered:**
{self._format_mechanisms_for_prompt(evidence['mechanisms'])}

**Access Control Matrix (Sample):**
{self._format_acm_sample(evidence['access_control_matrix']['endpoints'][:20])}

**Role Analysis:**
- Generic roles: {', '.join(evidence['roles']['generic'])}
- Domain-specific roles: {', '.join(evidence['roles']['domain_specific'])}

**Your Task:**
Generate a strategic recommendation for route-level authorization. Consider:

1. **Coverage Gaps:** Are critical endpoints unprotected?
2. **Role Design:** Are roles generic (USER/ADMIN) or domain-specific?
3. **Consistency:** Are authorization patterns consistent?
4. **Custom Patterns:** If custom mechanisms were found, assess their effectiveness

**CRITICAL SCOPE:**
This is ROUTE-LEVEL authorization only (can role X access endpoint Y?).
DO NOT recommend data-level authorization patterns like owner ID validation.
DO NOT suggest patterns like '#ownerId == authentication.principal.ownerId'.

**Required JSON Output:**
{{
  "title": "Clear, professional title using 'Consider...' framing",
  "summary": "2-3 sentences summarizing the authorization state and key recommendation",
  "design_recommendation": "Narrative guidance for authorization architecture (1-2 paragraphs). How should they think about roles? How should they map roles to business functions?",
  "implementation_recommendation": "Narrative guidance for technical implementation (1-2 paragraphs). Framework-specific steps, dependencies to add, annotations to use. Be specific to {context['framework']}.",
  "rationale": "Explanation of WHY this approach fits this application (2-3 sentences). Discuss trade-offs: framework vs custom vs gateway approaches."
}}

Keep recommendations actionable and specific to THIS application's context.
"""

    try:
        response = self.ai.call_claude(prompt)
        recommendation = json.loads(response)
        return recommendation
    except Exception as e:
        if self.debug:
            print(f"[ENDPOINT_AUTHORIZATION] AI recommendation failed: {e}")

        # Fallback to rule-based recommendation
        return self._generate_fallback_recommendation(evidence)
```

### Fallback Recommendation (Rule-Based)

When AI unavailable, use rule-based logic:

```python
def _generate_fallback_recommendation(self, evidence: Dict) -> Dict:
    """Generate recommendation without AI"""

    coverage = evidence['coverage_metrics']['coverage']
    unprotected = evidence['coverage_metrics']['unprotected']
    mechanisms = len(evidence['mechanisms'])

    # Determine title based on coverage
    if coverage == 0:
        title = "Consider Implementing Route-Level Authorization"
    elif coverage < 50:
        title = "Consider Expanding Authorization Coverage"
    elif coverage < 90:
        title = "Consider Protecting Remaining Endpoints"
    else:
        title = "Authorization Coverage is Strong"

    # Generate summary
    if mechanisms == 0:
        summary = f"No authorization mechanisms detected across {len(self.endpoints)} endpoints. Implementing route-level authorization is critical for protecting application resources."
    else:
        summary = f"{unprotected} of {len(self.endpoints)} endpoints ({100-coverage}%) lack authorization checks. Extending authorization to all sensitive endpoints will improve security posture."

    # Framework-specific implementation guidance
    framework_guidance = self._get_framework_guidance(self.framework)

    return {
        'title': title,
        'summary': summary,
        'design_recommendation': framework_guidance['design'],
        'implementation_recommendation': framework_guidance['implementation'],
        'rationale': framework_guidance['rationale']
    }
```

---

## Output Format

Following the defense report schema:

```json
{
  "agent_id": "endpoint_authorization",
  "agent_name": "Endpoint Authorization (Route-Level Access Control)",
  "defense_metadata": {
    "defense_name": "Spring Security @PreAuthorize (+ @Superadmin meta-annotation)",
    "defense_type": "standard + custom",
    "defense_mechanism": "annotation",
    "defense_patterns": [
      {
        "type": "annotation",
        "pattern": "@PreAuthorize",
        "description": "Spring Security method-level authorization"
      },
      {
        "type": "meta_annotation",
        "pattern": "@Superadmin",
        "description": "Custom meta-annotation wrapping @PreAuthorize('isSuperadmin()')"
      }
    ]
  },
  "evidence": {
    "mechanisms": [
      {
        "type": "meta_annotation",
        "pattern": "@Superadmin",
        "framework": "custom",
        "usage_count": 450,
        "underlying_mechanism": "@PreAuthorize('isSuperadmin()')",
        "examples": [
          "contrast.teamserver.superadmin.NgSuperadminController.method1",
          "contrast.teamserver.superadmin.NgSuperadminController.method2"
        ]
      }
    ],
    "access_control_matrix": {
      "endpoints": [
        {
          "route": "/ng/superadmin/groups",
          "method": "GET",
          "controller": "NgSuperadminController.getGroups",
          "authorization": "protected",
          "roles": ["SUPERADMIN"],
          "mechanism": "@Superadmin"
        }
      ],
      "protected_count": 1214,
      "unprotected_count": 1,
      "coverage_percentage": 99.9
    },
    "roles": {
      "used": ["SUPERADMIN", "SYSTEM_ADMIN", "USER"],
      "generic": ["USER"],
      "domain_specific": ["SUPERADMIN", "SYSTEM_ADMIN"],
      "generic_count": 1,
      "domain_specific_count": 2
    }
  },
  "metrics": {
    "exposures": 1215,
    "protected": 1214,
    "unprotected": 1,
    "coverage": 99.9
  },
  "recommendation": {
    "title": "Authorization Coverage is Strong",
    "summary": "Application has exceptional authorization coverage (99.9%) using custom meta-annotations that wrap Spring Security. Only 1 endpoint lacks explicit authorization.",
    "design_recommendation": "The custom @Superadmin and @SystemAdminNoServerAdmin meta-annotations provide clean, declarative authorization that aligns with business roles. Consider documenting these patterns for new developers and reviewing the single unprotected endpoint to determine if it should be public or requires authorization.",
    "implementation_recommendation": "For the unprotected endpoint, add an appropriate meta-annotation (@Superadmin or @SystemAdminNoServerAdmin) based on required access level. Ensure meta-annotation definitions stay synchronized with Spring Security expressions as authorization logic evolves.",
    "rationale": "Custom meta-annotations successfully abstract Spring Security complexity while maintaining strong type safety and IDE support. This pattern is appropriate for large enterprise applications with complex role hierarchies."
  }
}
```

---

## Implementation Notes

### Dependencies

```python
# Required modules
from compass.cpg_tool import CpgTool
from compass.ai_client import AIClient
from defenses.agents.base import DefenseAgent
```

### Key Methods

```python
class EndpointAuthorizationAgent(DefenseAgent):

    def get_agent_id(self) -> str:
        return "endpoint_authorization"

    def get_agent_name(self) -> str:
        return "Endpoint Authorization (Route-Level Access Control)"

    def should_run(self) -> Dict[str, Any]:
        """Always run for authorization analysis"""
        return {
            'should_run': True,
            'reason': 'Authorization analysis is fundamental',
            'confidence': 1.0
        }

    def analyze(self) -> Dict[str, Any]:
        """Main analysis entry point"""

        # Phase 1: Mechanism Discovery
        standard_mechanisms = self._discover_standard_mechanisms()

        should_discover_custom = self._should_run_custom_discovery(standard_mechanisms)
        if should_discover_custom['should_run']:
            custom_mechanisms = self._discover_custom_mechanisms()
        else:
            custom_mechanisms = []

        all_mechanisms = self._consolidate_mechanisms(
            standard_mechanisms,
            custom_mechanisms
        )

        # Phase 2: Finding Generation
        evidence = self._build_evidence(all_mechanisms)
        defense_metadata = self._build_defense_metadata(all_mechanisms)
        metrics = self._calculate_metrics(evidence)
        recommendation = self._generate_recommendation(evidence)

        return {
            'agent_id': self.get_agent_id(),
            'agent_name': self.get_agent_name(),
            'ran': True,
            'defense_metadata': defense_metadata,
            'evidence': evidence,
            'metrics': metrics,
            'recommendation': recommendation
        }
```

---

## Testing Strategy

### Test Cases

1. **Spring Petclinic** (Standard Patterns)
   - Expected: Low coverage (~29%), generic roles (USER, ADMIN)
   - Should recommend: Expand coverage, add domain-specific roles

2. **Teamserver** (Custom Meta-Annotations)
   - Expected: High coverage (99.9%), custom patterns discovered
   - Should recommend: Strong coverage, document meta-annotations

3. **Django Project** (Framework Patterns)
   - Expected: Django decorators (@permission_required)
   - Should recommend: Framework-appropriate guidance

4. **No Authorization** (Unprotected App)
   - Expected: 0% coverage, no mechanisms
   - Should recommend: Implement framework-based authorization

### Validation Criteria

- ✅ Discovers standard framework patterns
- ✅ Discovers custom meta-annotations via AI
- ✅ Calculates accurate coverage percentage
- ✅ Generates framework-specific recommendations
- ✅ Stays in scope (no IDOR recommendations)
- ✅ Provides actionable implementation guidance

---

## Future Enhancements

1. **Config File Parsing**
   - Extract roles from Spring SecurityConfig
   - Parse Django settings.py for permission classes
   - Identify role hierarchy definitions

2. **Role Hierarchy Analysis**
   - Detect role inheritance (SUPERADMIN > ADMIN > USER)
   - Recommend consolidation of similar roles
   - Identify redundant permissions

3. **Cross-Controller Consistency**
   - Detect inconsistent patterns across controllers
   - Recommend standardizing on single approach
   - Identify controllers missing authorization entirely

4. **Performance Optimization**
   - Cache Joern query results
   - Parallel pattern testing
   - Incremental analysis for large codebases

---

## References

- **Parent Documentation:** [README.md](../README.md)
- **Framework System:** [../../CLAUDE.md](../../CLAUDE.md)
- **AI Client:** [../../compass/ai_client.py](../../compass/ai_client.py)
- **CPG Tool:** [../../compass/cpg_tool.py](../../compass/cpg_tool.py)
- **Schema:** [../schema/defense-report-schema.json](../schema/defense-report-schema.json)
