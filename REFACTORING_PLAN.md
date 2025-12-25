# Endpoint-Centric Refactoring Plan

## Overview
Migrate from **behavior-based** to **endpoint-centric** schema in endpoint_authorization agent.

**Current (Behavior-Based):**
- Focus: Authorization "behaviors" (annotations, configs) scattered across code
- Structure: `behaviors = [{mechanism, method, roles, location_type}, ...]`
- Problem: Endpoints are implicit; hard to see what protects each endpoint

**Target (Endpoint-Centric):**
- Focus: HTTP endpoints with their complete authorization stack
- Structure: `endpoints = [{id, method, path, handler, authorizations[], effective_authorization}, ...]`
- Benefit: Clear view of what protects each endpoint; multi-layer auth visible

---

## Current Code Structure

### Phase 1: Discovery (Lines 499-1669)
```
analyze()
├── _discover_standard_mechanisms()         # FrameworkTool → behaviors[]
├── _detect_authorization_pattern()         # AI detective → architecture pattern
├── _discover_routes_and_trace_paths()      # Joern → execution paths
└── _discover_custom_defenses()             # AI code analysis → custom behaviors[]
    Result: self.all_mechanisms = [{framework, behaviors[], ...}, ...]
```

### Phase 2: Evidence Building (Lines 1941-2112)
```
_build_evidence()
├── analyze_roles()                         # Extract roles from behaviors
├── _generate_ai_coverage_metrics()         # Count protected/unprotected
├── build_defense_usage_matrix()            # Build matrix: endpoints × roles
├── _build_proposed_access_matrix()         # AI classify all endpoints
├── _verify_unprotected_routes()            # AI review findings
└── _discover_authorization_tests()         # Find existing tests
    Result: evidence = {mechanisms, defense_matrix, roles, metrics, ...}
```

### Phase 3: Recommendation (Lines 2114-2651)
```
_generate_recommendation()
└── _generate_ai_recommendation()
    └── _build_recommendation_prompt()      # Build prompt with evidence
        └── _parse_ai_response()            # Parse JSON response
    Result: {title, summary, design_rec, impl_rec, rationale}
```

---

## Migration Strategy

### STEP 1: Create Endpoint Builder (NEW)
**File:** `sar/agents/endpoint_builder.py`

```python
class EndpointBuilder:
    """Builds Endpoint objects from discovered behaviors"""

    def build_endpoints(
        self,
        route_methods: List[Dict],      # From Joern
        all_mechanisms: List[Dict]       # Current behaviors
    ) -> List[Endpoint]:
        """
        1. Start with all HTTP routes (from Joern query)
        2. For each route, find ALL authorizations:
           - Method-level (@PreAuthorize) → endpoint_guard
           - Class-level → controller_guard
           - HttpSecurity config → route_guard
           - Filters/Interceptors → middleware_guard
        3. Build Endpoint with authorizations[]
        4. Compute effective_authorization
        """

    def _find_authorizations_for_endpoint(
        self,
        endpoint_method: str,
        all_mechanisms: List[Dict]
    ) -> List[EndpointAuthorization]:
        """Find all authorizations that apply to this endpoint"""

    def _compute_effective_authorization(
        self,
        authorizations: List[EndpointAuthorization]
    ) -> EffectiveAuthorization:
        """
        Determine effective auth based on precedence:
        1. route_guard (HttpSecurity) - most global
        2. middleware_guard - affects multiple endpoints
        3. controller_guard - class level
        4. endpoint_guard - most specific (wins)
        """
```

### STEP 2: Update Discovery Phase
**File:** `sar/agents/endpoint_authorization.py`

**Changes to `analyze()` method:**
```python
def analyze(self) -> Dict[str, Any]:
    # ... existing discovery code ...

    # NEW: Build endpoint-centric structure
    from sar.agents.endpoint_builder import EndpointBuilder

    builder = EndpointBuilder(cpg_tool=self.cpg_tool, debug=self.debug)

    # Get all HTTP routes
    routes = self.utils.query_all_endpoint_methods(self.matched_frameworks)

    # Build Endpoint objects
    self.endpoints = builder.build_endpoints(routes, self.all_mechanisms)

    # ... rest of analysis ...
```

**Keep existing methods:**
- `_discover_standard_mechanisms()` - still needed to find behaviors
- `_detect_authorization_pattern()` - still useful for architecture understanding
- `_discover_custom_defenses()` - still needed for custom patterns

**What changes:**
- Behaviors are intermediate format → feed into Endpoint builder
- `self.all_mechanisms` becomes internal, `self.endpoints` is primary

### STEP 3: Update Evidence Building
**File:** `sar/agents/endpoint_authorization.py`

**Changes to `_build_evidence()` method:**
```python
def _build_evidence(self) -> Dict:
    # NEW: Work with endpoints instead of behaviors

    # Extract roles from all endpoints' authorizations
    all_roles = set()
    for endpoint in self.endpoints:
        for auth in endpoint.authorizations:
            if auth.authorization.type == "RBAC":
                all_roles.update(auth.authorization.roles_any_of or [])

    roles = {
        'used': list(all_roles),
        'generic_count': ...,
        'domain_specific_count': ...
    }

    # Calculate metrics from endpoints
    total_endpoints = len(self.endpoints)
    protected_endpoints = [e for e in self.endpoints if e.authorizations]
    unprotected_endpoints = [e for e in self.endpoints if not e.authorizations]

    metrics = {
        'exposures': total_endpoints,
        'protected': len(protected_endpoints),
        'unprotected': len(unprotected_endpoints),
        'coverage': len(protected_endpoints) / total_endpoints * 100
    }

    # Build NEW evidence structure
    evidence = {
        'endpoints': [e.dict() for e in self.endpoints],  # Pydantic .dict()
        'roles': roles,
        'auth_pattern': self.auth_pattern,
        'metrics': metrics,
        'verification': self._verify_endpoints(),
        'test_discovery': self._discover_authorization_tests()
    }

    return evidence
```

**Remove/Replace:**
- `build_defense_usage_matrix()` - replaced by endpoints themselves
- `_build_proposed_access_matrix()` - replaced by endpoints with effective_authorization
- `_generate_ai_coverage_metrics()` - simplified, calculate from endpoints

### STEP 4: Update AI Prompts
**File:** `sar/agents/endpoint_authorization.py`

**Changes to `_build_recommendation_prompt()`:**
```python
def _build_recommendation_prompt(self, context: Dict, evidence: Dict) -> str:
    # Format endpoints for AI
    endpoint_sample = []
    for endpoint in evidence['endpoints'][:20]:  # Sample
        endpoint_sample.append({
            'endpoint': f"{endpoint['method']} {endpoint['path']}",
            'handler': endpoint['handler'],
            'authorizations': [
                {
                    'enforcement': auth['enforcement_point'],
                    'type': auth['authorization']['type'],
                    'roles': auth['authorization'].get('roles_any_of', []),
                    'evidence': auth['evidence']['mechanism_name']
                }
                for auth in endpoint['authorizations']
            ],
            'effective': endpoint['effective_authorization']['description']
        })

    prompt = f"""
ENDPOINTS ANALYZED ({len(evidence['endpoints'])} total):

Sample endpoints with their authorization layers:
{json.dumps(endpoint_sample, indent=2)}

AUTHORIZATION LAYERS DETECTED:
{self._summarize_enforcement_points(evidence['endpoints'])}

YOUR TASK:
Review these endpoints and their authorization layers...
"""
```

**Add helper:**
```python
def _summarize_enforcement_points(self, endpoints: List[Dict]) -> str:
    """Summarize where authorization is enforced"""
    enforcement_counts = {}
    for endpoint in endpoints:
        for auth in endpoint['authorizations']:
            point = auth['enforcement_point']
            enforcement_counts[point] = enforcement_counts.get(point, 0) + 1

    return "\n".join(f"- {point}: {count} instances"
                     for point, count in enforcement_counts.items())
```

### STEP 5: Update Verification
**File:** `sar/agents/endpoint_authorization.py`

**Changes to `_verify_unprotected_routes()`:**
```python
def _verify_endpoints(self) -> Dict:
    """AI review of endpoint findings"""

    protected = [e for e in self.endpoints if e.authorizations]
    unprotected = [e for e in self.endpoints if not e.authorizations]

    # Show AI sample of protected endpoints
    protected_sample = [
        {
            'endpoint': f"{e.method} {e.path}",
            'layers': len(e.authorizations),
            'effective': e.effective_authorization.description
        }
        for e in protected[:10]
    ]

    # Show AI sample of unprotected endpoints
    unprotected_sample = [
        {
            'endpoint': f"{e.method} {e.path}",
            'handler': e.handler
        }
        for e in unprotected[:10]
    ]

    prompt = f"""
Review endpoint analysis:

PROTECTED ENDPOINTS ({len(protected)}):
{json.dumps(protected_sample, indent=2)}

UNPROTECTED ENDPOINTS ({len(unprotected)}):
{json.dumps(unprotected_sample, indent=2)}

Did we miss any authorization mechanisms?
"""
    # ... rest of AI review ...
```

### STEP 6: Update Report Output
**Files:** `sar/report_utils.py`, `show_acm.py`

**Changes to report structure:**
```python
# In _build_evidence(), change return to:
evidence = {
    'endpoints': [e.dict() for e in self.endpoints],  # NEW
    # REMOVE: 'mechanisms', 'defense_usage_matrix'
    'roles': roles,
    'metrics': metrics,
    ...
}
```

**Update show_acm.py:**
- Read `evidence['endpoints']` instead of `evidence['defense_usage_matrix']`
- Build matrix from endpoints:
  ```python
  for endpoint in endpoints:
      row = endpoint['effective_authorization']['roles_any_of']
      matrix.append(row)
  ```

---

## Migration Checklist

### Phase 1: Create Foundation
- [ ] Create `sar/agents/endpoint_builder.py`
- [ ] Implement `EndpointBuilder.build_endpoints()`
- [ ] Implement `EndpointBuilder._find_authorizations_for_endpoint()`
- [ ] Implement `EndpointBuilder._compute_effective_authorization()`
- [ ] Write unit tests for EndpointBuilder

### Phase 2: Update Discovery
- [ ] Import EndpointBuilder in analyze()
- [ ] Call builder.build_endpoints() after discovery
- [ ] Store result in self.endpoints
- [ ] Keep self.all_mechanisms for backward compat (temporarily)

### Phase 3: Update Evidence
- [ ] Replace `_build_evidence()` to use endpoints
- [ ] Update role extraction to work with endpoints
- [ ] Update metrics calculation to work with endpoints
- [ ] Remove calls to `build_defense_usage_matrix()`
- [ ] Remove `_build_proposed_access_matrix()` (replaced by effective_authorization)
- [ ] Update `_verify_endpoints()` to work with endpoint list

### Phase 4: Update AI Prompts
- [ ] Update `_build_recommendation_prompt()` to show endpoints
- [ ] Add `_summarize_enforcement_points()` helper
- [ ] Update verification prompt to show endpoint structure
- [ ] Test AI responses with new format

### Phase 5: Update Report
- [ ] Update evidence structure in `_build_evidence()`
- [ ] Update `show_acm.py` to read from endpoints
- [ ] Test report generation
- [ ] Verify JSON schema compatibility

### Phase 6: Testing
- [ ] Run against Spring PetClinic
- [ ] Verify all 17 endpoints detected
- [ ] Verify authorization layers captured correctly
- [ ] Verify effective_authorization computed correctly
- [ ] Compare old vs new output

### Phase 7: Cleanup
- [ ] Remove unused behavior-based utility methods
- [ ] Remove `build_defense_usage_matrix()` if unused elsewhere
- [ ] Update documentation
- [ ] Commit changes

---

## Data Flow Comparison

### BEFORE (Behavior-Based):
```
Joern queries → behaviors[] → defense_matrix → AI classification → proposed_matrix
                    ↓
                evidence = {mechanisms, defense_matrix, proposed_matrix}
                    ↓
                AI recommendation
```

### AFTER (Endpoint-Centric):
```
Joern queries → behaviors[] → EndpointBuilder → endpoints[]
                                                    ↓
                           (endpoints have effective_authorization built-in)
                                                    ↓
                           evidence = {endpoints, roles, metrics}
                                                    ↓
                           AI recommendation (works directly with endpoints)
```

---

## Key Benefits

1. **Clarity:** Each endpoint shows complete authorization stack
2. **Multi-layer:** Can see route_guard + controller_guard + endpoint_guard all together
3. **Precedence:** effective_authorization handles complex precedence rules
4. **Maintainability:** Endpoints are self-contained units
5. **Testing:** Easy to validate each endpoint's authorization
6. **Extensibility:** Easy to add new enforcement_point types

---

## Risks & Mitigation

**Risk 1: Breaking existing reports**
- Mitigation: Keep old format in parallel during transition
- Mitigation: Update show_acm.py to handle both formats

**Risk 2: Complex effective_authorization logic**
- Mitigation: Start simple (last-wins), refine later
- Mitigation: Unit test precedence rules extensively

**Risk 3: Performance (N endpoints × M mechanisms)**
- Mitigation: Current code already does similar work
- Mitigation: Add caching if needed

**Risk 4: AI prompts too complex**
- Mitigation: Show sample, not all endpoints
- Mitigation: Summarize authorization layers

---

## Timeline Estimate

- Phase 1 (Foundation): 2-3 hours
- Phase 2 (Discovery): 1 hour
- Phase 3 (Evidence): 2 hours
- Phase 4 (Prompts): 1 hour
- Phase 5 (Report): 1 hour
- Phase 6 (Testing): 2 hours
- Phase 7 (Cleanup): 1 hour

**Total: ~10-12 hours of focused work**

---

## Success Criteria

✅ All 17 PetClinic endpoints detected
✅ Multi-layer authorizations captured (e.g., SecurityConfig + @PreAuthorize)
✅ Effective authorization computed correctly
✅ AI recommendations reference endpoints clearly
✅ Reports show endpoint-centric view
✅ No regression in coverage calculation
✅ Code is cleaner and more maintainable
