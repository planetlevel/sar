# Endpoint Authorization Agent Improvements

Based on user feedback review, these improvements will make the endpoint authorization recommendations more actionable, technically accurate, and compelling.

## Priority 1: Critical Correctness Issues

### 1. Detect and Use Consistent Role Expression Conventions
**Problem**: Mixed conventions (`hasRole('ROLE_X')` vs `hasAnyRole("X")`) cause implementation errors

**Solution**:
- Query existing `@PreAuthorize` expressions in codebase
- Detect actual convention used (ROLE_ prefix or not, hasRole vs hasAuthority)
- Generate all examples using detected convention
- Warn if multiple conventions found (inconsistency)

**Implementation**:
```python
def _detect_role_convention(self, standard_mechanisms: List[Dict]) -> Dict:
    """
    Analyze existing @PreAuthorize expressions to detect role convention

    Returns:
        {
            'convention': 'hasRole_no_prefix' | 'hasRole_with_prefix' | 'hasAuthority',
            'examples': ['hasRole("ADMIN")', ...],
            'inconsistencies': [...],
            'recommendation': 'Use hasRole("ROLE") consistently'
        }
    """
```

### 2. Replace "PUBLIC Role" with Explicit PermitAll Allowlist
**Problem**: "PUBLIC role" implies authenticated identity for public endpoints

**Solution**:
- Remove all "PUBLIC role" guidance from AI prompts
- Recommend explicit `permitAll()` HTTP security config
- Or `@PermitAll` annotation where supported
- Emphasize: public endpoints must be explicitly documented

**Implementation**:
- Update `_build_recommendation_prompt()`: remove PUBLIC role mentions
- Add explicit guidance: "Create explicit public endpoint allowlist with permitAll()"
- Generate table of suggested public endpoints (health, login, static)

### 3. Define "Protected" Standard Explicitly
**Problem**: Implicit definition (has annotation) misses HTTP config matchers

**Solution**:
- Query both `@PreAuthorize` annotations AND `HttpSecurity` request matchers
- Define standard: Every route must be one of:
  - `permitAll` - explicitly public
  - `authenticated` - requires login, no role
  - `role/expression` - requires specific authorization
- Show classification for each route

**Implementation**:
```python
def _query_http_security_config(self) -> List[Dict]:
    """
    Query for HttpSecurity request matcher configurations

    Look for:
    - .antMatchers(...).permitAll()
    - .antMatchers(...).authenticated()
    - .antMatchers(...).hasRole(...)
    """
```

## Priority 2: Actionability Improvements

### 4. Generate Route-by-Route Classification Table
**Problem**: Report punts hard work to "audit endpoints"

**Solution**: Include complete table with suggested classifications

**Format**:
| Route | HTTP Method | Controller | Current Protection | Proposed | Suggested Expression |
|-------|-------------|------------|-------------------|----------|---------------------|
| `/api/admin/users` | DELETE | NgAccessGroupsRestController.deleteAccessGroup | @PreAuthorize("hasRole('ADMIN')") | role-based | `@PreAuthorize("hasRole('ADMIN')")` |
| `/health` | GET | HealthCheckRestController.live | none | permitAll | `permitAll()` in HttpSecurity |
| `/api/users/{id}` | GET | NgUserRestController.getUser | none | authenticated | `@PreAuthorize("isAuthenticated()")` |

**Implementation**:
```python
def _classify_route(self, route: Dict) -> Dict:
    """
    Classify a route based on path pattern, HTTP method, and controller

    Returns:
        {
            'classification': 'permitAll' | 'authenticated' | 'role-based',
            'suggested_expression': '@PreAuthorize("...")',
            'rationale': 'Why this classification'
        }
    """
```

### 5. Add "Default Deny" Statement
**Problem**: Missing key posture decision

**Solution**: Explicitly state in recommendation:
> **Default Deny Policy**: Any route NOT in the explicit permitAll allowlist requires at minimum `authenticated()`. No endpoints should be implicitly public.

### 6. Add "Definition of Done" Criteria
**Problem**: No clear completion criteria

**Solution**: Add measurable done criteria:
```markdown
## Definition of Done

✅ 100% of routes explicitly classified (permitAll / authenticated / role-based)
✅ All public endpoints documented in explicit allowlist with business justification
✅ CI/CD pipeline fails if new routes added without authorization annotation
✅ Authorization test suite passes (see guardrails below)
✅ Access control matrix reviewed and approved by security team
```

### 7. Include Test/Guardrail Code
**Problem**: No enforcement mechanism

**Solution**: Provide concrete test code:
```java
@SpringBootTest
class EndpointAuthorizationTest {

    @Autowired
    private WebApplicationContext context;

    @Test
    void allEndpointsMustHaveExplicitAuthorization() {
        // Get all @RequestMapping methods
        Map<RequestMappingInfo, HandlerMethod> mappings =
            context.getBean(RequestMappingHandlerMapping.class)
                   .getHandlerMethods();

        Set<String> publicEndpoints = getPublicEndpointAllowlist();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : mappings.entrySet()) {
            HandlerMethod method = entry.getValue();
            String route = entry.getKey().toString();

            // Check if in public allowlist
            if (publicEndpoints.contains(route)) {
                continue;
            }

            // Must have @PreAuthorize or other security annotation
            boolean hasAuth =
                method.hasMethodAnnotation(PreAuthorize.class) ||
                method.hasMethodAnnotation(Secured.class) ||
                method.getBeanType().isAnnotationPresent(PreAuthorize.class);

            assertThat(hasAuth)
                .withFailMessage("Endpoint %s lacks authorization annotation", route)
                .isTrue();
        }
    }

    private Set<String> getPublicEndpointAllowlist() {
        return Set.of(
            "/health",
            "/actuator/health",
            "/login",
            "/error"
        );
    }
}
```

## Priority 3: Technical Accuracy

### 8. Version-Aware Config Recommendations
**Problem**: Recommending deprecated `WebSecurityConfigurerAdapter`

**Solution**: Detect Spring Security version, recommend appropriately:

**For Spring Security 5.7+ (Boot 2.7):**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/health", "/actuator/health").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

**Implementation**:
```python
def _detect_spring_security_version(self) -> str:
    """Query for Spring Security version from dependencies"""
    # Check pom.xml or build.gradle
    # Return: '5.7', '5.8', '6.0', etc.

def _generate_config_example(self, version: str) -> str:
    """Generate config example appropriate for detected version"""
    if version >= '5.7':
        return SECURITY_FILTER_CHAIN_EXAMPLE
    else:
        return WEB_SECURITY_ADAPTER_EXAMPLE
```

### 9. Remove Service-Layer Guidance
**Problem**: Violates stated scope (endpoint-only)

**Solution**:
- Remove all mentions of service-layer authorization from endpoint agent
- Add note: "Service-layer authorization is analyzed separately"
- Keep focus purely on route-level access control

## Priority 4: Evidence Utilization

### 10. Show Current Protection Mechanisms in Detail
**Problem**: Doesn't explain WHY routes are protected/unprotected

**Solution**: Enhance evidence to show specific mechanisms:
```json
{
  "route": "GET /api/users",
  "protection": {
    "method_annotation": "@PreAuthorize(\"hasRole('ADMIN')\")",
    "class_annotation": null,
    "http_security_matcher": ".antMatchers(\"/api/admin/**\").hasRole(\"ADMIN\")",
    "effective": "hasRole('ADMIN')",
    "source": "method_annotation"
  }
}
```

## Implementation Phases

### Phase 1 - Critical Fixes (Week 1)
- [ ] Detect role convention from existing code
- [ ] Update AI prompt to use detected convention
- [ ] Replace PUBLIC role with permitAll allowlist
- [ ] Define "protected" standard explicitly

### Phase 2 - Actionability (Week 2)
- [ ] Generate route-by-route classification table
- [ ] Add default deny statement
- [ ] Add definition of done
- [ ] Include test/guardrail code

### Phase 3 - Technical Accuracy (Week 3)
- [ ] Detect Spring Security version
- [ ] Generate version-appropriate config examples
- [ ] Remove service-layer guidance
- [ ] Query HttpSecurity config (if possible)

### Phase 4 - Evidence Enhancement (Week 4)
- [ ] Show detailed protection mechanisms
- [ ] Classify each unprotected route
- [ ] Generate suggested expressions per route
- [ ] Add rationale for classifications

## Success Metrics

After implementation, recommendations should achieve:
- **Understandability**: Excellent - Clear what to do
- **Clarity**: Excellent - Explicit protection standard and done criteria
- **Incisiveness**: Excellent - Route-by-route specific guidance
- **Technical Accuracy**: Excellent - Correct for Boot 2.7/Spring Security 5.x
- **Actionability**: Excellent - Complete implementation plan with code
- **Compelling**: Excellent - Specific gaps with enforcement mechanism
