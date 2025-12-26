"""
EndpointBuilder - Builds endpoint-centric authorization view from behaviors

Converts behavior-based discovery results into endpoint-centric structure where
each HTTP endpoint shows all its authorization layers (route, middleware, controller, endpoint).
"""

from typing import Dict, Any, List, Optional
from sar.endpoint_authorization_schema import (
    Endpoint, EndpointAuthorization, EffectiveAuthorization,
    Authorization, Evidence, EnforcementPoint, Scope, AuthorizationType
)


class EndpointBuilder:
    """
    Builds Endpoint objects from discovered behaviors

    Takes behavior-based discovery results and converts to endpoint-centric view
    where each endpoint shows:
    - All authorization layers that apply to it
    - Effective authorization (result of all layers combined)
    - Clear evidence trail for each authorization
    """

    def __init__(self, cpg_tool, ai_client=None, debug: bool = False):
        self.cpg_tool = cpg_tool
        self.ai_client = ai_client
        self.debug = debug

    def build_endpoints(
        self,
        route_methods: List[Dict],
        all_mechanisms: List[Dict]
    ) -> List[Endpoint]:
        """
        Build Endpoint objects from discovered routes and behaviors

        Args:
            route_methods: List of HTTP routes from Joern query
                [{'method': 'full.signature', 'httpMethod': 'GET', 'route': '/owners/{id}', ...}, ...]
            all_mechanisms: List of mechanism dicts with behaviors
                [{'framework': 'spring-security', 'behaviors': [{...}, ...], ...}, ...]

        Returns:
            List of Endpoint objects with authorizations and effective_authorization

        Strategy:
        1. Start with all HTTP routes (from Joern query)
        2. For each route, find ALL authorizations that apply:
           - Method-level (@PreAuthorize) → endpoint_guard
           - Class-level → controller_guard
           - HttpSecurity config → route_guard
           - Filters/Interceptors → middleware_guard
        3. Build Endpoint with authorizations[]
        4. Compute effective_authorization based on precedence
        """
        if self.debug:
            print(f"[ENDPOINT_BUILDER] Building endpoints from {len(route_methods)} routes and {len(all_mechanisms)} mechanisms")

        endpoints = []

        # Build lookup maps:
        # 1. method_signature -> behaviors (method-specific)
        # 2. global behaviors (no method - apply to all endpoints)
        # 3. http_security_rules (parsed URL patterns from HttpSecurity config)
        behaviors_by_method, global_behaviors, http_security_rules = self._index_behaviors(all_mechanisms)

        for route in route_methods:
            method_sig = route.get('method', '')
            http_method = route.get('httpMethod', '*')
            route_path = route.get('route', route.get('path', ''))

            # Parse handler name from method signature
            handler = self._format_handler(method_sig)

            # Determine if we have a real route path (starts with /) or need fallback
            has_real_path = route_path and route_path.startswith('/')

            # FALLBACK: If no route path from query, use ClassName.methodName format
            # This handles the case where Joern route extraction fails
            display_path = route_path if has_real_path else handler

            # Generate unique endpoint ID
            # If real route path available, use method_path format: "GET_/owners/new"
            # If route unavailable, use method_handler format: "GET_OwnerController.initCreationForm"
            endpoint_id = f"{http_method}_{display_path}"

            # Find all authorizations for this endpoint
            authorizations = self._find_authorizations_for_endpoint(
                method_sig,
                route_path,
                behaviors_by_method,
                global_behaviors,
                http_security_rules
            )

            # Compute effective authorization
            effective_auth = self._compute_effective_authorization(authorizations)

            # Create Endpoint
            endpoint = Endpoint(
                id=endpoint_id,
                method=http_method,
                path=display_path,
                handler=handler,
                authorizations=authorizations,
                effective_authorization=effective_auth
            )

            endpoints.append(endpoint)

        if self.debug:
            print(f"[ENDPOINT_BUILDER] Built {len(endpoints)} endpoints")
            protected = [e for e in endpoints if e.authorizations]
            print(f"[ENDPOINT_BUILDER]   Protected: {len(protected)}")
            print(f"[ENDPOINT_BUILDER]   Unprotected: {len(endpoints) - len(protected)}")

        return endpoints

    def _index_behaviors(self, all_mechanisms: List[Dict]) -> tuple[Dict[str, List[Dict]], List[Dict], Optional[List[Dict]]]:
        """
        Build lookups for behaviors:
        1. method_signature -> behaviors (method-specific authorizations)
        2. List of global behaviors (apply to ALL endpoints, e.g. filters)
        3. HttpSecurity rules (parsed URL patterns with specific authorization)

        Returns:
            (behaviors_by_method, global_behaviors, http_security_rules)
        """
        by_method = {}
        global_behaviors = []
        http_security_rules = None

        for mechanism in all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                method_sig = behavior.get('method', '')
                behavior_type = behavior.get('type', '')

                if self.debug and mechanism.get('framework') == 'spring-security':
                    print(f"[ENDPOINT_BUILDER] spring-security behavior: type={behavior_type}, method={method_sig[:80] if method_sig else 'NONE'}")

                # Special handling for HttpSecurity configuration
                if behavior_type == 'http_security_config':
                    # Parse HttpSecurity with AI to extract specific rules
                    parsed_rules = self._parse_http_security_with_ai(behavior)
                    if parsed_rules:
                        http_security_rules = parsed_rules
                        # Store behavior reference for evidence
                        for rule in parsed_rules:
                            rule['_behavior'] = behavior
                    # Don't add to global_behaviors if we have specific rules
                    continue

                # Check if this is a global authorization (applies to ALL endpoints)
                # - Filters/interceptors without specific method
                is_global = (
                    'security_filter' in behavior_type.lower() or
                    not method_sig
                )

                if is_global:
                    # Global behavior - applies to all endpoints
                    global_behaviors.append(behavior)
                else:
                    # Method-specific behavior
                    if method_sig not in by_method:
                        by_method[method_sig] = []
                    by_method[method_sig].append(behavior)

        if self.debug:
            if http_security_rules:
                print(f"[ENDPOINT_BUILDER] Parsed {len(http_security_rules)} HttpSecurity rules")
                for rule in http_security_rules:
                    roles_str = ', '.join(rule.get('roles', [])) if rule.get('roles') else 'none'
                    print(f"[ENDPOINT_BUILDER]   - {rule['url_pattern']}: {rule['type']} [{roles_str}]")
            if global_behaviors:
                print(f"[ENDPOINT_BUILDER] Found {len(global_behaviors)} global behaviors (filters, etc.)")
                for gb in global_behaviors:
                    print(f"[ENDPOINT_BUILDER]   - {gb.get('mechanism', 'unknown')}: {gb.get('type', 'unknown')}")

        return by_method, global_behaviors, http_security_rules

    def _find_authorizations_for_endpoint(
        self,
        endpoint_method: str,
        endpoint_path: str,
        behaviors_by_method: Dict[str, List[Dict]],
        global_behaviors: List[Dict],
        http_security_rules: Optional[List[Dict]] = None
    ) -> List[EndpointAuthorization]:
        """
        Find all authorizations that apply to this endpoint

        Args:
            endpoint_method: Full method signature
            endpoint_path: Route path (e.g., "/owners/{id}")
            behaviors_by_method: Method-specific behaviors
            global_behaviors: Global behaviors (filters, etc.)
            http_security_rules: Parsed HttpSecurity URL patterns and rules

        Returns:
            List of EndpointAuthorization objects (ordered by precedence)
        """
        authorizations = []

        # 1. Method-specific behaviors (annotations on this specific method)
        method_behaviors = behaviors_by_method.get(endpoint_method, [])
        for behavior in method_behaviors:
            auth = self._behavior_to_endpoint_authorization(behavior)
            if auth:
                authorizations.append(auth)

        # 2. HttpSecurity rules (URL pattern matching)
        if http_security_rules and endpoint_path:
            for rule in http_security_rules:
                if self._url_matches_pattern(endpoint_path, rule['url_pattern']):
                    auth = self._http_security_rule_to_authorization(rule)
                    if auth:
                        authorizations.append(auth)
                        break  # First matching rule wins (Spring Security semantics)

        # 3. Global behaviors (filters, etc.)
        for behavior in global_behaviors:
            auth = self._behavior_to_endpoint_authorization(behavior)
            if auth:
                authorizations.append(auth)

        # Sort by precedence (most specific first)
        # Order: endpoint_guard > controller_guard > middleware_guard > route_guard
        precedence_order = {
            EnforcementPoint.ENDPOINT_GUARD: 0,
            EnforcementPoint.CONTROLLER_GUARD: 1,
            EnforcementPoint.MIDDLEWARE_GUARD: 2,
            EnforcementPoint.ROUTE_GUARD: 3,
            EnforcementPoint.INLINE_GUARD: 4,
            EnforcementPoint.SERVICE_GUARD: 5,
            EnforcementPoint.DATA_GUARD: 6,
            EnforcementPoint.UNKNOWN: 7
        }

        authorizations.sort(key=lambda a: precedence_order.get(a.enforcement_point, 999))

        return authorizations

    def _behavior_to_endpoint_authorization(self, behavior: Dict) -> Optional[EndpointAuthorization]:
        """
        Convert a behavior dict to EndpointAuthorization

        Args:
            behavior: Behavior dict from discovery phase
                {
                    'type': 'authorization_annotation',
                    'mechanism': '@PreAuthorize',
                    'method': 'full.signature',
                    'class': 'OwnerController',
                    'file': 'OwnerController.java',
                    'line': 42,
                    'roles': ['ADMIN'],
                    'location_type': 'endpoint',
                    'httpMethod': 'POST'
                }

        Returns:
            EndpointAuthorization or None if can't convert
        """
        mechanism_name = behavior.get('mechanism', 'unknown')
        location_type = behavior.get('location_type', 'unknown')
        roles = behavior.get('roles', [])
        file_path = behavior.get('file', 'unknown')
        line = behavior.get('line', 0)

        # Determine enforcement point
        enforcement_point = self._infer_enforcement_point(mechanism_name, location_type, behavior)

        # Determine scope
        scope = self._infer_scope(location_type, behavior)

        # Build authorization
        if roles:
            authorization = Authorization(
                type=AuthorizationType.RBAC,
                roles_any_of=roles,
                rule=None
            )
            description = f"Requires any of: {', '.join(roles)}"
        else:
            authorization = Authorization(
                type=AuthorizationType.OTHER,
                roles_any_of=None,
                rule=f"{mechanism_name} authorization"
            )
            description = f"Protected by {mechanism_name}"

        # Build evidence
        evidence = Evidence(
            ref=f"{file_path}:{line}",
            mechanism_name=mechanism_name
        )

        return EndpointAuthorization(
            enforcement_point=enforcement_point,
            scope=scope,
            authorization=authorization,
            description=description,
            evidence=evidence
        )

    def _infer_enforcement_point(
        self,
        mechanism_name: str,
        location_type: str,
        behavior: Dict
    ) -> EnforcementPoint:
        """
        Infer enforcement point from mechanism name and location type

        Examples:
        - @PreAuthorize on method → endpoint_guard
        - @Secured on class → controller_guard
        - HttpSecurity config → route_guard
        - @Superadmin (custom) on method → endpoint_guard
        """
        # Route-level (HttpSecurity configuration)
        if 'SecurityFilterChain' in mechanism_name or 'HttpSecurity' in mechanism_name:
            return EnforcementPoint.ROUTE_GUARD

        # Controller-level (class annotations)
        if location_type == 'class' or '(class-level)' in mechanism_name:
            return EnforcementPoint.CONTROLLER_GUARD

        # Endpoint-level (method annotations)
        if location_type == 'endpoint':
            return EnforcementPoint.ENDPOINT_GUARD

        # Service-level
        if location_type == 'service':
            return EnforcementPoint.SERVICE_GUARD

        # Manual checks in code
        if 'if' in mechanism_name.lower() or 'check' in mechanism_name.lower():
            return EnforcementPoint.INLINE_GUARD

        # Default
        return EnforcementPoint.UNKNOWN

    def _infer_scope(self, location_type: str, behavior: Dict) -> Scope:
        """
        Infer scope from location type

        Examples:
        - HttpSecurity config → global
        - Class annotation → controller
        - Method annotation → endpoint
        """
        if location_type == 'class':
            return Scope.CONTROLLER
        elif location_type == 'endpoint':
            return Scope.ENDPOINT
        elif location_type == 'service':
            return Scope.CONTROLLER  # Service class applies to all methods
        else:
            return Scope.UNKNOWN

    def _compute_effective_authorization(
        self,
        authorizations: List[EndpointAuthorization]
    ) -> EffectiveAuthorization:
        """
        Determine effective authorization based on precedence

        Precedence (most specific wins):
        1. endpoint_guard (method-level) - WINS
        2. controller_guard (class-level)
        3. middleware_guard (interceptors)
        4. route_guard (HttpSecurity) - most global

        Args:
            authorizations: List of EndpointAuthorization (already sorted by precedence)

        Returns:
            EffectiveAuthorization representing net result
        """
        if not authorizations:
            # No authorization found
            return EffectiveAuthorization(
                type=AuthorizationType.UNKNOWN,
                roles_any_of=None,
                description="No authorization detected"
            )

        # Most specific authorization wins (first in sorted list)
        winning_auth = authorizations[0]

        # Build effective authorization from winning auth
        return EffectiveAuthorization(
            type=winning_auth.authorization.type,
            roles_any_of=winning_auth.authorization.roles_any_of,
            description=f"{winning_auth.enforcement_point}: {winning_auth.description}"
        )

    def _is_global_pattern(self, url_pattern: str) -> bool:
        """
        Check if a URL pattern is a catch-all (global) pattern

        Examples of global patterns:
        - "/**" - matches all paths
        - "/*" - matches all single-level paths
        - "/" - root only (not global)
        - "" or "*" - empty/wildcard

        Args:
            url_pattern: URL pattern from HttpSecurity rule

        Returns:
            True if pattern applies globally, False otherwise
        """
        if not url_pattern:
            return False

        # Common catch-all patterns (framework-agnostic)
        catch_all_patterns = ['/**', '/*', '*', '**']

        return url_pattern in catch_all_patterns

    def _url_matches_pattern(self, url: str, pattern: str) -> bool:
        """
        Check if URL matches ant-style pattern

        Examples:
        - "/admin/**" matches "/admin/users", "/admin/config/settings"
        - "/api/*" matches "/api/users" but not "/api/users/123"
        - "/**" matches everything
        """
        import re

        # Convert Spring ant pattern to regex
        # ** = any number of path segments
        # * = single path segment (no slashes)
        # ? = single character

        # Escape special regex chars except our wildcards
        regex_pattern = re.escape(pattern)

        # Replace ant wildcards with regex equivalents
        regex_pattern = regex_pattern.replace(r'\*\*', '<<DOUBLESTAR>>')
        regex_pattern = regex_pattern.replace(r'\*', '[^/]+')  # * matches within single segment
        regex_pattern = regex_pattern.replace('<<DOUBLESTAR>>', '.*')  # ** matches across segments
        regex_pattern = regex_pattern.replace(r'\?', '.')  # ? matches single char

        # Anchor the pattern
        regex_pattern = f'^{regex_pattern}$'

        return bool(re.match(regex_pattern, url))

    def _http_security_rule_to_authorization(self, rule: Dict) -> Optional[EndpointAuthorization]:
        """
        Convert HttpSecurity rule to EndpointAuthorization

        Args:
            rule: {
                'url_pattern': '/admin/**',
                'type': 'RBAC' | 'AUTHENTICATED' | 'PERMIT_ALL',
                'roles': ['ADMIN'],
                'description': '...',
                '_behavior': {...}  # Original behavior for evidence
            }
        """
        rule_type = rule.get('type', 'AUTHENTICATED')
        roles = rule.get('roles', [])
        behavior = rule.get('_behavior', {})
        url_pattern = rule.get('url_pattern', '')

        # Build authorization based on type
        if rule_type == 'RBAC' and roles:
            authorization = Authorization(
                type=AuthorizationType.RBAC,
                roles_any_of=roles,
                rule=None
            )
            description = f"Requires any of: {', '.join(roles)}"
        elif rule_type == 'PERMIT_ALL':
            # Explicitly configured to permit all - report this!
            authorization = Authorization(
                type=AuthorizationType.OTHER,
                roles_any_of=None,
                rule="Permits all requests (no authorization required)"
            )
            description = "Explicitly configured to permit all requests"
        else:  # AUTHENTICATED
            authorization = Authorization(
                type=AuthorizationType.OTHER,
                roles_any_of=None,
                rule="Authentication required"
            )
            description = "Requires authentication"

        # Determine scope based on URL pattern
        # Catch-all patterns like /** = global scope
        scope = Scope.GLOBAL if self._is_global_pattern(url_pattern) else Scope.UNKNOWN

        # Build evidence from behavior
        file_path = behavior.get('file', 'unknown')
        line = behavior.get('line', 0)
        mechanism_name = behavior.get('mechanism', 'HttpSecurity')
        config_code = rule.get('_config_code', '')

        evidence = Evidence(
            ref=f"{file_path}:{line}",
            mechanism_name=mechanism_name,
            config_snippet=config_code if config_code else None
        )

        return EndpointAuthorization(
            enforcement_point=EnforcementPoint.ROUTE_GUARD,
            scope=scope,
            authorization=authorization,
            description=description,
            evidence=evidence
        )

    def _parse_http_security_with_ai(self, behavior: Dict) -> Optional[List[Dict]]:
        """
        Use AI to parse HttpSecurity configuration and extract authorization rules

        Returns:
            List of rule dicts: [
                {
                    'url_pattern': '/admin/**',
                    'roles': ['ADMIN'],
                    'type': 'RBAC',  # or 'AUTHENTICATED', 'PERMIT_ALL'
                    'description': 'Admin endpoints require ADMIN role'
                },
                ...
            ]
            Returns None if configuration permits all or has no meaningful authorization
        """
        if not self.ai_client:
            if self.debug:
                print("[ENDPOINT_BUILDER] No AI client available for HttpSecurity parsing")
            return None

        # Get source code location from behavior
        file_path = behavior.get('file', '')
        line = behavior.get('line', 0)

        if not file_path:
            return None

        # Make file path absolute if relative
        import os
        if not os.path.isabs(file_path):
            # Try to get project root from cpg_tool
            if hasattr(self.cpg_tool, 'project_dir'):
                file_path = os.path.join(self.cpg_tool.project_dir, file_path)

        # Read the source file and extract the configure method
        try:
            with open(file_path, 'r') as f:
                source_lines = f.readlines()

            # Extract the relevant method/configuration code
            # Start from the behavior's line and extract the method body
            method_start = max(0, line - 1)  # Line numbers are 1-indexed

            # Find the method signature (go back if needed)
            for i in range(method_start, max(0, method_start - 20), -1):
                line_text = source_lines[i]
                # Look for method declaration patterns (public/protected/private void/etc methodName(...))
                if any(keyword in line_text for keyword in ['public ', 'protected ', 'private ', '@Override']) and '(' in line_text:
                    method_start = i
                    break

            # Extract method body (find matching braces)
            brace_count = 0
            method_lines = []
            for i in range(method_start, len(source_lines)):
                line_text = source_lines[i]
                method_lines.append(line_text)

                brace_count += line_text.count('{')
                brace_count -= line_text.count('}')

                if brace_count == 0 and '{' in ''.join(method_lines):
                    break

            config_code = ''.join(method_lines)

            if self.debug:
                print(f"[ENDPOINT_BUILDER] Parsing HttpSecurity configuration with AI ({len(config_code)} chars)")

            # Use AI to parse the configuration
            prompt = f"""You are analyzing HTTP security configuration code to extract authorization rules.

Here is the configuration code:

```
{config_code}
```

Your task: Parse the authorization rules and return a JSON array. Each rule should specify:
1. url_pattern: URL pattern that this rule applies to (e.g., "/admin/**", "/api/**", "/**")
2. type: One of: "RBAC" (role-based access), "AUTHENTICATED" (any authenticated user), or "PERMIT_ALL" (public/no auth)
3. roles: Array of role names (for RBAC type), empty array otherwise
4. description: Brief description of what this rule does

IMPORTANT INSTRUCTIONS:
- Look for URL patterns and what authorization they require (roles, authentication, or permitAll)
- If configuration explicitly permits all requests (permitAll), use type "PERMIT_ALL"
- If configuration requires authentication but no specific roles, use type "AUTHENTICATED"
- Extract ALL URL patterns with their authorization requirements
- For role requirements, extract role names (strip any framework prefix like "ROLE_" if present)
- Return rules in order from most specific to least specific (first match wins in most frameworks)
- ALWAYS return rules for permitAll configurations - they show intentional public access

Return ONLY valid JSON array, no explanations or markdown.

Example outputs:

If the code has specific role requirements:
[
  {{"url_pattern": "/admin/**", "type": "RBAC", "roles": ["ADMIN"], "description": "Admin area requires ADMIN role"}},
  {{"url_pattern": "/api/**", "type": "AUTHENTICATED", "roles": [], "description": "API requires authentication"}},
  {{"url_pattern": "/**", "type": "AUTHENTICATED", "roles": [], "description": "All other requests require authentication"}}
]

If the code explicitly permits everything (permitAll on all requests):
[
  {{"url_pattern": "/**", "type": "PERMIT_ALL", "roles": [], "description": "Permits all requests without authorization"}}
]

If there's NO security configuration or it's unclear:
[]

Now analyze the code above and return the authorization rules:
"""

            response = self.ai_client.call_claude(prompt)

            if not response:
                return None

            # Parse JSON response
            import json
            try:
                # Extract JSON from response (might have explanatory text)
                json_start = response.find('[')
                json_end = response.rfind(']') + 1
                if json_start >= 0 and json_end > json_start:
                    json_text = response[json_start:json_end]
                    rules = json.loads(json_text)

                    if self.debug:
                        print(f"[ENDPOINT_BUILDER] Parsed {len(rules)} HttpSecurity rules")
                        for rule in rules:
                            print(f"[ENDPOINT_BUILDER]   - {rule['url_pattern']}: {rule['type']} {rule.get('roles', [])}")

                    # Add the config code to each rule for evidence
                    for rule in rules:
                        rule['_config_code'] = config_code

                    return rules if rules else None
                else:
                    if self.debug:
                        print("[ENDPOINT_BUILDER] No JSON array found in AI response")
                    return None
            except json.JSONDecodeError as e:
                if self.debug:
                    print(f"[ENDPOINT_BUILDER] JSON parse error: {e}")
                return None

        except Exception as e:
            if self.debug:
                print(f"[ENDPOINT_BUILDER] Error parsing HttpSecurity: {e}")
            return None

    def _format_handler(self, method_sig: str) -> str:
        """
        Format method signature as human-readable handler

        Examples:
        - 'org.springframework.samples.petclinic.owner.OwnerController.updateOwner:String(int)'
          → 'OwnerController.updateOwner'
        - 'com.example.PetService.findPet:Pet(Long)'
          → 'PetService.findPet'

        Handles full Joern signatures: package.Class.method:returnType(params)
        """
        if not method_sig:
            return 'unknown'

        # Format: package.Class.method:returnType(params)
        # Step 1: Split on colon to separate method from signature
        if ':' in method_sig:
            method_part = method_sig.split(':')[0]
        else:
            method_part = method_sig

        # Step 2: Remove parameter list if present (shouldn't be, but handle it)
        if '(' in method_part:
            method_part = method_part.split('(')[0]

        # Step 3: Get ClassName.methodName from package.path
        # Example: org.springframework.samples.petclinic.owner.OwnerController.initCreationForm
        #          → OwnerController.initCreationForm
        parts = method_part.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"

        return method_sig
