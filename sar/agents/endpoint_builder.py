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

    def __init__(self, cpg_tool, debug: bool = False):
        self.cpg_tool = cpg_tool
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
        behaviors_by_method, global_behaviors = self._index_behaviors(all_mechanisms)

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
                global_behaviors
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

    def _index_behaviors(self, all_mechanisms: List[Dict]) -> tuple[Dict[str, List[Dict]], List[Dict]]:
        """
        Build lookups for behaviors:
        1. method_signature -> behaviors (method-specific authorizations)
        2. List of global behaviors (apply to ALL endpoints, e.g. HttpSecurity)

        Returns:
            (behaviors_by_method, global_behaviors)
        """
        by_method = {}
        global_behaviors = []

        for mechanism in all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                method_sig = behavior.get('method', '')

                if method_sig:
                    # Method-specific behavior
                    if method_sig not in by_method:
                        by_method[method_sig] = []
                    by_method[method_sig].append(behavior)
                else:
                    # Global behavior (no method - applies to all endpoints)
                    # E.g., HttpSecurity configuration
                    global_behaviors.append(behavior)

        return by_method, global_behaviors

    def _find_authorizations_for_endpoint(
        self,
        endpoint_method: str,
        endpoint_path: str,
        behaviors_by_method: Dict[str, List[Dict]],
        global_behaviors: List[Dict]
    ) -> List[EndpointAuthorization]:
        """
        Find all authorizations that apply to this endpoint

        Args:
            endpoint_method: Full method signature
            endpoint_path: Route path (e.g., "/owners/{id}")
            behaviors_by_method: Method-specific behaviors
            global_behaviors: Global behaviors (HttpSecurity, etc.)

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

        # 2. Global behaviors (HttpSecurity, filters, etc.)
        # TODO: In future, filter by URL pattern matching (e.g., /api/** matches /api/users)
        # For now, apply all global behaviors to all endpoints
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
