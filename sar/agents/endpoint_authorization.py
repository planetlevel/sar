"""
Endpoint Authorization Agent

Analyzes HTTP route-level access control to determine if endpoints have appropriate
authorization checks. Discovers both standard framework patterns and custom
authorization mechanisms through agentic AI investigation.

SCOPE: HTTP endpoints only (controllers/routes). Does NOT cover @Scheduled jobs,
@EventListener, message listeners, or internal service-to-service calls.

Three-Phase Analysis:
1. Mechanism Discovery - Find standard + custom authorization patterns
2. Architecture Evaluation - Assess authorization architecture quality
3. Finding Generation - Generate actionable recommendations
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import os
from .authorization_utils import AuthorizationUtils
from sar.report_utils import build_defense_usage_matrix, build_defense_metadata, calculate_metrics


class EndpointAuthorizationAgent:
    """
    Analyzes HTTP endpoint-level ROLE-BASED authorization (route access control)

    Scope:
    - ✅ Can role X access HTTP endpoint Y?
    - ✅ Which HTTP endpoints require which roles?
    - ✅ Framework-based role checks (annotations, middleware)
    - ✅ Custom role authorization (meta-annotations, custom methods)
    - ✅ Prevents unauthorized HTTP access via web framework
    - ✅ Focus: ROLES (ADMIN, USER, VET, OWNER, etc.)

    Out of Scope:
    - ❌ Fine-grained permissions/authorities (handled by separate agent)
    - ❌ Data-level authorization / IDOR
    - ❌ Authentication mechanisms
    - ❌ Session management
    - ❌ Non-HTTP entry points (@Scheduled, @EventListener, message listeners, etc.)
    """

    def __init__(self,
                 cpg_tool,
                 project_dir: str,
                 ai_client = None,
                 architecture_report: Dict = None,
                 debug: bool = False):
        self.cpg_tool = cpg_tool
        self.project_dir = project_dir
        self.ai = ai_client
        self.architecture_report = architecture_report or {}
        self.debug = debug

        # Get frameworks directory (relative to sar/ directory)
        sar_dir = Path(__file__).parent.parent
        self.frameworks_dir = sar_dir / 'frameworks'

        # Initialize utility helper
        self.utils = AuthorizationUtils(
            cpg_tool=cpg_tool,
            project_dir=project_dir,
            frameworks_dir=self.frameworks_dir,
            ai_client=ai_client,
            debug=debug
        )

        # State from Phase 1
        self.standard_mechanisms = []
        self.all_mechanisms = []

        # State from Phase 2
        self.architecture_evaluation = {}

        # State from Phase 3
        self.discovered_exposures = []  # Exposures discovered during metrics calculation

        # Detect Spring versions for version-specific recommendations
        self.spring_versions = self._detect_spring_versions()

    def _detect_spring_versions(self) -> Dict[str, Optional[str]]:
        """
        Detect Spring Boot and Spring Security versions from architecture report

        Returns dict with 'spring_boot' and 'spring_security' version strings
        """
        versions = {
            'spring_boot': None,
            'spring_security': None
        }

        if not self.architecture_report:
            return versions

        # Extract from architecture report libraries section
        libraries = self.architecture_report.get('libraries', [])

        for lib in libraries:
            name = lib.get('name', '').lower()
            version = lib.get('version', '')

            if 'spring-boot' in name and not versions['spring_boot']:
                versions['spring_boot'] = version
            elif 'spring-security' in name and not versions['spring_security']:
                versions['spring_security'] = version

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Detected Spring versions:")
            print(f"  Spring Boot: {versions['spring_boot'] or 'not detected'}")
            print(f"  Spring Security: {versions['spring_security'] or 'not detected'}")

        return versions

    def _ai_discover_roles(self, endpoint_sample: List[Dict], current_roles: List[str]) -> Dict:
        """
        Phase 1: Discover domain-specific roles from sample of endpoints

        Args:
            endpoint_sample: List of ~30 representative endpoints (protected + unprotected)
            current_roles: Current roles from Joern analysis (e.g., ['USER', 'ADMIN'])

        Returns:
            {
                'current_roles': ['USER', 'ADMIN'],
                'proposed_roles': ['VET', 'OWNER', 'RECEPTIONIST', 'ADMIN'],
                'role_mapping': {'USER': 'OWNER', 'ADMIN': 'ADMIN'},
                'rationale': 'Why these roles are appropriate for this domain'
            }
        """
        prompt = f"""Analyze this application and propose domain-specific roles.

SAMPLE ENDPOINTS ({len(endpoint_sample)} representative samples):
{json.dumps(endpoint_sample, indent=2)}

CURRENT ROLES: {', '.join(current_roles) if current_roles else 'None detected'}

YOUR TASK:
1. Infer the application domain from endpoint names (OwnerController, PetController, etc.)
2. Propose domain-specific roles that reflect real business functions:
   - For veterinary clinic: VET, OWNER, RECEPTIONIST, ADMIN
   - For e-commerce: CUSTOMER, VENDOR, WAREHOUSE, ADMIN
   - For banking: CUSTOMER, TELLER, LOAN_OFFICER, MANAGER
   - Generic ADMIN/USER should only be used if no clear domain emerges

3. Map existing roles to proposed roles (e.g., USER → OWNER)

CRITICAL: NEVER SUGGEST "PUBLIC" AS A ROLE
- PUBLIC is not a role - it means "no authentication required"
- Public endpoints are configured at the HTTP/framework level with an allowlist, not with a role
- Do NOT include PUBLIC, ANONYMOUS, or UNAUTHENTICATED in the proposed roles list
- Roles are for AUTHENTICATED users with different permissions

IMPORTANT CONTEXT:
- Roles represent different business functions and their required operations
- ADMIN = System administrator role for administrative operations (config, diagnostics, user management)
- Other roles = Operational/functional roles for day-to-day business operations
- Each role should correspond to a distinct set of responsibilities in the application domain

Return JSON ONLY:
{{
  "current_roles": ["ADMIN", "USER"],
  "proposed_roles": ["VET", "OWNER", "RECEPTIONIST", "ADMIN"],
  "role_mapping": {{"USER": "OWNER", "ADMIN": "ADMIN"}},
  "rationale": "This is a veterinary clinic application. VET performs medical operations, OWNER manages pets, RECEPTIONIST handles registration."
}}
"""

        try:
            response = self.ai.call_claude(prompt, max_tokens=1000, temperature=0.3)
            if response:
                import re
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    result = json.loads(match.group(0))
                    if 'proposed_roles' in result and 'role_structure' not in result:
                        # Valid response
                        return result
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Role discovery failed: {e}")

        # Fallback: keep existing roles
        return {
            'current_roles': current_roles,
            'proposed_roles': current_roles if current_roles else ['USER', 'ADMIN'],
            'role_mapping': {role: role for role in current_roles},
            'rationale': 'Maintaining existing role structure (AI analysis unavailable)'
        }

    def _ai_classify_endpoints_chunked(self, endpoints: List[Dict], role_structure: Dict, chunk_size: int = 100) -> List[Dict]:
        """
        Phase 2: Classify all endpoints in chunks using discovered roles

        Uses compact bitset encoding to reduce tokens dramatically:
        - Input: idx http_method name current_bitset
        - Output: idx classification suggested_bits brief_reason

        Args:
            endpoints: All endpoints to classify
            role_structure: Role structure from Phase 1
            chunk_size: Endpoints per chunk (default 100 with bitset encoding)

        Returns:
            List of endpoint classifications
        """
        proposed_roles = role_structure['proposed_roles']
        all_classifications = []

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Classifying {len(endpoints)} endpoints in chunks of {chunk_size}")
            print(f"[{self.get_agent_id().upper()}] Proposed roles: {', '.join(proposed_roles)}")

        # Process in chunks
        for chunk_start in range(0, len(endpoints), chunk_size):
            chunk = endpoints[chunk_start:chunk_start+chunk_size]

            # Build compact representations
            compact_endpoints = []
            for idx, ep in enumerate(chunk):
                endpoint_name = ep.get('endpoint', '')

                # Parse endpoint format: "GET /api/owners" or "GET OwnerController.getOwner"
                parts = endpoint_name.split(' ', 1)
                http_method = parts[0] if parts else 'GET'
                method_name = parts[1] if len(parts) > 1 else endpoint_name

                # Build current protection bitset
                current_roles_list = ep.get('roles', []) if ep.get('protected') else []
                current_bits = ''.join('1' if role in current_roles_list else '0' for role in proposed_roles)

                compact_endpoints.append(f"{idx} {http_method} {method_name} {current_bits}")

            prompt = f"""You are creating a DEFENSE DEPLOYMENT MATRIX showing which role checks to apply at each endpoint.

ROLES: {' '.join(f"{i}={role}" for i, role in enumerate(proposed_roles))}

IMPORTANT: This matrix shows WHICH ROLE(S) TO CHECK at each endpoint, not who has access.
- Each bit = "should this endpoint check for this role?"
- Be thoughtful: which role(s) make sense to CHECK based on the operation?
- ADMIN checks should ONLY appear on admin-specific operations (config, diagnostics, system management)
- Most endpoints check for operational roles (VET, OWNER, RECEPTIONIST) NOT admin

ENDPOINTS (compact format):
{chr(10).join(compact_endpoints)}

CLASSIFICATION CODES:
- P = PUBLIC (no authentication required - configured at framework/HTTP layer)
- A = AUTHENTICATED (any logged-in user - requires authentication but no specific role)
- R = ROLE_SPECIFIC (check for specific role(s) - requires authentication + role check)

CRITICAL: PUBLIC IS NOT A ROLE
- P classification means "no authentication required" - configured at framework level, NOT a role check
- Never set role bits for PUBLIC endpoints (bitset should be 0000)
- PUBLIC endpoints are allowlisted at the HTTP/framework layer, they do NOT get role checks

OUTPUT FORMAT (one line per endpoint):
idx classification suggested_bits brief_reason

Example (assuming roles: 0=VET 1=OWNER 2=RECEPTIONIST 3=ADMIN):
0 R 1000 medical operations
1 P 0000 public welcome (no role bits - framework allowlist)
2 R 0001 crash testing
3 R 0110 pet registration
4 R 1110 visit scheduling

INSTRUCTIONS:
- P classification: bitset must be 0000 (no roles) - configured at framework/HTTP layer
- A classification: bitset must be 0000 (no specific roles) - any authenticated user
- R classification: set bits for which role(s) should be checked
- ADMIN bit should ONLY be set for admin-specific operations (config, crash testing, system management)
- For rationale: Brief phrase explaining the FUNCTION (don't repeat role names - the bitset shows that)
- Return ONLY {len(chunk)} data lines, NO preamble, NO markdown

YOUR RESPONSE (data lines only):"""

            try:
                response = self.ai.call_claude(prompt, max_tokens=2000, temperature=0.3)
                if response:
                    lines = response.strip().split('\n')

                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue

                        parts = line.split(None, 3)  # Split on whitespace, max 4 parts
                        if len(parts) < 4:
                            continue

                        try:
                            idx = int(parts[0])
                        except ValueError:
                            # Skip lines that don't start with a number (preamble text)
                            continue

                        classification = parts[1]
                        suggested_bits = parts[2]
                        rationale = parts[3]

                        # Map classification codes
                        if classification == 'P':
                            suggested_auth = 'PUBLIC'
                            suggested_role = None
                        elif classification == 'A':
                            suggested_auth = 'AUTHENTICATED'
                            suggested_role = 'USER'
                        elif classification == 'R':
                            suggested_auth = 'ROLE_SPECIFIC'
                            # Decode bitset to role names
                            roles = [proposed_roles[i] for i, bit in enumerate(suggested_bits) if bit == '1' and i < len(proposed_roles)]
                            suggested_role = roles if roles else proposed_roles[0]
                        else:
                            suggested_auth = 'AUTHENTICATED'
                            suggested_role = 'USER'

                        if idx < len(chunk):
                            endpoint_data = chunk[idx]
                            all_classifications.append({
                                'endpoint': endpoint_data.get('endpoint', ''),
                                'current_auth': ', '.join(endpoint_data.get('roles', [])) if endpoint_data.get('protected') else None,
                                'suggested_auth': suggested_auth,
                                'suggested_role': suggested_role,
                                'rationale': rationale
                            })

                if self.debug:
                    print(f"[{self.get_agent_id().upper()}]   ✓ Chunk {chunk_start//chunk_size + 1} classified {len([c for c in all_classifications if c['endpoint'] in [ep['endpoint'] for ep in chunk]])} endpoints")

            except Exception as e:
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}]   ✗ Chunk {chunk_start//chunk_size + 1} failed: {e}")

                # Fallback for this chunk: mark as needing review
                for ep in chunk:
                    all_classifications.append({
                        'endpoint': ep.get('endpoint', ''),
                        'current_auth': ', '.join(ep.get('roles', [])) if ep.get('protected') else None,
                        'suggested_auth': 'AUTHENTICATED',
                        'suggested_role': 'USER',
                        'rationale': 'Needs manual review (AI classification failed)'
                    })

        return all_classifications

    def _ai_analyze_access_control_matrix(self, defense_matrix: Dict, roles: Dict) -> Dict:
        """
        Two-phase AI analysis:
        1. Sample 30 random endpoints → discover domain-specific roles
        2. Classify ALL endpoints in chunks using discovered roles

        Returns:
            {
                'role_structure': {...},
                'endpoint_classifications': [...],
                'total_endpoints': int,
                ...
            }
        """
        if not self.ai:
            raise ValueError("AI client required for endpoint authorization agent - algorithmic fallback removed")

        rows = defense_matrix.get('rows', [])
        columns = defense_matrix.get('columns', [])
        matrix = defense_matrix.get('matrix', [])
        row_protected = defense_matrix.get('row_protected', [])

        # Build current state summary
        current_state = []
        for i, endpoint_name in enumerate(rows):
            is_protected = row_protected[i] if i < len(row_protected) else False
            current_roles = []

            if is_protected and i < len(matrix):
                for j, has_role in enumerate(matrix[i]):
                    if has_role and j < len(columns):
                        current_roles.append(columns[j])

            current_state.append({
                'endpoint': endpoint_name,
                'protected': is_protected,
                'roles': current_roles if current_roles else None
            })

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Two-phase AI analysis:")
            print(f"[{self.get_agent_id().upper()}]   Phase 1: Role discovery from 30 random samples")
            print(f"[{self.get_agent_id().upper()}]   Phase 2: Chunked endpoint classification")

        # ========================================================================
        # PHASE 1: Role Discovery from 30 Random Samples
        # ========================================================================

        import random

        # Sample 30 endpoints (mix of protected and unprotected)
        protected_endpoints = [e for e in current_state if e.get('protected')]
        unprotected_endpoints = [e for e in current_state if not e.get('protected')]

        sample = []
        # Take up to 15 protected
        sample.extend(protected_endpoints[:15])
        # Take up to 15 unprotected (randomly if more than 15)
        if len(unprotected_endpoints) > 15:
            sample.extend(random.sample(unprotected_endpoints, 15))
        else:
            sample.extend(unprotected_endpoints)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}]   Sampled {len(sample)} endpoints ({sum(1 for e in sample if e.get('protected'))} protected, {sum(1 for e in sample if not e.get('protected'))} unprotected)")

        # Discover domain-specific roles from sample
        role_structure = self._ai_discover_roles(sample, roles.get('used', []))

        if self.debug:
            print(f"[{self.get_agent_id().upper()}]   Discovered roles: {', '.join(role_structure['proposed_roles'])}")
            print(f"[{self.get_agent_id().upper()}]   Rationale: {role_structure['rationale']}")

        # ========================================================================
        # PHASE 2: Chunked Endpoint Classification
        # ========================================================================

        endpoint_classifications = self._ai_classify_endpoints_chunked(
            current_state,
            role_structure,
            chunk_size=100
        )

        # Build result
        result = {
            'role_structure': role_structure,
            'endpoint_classifications': endpoint_classifications,
            'total_endpoints': len(endpoint_classifications),
            'currently_protected': sum(1 for e in endpoint_classifications if e.get('current_auth')),
            'suggested_authenticated': sum(1 for e in endpoint_classifications if e.get('suggested_auth') == 'AUTHENTICATED'),
            'suggested_role_specific': sum(1 for e in endpoint_classifications if e.get('suggested_auth') == 'ROLE_SPECIFIC')
        }

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] AI matrix analysis complete:")
            print(f"  Endpoints analyzed: {result['total_endpoints']}")
            print(f"  Suggested AUTHENTICATED: {result['suggested_authenticated']}")
            print(f"  Suggested ROLE_SPECIFIC: {result['suggested_role_specific']}")

        return result

    def _build_proposed_access_matrix(self, evidence: Dict) -> Dict:
        """
        Build enhanced access control matrix with suggested authorization for ALL endpoints

        Uses AI to analyze the actual endpoints and propose appropriate role structure
        and classifications based on the application domain.

        Returns complete matrix showing:
        - All endpoints (protected + unprotected)
        - Current authorization (if any)
        - Suggested authorization with rationale
        - Proposed role structure
        """
        defense_matrix = evidence.get('defense_usage_matrix', {})
        roles = evidence.get('roles', {})

        # Use AI to analyze matrix and propose role structure + endpoint classifications
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Using AI to analyze access control matrix...")

        return self._ai_analyze_access_control_matrix(defense_matrix, roles)


    def get_agent_id(self) -> str:
        return "endpoint_authorization"

    def get_agent_name(self) -> str:
        return "Endpoint Authorization (Route-Level Access Control)"

    def get_category(self) -> str:
        return "authorization"

    def should_run(self) -> Dict[str, Any]:
        """
        Check if agent should run

        Requires AI client for analysis
        """
        if not self.ai:
            return {
                'should_run': False,
                'reason': 'AI client required for endpoint authorization agent (algorithmic fallback removed)',
                'confidence': 1.0
            }

        return {
            'should_run': True,
            'reason': 'Route-level authorization analysis is fundamental for security',
            'confidence': 1.0
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Main analysis entry point - runs all three phases

        Returns defense report following CycloneDX schema
        """
        if self.debug:
            print(f"\n[{self.get_agent_id().upper()}] Starting analysis...")

        # Phase 1: Mechanism Discovery
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Phase 1: Mechanism Discovery")

        self.standard_mechanisms = self._discover_standard_mechanisms()

        # Detect authorization architecture pattern
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Detecting authorization architecture pattern...")

        self.auth_pattern = self._detect_authorization_pattern()

        # Discover routes and trace execution paths for Phase 1.5
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Discovering routes and tracing execution paths...")

        self._discover_routes_and_trace_paths()

        # Phase 1.5: Custom Defense Discovery
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Phase 1.5: Custom Defense Discovery")

        self.custom_mechanisms = self._discover_custom_defenses()

        # Consolidate ALL mechanisms (standard + custom)
        self.all_mechanisms = self.standard_mechanisms + self.custom_mechanisms

        # Phase 2: Architecture Evaluation (handled by AI in recommendation generation)

        # Phase 3: Finding Generation
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Phase 3: Finding Generation")

        evidence = self._build_evidence()
        defense_metadata = build_defense_metadata(self.all_mechanisms)
        metrics = calculate_metrics(evidence)
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

    # ========================================================================
    # PHASE 1: MECHANISM DISCOVERY
    # ========================================================================

    def _discover_standard_mechanisms(self) -> List[Dict]:
        """
        Discover standard authorization mechanisms using FrameworkTool

        This method now delegates ALL complexity to FrameworkTool:
        - Framework detection
        - Pattern loading
        - Query execution
        - Result parsing

        Agent just asks: "What authorization patterns exist?" and gets standardized results.
        """
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Using FrameworkTool to find authorization patterns...")

        # Use FrameworkTool centralized pattern searching
        # This replaces ~80 lines of framework detection, loading, pattern extraction, and query execution
        from sar.framework_tool import FrameworkTool

        tool = FrameworkTool(
            project_dir=self.project_dir,
            cpg_tool=self.cpg_tool
        )

        # Detect frameworks
        frameworks = tool.detect_frameworks()

        # Save for later use (needed by other methods)
        self.matched_frameworks = frameworks

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Detected {len(frameworks)} frameworks")
            for fw_id, fw_def in frameworks.items():
                print(f"[{self.get_agent_id().upper()}]   - {fw_id}: {fw_def.name}")

        # Find all authorization patterns
        all_behaviors = tool.find_authorization_patterns(frameworks)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(all_behaviors)} total authorization behaviors")

        # Group behaviors by framework for mechanism reporting
        # This preserves the expected data structure for downstream code
        mechanisms_by_framework = {}
        for behavior in all_behaviors:
            fw = behavior.get('framework', 'unknown')
            if fw not in mechanisms_by_framework:
                mechanisms_by_framework[fw] = []
            mechanisms_by_framework[fw].append(behavior)

        # Build mechanism dicts in expected format
        standard_mechanisms = []
        for framework_name, behaviors in mechanisms_by_framework.items():
            if behaviors:
                # Extract patterns from first behavior (they're all from same framework/category)
                first_behavior = behaviors[0]

                standard_mechanisms.append({
                    'framework': framework_name,
                    'category': 'authorization',
                    'type': 'standard',
                    'patterns': [],  # Patterns abstracted away in FrameworkTool
                    'behaviors': behaviors,
                    'count': len(behaviors),
                    # Metadata from standardized Behavior format
                    'pattern_group_target': 'joern',  # All current patterns use joern
                    'pattern_group_search_type': first_behavior.get('type', 'authorization_annotation'),
                    'pattern_group_description': f'{framework_name} authorization patterns'
                })

                if self.debug:
                    print(f"[{self.get_agent_id().upper()}]   ✓ {framework_name}: {len(behaviors)} behaviors")

        return standard_mechanisms

    def _gather_architectural_evidence(self) -> Dict:
        """
        Gather all evidence about where/how authorization is applied

        Evidence collected:
        - Class names and packages
        - HTTP annotations present
        - Sample behaviors for AI analysis
        """
        if not self.standard_mechanisms:
            return {}

        evidence = {
            'total_auth_methods': 0,
            'class_name_patterns': {},  # *Controller: 20, *Service: 45, etc.
            'package_distribution': {},  # controller: 20, service: 45, repository: 10
            'http_mapping_presence': 0,  # How many have HTTP methods
            'sample_behaviors': []  # Representative samples for AI
        }

        all_class_names = []
        all_method_signatures = []

        for mechanism in self.standard_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                evidence['total_auth_methods'] += 1

                # Analyze class name pattern
                class_name = behavior.get('class', '')
                class_pattern = self.utils.extract_class_pattern(class_name)
                evidence['class_name_patterns'][class_pattern] = \
                    evidence['class_name_patterns'].get(class_pattern, 0) + 1

                # Analyze package
                package = self.utils.extract_package(class_name)
                package_layer = self.utils.classify_package(package)
                evidence['package_distribution'][package_layer] = \
                    evidence['package_distribution'].get(package_layer, 0) + 1

                # Check for HTTP annotations (location_type == 'endpoint' or httpMethod present)
                if behavior.get('location_type') == 'endpoint' or \
                   (behavior.get('httpMethod') and behavior['httpMethod'] != 'UNKNOWN'):
                    evidence['http_mapping_presence'] += 1

                # Collect class names and method signatures for Joern queries
                if class_name and class_name not in all_class_names:
                    all_class_names.append(class_name)

                method_sig = behavior.get('method', '')
                if method_sig and method_sig not in all_method_signatures:
                    all_method_signatures.append(method_sig)

                # Gather sample behaviors (first 10)
                if len(evidence['sample_behaviors']) < 10:
                    evidence['sample_behaviors'].append({
                        'class': class_name,
                        'method': method_sig[-80:] if len(method_sig) > 80 else method_sig,
                        'mechanism': behavior.get('mechanism', ''),
                        'file': behavior.get('file', ''),
                        'location_type': behavior.get('location_type', ''),
                        'httpMethod': behavior.get('httpMethod', '')
                    })

        # Query Joern for additional evidence (limit to reasonable size)
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Querying for interfaces, markers, and callers...")

        evidence['interface_implementations'] = self.utils.query_interface_implementations(
            all_class_names[:100]  # Limit for performance
        )
        evidence['architectural_markers'] = self.utils.query_architectural_markers(
            all_class_names[:100]
        )
        evidence['caller_analysis'] = self.utils.query_caller_relationships(
            all_method_signatures[:50]  # Sample for performance
        )

        return evidence

    def _ai_analyze_architecture(self, evidence: Dict) -> Dict:
        """
        Use AI to analyze all evidence and determine authorization architecture

        AI acts as architectural detective to solve the puzzle of WHERE
        authorization is applied and WHY
        """
        if not self.ai:
            raise ValueError("AI client required for architecture analysis - algorithmic fallback removed")

        if not evidence:
            raise ValueError("No evidence provided for architecture analysis")

        # Build prompt with all evidence
        import json

        prompt = f"""You are an architectural detective analyzing where authorization is applied in this application.

EVIDENCE GATHERED:

1. CLASS NAME PATTERNS:
{json.dumps(evidence.get('class_name_patterns', {}), indent=2)}

2. PACKAGE DISTRIBUTION:
{json.dumps(evidence.get('package_distribution', {}), indent=2)}

3. HTTP MAPPING PRESENCE:
{evidence.get('http_mapping_presence', 0)} out of {evidence.get('total_auth_methods', 0)} authorized methods have HTTP route annotations (@GetMapping, etc.)

4. INTERFACE IMPLEMENTATIONS:
{json.dumps(evidence.get('interface_implementations', {}), indent=2)}

5. ARCHITECTURAL MARKERS (other annotations found):
{json.dumps(evidence.get('architectural_markers', {}), indent=2)}

6. CALLER ANALYSIS (who calls authorized methods):
{json.dumps(evidence.get('caller_analysis', {}), indent=2)}

7. SAMPLE BEHAVIORS (first 10):
{json.dumps(evidence.get('sample_behaviors', []), indent=2)}

YOUR TASK:
Analyze this evidence like a detective solving a puzzle. Determine:

1. WHERE is authorization applied?
   - Controller/Endpoint layer (HTTP boundary)
   - Service layer (business logic)
   - Repository layer (data access)
   - Filter/Interceptor layer (request processing)
   - Configuration layer (centralized rules)
   - Aspect-Oriented (cross-cutting)
   - Mixed (multiple layers)

2. WHY this architecture?
   - What clues led you to this conclusion?
   - What's the common pattern across authorized methods?

3. WHAT does this mean for coverage?
   - How should we measure protection given this architecture?

Respond in JSON ONLY (no markdown, no explanations outside JSON):
{{
  "pattern": "endpoint_layer|service_layer|repository_layer|filter_layer|config_layer|aspect_oriented|mixed",
  "confidence": 0.0-1.0,
  "primary_layer": "where most auth is concentrated",
  "evidence_summary": "What clues led to this conclusion (1-2 sentences)",
  "coverage_approach": "how to measure protection (1 sentence)",
  "architecture_description": "1-2 sentence explanation of the authorization architecture"
}}
"""

        try:
            response = self.ai.call_claude(prompt, max_tokens=1500, temperature=0)
            if response:
                import re
                # Extract JSON from response (handle markdown code blocks)
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    result = json.loads(match.group(0))

                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] AI Architecture Analysis:")
                        print(f"[{self.get_agent_id().upper()}]   Pattern: {result.get('pattern')}")
                        print(f"[{self.get_agent_id().upper()}]   Confidence: {result.get('confidence')}")
                        print(f"[{self.get_agent_id().upper()}]   Primary Layer: {result.get('primary_layer')}")

                    return result
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI analysis failed: {e}")
            raise ValueError(f"AI architecture analysis failed: {e}")


    def _detect_authorization_pattern(self) -> Dict:
        """
        Detective approach: Gather evidence and solve the architectural puzzle

        This method figures out WHERE authorization is applied by analyzing
        commonalities across all authorization locations.

        Returns comprehensive architecture analysis
        """
        # STEP 1: Gather evidence from all authorization behaviors
        evidence = self._gather_architectural_evidence()

        if not evidence:
            return {
                'pattern': 'none',
                'confidence': 1.0,
                'primary_layer': 'none',
                'evidence_summary': 'No authorization mechanisms detected',
                'coverage_approach': 'N/A',
                'architecture_description': 'No authorization detected in codebase'
            }

        # STEP 2: Use AI to analyze evidence and determine architecture
        architecture = self._ai_analyze_architecture(evidence)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Architecture Pattern Detected:")
            print(f"[{self.get_agent_id().upper()}]   Pattern: {architecture.get('pattern')}")
            print(f"[{self.get_agent_id().upper()}]   Primary Layer: {architecture.get('primary_layer')}")
            print(f"[{self.get_agent_id().upper()}]   Confidence: {architecture.get('confidence')}")
            print(f"[{self.get_agent_id().upper()}]   Summary: {architecture.get('evidence_summary')}")

        return architecture

    # REMOVED: _run_ai_analysis() - ai_insights was redundant with main recommendation
    # This method generated architecture_summary, coverage_gaps, recommendations, sound_design, reasoning
    # but this duplicated the detailed AI-generated analysis already in design_recommendation,
    # implementation_recommendation, and rationale fields. The prompts also asked about service
    # layer and data-level authorization which is outside the scope of endpoint authorization agent.
    #
    # Removed 2025-12-21 per user feedback

    def _build_ai_context(self) -> Dict:
        """
        Build comprehensive context for AI analysis

        Includes:
        - Standard mechanisms found
        - Protected locations (endpoints, services, code)
        - Framework definitions checked
        - Architecture pattern information
        - Questions to investigate
        """
        # Count protected locations by type
        protected_locations = {
            'endpoint': set(),
            'service': set(),
            'code': set(),
            'unknown': set()
        }

        for mechanism in self.standard_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                location_type = behavior.get('location_type', 'unknown')
                location = behavior.get('location', '')
                if location:
                    protected_locations[location_type].add(location)

        # Total authorization behaviors found
        total_auth_behaviors = sum(len(m.get('behaviors', [])) for m in self.standard_mechanisms)

        # Gather framework context
        frameworks_checked = [f.stem for f in self.frameworks_dir.glob('*.json')] if self.frameworks_dir.exists() else []
        frameworks_matched = [m['framework'] for m in self.standard_mechanisms]

        return {
            'total_auth_behaviors': total_auth_behaviors,
            'protected_locations': {
                'endpoint_count': len(protected_locations['endpoint']),
                'service_count': len(protected_locations['service']),
                'code_count': len(protected_locations['code']),
                'unknown_count': len(protected_locations['unknown'])
            },
            'frameworks_checked': frameworks_checked[:10],
            'frameworks_matched': frameworks_matched,
            'standard_mechanisms': self.standard_mechanisms,
            'standard_patterns': self.utils.get_standard_pattern_summary(self.standard_mechanisms),
            'architecture_pattern': self.auth_pattern,  # From detective analysis
            'questions_to_investigate': [
                'How is authorization configured in this application?',
                'Are protected locations intentionally secured or are there gaps?',
                'Is the authorization approach consistent and maintainable?',
                'Are there custom authorization patterns not detected by framework definitions?',
                'Does the architecture pattern match the application design?'
            ]
        }

    def _build_architecture_investigation_prompt(self, context: Dict) -> str:
        """Build prompt for AI to investigate authorization architecture"""
        # Sample authorization behaviors
        auth_samples = []
        for mech in context['standard_mechanisms'][:3]:
            for behavior in mech.get('behaviors', [])[:5]:
                auth_samples.append({
                    'class': behavior.get('class', 'unknown'),
                    'method': behavior.get('method', 'unknown')[-60:],  # Last 60 chars
                    'mechanism': behavior.get('mechanism', ''),  # Can be annotation, method, config, filter
                    'location': behavior.get('location', 'unknown'),
                    'location_type': behavior.get('location_type', 'unknown'),
                    'roles': behavior.get('roles', [])
                })

        # Get architecture pattern from detective analysis
        arch_pattern = context.get('architecture_pattern', {})

        return f"""You are a security architecture analyst investigating how authorization works in this application.

FINDINGS:
- Found {context['total_auth_behaviors']} authorization behaviors
- Protected locations: {context['protected_locations']['endpoint_count']} endpoints, {context['protected_locations']['service_count']} services, {context['protected_locations']['code_count']} other code locations
- Architecture pattern detected: {arch_pattern.get('pattern', 'unknown')} (confidence: {arch_pattern.get('confidence', 0)})
- Primary layer: {arch_pattern.get('primary_layer', 'unknown')}
- Frameworks: {', '.join(context['frameworks_matched'])}

AUTHORIZATION SAMPLES (first 15):
{json.dumps(auth_samples[:15], indent=2)}

ARCHITECTURE ANALYSIS:
{json.dumps(arch_pattern, indent=2)}

YOUR TASK:
Analyze this data and provide recommendations for improving authorization coverage. Answer these questions:

1. WHAT is the current authorization architecture?
   - Summarize WHERE authorization is applied (which architectural layers)
   - Is this consistent across the application?

2. WHERE are potential gaps in coverage?
   - Are there unprotected locations that should have authorization?
   - Is the pattern sound or are there architectural concerns?

3. HOW should coverage be improved?
   - Specific recommendations based on the architecture pattern
   - Should authorization be added at endpoints, services, or both?

4. WHAT is the recommended approach?
   - Should the application continue with current architecture?
   - Or should it migrate to a different pattern?

Respond in JSON:
{{
  "architecture_summary": "1-2 sentence description of current authorization architecture",
  "coverage_gaps": ["list", "of", "potential", "gaps"],
  "recommendations": ["specific", "actionable", "recommendations"],
  "sound_design": true/false,
  "reasoning": "Why you reached this conclusion based on the evidence"
}}"""

    def _parse_architecture_analysis(self, response_text: str) -> Dict:
        """Parse AI's architecture analysis response"""
        import json
        import re

        # Try to extract JSON
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except:
                pass

        # Fallback
        return {
            'pattern': 'unknown',
            'description': 'Could not parse AI analysis',
            'raw_response': response_text[:500]
        }

    # REMOVED: _extract_mechanisms_from_ai() - no longer needed after ai_insights removal

    # ========================================================================
    # PHASE 1.5: CUSTOM DEFENSE DISCOVERY
    # ========================================================================

    def _discover_routes_and_trace_paths(self):
        """
        Discover HTTP routes and trace their execution paths

        This gives us the actual request flow:
        Route → Controller → Service Layer → Data Access

        Much better than random sampling - we analyze real execution paths
        """
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Discovering routes and tracing execution paths...")

        # Step 1: Find all route entry points (methods with routing annotations)
        routes = self.utils.query_all_endpoint_methods(self.matched_frameworks)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(routes)} route entry points")

        # Step 2: For each route, trace what it calls (execution path)
        execution_paths = []

        # Sample routes to trace (don't trace all if there are hundreds)
        routes_to_trace = routes[:50] if len(routes) > 50 else routes

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Tracing execution paths for {len(routes_to_trace)} routes...")

        for route in routes_to_trace:
            route_method = route.get('method', '')

            # Trace call graph from this route
            called_methods = self._trace_call_graph(route_method, depth=2)

            execution_paths.append({
                'route': route,
                'entry_point': route_method,
                'called_methods': called_methods,
                'path_length': len(called_methods)
            })

        self.execution_paths = execution_paths

        # Store all unique methods in execution paths as discovered_exposures
        all_methods = set()
        for path in execution_paths:
            all_methods.add(path['entry_point'])
            all_methods.update(path['called_methods'])

        # Convert back to dict format for compatibility
        self.discovered_exposures = [{'method': m} for m in all_methods]

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Traced {len(execution_paths)} execution paths")
            print(f"[{self.get_agent_id().upper()}] Found {len(self.discovered_exposures)} unique methods in paths")

    def _trace_call_graph(self, method_sig: str, depth: int = 2) -> List[str]:
        """
        Trace what a method calls using Joern call graph

        Args:
            method_sig: Full method signature to trace from
            depth: How many levels deep to trace (default 2)

        Returns:
            List of method signatures called (directly and transitively)
        """
        if depth <= 0:
            return []

        # Escape special characters in method signature for Joern
        escaped_sig = method_sig.replace('"', '\\"')

        query = f'''
            cpg.method.fullName("{escaped_sig}")
              .callee
              .filterNot(_.isExternal)
              .fullName
              .dedup
              .l
              .toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if result.success and result.output and result.output.strip():
                called = json.loads(result.output)

                # If depth > 1, recursively trace what those methods call
                if depth > 1 and called:
                    transitive = []
                    for callee in called[:10]:  # Limit to avoid explosion
                        transitive.extend(self._trace_call_graph(callee, depth - 1))
                    called.extend(transitive)

                return list(set(called))  # Dedupe
        except:
            pass

        return []

    def _discover_custom_defenses(self) -> List[Dict]:
        """
        Discover custom authorization patterns by analyzing unprotected exposures

        Language/framework agnostic approach:
        1. Identify exposure pattern from WHERE standard defenses exist
        2. Find ALL exposures matching that pattern
        3. Sample high-risk unprotected exposures
        4. Read source code for those exposures
        5. Use AI to identify custom defense patterns in code
        6. Query CPG to find similar custom patterns
        7. Return custom mechanisms in standard format

        Returns:
            List of custom mechanism dicts matching standard_mechanisms format
        """
        if not self.ai:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Skipping custom defense discovery - no AI client")
            return []

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Starting custom defense discovery...")

        # Step 1: Get some unprotected exposures from existing discovery
        # We already discovered exposures in _generate_ai_coverage_metrics
        if not hasattr(self, 'discovered_exposures') or not self.discovered_exposures:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] No exposures discovered yet, skipping custom defense discovery")
            return []

        # Identify which are unprotected
        protected_methods = set()
        for mechanism in self.standard_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                protected_methods.add(behavior.get('method', ''))

        unprotected_exposures = [
            exp for exp in self.discovered_exposures
            if exp.get('method', '') not in protected_methods
        ]

        if not unprotected_exposures:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] All exposures protected by standard defenses")
            return []

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(unprotected_exposures)} unprotected exposures")

        # Step 2: Sample unprotected exposures (mix of high-risk and random)
        samples = self._sample_exposures_for_analysis(unprotected_exposures)

        if not samples:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] No exposures to analyze")
            return []

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Sampled {len(samples)} exposures for analysis")

        # Step 3: Read source code for ALL sampled exposures
        code_samples = self._read_exposure_source_code(samples)

        if not code_samples:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Could not read source code for exposures")
            return []

        # Step 4: Give ALL code samples to AI - let it figure out the patterns
        custom_patterns = self._ai_identify_custom_patterns(code_samples)

        if not custom_patterns:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] No custom defense patterns identified")
            return []

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] AI identified {len(custom_patterns)} custom pattern(s)")
            for i, pattern in enumerate(custom_patterns, 1):
                print(f"[{self.get_agent_id().upper()}]   Pattern {i}: {pattern.get('type')} - {pattern.get('pattern')}")

        # Step 7: Query CPG to find all instances of custom patterns
        custom_mechanisms = self._query_custom_patterns(custom_patterns)

        if self.debug:
            total_behaviors = sum(len(m.get('behaviors', [])) for m in custom_mechanisms)
            print(f"[{self.get_agent_id().upper()}] Found {total_behaviors} behaviors using custom patterns")

        return custom_mechanisms

    def _sample_exposures_for_analysis(self, unprotected_exposures: List[Dict]) -> List[Dict]:
        """
        Sample exposures from execution paths for AI analysis

        Strategy:
        - Use traced execution paths (routes → controllers → services)
        - Prioritize high-risk unprotected methods
        - Sample complete execution paths to give AI architectural context
        - Goal: ~30-50 methods from ~10-15 execution paths
        """
        import random

        if not hasattr(self, 'execution_paths') or not self.execution_paths:
            # Fallback to simple sampling if no execution paths
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] No execution paths, using simple sampling")
            return self._simple_sample(unprotected_exposures)

        high_risk_keywords = [
            'delete', 'remove', 'revoke',
            'admin', 'superadmin', 'systemadmin',
            'create', 'update', 'modify',
            'password', 'token', 'key', 'secret', 'credential',
            'grant', 'permission', 'role', 'access'
        ]

        # Build set of unprotected methods for quick lookup
        unprotected_methods = {exp.get('method') for exp in unprotected_exposures}

        # Score execution paths by risk
        scored_paths = []
        for path in self.execution_paths:
            route_info = path.get('route', {})
            route_method = route_info.get('method', '')
            http_method = route_info.get('httpMethod', '').lower()

            # Count unprotected methods in this path
            unprotected_in_path = [
                m for m in path.get('called_methods', [])
                if m in unprotected_methods
            ]
            if route_method in unprotected_methods:
                unprotected_in_path.append(route_method)

            # Calculate risk score
            risk_score = 0
            if http_method == 'delete':
                risk_score += 10
            if any(keyword in route_method.lower() for keyword in high_risk_keywords):
                risk_score += 5
            risk_score += len(unprotected_in_path)  # More unprotected = higher risk

            scored_paths.append({
                'path': path,
                'risk_score': risk_score,
                'unprotected_count': len(unprotected_in_path)
            })

        # Sort by risk score (highest first)
        scored_paths.sort(key=lambda x: x['risk_score'], reverse=True)

        # Take top 15 paths, but ensure we get at least 10 with unprotected methods
        selected_paths = []
        paths_with_unprotected = [p for p in scored_paths if p['unprotected_count'] > 0]
        paths_without_unprotected = [p for p in scored_paths if p['unprotected_count'] == 0]

        selected_paths.extend(paths_with_unprotected[:12])  # Top 12 with unprotected
        remaining = 15 - len(selected_paths)
        if remaining > 0 and paths_without_unprotected:
            selected_paths.extend(paths_without_unprotected[:remaining])

        # Extract all methods from selected paths
        sampled_exposures = []
        for scored_path in selected_paths:
            path = scored_path['path']
            route_info = path.get('route', {})

            # Add route entry point
            sampled_exposures.append({
                'method': route_info.get('method', ''),
                'file': route_info.get('file', ''),
                'line': route_info.get('line', 0),
                'httpMethod': route_info.get('httpMethod', ''),
                'path_context': 'route_entry_point'
            })

            # Add methods called from this route
            for called_method in path.get('called_methods', [])[:5]:  # Limit to 5 per path
                # Find file/line for this method
                method_info = self._lookup_method_location(called_method)
                sampled_exposures.append({
                    'method': called_method,
                    'file': method_info.get('file', ''),
                    'line': method_info.get('line', 0),
                    'httpMethod': 'UNKNOWN',
                    'path_context': f"called_from_{route_info.get('httpMethod', 'UNKNOWN')}_{route_info.get('route', '')}"
                })

        return sampled_exposures[:50]  # Cap at 50 total

    def _simple_sample(self, unprotected_exposures: List[Dict]) -> List[Dict]:
        """Fallback sampling when no execution paths available"""
        import random
        high_risk_keywords = [
            'delete', 'remove', 'revoke', 'admin', 'superadmin',
            'create', 'update', 'modify', 'password', 'token'
        ]

        high_risk = []
        normal_risk = []

        for exposure in unprotected_exposures:
            method = exposure.get('method', '').lower()
            http_method = exposure.get('httpMethod', '').lower()

            if http_method == 'delete' or any(keyword in method for keyword in high_risk_keywords):
                high_risk.append(exposure)
            else:
                normal_risk.append(exposure)

        samples = high_risk[:20]
        remaining = 30 - len(samples)
        if remaining > 0 and normal_risk:
            samples.extend(random.sample(normal_risk, min(remaining, len(normal_risk))))

        return samples

    def _lookup_method_location(self, method_sig: str) -> Dict:
        """Look up file/line for a method signature using Joern"""
        escaped_sig = method_sig.replace('"', '\\"')
        query = f'''
            cpg.method.fullName("{escaped_sig}")
              .map {{ m =>
                Map(
                  "file" -> m.file.name.headOption.getOrElse("unknown"),
                  "line" -> m.lineNumber.getOrElse(0)
                )
              }}.headOption.getOrElse(Map("file" -> "unknown", "line" -> 0))
              .toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if result.success and result.output and result.output.strip():
                return json.loads(result.output)
        except:
            pass

        return {'file': 'unknown', 'line': 0}

    def _read_exposure_source_code(self, exposures: List[Dict]) -> List[Dict]:
        """
        Read source code for sampled exposures

        Returns list of dicts with method info and source code
        """
        code_samples = []

        for exposure in exposures:
            method_sig = exposure.get('method', '')
            file_path = exposure.get('file', '')
            line_num = exposure.get('line', 0)

            if not file_path or not line_num:
                continue

            # Build full file path
            full_path = os.path.join(self.project_dir, file_path)

            try:
                # Read surrounding code context (method and annotations above it)
                with open(full_path, 'r') as f:
                    lines = f.readlines()

                # Get ~30 lines of context (annotations + method)
                start = max(0, line_num - 15)
                end = min(len(lines), line_num + 15)
                code_context = ''.join(lines[start:end])

                code_samples.append({
                    'method': method_sig,
                    'file': file_path,
                    'line': line_num,
                    'code': code_context,
                    'exposure': exposure
                })

            except Exception as e:
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] Could not read {file_path}: {e}")
                continue

        return code_samples

    def _build_execution_path_summary(self) -> str:
        """Build summary of execution paths for AI context"""
        if not hasattr(self, 'execution_paths') or not self.execution_paths:
            return "No execution paths traced"

        summary_lines = [
            f"Traced {len(self.execution_paths)} execution paths from routes through business logic:",
            ""
        ]

        for i, path in enumerate(self.execution_paths[:10], 1):  # Show first 10
            route_info = path.get('route', {})
            http_method = route_info.get('httpMethod', 'UNKNOWN')
            route = route_info.get('route', 'unknown')
            path_length = path.get('path_length', 0)

            summary_lines.append(f"{i}. {http_method} {route}")
            summary_lines.append(f"   → Calls {path_length} methods in business logic")

        if len(self.execution_paths) > 10:
            summary_lines.append(f"... and {len(self.execution_paths) - 10} more paths")

        return "\n".join(summary_lines)

    def _ai_identify_custom_patterns(self, code_samples: List[Dict]) -> List[Dict]:
        """
        Use AI to analyze code samples and identify custom defense patterns

        Uses execution path context to understand application architecture

        Returns list of custom pattern dicts with query info
        """
        if not code_samples:
            return []

        # Build execution path context
        path_summary = self._build_execution_path_summary()

        # Build prompt with ALL code samples grouped by execution path
        samples_by_path = {}
        for sample in code_samples:
            path_ctx = sample.get('exposure', {}).get('path_context', 'unknown')
            if path_ctx not in samples_by_path:
                samples_by_path[path_ctx] = []
            samples_by_path[path_ctx].append(sample)

        samples_text = []
        path_num = 1
        for path_context, samples in samples_by_path.items():
            if path_context.startswith('route_entry_point'):
                samples_text.append(f"\n=== EXECUTION PATH {path_num} ===\n")
                path_num += 1

            for i, sample in enumerate(samples, 1):
                # Truncate very long code
                code = sample['code'][:500] if len(sample['code']) > 500 else sample['code']
                role_indicator = "ROUTE" if path_context.startswith('route_entry_point') else "CALLED"
                samples_text.append(f"""
[{role_indicator}] {sample['file']}:{sample['line']}
{code}
---
""")

        prompt = f"""You are analyzing {len(code_samples)} methods from {len(samples_by_path)} execution paths to identify custom authorization patterns.

EXECUTION PATH CONTEXT:
{path_summary}

These methods are organized by request flow (route → controller → service).
Each execution path shows how a route calls into business logic.

CODE SAMPLES ({len(code_samples)} methods from traced execution paths):
{''.join(samples_text)}

TASK:
Analyze these execution paths and identify ANY custom authorization patterns:

1. CUSTOM ANNOTATIONS (highest priority):
   - @Superadmin, @Admin, @RequiresRole, etc.
   - Meta-annotations wrapping @PreAuthorize
   - Class-level annotations protecting all methods

2. MANUAL CHECKS:
   - Permission checks in code (e.g., if (!hasPermission(...)))
   - Service calls that check authorization
   - Custom filters or interceptors

3. ARCHITECTURAL PATTERNS:
   - Where does authorization happen in the request flow?
   - At route entry? In controllers? In services?
   - Consistent pattern across execution paths?

Return JSON listing EVERY distinct pattern:
{{
  "patterns_found": [
    {{
      "type": "custom_annotation|class_level|manual_check|filter|interceptor",
      "pattern": "exact annotation name or code pattern",
      "description": "what it does and where in execution path",
      "confidence": "high|medium|low",
      "locations": "route_level|controller_level|service_level|mixed"
    }}
  ],
  "architectural_notes": "Brief observation about where authorization happens in request flow"
}}

If you see NO custom authorization patterns, return: {{"patterns_found": [], "architectural_notes": "No custom patterns detected"}}
"""

        try:
            response = self.ai.call_claude(prompt, max_tokens=2000, temperature=0.3)
            if response:
                import re
                # Find JSON in response
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    json_str = match.group(0)
                    # Try parsing with strict=False to handle control characters
                    result = json.loads(json_str, strict=False)
                    return result.get('patterns_found', [])
        except json.JSONDecodeError as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] JSON parse error: {e}")
                # Try to salvage by extracting patterns_found array directly
                try:
                    patterns_match = re.search(r'"patterns_found"\s*:\s*\[(.*?)\]', response, re.DOTALL)
                    if patterns_match and '"patterns_found": []' in response:
                        # Empty patterns array - no custom defenses found
                        return []
                except:
                    pass
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI pattern identification failed: {e}")

        return []

    def _query_custom_patterns(self, custom_patterns: List[Dict]) -> List[Dict]:
        """
        Query CPG to find all instances of identified custom patterns

        Returns list of mechanism dicts in standard format
        """
        mechanisms = []

        for pattern_info in custom_patterns:
            pattern_type = pattern_info.get('type', '')
            pattern = pattern_info.get('pattern', '')

            if not pattern:
                continue

            # Clean annotation name (remove @ prefix if present)
            if pattern.startswith('@'):
                pattern = pattern[1:]

            if pattern_type == 'custom_annotation':
                # Query for custom annotation
                behaviors = self._query_custom_annotation(pattern)
                if behaviors:
                    mechanisms.append({
                        'framework': 'custom',
                        'category': 'custom_annotations',
                        'type': 'custom',
                        'patterns': [pattern],
                        'behaviors': behaviors,
                        'discovery_method': 'ai_code_analysis'
                    })

            elif pattern_type == 'class_level':
                # Query for class-level authorization
                behaviors = self._query_class_level_authorization(pattern)
                if behaviors:
                    mechanisms.append({
                        'framework': 'custom',
                        'category': 'class_level_authorization',
                        'type': 'custom',
                        'patterns': [pattern],
                        'behaviors': behaviors,
                        'discovery_method': 'ai_code_analysis'
                    })

        return mechanisms

    def _query_custom_annotation(self, annotation_name: str) -> List[Dict]:
        """Query CPG for methods with custom annotation"""
        query = f'''
            cpg.method
              .where(_.annotation.name("{annotation_name}"))
              .map {{ m =>
                Map(
                  "method" -> m.fullName,
                  "file" -> m.file.name.headOption.getOrElse("unknown"),
                  "line" -> m.lineNumber.getOrElse(0),
                  "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
                  "annotation" -> "{annotation_name}"
                )
              }}.toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if result.success and result.output and result.output.strip():
                # Check if output is valid JSON
                try:
                    behaviors = json.loads(result.output)
                    if not behaviors:  # Empty list
                        return []

                    # Convert to standard behavior format
                    return [{
                        'type': 'authorization_annotation',
                        'mechanism': annotation_name,
                        'method': b.get('method', ''),
                        'class': b.get('class', ''),
                        'file': b.get('file', ''),
                        'line': b.get('line', 0),
                        'roles': [annotation_name.lower()],  # Infer role from annotation name
                        'location': f"{b.get('class', '')} (line {b.get('line', 0)})",
                        'location_type': 'endpoint',
                        'httpMethod': 'UNKNOWN'
                    } for b in behaviors]
                except json.JSONDecodeError:
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] Invalid JSON from query for {annotation_name}")
                    return []
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Query failed for {annotation_name}: {e}")

        return []

    def _query_class_level_authorization(self, annotation_name: str) -> List[Dict]:
        """Query CPG for classes with authorization annotation, return all their methods"""
        # First, find classes with the annotation
        query = f'''
            cpg.typeDecl
              .where(_.annotation.name("{annotation_name}"))
              .method
              .isPublic
              .map {{ m =>
                Map(
                  "method" -> m.fullName,
                  "file" -> m.file.name.headOption.getOrElse("unknown"),
                  "line" -> m.lineNumber.getOrElse(0),
                  "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
                  "class_annotation" -> "{annotation_name}"
                )
              }}.toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if result.success and result.output:
                behaviors = json.loads(result.output)

                # Convert to standard behavior format
                return [{
                    'type': 'authorization_annotation',
                    'mechanism': f"{annotation_name} (class-level)",
                    'method': b.get('method', ''),
                    'class': b.get('class', ''),
                    'file': b.get('file', ''),
                    'line': b.get('line', 0),
                    'roles': [annotation_name.lower()],
                    'location': f"{b.get('class', '')} (inherited from class annotation)",
                    'location_type': 'endpoint',
                    'httpMethod': 'UNKNOWN'
                } for b in behaviors]
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Query failed for class-level {annotation_name}: {e}")

        return []

    # ========================================================================
    # PHASE 2: ARCHITECTURE EVALUATION
    # ========================================================================
    # Architecture evaluation is now handled by AI in the recommendation generation phase

    # ========================================================================
    # PHASE 3: FINDING GENERATION
    # ========================================================================

    def _generate_ai_coverage_metrics(self, defense_matrix: Dict) -> Dict:
        """
        Use AI to generate coverage metrics - NO FALLBACK

        TERMINOLOGY (see CRITICAL-COVERAGE-TERMINOLOGY.md):
        - exposures = places where defenses should be applied
        - protected_exposures = exposures with defenses
        - Coverage = protected_exposures / total_exposures × 100%

        Raises ValueError if AI is unavailable or fails
        """
        if not self.ai:
            raise ValueError("AI client required for coverage metrics - no fallback allowed")

        if self.debug:
            pattern = self.auth_pattern.get('pattern', 'unknown')
            primary_layer = self.auth_pattern.get('primary_layer', 'unknown')
            total_auth = sum(len(m.get('behaviors', [])) for m in self.standard_mechanisms)
            print(f"[{self.get_agent_id().upper()}] Calculating coverage metrics...")
            print(f"  Pattern: {pattern}")
            print(f"  Primary layer: {primary_layer}")
            print(f"  Total auth behaviors: {total_auth}")

        # Call AI metrics - will raise ValueError if it fails (no fallback)
        metrics = self._ask_ai_for_metrics()

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] AI metrics: {metrics['metric_type']}")
            print(f"  Exposures: {metrics.get('exposures', 'N/A')}")
            print(f"  Protected: {metrics.get('protected', 'N/A')}")
            print(f"  Coverage: {metrics.get('coverage', 'N/A')}%")

        return metrics

    def _ask_ai_for_metrics(self) -> Optional[Dict]:
        """
        Calculate coverage metrics: protected_exposures / total_exposures

        TERMINOLOGY (see CRITICAL-COVERAGE-TERMINOLOGY.md):
        - exposures = places where defenses should be applied (denominator)
        - protected_exposures = exposures with defenses (numerator)
        - Coverage = protected_exposures / total_exposures × 100%

        CRITICAL: Exposure discovery is DYNAMIC based on WHERE mechanisms are found
        - If mechanisms at endpoints → query endpoints
        - If mechanisms at service layer → query service methods
        - If NO mechanisms → use AI to propose best fit based on architecture
        """
        if not self.ai:
            raise ValueError("AI client required for metrics calculation - no fallback allowed")

        # Determine exposure type based on detected authorization pattern
        pattern = self.auth_pattern.get('pattern', 'endpoint_layer')

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Discovering exposures based on pattern: {pattern}")

        # Discover ALL exposures based on WHERE mechanisms are located
        if pattern == 'endpoint_layer':
            # Endpoint-level: exposures = methods with routing annotations from detected frameworks
            total_exposures = self.utils.query_all_endpoint_methods(self.matched_frameworks)
            location_type_filter = 'endpoint'
            exposure_description = "endpoints with routing annotations"
        elif pattern == 'service_layer':
            # Service-level: exposures = public methods in @Service classes
            total_exposures = self.utils._discover_service_methods()
            # Convert from string format to dict format for consistency
            total_exposures = [{'method': m} for m in total_exposures]
            location_type_filter = 'service'
            exposure_description = "public service methods"
        elif pattern == 'mixed':
            # Mixed: combine endpoints and service methods
            endpoints = self.utils.query_all_endpoint_methods(self.matched_frameworks)
            services = self.utils._discover_service_methods()
            services = [{'method': m} for m in services]
            total_exposures = endpoints + services
            location_type_filter = None  # Accept any location type
            exposure_description = "endpoints and service methods"
        elif pattern == 'none':
            # No mechanisms found: propose best fit based on application architecture
            # Try endpoints first (most common)
            total_exposures = self.utils.query_all_endpoint_methods(self.matched_frameworks)
            if total_exposures:
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] No authorization mechanisms found. Application has {len(total_exposures)} endpoints that should be protected.")
                location_type_filter = None  # No mechanisms to filter
                exposure_description = "endpoints (recommended for authorization)"
            else:
                # No endpoints, try services
                services = self.utils._discover_service_methods()
                if services:
                    total_exposures = [{'method': m} for m in services]
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] No authorization mechanisms found. Application has {len(services)} service methods that should be protected.")
                    location_type_filter = None
                    exposure_description = "service methods (recommended for authorization)"
                else:
                    # No obvious exposures found
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] No authorization mechanisms and no obvious exposures found.")
                    total_exposures = []
                    location_type_filter = None
                    exposure_description = "no obvious exposures detected"
        else:
            # Unknown pattern: default to endpoints
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] WARNING: Unknown pattern '{pattern}', defaulting to endpoint discovery")
            total_exposures = self.utils.query_all_endpoint_methods(self.matched_frameworks)
            location_type_filter = 'endpoint'
            exposure_description = "endpoints (default)"

        # Count protected exposures (those with authorization defenses)
        # CRITICAL: Only count behaviors that match actual exposures in total_exposures
        # Build set of exposure methods for fast lookup
        exposure_methods = set(exp.get('method', '') for exp in total_exposures)

        protected_exposures = []
        for mechanism in self.standard_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                behavior_method = behavior.get('method', '')

                # Check if this behavior protects an actual exposure
                if behavior_method in exposure_methods:
                    # Additional filter by location_type if specified
                    if location_type_filter is None or behavior.get('location_type') == location_type_filter:
                        protected_exposures.append({
                            'method': behavior_method,
                            'class': behavior.get('class', ''),
                            'httpMethod': behavior.get('httpMethod', 'UNKNOWN'),
                            'route': behavior.get('location', ''),
                            'mechanism': behavior.get('mechanism', ''),
                            'line': behavior.get('line', 0)
                        })

        # Calculate metrics
        total_count = len(total_exposures)
        protected_count = len(protected_exposures)
        unprotected_count = total_count - protected_count
        coverage_pct = (protected_count / total_count * 100) if total_count > 0 else 0

        # Format samples for AI verification
        protected_sample = json.dumps(protected_exposures[:15], indent=2) if protected_exposures else "[]"
        total_sample = json.dumps(total_exposures[:20], indent=2) if total_exposures else "[]"

        # Dynamic metric type based on pattern
        metric_type = pattern if pattern in ['endpoint_layer', 'service_layer', 'mixed'] else 'endpoint_layer'

        prompt = f"""Calculate authorization coverage metrics.

ARCHITECTURE PATTERN: {pattern}
EXPOSURE TYPE: {exposure_description}

EXPOSURES (places needing protection): {total_count} {exposure_description}
PROTECTED EXPOSURES (with authorization): {protected_count} locations

PROTECTED EXPOSURES (first 15 of {protected_count}):
{protected_sample}

ALL EXPOSURES (first 20 of {total_count}):
{total_sample}

Return these EXACT values in JSON:
{{
  "metric_type": "{metric_type}",
  "exposures": {total_count},
  "protected": {protected_count},
  "unprotected": {unprotected_count},
  "coverage": {coverage_pct:.1f},
  "explanation": "{protected_count} protected out of {total_count} total exposures ({exposure_description})"
}}"""

        try:
            response = self.ai.call_claude(prompt, max_tokens=500, temperature=0)
            if response:
                import re
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    metrics = json.loads(match.group(0))
                    # Store exposures for matrix building
                    self.discovered_exposures = total_exposures
                    return metrics
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI metrics query failed: {e}")
            raise  # Re-raise to fail fast - no fallback allowed

        # If AI didn't return metrics, fail
        raise ValueError("AI failed to return coverage metrics")

    def _build_evidence(self) -> Dict:
        """Build comprehensive evidence for recommendation generation"""
        # Analyze roles using utility
        roles = self.utils.analyze_roles(self.all_mechanisms)

        # Generate AI-powered metrics that understand the architecture pattern
        # Uses self.discovered_exposures from quick discovery
        coverage_metrics = self._generate_ai_coverage_metrics(None)

        # Build defense usage matrix using discovered exposures
        defense_matrix = build_defense_usage_matrix(
            exposures=self.discovered_exposures,
            all_mechanisms=self.all_mechanisms,
            defense_type='authorization'
        )

        # Build proposed access control matrix with AI-powered role analysis
        # This provides a complete classification of ALL endpoints with suggested authorization
        proposed_matrix = self._build_proposed_access_matrix({
            'defense_usage_matrix': defense_matrix,
            'roles': roles
        })

        # Verify unprotected routes - check for additional protection mechanisms
        verification_report = self._verify_unprotected_routes()

        evidence = {
            'mechanisms': self.all_mechanisms,
            'defense_usage_matrix': defense_matrix,  # Current state
            'roles': roles,
            'auth_pattern': self.auth_pattern,  # Architecture pattern (endpoint vs service level)
            'coverage_metrics': coverage_metrics,  # AI-generated metrics
            'proposed_access_matrix': proposed_matrix,  # AI-generated classifications with ALL endpoints
            'verification': verification_report  # Verification of unprotected routes
        }

        return evidence

    def _verify_unprotected_routes(self) -> Dict:
        """
        AI-driven verification of unprotected routes

        Uses AI to:
        1. Analyze what protection mechanisms we've already found
        2. Propose additional mechanisms that might exist in this type of application
        3. Generate Joern queries to search for those mechanisms
        4. Execute queries and report findings

        This is more flexible than hardcoded checks - AI adapts to the specific
        application type, framework, and domain.

        Returns verification report with:
        - mechanisms_tested: List of protection types checked
        - additional_protections_found: New protections discovered during verification
        - verified_unprotected_count: Count of routes confirmed unprotected
        - updated_coverage: New coverage if additional protections found
        """
        if not self.ai:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Skipping verification - no AI client")

            # Calculate unprotected count consistently with main logic
            # Only count behaviors that match actual exposures
            exposure_methods = set(exp.get('method', '') for exp in self.discovered_exposures)
            protected_methods = set(
                b.get('method', '')
                for m in self.all_mechanisms
                for b in m.get('behaviors', [])
                if b.get('method', '') in exposure_methods
            )
            unprotected = len([e for e in self.discovered_exposures if e.get('method', '') not in protected_methods])

            return {
                'mechanisms_tested': [],
                'additional_protections_found': [],
                'verified_unprotected_count': unprotected,
                'updated_coverage': None
            }

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] AI-driven verification of unprotected routes...")

        # Get list of unprotected exposures
        # CRITICAL: Only count behaviors that match actual exposures (not config code like SecurityConfig)
        unprotected_exposures = []
        protected_methods = set()

        # Build set of all exposure methods
        exposure_methods = set(exp.get('method', '') for exp in self.discovered_exposures)

        for mechanism in self.all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                behavior_method = behavior.get('method', '')
                # Only count if this behavior protects an actual exposure
                if behavior_method in exposure_methods:
                    protected_methods.add(behavior_method)

        for exposure in self.discovered_exposures:
            method = exposure.get('method', '')
            if method and method not in protected_methods:
                unprotected_exposures.append(exposure)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}]   Found {len(unprotected_exposures)} unprotected exposures to verify")

        # Ask AI what other protection mechanisms to check for
        verification_plan = self._ai_generate_verification_plan(unprotected_exposures)

        if not verification_plan or not verification_plan.get('checks'):
            if self.debug:
                print(f"[{self.get_agent_id().upper()}]   AI provided no additional checks")
            return {
                'mechanisms_tested': [],
                'additional_protections_found': [],
                'verified_unprotected_count': len(unprotected_exposures),
                'updated_coverage': None
            }

        # Execute AI-generated verification checks
        mechanisms_tested = []
        additional_protections = []

        for check in verification_plan['checks']:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}]   Checking: {check['description']}")

            # Execute the Joern query
            protections = self._execute_verification_query(check, unprotected_exposures)

            mechanisms_tested.append({
                'type': check['type'],
                'description': check['description'],
                'checked': True,
                'found': len(protections),
                'query': check.get('query', '')[:200]  # Truncate for report
            })
            additional_protections.extend(protections)

            if self.debug and protections:
                print(f"[{self.get_agent_id().upper()}]     Found {len(protections)} protection(s)")

        # Calculate updated coverage if additional protections found
        original_protected = len(protected_methods)
        new_protected = len(set(p.get('method') for p in additional_protections if p.get('method') != 'N/A'))
        total_exposures = len(self.discovered_exposures)

        updated_coverage = None
        if new_protected > 0:
            new_total_protected = original_protected + new_protected
            updated_coverage = {
                'exposures': total_exposures,
                'protected': new_total_protected,
                'unprotected': total_exposures - new_total_protected,
                'coverage': (new_total_protected / total_exposures * 100) if total_exposures > 0 else 0
            }

        verified_unprotected = len(unprotected_exposures) - new_protected

        if self.debug:
            print(f"[{self.get_agent_id().upper()}]   Verification complete:")
            print(f"[{self.get_agent_id().upper()}]     Tested {len(mechanisms_tested)} protection mechanism types")
            print(f"[{self.get_agent_id().upper()}]     Found {new_protected} additional protections")
            print(f"[{self.get_agent_id().upper()}]     Verified {verified_unprotected} routes as genuinely unprotected")

        return {
            'mechanisms_tested': mechanisms_tested,
            'additional_protections_found': additional_protections,
            'verified_unprotected_count': verified_unprotected,
            'updated_coverage': updated_coverage
        }

    def _ai_generate_verification_plan(self, unprotected_exposures: List[Dict]) -> Dict:
        """
        Ask AI to generate a verification plan

        AI analyzes:
        - What we've already found (standard mechanisms)
        - Sample of unprotected exposures
        - Application framework/type

        AI proposes:
        - Additional protection mechanisms to check for
        - Joern queries to find them
        """
        # Build context about what we've already found
        found_mechanisms = []
        for mechanism in self.all_mechanisms:
            found_mechanisms.append({
                'framework': mechanism.get('framework'),
                'type': mechanism.get('type'),
                'count': len(mechanism.get('behaviors', [])),
                'patterns': mechanism.get('patterns', [])[:3]  # Sample
            })

        # Sample unprotected exposures
        sample_size = min(20, len(unprotected_exposures))
        sample = unprotected_exposures[:sample_size]

        prompt = f"""You are analyzing a codebase to verify that routes marked as "unprotected" are genuinely unprotected.

WHAT WE'VE ALREADY FOUND:
{json.dumps(found_mechanisms, indent=2)}

SAMPLE UNPROTECTED EXPOSURES ({sample_size} of {len(unprotected_exposures)}):
{json.dumps(sample, indent=2)}

FRAMEWORKS DETECTED:
{', '.join(set(m.get('framework', 'unknown') for m in self.all_mechanisms))}

YOUR TASK:
Think critically about what SPECIFIC corner-case authorization/protection mechanisms might exist in THIS APPLICATION that we haven't checked yet.

We're looking for mechanisms we might have MISSED - focus on corner cases and non-obvious patterns.

Consider these specific types:
- Class-level authorization annotations (not method-level)
- HTTP security configuration files (SecurityConfig, WebSecurityConfigurerAdapter)
  * Methods with HttpSecurity parameter that define .authorizeRequests() or .authorizeHttpRequests()
  * Check for .anyRequest().permitAll() (makes ALL routes public!)
  * Check for .requestMatchers("/pattern").permitAll() (specific public routes)
- Security filters in filter chains
- HandlerInterceptors registered in WebMvcConfigurer
- AOP aspects with @Around/@Before on authorization
- Custom domain-specific authorization annotations
- Framework-specific security mechanisms (Spring Method Security, etc.)
- Servlet filters with authorization logic

For each mechanism type you want to check, provide:
1. Type identifier (snake_case)
2. Human-readable description
3. Joern query to find it (or "READ_SOURCE" if you need to read actual source code)

Return JSON ONLY:
{{
  "checks": [
    {{
      "type": "class_level_auth",
      "description": "Authorization annotations on controller classes",
      "query": "cpg.typeDecl.where(_.annotation.name.matches(\\".*Authorize.*\\")).map {{ t => Map(\\"class\\" -> t.fullName, \\"annotations\\" -> t.annotation.name.l) }}.toJson"
    }},
    {{
      "type": "http_security_config",
      "description": "HttpSecurity configuration methods - READ source to check for .anyRequest().permitAll()",
      "query": "READ_SOURCE"
    }}
  ],
  "rationale": "Why we're checking these specific mechanisms"
}}

IMPORTANT: If you need to READ and PARSE source code (like HttpSecurity configs), use "query": "READ_SOURCE"

Limit to 5-8 most important checks. Focus on mechanisms likely to exist in this type of application.
"""

        try:
            response = self.ai.call_claude(prompt, max_tokens=2000, temperature=0.3)
            if response:
                import re
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    result = json.loads(match.group(0))
                    if 'checks' in result:
                        if self.debug:
                            print(f"[{self.get_agent_id().upper()}]   AI proposed {len(result['checks'])} verification checks")
                        return result
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}]   AI verification plan failed: {e}")

        return {}

    def _execute_verification_query(self, check: Dict, unprotected_exposures: List[Dict]) -> List[Dict]:
        """Execute a verification query generated by AI"""
        query = check.get('query', '')
        if not query:
            return []

        # Handle READ_SOURCE queries (need to read actual source files)
        if query == "READ_SOURCE":
            return self._read_and_parse_http_security_config(check, unprotected_exposures)

        protections = []
        try:
            result = self.cpg_tool.query(query)
            if result.success and result.output and result.output.strip():
                data = self.cpg_tool.parse_json_result(result.output)

                # Convert query results to protection records
                for item in data:
                    protections.append({
                        'method': item.get('method', 'N/A'),
                        'class': item.get('class', item.get('typeDecl', 'Unknown')),
                        'mechanism': f"{check['type']}: {item.get('annotation', item.get('name', check['description']))}",
                        'file': item.get('file', 'unknown'),
                        'protection_type': check['type'],
                        'note': f"Found by AI-driven verification: {check['description']}"
                    })
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}]     Query failed: {e}")

        return protections

    def _read_and_parse_http_security_config(self, check: Dict, unprotected_exposures: List[Dict]) -> List[Dict]:
        """
        Use AI to read and parse security configuration files to extract actual security rules

        This is language-agnostic - AI figures out what the config means
        """
        protections = []

        # Find config files that need parsing (from our framework detection)
        config_behaviors = [m for m in self.all_mechanisms if m.get('type') == 'http_security_config']

        if not config_behaviors:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}]     No security configs found to parse")
            return protections

        # Group configs by file to avoid reading same file multiple times
        files_to_analyze = {}
        for config in config_behaviors:
            file_path = config.get('file', '')
            if file_path and file_path not in files_to_analyze:
                files_to_analyze[file_path] = config

        # Have AI analyze each config file
        for file_path, config in files_to_analyze.items():
            try:
                full_path = self.project_dir / file_path
                if not full_path.exists():
                    continue

                with open(full_path, 'r') as f:
                    source_code = f.read()

                # Ask AI to parse the security configuration
                prompt = f"""Analyze this security configuration file and extract HTTP-layer security rules.

FILE: {file_path}
CLASS: {config.get('class', 'Unknown')}

SOURCE CODE:
```
{source_code}
```

TASK: Extract security rules that control HTTP request access. Look for:
- Rules that affect all public (e.g., .anyRequest().permitAll())
- Rules that require authentication for all routes
- Specific route patterns that are public/protected
- ANY HTTP-layer access control configuration

Return JSON array of protection rules found:
[
  {{
    "mechanism": "Brief description of what rule does",
    "protection_type": "http_permitall|http_authenticated|http_pattern|custom",
    "severity": "critical|high|medium|low",
    "note": "Detailed explanation of security impact"
  }}
]

If no HTTP security rules found, return: []
"""

                try:
                    response = self.ai.call_claude(prompt, max_tokens=1500, temperature=0.2)
                    if response:
                        import re
                        match = re.search(r'\[.*\]', response, re.DOTALL)
                        if match:
                            import json
                            rules = json.loads(match.group(0))

                            for rule in rules:
                                protections.append({
                                    'method': config.get('method', 'security_config'),
                                    'class': config.get('class', 'Unknown'),
                                    'mechanism': rule.get('mechanism', 'Security configuration'),
                                    'file': file_path,
                                    'protection_type': rule.get('protection_type', 'custom'),
                                    'note': rule.get('note', 'Security rule found in configuration')
                                })

                                if self.debug:
                                    severity = rule.get('severity', 'medium')
                                    icon = '🚨' if severity == 'critical' else '⚠️' if severity == 'high' else 'ℹ️'
                                    print(f"[{self.get_agent_id().upper()}]     {icon} {rule.get('mechanism')}")

                except Exception as e:
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}]     AI parsing failed for {file_path}: {e}")

            except Exception as e:
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}]     Error reading {file_path}: {e}")

        return protections

    def _generate_recommendation(self, evidence: Dict) -> Dict:
        """
        Use AI to generate strategic authorization recommendation

        Falls back to rule-based if AI unavailable
        """
        coverage = evidence['coverage_metrics']['coverage']
        unprotected = evidence['coverage_metrics']['unprotected']
        # Use exposures if available, fall back to total_endpoints for backward compatibility
        total = evidence['coverage_metrics'].get('exposures', evidence['coverage_metrics'].get('total_endpoints', 0))

        # Try AI generation
        try:
            recommendation = self._generate_ai_recommendation(evidence)
            if recommendation:
                return recommendation
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI recommendation failed: {e}, using fallback")

        # Fallback to rule-based (delegated to utils) - no evaluation data available
        return self.utils.generate_fallback_recommendation(coverage, unprotected, total, None)

    def _generate_ai_recommendation(self, evidence: Dict) -> Optional[Dict]:
        """
        Generate tailored recommendation using AI

        AI analyzes the specific application context to provide actionable,
        application-specific guidance rather than generic recommendations
        """
        # Build context for AI
        coverage_metrics = evidence['coverage_metrics']
        roles = evidence['roles']
        mechanisms = evidence['mechanisms']

        # Prepare context summary
        context = {
            'coverage': coverage_metrics['coverage'],
            'exposures': coverage_metrics.get('exposures', coverage_metrics.get('total_endpoints', 0)),
            'total_endpoints': coverage_metrics.get('total_endpoints', 0),  # Keep for compatibility
            'protected': coverage_metrics['protected'],
            'unprotected': coverage_metrics['unprotected'],
            'roles_used': roles['used'],
            'generic_role_count': roles['generic_count'],
            'domain_specific_role_count': roles['domain_specific_count'],
            'mechanism_count': len(mechanisms),
            'frameworks': [m.get('framework') for m in mechanisms]
        }

        # Create AI prompt
        prompt = self._build_recommendation_prompt(context, evidence)

        # Call AI
        try:
            if self.debug:
                print(f"\n{'='*70}")
                print(f"[AI PROMPT] Recommendation Generation")
                print(f"{'='*70}")
                print(prompt)
                print(f"{'='*70}\n")

            response_text = self.ai.call_claude(
                prompt=prompt,
                max_tokens=4000,  # Increased from 2000 to accommodate full recommendations
                temperature=0.7
            )

            if self.debug and response_text:
                print(f"\n{'='*70}")
                print(f"[AI RESPONSE] Recommendation Generation")
                print(f"{'='*70}")
                print(response_text)
                print(f"{'='*70}\n")

            if response_text:
                # Parse AI response into structured recommendation
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] Calling _parse_ai_response()...")
                recommendation = self._parse_ai_response(response_text)
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] _parse_ai_response() returned: {type(recommendation)} with keys: {list(recommendation.keys()) if isinstance(recommendation, dict) else 'N/A'}")
                return recommendation

        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI call failed: {e}")
            return None

        return None

    def _build_spring_security_guidance(self) -> str:
        """
        Build version-specific Spring Security guidance section

        Provides correct configuration patterns based on detected Spring Boot/Security versions
        """
        spring_boot = self.spring_versions.get('spring_boot')
        spring_security = self.spring_versions.get('spring_security')

        # Determine configuration style based on version
        if spring_boot and spring_boot.startswith('3'):
            config_style = "Boot 3.x"
            config_guidance = """
   - Continue using your existing configuration style
   - If adding method security for the first time: @EnableMethodSecurity(prePostEnabled = true)
   - If adding HTTP security for the first time: SecurityFilterChain bean (WebSecurityConfigurerAdapter removed in Boot 3)
   - Example SecurityFilterChain pattern:
     @Bean
     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
         http.authorizeHttpRequests(authz -> authz
             .requestMatchers("/health", "/actuator/**").permitAll()
             .anyRequest().authenticated()
         );
         return http.build();
     }"""
        elif spring_boot and spring_boot.startswith('2.7'):
            config_style = "Boot 2.7.x"
            config_guidance = """
   - Continue using your existing configuration style
   - If adding method security: @EnableMethodSecurity (modern) or @EnableGlobalMethodSecurity (legacy, still works)
   - If adding HTTP security: SecurityFilterChain bean (modern) or WebSecurityConfigurerAdapter (legacy, still works)
   - Modern style is more future-proof for Boot 3 migration"""
        elif spring_boot and spring_boot.startswith('2'):
            config_style = f"Boot {spring_boot}"
            config_guidance = """
   - Continue using your existing configuration style
   - If adding method security: @EnableGlobalMethodSecurity(prePostEnabled = true)
   - If adding HTTP security: extend WebSecurityConfigurerAdapter"""
        else:
            config_style = "Version not detected"
            config_guidance = """
   - Continue with your existing configuration style
   - If method security not enabled, enable it using your framework's standard mechanism"""

        return f"""
SPRING SECURITY BEST PRACTICES (CRITICAL - FOLLOW EXACTLY):
Detected Versions: Spring Boot {spring_boot or 'unknown'}, Spring Security {spring_security or 'unknown'}
Configuration Style: {config_style}

1. Public Endpoints (CRITICAL - DO NOT use PUBLIC role):
   - Use permitAll() in HttpSecurity configuration for truly public endpoints
   - Example: http.authorizeHttpRequests().requestMatchers("/health", "/actuator/**").permitAll()
   - DO NOT create a "PUBLIC" role - this creates confusion about authentication state
   - DO NOT use @PreAuthorize("permitAll()") on methods - permitAll() is HTTP security, not method security
   - Leave public endpoints UNANNOTATED at method level (protected by HTTP security allowlist)

2. Method Security Annotations (for protected endpoints):
   - Use @PreAuthorize("hasRole('ADMIN')") for role checks (this agent focuses on ROLES only)
   - Use @PreAuthorize("isAuthenticated()") for any authenticated user (no specific role)
   - For JSR-250 style: @RolesAllowed({{"ADMIN", "USER"}}) if enabled
   - Note: Fine-grained permissions/authorities are handled by a separate agent

3. Configuration:{config_guidance}

4. Scope Limitations (IMPORTANT):
   - Controller/endpoint authorization ONLY protects HTTP access via Spring MVC request handling
   - Does NOT automatically protect: @Scheduled methods, @EventListener, message listeners, WebSocket endpoints, internal service-to-service calls
   - Phrase protection as "prevents unauthorized HTTP access" not "prevents all unauthorized access"
   - If non-HTTP entry points exist, they need separate authorization mechanisms

5. Default-Deny Stance:
   - Configure .anyRequest().authenticated() as the default
   - Explicitly allowlist public endpoints with .requestMatchers(...).permitAll()
   - This ensures new endpoints are secure by default"""

    def _format_verification_mechanisms(self, verification: Dict) -> str:
        """Format the list of protection mechanisms that were tested"""
        mechanisms = verification.get('mechanisms_tested', [])
        if not mechanisms:
            return "None (verification not performed)"

        lines = []
        for mech in mechanisms:
            status = "✓" if mech['found'] > 0 else "✗"
            lines.append(f"  {status} {mech['description']}: {mech['found']} found")

        return "\n".join(lines)

    def _format_verification_results(self, verification: Dict) -> str:
        """Format the verification results summary"""
        additional = verification.get('additional_protections_found', [])
        verified_unprotected = verification.get('verified_unprotected_count', 0)
        updated_coverage = verification.get('updated_coverage')

        if not additional:
            return f"  ✓ No additional protections found\n  ✓ {verified_unprotected} routes confirmed as genuinely unprotected"

        # Additional protections were found
        lines = [f"  ⚠ Found {len(additional)} additional protection(s):"]
        for prot in additional[:10]:  # Show first 10
            lines.append(f"    - {prot.get('mechanism', 'Unknown')} on {prot.get('class', 'Unknown')}")
            if 'note' in prot:
                lines.append(f"      Note: {prot['note']}")

        if len(additional) > 10:
            lines.append(f"    ... and {len(additional) - 10} more")

        if updated_coverage:
            lines.append(f"\n  Updated Coverage: {updated_coverage['protected']}/{updated_coverage['exposures']} ({updated_coverage['coverage']:.1f}%)")

        lines.append(f"  ✓ {verified_unprotected} routes confirmed as genuinely unprotected after verification")

        return "\n".join(lines)

    def _build_recommendation_prompt(self, context: Dict, evidence: Dict) -> str:
        """Build detailed prompt for AI recommendation generation"""
        # Get architecture pattern info
        auth_pattern = evidence.get('auth_pattern', {})
        pattern_type = auth_pattern.get('pattern', 'unknown')
        primary_layer = auth_pattern.get('primary_layer', 'unknown')

        # Count locations by type
        location_counts = {
            'endpoint': 0,
            'service': 0,
            'code': 0,
            'unknown': 0
        }
        for mechanism in evidence.get('mechanisms', []):
            for behavior in mechanism.get('behaviors', []):
                location_type = behavior.get('location_type', 'unknown')
                location_counts[location_type] += 1

        # Get Spring Security guidance
        spring_guidance = self._build_spring_security_guidance()

        # Build proposed access control matrix
        proposed_matrix = self._build_proposed_access_matrix(evidence)

        return f"""You are a security architect analyzing authorization in an application.

CRITICAL: Your output must be FRAMEWORK-SPECIFIC. Use the EXACT frameworks, versions, and APIs detected in this application. DO NOT write generic advice or use placeholders.

APPLICATION CONTEXT:
- Total endpoints: {context.get('total_endpoints', 0)}
- Protected: {context['protected']} ({context['coverage']:.1f}%)
- Unprotected: {context['unprotected']}
- Frameworks detected: {', '.join(set(context['frameworks']))}

CRITICAL - OUTPUT MUST BE FRAMEWORK-SPECIFIC:
Your recommendation MUST use the EXACT detected frameworks and versions. DO NOT write generic advice.
- Use actual API calls, annotations, and configuration syntax from the detected framework
- Reference the specific versions detected above
- Show concrete code examples using the framework's actual methods (not placeholders)
- If multiple frameworks detected, integrate guidance for all of them
- Example: Instead of "configure authorization in your framework", write "use @PreAuthorize in Spring Security 6.x"

{spring_guidance}

AUTHORIZATION ARCHITECTURE PATTERN:
- Pattern: {pattern_type}
- Primary layer: {primary_layer}
- Authorization locations breakdown:
  * Endpoint-level (controllers): {location_counts['endpoint']} behaviors
  * Service-level (business logic): {location_counts['service']} behaviors
  * Code-level (other): {location_counts['code']} behaviors
- Description: {auth_pattern.get('architecture_description', 'Unknown pattern')}

CRITICAL: This application uses {pattern_type} authorization. The recommendation MUST acknowledge this architecture and explain whether it's appropriate.

NOTE: Coverage metrics are calculated based on authorization exposures:
- If authorization is at the service layer: Exposures = classes with auth behaviors
- If authorization is at the endpoint layer: Exposures = HTTP routes
- If authorization is at the code layer: Exposures = protected code locations
- Coverage % reflects protection of exposures at the detected architectural layer

ROLES DEFINED:
- Total roles: {len(context['roles_used'])}
- Generic roles: {context['generic_role_count']} (e.g., USER, ADMIN)
- Domain-specific roles: {context['domain_specific_role_count']}
- Roles found: {', '.join(context['roles_used'][:20])}

CRITICAL - SCOPE LIMITATION FOR THIS AGENT:
This agent focuses on endpoint authorization only (which roles can access which endpoints).
- Use role-based checks: Simple role names like ADMIN, USER, VET, OWNER
- If you see permission/authority strings (e.g., APPLICATION_EDIT_VULNERABILITY_DELETE), IGNORE them - they are handled by a separate permissions agent
- Focus your recommendations on assigning ROLES to endpoints, not fine-grained permissions
- Use the framework's role-checking mechanism in your examples

PROPOSED ACCESS CONTROL MATRIX:
This section provides a complete classification of ALL {proposed_matrix['total_endpoints']} endpoints with suggested authorization.

Role Structure:
- Current roles: {', '.join(proposed_matrix['role_structure']['current_roles'])}
- Proposed roles: {', '.join(proposed_matrix['role_structure']['proposed_roles'])}
- Rationale: {proposed_matrix['role_structure']['rationale']}

IMPORTANT: This is a PROPOSED access control matrix. Review each classification and adjust based on:
1. Business requirements and use cases
2. Data sensitivity and privacy concerns
3. Compliance and regulatory requirements
4. Current application behavior and user expectations

VERIFICATION OF UNPROTECTED ROUTES:
To ensure unprotected routes are genuinely unprotected, we verified {context['unprotected']} unprotected routes against additional protection mechanisms.

Protection Mechanisms Tested:
{self._format_verification_mechanisms(evidence.get('verification', {}))}

Verification Results:
{self._format_verification_results(evidence.get('verification', {}))}

This verification provides evidence that the reported unprotected routes are genuinely unprotected and not protected by alternative mechanisms we may have initially missed.

TASK:
Generate a tailored authorization recommendation for THIS specific application. You MUST:
1. EXPLICITLY acknowledge the detected authorization architecture pattern ({pattern_type} at {primary_layer})
2. Explain if the current architecture pattern is sound for this application
3. Review the PROPOSED ACCESS CONTROL MATRIX above and either:
   a) Agree with the classifications and explain why they're appropriate, OR
   b) Adjust classifications where business requirements differ and explain your reasoning
4. Consider the application's current authorization state and proposed improvements
5. Reference the specific frameworks being used
6. Evaluate the proposed role structure and whether it meets the application's needs
7. Address the coverage gaps and explain how the proposed matrix resolves them
8. Infer what this application does based on roles/frameworks/endpoint names
9. For any classifications you modify from the proposed matrix, provide clear rationale
10. Discuss whether the proposed role structure should be simplified or expanded

CRITICAL: Respond with valid JSON only. Use \\n for newlines within strings, NOT literal newlines.

Provide your recommendation in this exact JSON format:
{{
  "title": "One-line recommendation title",
  "summary": "Brief 1-2 sentence summary acknowledging the current architecture pattern and what needs to be done",
  "design_recommendation": "Strategic guidance (400-600 words). MUST start by explicitly discussing the {pattern_type} authorization architecture found at {primary_layer}. Is it sound? Is {primary_layer} the right place for auth checks? Then discuss existing roles. Explain access control matrix. Discuss which locations need authorization. Use \\n for line breaks.",
  "implementation_recommendation": "Concrete technical steps (400-600 words). MUST be FRAMEWORK-SPECIFIC using exact detected frameworks and versions. MUST include:\\n- Step 0: Establish default-deny at HTTP layer - show ACTUAL framework configuration code (not generic)\\n- Step 1: Review and implement the PROPOSED ACCESS CONTROL MATRIX classifications (agree with suggested classifications or provide adjusted ones)\\n- Step 2: Add public endpoints to allowlist - show ACTUAL framework config syntax for detected version\\n- Step 3: Add role check annotations to protected endpoints - use ACTUAL framework annotations from detected version\\n- Step 4: For 3-5 example endpoints from the matrix, show EXACT code with ACTUAL role names and framework syntax\\n- Step 5: Add CI test using detected test framework - show ACTUAL test code that enumerates endpoints and fails on unannotated routes\\n- All code examples MUST use framework-specific syntax, NOT placeholders or generic instructions\\nUse \\n for line breaks.",
  "rationale": "Why this approach (400-600 words). Explain why {primary_layer} authorization is appropriate (or not) for this application. IMPORTANT: Scope claims to HTTP access only - acknowledge that controller auth does NOT protect @Scheduled, @EventListener, message listeners, or internal service calls. Compare against other architectural patterns (controller-level, service-level, API gateways, custom schemes). Discuss trade-offs. Explain urgency based on {context['coverage']:.1f}% coverage. Use \\n for line breaks."
}}

CRITICAL REQUIREMENTS:
- First paragraph of design_recommendation MUST discuss the {pattern_type} authorization architecture pattern at {primary_layer}
- Explicitly state whether auth at {primary_layer} is appropriate for this application
- Reference and review the PROPOSED ACCESS CONTROL MATRIX - either agree with it or adjust specific classifications with rationale
- DO NOT recommend creating a PUBLIC role - use permitAll() in HTTP security config instead
- DO NOT recommend @PreAuthorize("permitAll()") - that's wrong, use HTTP security config
- Scope protection claims to "prevents unauthorized HTTP access" not "prevents all access"
- Each section must be 400-600 words (not 200-300)
- Include actual code examples with real role names from the application: {', '.join(context['roles_used'][:10])}
- CRITICAL: All code examples MUST use framework-specific syntax from detected frameworks ({', '.join(set(context['frameworks']))})
- CRITICAL: All configuration examples MUST reference the exact detected versions (see Spring Security guidance above)
- NO GENERIC PLACEHOLDERS: Use actual framework API calls, annotations, methods - not "configure in your framework"
- Provide concrete, actionable guidance referencing the matrix classifications
- MUST include CI test recommendation (Step 5) that enumerates all endpoints and fails on unannotated routes - this prevents regression
- Discuss whether the proposed role structure is appropriate or should be adjusted

Generate the recommendation now:"""

    def _parse_ai_response(self, response_text: str) -> Dict:
        """Parse AI response into structured recommendation"""
        import json
        import re

        # Try to extract JSON from response
        # Look for JSON block
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)

            try:
                rec = json.loads(json_str)
                # Validate required fields
                required = ['title', 'summary', 'design_recommendation',
                           'implementation_recommendation', 'rationale']
                if all(k in rec for k in required):
                    return rec
            except json.JSONDecodeError as e:
                # Try to repair truncated JSON by adding closing quotes and braces
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] JSON parse error: {e}")
                    print(f"[{self.get_agent_id().upper()}] Attempting to repair truncated JSON...")

                # Attempt repair: close any open string and object
                repaired = json_str
                if not repaired.endswith('}'):
                    # Count opening braces vs closing braces
                    open_count = repaired.count('{')
                    close_count = repaired.count('}')
                    # Add missing closing quotes if string was cut off
                    if repaired.count('"') % 2 == 1:
                        repaired += '"'
                    # Add missing closing braces
                    repaired += '}' * (open_count - close_count)

                try:
                    rec = json.loads(repaired)
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] Successfully repaired JSON")
                    # Accept partial recommendations - fill in missing fields
                    return {
                        'title': rec.get('title', 'Authorization recommendation available'),
                        'summary': rec.get('summary', 'AI-generated recommendation (partial)'),
                        'design_recommendation': rec.get('design_recommendation', 'See full response below'),
                        'implementation_recommendation': rec.get('implementation_recommendation', 'Response was truncated - increase max_tokens'),
                        'rationale': rec.get('rationale', 'Response was truncated - increase max_tokens')
                    }
                except json.JSONDecodeError:
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] JSON repair failed")

        # Fallback: return minimal structure noting AI parse failure
        return {
            'title': 'Authorization recommendation available',
            'summary': 'AI-generated recommendation could not be parsed',
            'design_recommendation': response_text[:1000] if len(response_text) > 1000 else response_text,
            'implementation_recommendation': 'See design recommendation above',
            'rationale': 'AI analysis provided but structured parsing failed'
        }

    def run(self) -> Dict[str, Any]:
        """Main entry point"""
        should_run = self.should_run()

        if not should_run['should_run']:
            return {
                'agent_id': self.get_agent_id(),
                'agent_name': self.get_agent_name(),
                'ran': False,
                'reason': should_run['reason']
            }

        return self.analyze()
