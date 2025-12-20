"""
Endpoint Authorization Agent

Analyzes route-level access control to determine if endpoints have appropriate
authorization checks. Discovers both standard framework patterns and custom
authorization mechanisms through agentic AI investigation.

Three-Phase Analysis:
1. Mechanism Discovery - Find standard + custom authorization patterns
2. Architecture Evaluation - Assess authorization architecture quality
3. Finding Generation - Generate actionable recommendations
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import json
from .authorization_utils import AuthorizationUtils


class EndpointAuthorizationAgent:
    """
    Analyzes endpoint-level authorization (route access control)

    Scope:
    - ✅ Can role X access endpoint Y?
    - ✅ Which endpoints require which roles?
    - ✅ Framework-based authorization (annotations, middleware)
    - ✅ Custom authorization (meta-annotations, custom methods)

    Out of Scope:
    - ❌ Data-level authorization / IDOR
    - ❌ Authentication mechanisms
    - ❌ Session management
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
        self.ai_analysis_result = None  # Renamed from custom_mechanisms
        self.all_mechanisms = []

        # State from Phase 2
        self.architecture_evaluation = {}

    def get_agent_id(self) -> str:
        return "endpoint_authorization"

    def get_agent_name(self) -> str:
        return "Endpoint Authorization (Route-Level Access Control)"

    def get_category(self) -> str:
        return "authorization"

    def should_run(self) -> Dict[str, Any]:
        """Always run - authorization analysis is fundamental"""
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

        # ALWAYS run AI analysis to understand authorization architecture
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Running AI architecture analysis...")

        self.ai_analysis_result = self._run_ai_analysis()

        # Consolidate mechanisms
        self.all_mechanisms = self.standard_mechanisms + self._extract_mechanisms_from_ai()

        # Phase 2: Architecture Evaluation
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Phase 2: Architecture Evaluation")

        self.architecture_evaluation = self._evaluate_architecture()

        # Phase 3: Finding Generation
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Phase 3: Finding Generation")

        evidence = self._build_evidence()
        defense_metadata = self.utils.build_defense_metadata(self.all_mechanisms)
        metrics = self.utils.calculate_metrics(evidence)
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
        Algorithmic discovery: Load patterns from framework definitions
        NO hardcoded patterns - everything comes from frameworks/*.json

        Steps:
        1. Detect which libraries are present in the project (using deptrast)
        2. Load framework JSON files for those libraries only
        3. Extract authorization patterns and query CPG
        """
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Detecting project libraries...")

        # Step 1: Detect libraries in the project (delegated to utils)
        present_libraries = self.utils.detect_project_libraries()

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(present_libraries)} libraries in project")

        # Step 2: Load framework definitions for detected libraries only
        matching_frameworks = self.utils.load_matching_frameworks(present_libraries)

        # Save for later use (needed by _ask_ai_for_metrics)
        self.matched_frameworks = matching_frameworks

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Matched {len(matching_frameworks)} framework definitions")

        standard_mechanisms = []

        # Step 3: Extract authorization patterns and query
        for framework_name, framework_config in matching_frameworks.items():
            auth_patterns = self.utils.extract_authorization_patterns(framework_config)

            if not auth_patterns:
                continue

            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Checking {framework_name}: {len(auth_patterns)} pattern categories")

            # Execute queries for each pattern category
            for pattern_category, pattern_config in auth_patterns.items():
                # Skip if pattern_config is not a dict
                if not isinstance(pattern_config, dict):
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}] Skipping {framework_name}.{pattern_category}: invalid config type")
                    continue

                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] Executing queries for {framework_name}.{pattern_category}...")

                behaviors = self.utils.execute_pattern_queries(
                    framework=framework_name,
                    category=pattern_category,
                    config=pattern_config
                )

                if self.debug:
                    print(f"[{self.get_agent_id().upper()}]   → Got {len(behaviors)} behaviors")

                if behaviors:
                    if self.debug:
                        print(f"[{self.get_agent_id().upper()}]   ✓ {framework_name}.{pattern_category}: {len(behaviors)} behaviors")

                    standard_mechanisms.append({
                        'framework': framework_name,
                        'category': pattern_category,
                        'type': 'standard',
                        'patterns': pattern_config.get('patterns', []),
                        'behaviors': behaviors,
                        'count': len(behaviors)
                    })

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
        if not evidence or not self.ai:
            return self._algorithmic_pattern_detection(evidence)

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

        # Fallback to algorithmic detection
        return self._algorithmic_pattern_detection(evidence)

    def _algorithmic_pattern_detection(self, evidence: Dict) -> Dict:
        """
        Fallback algorithmic pattern detection when AI is unavailable

        Uses simple heuristics based on evidence
        """
        if not evidence or evidence.get('total_auth_methods', 0) == 0:
            return {
                'pattern': 'none',
                'confidence': 1.0,
                'primary_layer': 'none',
                'evidence_summary': 'No authorization mechanisms detected',
                'coverage_approach': 'N/A',
                'architecture_description': 'No authorization detected in codebase'
            }

        total = evidence['total_auth_methods']
        http_count = evidence.get('http_mapping_presence', 0)
        http_ratio = http_count / total if total > 0 else 0

        # Simple heuristic: if >50% have HTTP mappings, it's endpoint-level
        if http_ratio > 0.5:
            pattern = 'endpoint_layer'
            primary = 'HTTP endpoints (controllers)'
            description = 'Authorization is primarily applied at the controller/endpoint layer'
        elif http_ratio < 0.1:
            pattern = 'service_layer'
            primary = 'business logic (service layer)'
            description = 'Authorization is primarily applied at the service layer'
        else:
            pattern = 'mixed'
            primary = 'multiple layers'
            description = 'Authorization is applied across multiple architectural layers'

        return {
            'pattern': pattern,
            'confidence': 0.7,  # Lower confidence than AI
            'primary_layer': primary,
            'evidence_summary': f'{http_count}/{total} methods have HTTP mappings',
            'coverage_approach': 'measure protection at identified layers',
            'architecture_description': description
        }

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

    def _run_ai_analysis(self) -> Optional[Dict]:
        """
        ALWAYS run AI analysis to understand authorization architecture

        AI investigates:
        - How are standard mechanisms being used?
        - Is coverage intentional or incomplete?
        - Are there custom patterns not in framework definitions?
        - Is the architecture sound?

        Returns AI analysis result with insights
        """
        # Build context for AI
        context = self._build_ai_context()

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] AI Context:")
            print(f"  Standard mechanisms: {len(self.standard_mechanisms)}")
            print(f"  Frameworks matched: {context['frameworks_matched']}")

        # Build AI prompt for architecture investigation
        prompt = self._build_architecture_investigation_prompt(context)

        try:
            if self.debug:
                print(f"\n{'='*70}")
                print(f"[AI PROMPT] Architecture Investigation")
                print(f"{'='*70}")
                print(prompt)
                print(f"{'='*70}\n")

            response_text = self.ai.call_claude(
                prompt=prompt,
                max_tokens=3000,
                temperature=0.3
            )

            if self.debug and response_text:
                print(f"\n{'='*70}")
                print(f"[AI RESPONSE] Architecture Investigation")
                print(f"{'='*70}")
                print(response_text)
                print(f"{'='*70}\n")

            if response_text:
                # Parse AI's architecture analysis
                analysis = self._parse_architecture_analysis(response_text)
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] AI identified pattern: {analysis.get('pattern', 'unknown')}")
                return analysis

        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI analysis failed: {e}")

        return None

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

    def _extract_mechanisms_from_ai(self) -> List[Dict]:
        """
        Extract custom mechanisms discovered by AI analysis

        Returns list of mechanisms in same format as standard_mechanisms
        """
        if not self.ai_analysis_result:
            return []

        # TODO: Parse AI analysis result and extract custom mechanisms
        return []

    # ========================================================================
    # PHASE 2: ARCHITECTURE EVALUATION
    # ========================================================================

    def _evaluate_architecture(self) -> Dict:
        """
        Evaluate authorization architecture quality across four dimensions

        Focus: Is the authorization ARCHITECTURE sound, not just "are mechanisms good"
        """
        evaluation = {
            'consistency': self._evaluate_consistency(),
            'centralization': self._evaluate_centralization(),
            'boundaries': self._evaluate_boundaries(),
            'maintainability': self._evaluate_maintainability()
        }

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Architecture evaluation:")
            print(f"  Consistency: {evaluation['consistency']['assessment']}")
            print(f"  Centralization: {evaluation['centralization']['assessment']}")
            print(f"  Boundaries: {evaluation['boundaries']['assessment']}")
            print(f"  Maintainability: {evaluation['maintainability']['assessment']}")

        return evaluation

    def _evaluate_consistency(self) -> Dict:
        """
        Is authorization applied consistently across the application?
        """
        # Discover HTTP endpoints via Joern
        discovered_endpoints = self.utils._discover_http_endpoints()

        # Map endpoints to their authorization patterns
        endpoint_patterns = {}
        for endpoint_location in discovered_endpoints:
            patterns = []

            for mechanism in self.all_mechanisms:
                for behavior in mechanism.get('behaviors', []):
                    # Only match endpoint-level behaviors (service-level won't match routes)
                    if behavior.get('location_type') == 'endpoint':
                        # For endpoint-level, location is "GET /path" format
                        if behavior.get('location') == endpoint_location:
                            patterns.append(mechanism.get('framework', 'unknown'))

            endpoint_patterns[endpoint_location] = patterns

        # Analyze consistency
        protected = sum(1 for patterns in endpoint_patterns.values() if patterns)
        unprotected = len(endpoint_patterns) - protected
        multiple_patterns = sum(1 for patterns in endpoint_patterns.values() if len(patterns) > 1)

        coverage_pct = (protected / len(discovered_endpoints)) * 100 if discovered_endpoints else 0

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

    def _evaluate_centralization(self) -> Dict:
        """
        Is the authorization approach centralized or fragmented?
        """
        # Group mechanisms by type
        mechanism_types = {}
        for mech in self.all_mechanisms:
            mech_type = mech.get('type', 'unknown')
            if mech_type not in mechanism_types:
                mechanism_types[mech_type] = []
            mechanism_types[mech_type].append(mech)

        approach_count = len(mechanism_types)
        is_centralized = approach_count <= 2

        return {
            'approach_count': approach_count,
            'mechanism_types': list(mechanism_types.keys()),
            'mechanisms_per_type': {k: len(v) for k, v in mechanism_types.items()},
            'is_centralized': is_centralized,
            'assessment': 'centralized' if is_centralized
                         else 'somewhat_fragmented' if approach_count <= 4
                         else 'highly_fragmented'
        }

    def _evaluate_boundaries(self) -> Dict:
        """
        Are authorization decisions made at appropriate boundaries?
        """
        # Simplified boundary analysis
        # Real implementation would parse behavior locations
        boundary_locations = {
            'entry_point': len(self.all_mechanisms),  # Assume mechanisms are at entry points
            'embedded': 0
        }

        boundary_score = 1.0 if self.all_mechanisms else 0.0

        return {
            'boundary_locations': boundary_locations,
            'boundary_score': round(boundary_score, 2),
            'assessment': 'appropriate' if boundary_score >= 0.9
                         else 'mostly_appropriate' if boundary_score >= 0.7
                         else 'scattered'
        }

    def _evaluate_maintainability(self) -> Dict:
        """
        Is the architecture maintainable and testable?
        """
        # Check for declarative vs imperative
        declarative = [m for m in self.all_mechanisms
                      if m.get('type') in ['standard', 'annotation', 'meta_annotation']]
        imperative = [m for m in self.all_mechanisms
                     if m.get('type') in ['custom_method', 'interceptor']]

        declarative_ratio = len(declarative) / len(self.all_mechanisms) if self.all_mechanisms else 0

        return {
            'declarative_count': len(declarative),
            'imperative_count': len(imperative),
            'declarative_ratio': round(declarative_ratio, 2),
            'assessment': 'maintainable' if declarative_ratio >= 0.7
                         else 'moderate' if declarative_ratio >= 0.4
                         else 'complex'
        }

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
            print(f"  Opportunities: {metrics.get('opportunities', 'N/A')}")
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
        # Filter by location_type based on detected pattern
        protected_exposures = []
        for mechanism in self.standard_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                # Check if behavior matches the expected location type
                if location_type_filter is None or behavior.get('location_type') == location_type_filter:
                    protected_exposures.append({
                        'method': behavior.get('method', ''),
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
  "opportunities": {total_count},
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
                    return json.loads(match.group(0))
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI metrics query failed: {e}")
            raise  # Re-raise to fail fast - no fallback allowed

        # If AI didn't return metrics, fail
        raise ValueError("AI failed to return coverage metrics")

    def _build_evidence(self) -> Dict:
        """Build comprehensive evidence for recommendation generation"""
        # Use utility to build defense usage matrix (algorithmic route-level coverage)
        defense_matrix = self.utils.build_defense_usage_matrix(
            self.all_mechanisms,
            defense_type='authorization'
        )

        # Analyze roles using utility
        roles = self.utils.analyze_roles(self.all_mechanisms)

        # Generate AI-powered metrics that understand the architecture pattern
        coverage_metrics = self._generate_ai_coverage_metrics(defense_matrix)

        evidence = {
            'mechanisms': self.all_mechanisms,
            'defense_usage_matrix': defense_matrix,  # Keep for reference
            'roles': roles,
            'auth_pattern': self.auth_pattern,  # Architecture pattern (endpoint vs service level)
            'evaluation': self.architecture_evaluation,
            'coverage_metrics': coverage_metrics,  # AI-generated metrics
            'ai_insights': self.ai_analysis_result  # Include AI analysis if available
        }

        return evidence

    def _generate_recommendation(self, evidence: Dict) -> Dict:
        """
        Use AI to generate strategic authorization recommendation

        Falls back to rule-based if AI unavailable
        """
        coverage = evidence['coverage_metrics']['coverage']
        unprotected = evidence['coverage_metrics']['unprotected']
        # Use opportunities if available, fall back to total_endpoints for backward compatibility
        total = evidence['coverage_metrics'].get('opportunities', evidence['coverage_metrics'].get('total_endpoints', 0))
        eval_result = evidence['evaluation']

        # Try AI generation
        try:
            recommendation = self._generate_ai_recommendation(evidence)
            if recommendation:
                return recommendation
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI recommendation failed: {e}, using fallback")

        # Fallback to rule-based (delegated to utils)
        return self.utils.generate_fallback_recommendation(coverage, unprotected, total, eval_result)

    def _generate_ai_recommendation(self, evidence: Dict) -> Optional[Dict]:
        """
        Generate tailored recommendation using AI

        AI analyzes the specific application context to provide actionable,
        application-specific guidance rather than generic recommendations
        """
        # Build context for AI
        coverage_metrics = evidence['coverage_metrics']
        eval_result = evidence['evaluation']
        roles = evidence['roles']
        mechanisms = evidence['mechanisms']

        # Prepare context summary
        context = {
            'coverage': coverage_metrics['coverage'],
            'opportunities': coverage_metrics.get('opportunities', coverage_metrics.get('total_endpoints', 0)),
            'total_endpoints': coverage_metrics.get('total_endpoints', 0),  # Keep for compatibility
            'protected': coverage_metrics['protected'],
            'unprotected': coverage_metrics['unprotected'],
            'consistency': eval_result['consistency']['assessment'],
            'centralization': eval_result['centralization']['assessment'],
            'boundaries': eval_result['boundaries']['assessment'],
            'maintainability': eval_result['maintainability']['assessment'],
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

        return f"""You are a security architect analyzing authorization in an application.

APPLICATION CONTEXT:
- Total endpoints: {context.get('total_endpoints', 0)}
- Protected: {context['protected']} ({context['coverage']:.1f}%)
- Unprotected: {context['unprotected']}
- Frameworks detected: {', '.join(set(context['frameworks']))}

AUTHORIZATION ARCHITECTURE PATTERN:
- Pattern: {pattern_type}
- Primary layer: {primary_layer}
- Authorization locations breakdown:
  * Endpoint-level (controllers): {location_counts['endpoint']} behaviors
  * Service-level (business logic): {location_counts['service']} behaviors
  * Code-level (other): {location_counts['code']} behaviors
- Description: {auth_pattern.get('architecture_description', 'Unknown pattern')}

CRITICAL: This application uses {pattern_type} authorization. The recommendation MUST acknowledge this architecture and explain whether it's appropriate.

NOTE: Coverage metrics are calculated based on authorization opportunities:
- If authorization is at the service layer: Opportunities = classes with auth behaviors
- If authorization is at the endpoint layer: Opportunities = HTTP routes
- If authorization is at the code layer: Opportunities = protected code locations
- Coverage % reflects protection of opportunities at the detected architectural layer

ARCHITECTURE EVALUATION:
- Consistency: {context['consistency']}
- Centralization: {context['centralization']}
- Boundaries: {context['boundaries']}
- Maintainability: {context['maintainability']}

ROLES DEFINED:
- Total roles: {len(context['roles_used'])}
- Generic roles: {context['generic_role_count']} (e.g., USER, ADMIN)
- Domain-specific roles: {context['domain_specific_role_count']}
- Roles found: {', '.join(context['roles_used'][:20])}

TASK:
Generate a tailored authorization recommendation for THIS specific application. You MUST:
1. EXPLICITLY acknowledge the detected authorization architecture pattern ({pattern_type} at {primary_layer})
2. Explain if the current architecture pattern is sound for this application
3. Identify which locations (classes, endpoints, or code) SHOULD have authorization but don't
4. Consider the application's current authorization state and architecture
5. Reference the specific frameworks being used
6. Evaluate if the roles defined are appropriate
7. Address the coverage gaps and consistency issues
8. Infer what this application does based on roles/frameworks

CRITICAL: Respond with valid JSON only. Use \\n for newlines within strings, NOT literal newlines.

Provide your recommendation in this exact JSON format:
{{
  "title": "One-line recommendation title",
  "summary": "Brief 1-2 sentence summary acknowledging the current architecture pattern and what needs to be done",
  "design_recommendation": "Strategic guidance (400-600 words). MUST start by explicitly discussing the {pattern_type} authorization architecture found at {primary_layer}. Is it sound? Is {primary_layer} the right place for auth checks? Then discuss roles, recommend PUBLIC role, explain access control matrix, discuss which locations need annotations. Use \\n for line breaks.",
  "implementation_recommendation": "Concrete technical steps (400-600 words). Provide detailed numbered steps for implementing authorization on the remaining locations (classes, endpoints, or code). Include specific code examples with actual annotations, show which locations need @PreAuthorize or other auth mechanisms, explain how to add authorization to locations that are missing it, include testing approaches. Use \\n for line breaks.",
  "rationale": "Why this approach (400-600 words). Explain why {primary_layer} authorization is appropriate (or not) for this application. Compare against other architectural patterns (controller-level, service-level, API gateways, custom schemes). Discuss trade-offs between different authorization architectures. Explain urgency based on {context['coverage']:.1f}% coverage. Use \\n for line breaks."
}}

CRITICAL REQUIREMENTS:
- First paragraph of design_recommendation MUST discuss the {pattern_type} authorization architecture pattern at {primary_layer}
- Explicitly state whether auth at {primary_layer} is appropriate for this application
- Identify which specific locations (classes, endpoints, or code) are missing authorization annotations
- Each section must be 400-600 words (not 200-300)
- Include actual code examples with real role names from the application
- Be application-specific using the actual roles: {', '.join(context['roles_used'][:10])}
- Provide concrete, actionable guidance with numbered implementation steps

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
