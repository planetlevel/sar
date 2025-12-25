"""
Endpoints Analysis Agent

Simple agent that counts endpoints and uses AI to assess application size.
This is a test agent to verify the defense analysis pipeline is working.
"""

from typing import Dict, Any, List
import json


class EndpointsAgent:
    """Analyzes endpoint count and application size"""

    def __init__(self,
                 cpg_tool,
                 project_dir: str,
                 ai_client,
                 debug: bool = False):
        self.cpg_tool = cpg_tool
        self.project_dir = project_dir
        self.ai = ai_client
        self.debug = debug

    def get_agent_id(self) -> str:
        return "endpoints"

    def get_agent_name(self) -> str:
        return "Endpoint Analysis"

    def get_category(self) -> str:
        return "infrastructure"

    def should_run(self) -> Dict[str, Any]:
        """Always run - this is a basic analysis"""
        return {
            'should_run': True,
            'reason': 'Basic endpoint count analysis',
            'confidence': 1.0
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Count endpoints and ask AI about application size

        Returns:
            {
                'agent_id': 'endpoints',
                'agent_name': str,
                'defense_metadata': {...},
                'evidence': {
                    'total_endpoints': int,
                    'by_method': {...},
                    'unique_controllers': int
                },
                'metrics': {
                    'exposures': int,
                    'protected': 0,
                    'unprotected': 0,
                    'coverage': 0
                },
                'recommendation': {
                    'title': '...',
                    'summary': '...',
                    'design_recommendation': '...',
                    'implementation_recommendation': '...',
                    'rationale': '...'
                }
            }
        """
        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Analyzing endpoints...")

        # Discover endpoints using FrameworkTool
        from sar.framework_tool import FrameworkTool
        tool = FrameworkTool(project_dir=self.project_dir, cpg_tool=self.cpg_tool)
        frameworks = tool.detect_frameworks()

        # Query for all endpoint methods
        from sar.agents.authorization_utils import AuthorizationUtils
        utils = AuthorizationUtils(
            cpg_tool=self.cpg_tool,
            project_dir=self.project_dir,
            frameworks_dir=None,  # Not needed for endpoint discovery
            ai_client=self.ai,
            debug=self.debug
        )
        self.endpoints = utils.query_all_endpoint_methods(frameworks)

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(self.endpoints)} endpoints")

        # Count endpoints
        total = len(self.endpoints)

        # Count by HTTP method
        by_method = {}
        for ep in self.endpoints:
            method = ep.get('httpMethod', 'UNKNOWN')
            by_method[method] = by_method.get(method, 0) + 1

        # Count unique controllers
        controllers = set(ep.get('controller', 'Unknown') for ep in self.endpoints)
        unique_controllers = len(controllers)

        # Sample endpoints for AI
        sample_endpoints = self.endpoints[:10]

        evidence = {
            'total_endpoints': total,
            'by_method': by_method,
            'unique_controllers': unique_controllers,
            'sample_endpoints': [
                {
                    'route': ep.get('route', ''),
                    'method': ep.get('httpMethod', ''),
                    'controller': ep.get('controller', '').split('.')[-1]  # Just class name
                }
                for ep in sample_endpoints
            ]
        }

        # Defense metadata (N/A for infrastructure analysis)
        defense_metadata = {
            'defense_name': 'N/A - Infrastructure Analysis',
            'defense_type': 'N/A',
            'defense_mechanism': 'N/A',
            'defense_patterns': []
        }

        # Metrics (no protection analysis for endpoint counting)
        metrics = {
            'exposures': total,
            'protected': 0,
            'unprotected': 0,
            'coverage': 0
        }

        # Ask AI about application size
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

    def _generate_recommendation(self, evidence: Dict) -> Dict:
        """Use AI to assess application size and generate recommendation"""

        total = evidence['total_endpoints']
        controllers = evidence['unique_controllers']
        by_method = evidence['by_method']
        sample = evidence['sample_endpoints']

        prompt = f"""
You are analyzing an application's endpoint count to assess its size and complexity.

EVIDENCE:
- Total endpoints: {total}
- Unique controllers: {controllers}
- By HTTP method: {json.dumps(by_method, indent=2)}
- Sample endpoints:
{json.dumps(sample, indent=2)}

TASK:
Assess the application size and provide a recommendation about defense analysis strategy.

Size categories:
- Small: < 20 endpoints (simple app, proof of concept)
- Medium: 20-100 endpoints (standard application)
- Large: 100-500 endpoints (complex application)
- Enterprise: > 500 endpoints (large enterprise system)

Return JSON with this structure:
{{
    "title": "Application Size: [Small|Medium|Large|Enterprise]",
    "summary": "Brief 2-3 sentence summary about what the endpoint count tells us about the application and defense analysis scope",
    "design_recommendation": "Brief suggestion about defense analysis approach based on app size (e.g., for large apps: focus on framework-level patterns; for small apps: review individual endpoints)",
    "implementation_recommendation": "Specific next steps for defense analysis (e.g., 'Run authorization agent', 'Check input validation patterns')",
    "rationale": "Why this classification and approach makes sense given the endpoint count and distribution"
}}

Keep it factual and actionable.
"""

        try:
            response = self.ai.call_claude(prompt)
            recommendation = json.loads(response)
            return recommendation
        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] AI analysis failed: {e}")

            # Fallback without AI
            if total < 20:
                assessment = "Small"
                approach = "Review individual endpoints manually for security patterns"
            elif total < 100:
                assessment = "Medium"
                approach = "Focus on framework-level patterns with spot checks on key endpoints"
            elif total < 500:
                assessment = "Large"
                approach = "Focus on framework-level patterns and controller-level authorization"
            else:
                assessment = "Enterprise"
                approach = "Prioritize framework-level patterns and automated defense discovery"

            return {
                'title': f"Application Size: {assessment}",
                'summary': f"Application has {total} endpoints across {controllers} controllers, classified as {assessment.lower()}.",
                'design_recommendation': approach,
                'implementation_recommendation': "Run authorization agent and input validation analyzer next.",
                'rationale': f"Classified as {assessment.lower()} based on endpoint count threshold. {approach} is most efficient for this scale."
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
