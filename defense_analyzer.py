"""
Defense Analyzer

Orchestrates execution of defense analysis agents.
"""

from typing import Dict, Any, List
import sys
import os
import uuid
from datetime import datetime, timezone

# Add compass to path if needed
compass_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if compass_dir not in sys.path:
    sys.path.insert(0, compass_dir)


class DefenseAnalyzer:
    """
    Orchestrates defense analysis agents

    Loads agents, executes them, and consolidates results.
    """

    def __init__(self,
                 cpg_tool,
                 project_dir: str,
                 ai_client=None,
                 debug: bool = False):
        """
        Initialize analyzer

        Args:
            cpg_tool: CpgTool instance for Joern queries
            project_dir: Project root directory
            ai_client: Optional AI client (creates default if None)
            debug: Enable debug output
        """
        self.cpg_tool = cpg_tool
        self.project_dir = project_dir
        self.debug = debug

        # Initialize AI client if not provided
        if ai_client is None:
            from sar.ai_client import AIClient
            self.ai = AIClient(debug=debug)
        else:
            self.ai = ai_client

        # Test AI connection early - fail fast if auth issues
        if self.ai.is_available():
            try:
                print("[Analyzer] Testing AI connection...")
                self.ai.test_connection()
                print("[Analyzer] ✓ AI connection verified")
            except RuntimeError as e:
                print(f"[Analyzer] ✗ AI connection failed: {e}")
                print("\nPlease check:")
                print("  - For Bedrock: Run ./login.sh to authenticate AWS SSO")
                print("  - For Anthropic API: Set ANTHROPIC_API_KEY environment variable")
                raise SystemExit(1)
        else:
            print("[Analyzer] WARNING: No AI client available")
            print("  - For Bedrock: Configure AWS credentials")
            print("  - For Anthropic API: Set ANTHROPIC_API_KEY environment variable")

        # Run deptrast to get architecture/dependency information
        self.architecture_report = self._run_deptrast()

        # Agent registry
        self.agents = []
        self._register_agents()

    def _run_deptrast(self) -> Dict[str, Any]:
        """
        Run deptrast to analyze project dependencies and architecture.

        Returns architecture report with libraries and framework versions.
        """
        try:
            from sar.deptrast_tool import DeptrastTool

            print("[Analyzer] Running deptrast for dependency analysis...")

            # Initialize DeptrastTool
            tool = DeptrastTool(debug=self.debug)

            # Analyze project to get SBOM
            result = tool.analyze_project(self.project_dir, output_format='sbom')

            if result['success']:
                # Transform SBOM components to architecture report format
                libraries = []
                for component in result.get('dependencies', []):
                    libraries.append({
                        'name': component.get('name', ''),
                        'version': component.get('version', '')
                    })

                if self.debug:
                    print(f"[Analyzer] ✓ Deptrast found {len(libraries)} libraries")

                return {'libraries': libraries}
            else:
                if self.debug:
                    error = result.get('stderr', result.get('error', 'Unknown error'))
                    print(f"[Analyzer] Warning: deptrast failed: {error}")
                return {}

        except Exception as e:
            if self.debug:
                print(f"[Analyzer] Warning: deptrast error: {e}")
            return {}

    def _register_agents(self):
        """Register all available agents"""
        from sar.agents import EndpointsAgent, LibrariesAgent, EndpointAuthorizationAgent

        agent_classes = [
            # EndpointsAgent,  # Disabled - not ready
            # LibrariesAgent,  # Disabled - not ready
            EndpointAuthorizationAgent,
        ]

        for AgentClass in agent_classes:
            try:
                agent = AgentClass(
                    cpg_tool=self.cpg_tool,
                    project_dir=self.project_dir,
                    ai_client=self.ai,
                    architecture_report=self.architecture_report,
                    debug=self.debug
                )
                self.agents.append(agent)

                if self.debug:
                    print(f"[Analyzer] Registered agent: {agent.get_agent_id()}")

            except Exception as e:
                if self.debug:
                    print(f"[Analyzer] Failed to register {AgentClass.__name__}: {e}")

    def run_all_agents(self) -> Dict[str, Any]:
        """
        Execute all registered agents

        Returns:
            {
                'agents_ran': int,
                'agents_skipped': int,
                'results_by_agent': {
                    'agent_id': {
                        'agent_name': str,
                        'ran': bool,
                        'evidence': {...},
                        'finding': {...}
                    }
                },
                'summary': {...}
            }
        """
        if self.debug:
            print(f"\n[Defense Analyzer] Starting")
            print(f"  Project: {self.project_dir}")
            print(f"  Agents: {len(self.agents)}")

        results = {
            'agents_ran': 0,
            'agents_skipped': 0,
            'results_by_agent': {}
        }

        for agent in self.agents:
            agent_id = agent.get_agent_id()

            try:
                if self.debug:
                    print(f"\n[{agent_id.upper()}] Running...")

                result = agent.run()
                results['results_by_agent'][agent_id] = result

                if result.get('ran'):
                    results['agents_ran'] += 1
                    if self.debug:
                        print(f"[{agent_id.upper()}] ✓ Complete")
                else:
                    results['agents_skipped'] += 1
                    if self.debug:
                        print(f"[{agent_id.upper()}] ⊘ Skipped: {result.get('reason')}")

            except Exception as e:
                if self.debug:
                    print(f"[{agent_id.upper()}] ✗ Error: {e}")
                    import traceback
                    traceback.print_exc()

                results['results_by_agent'][agent_id] = {
                    'agent_id': agent_id,
                    'agent_name': agent.get_agent_name(),
                    'ran': False,
                    'error': str(e)
                }
                results['agents_skipped'] += 1

        # Generate summary
        results['summary'] = self._generate_summary(results)

        return results

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary of analysis"""
        return {
            'total_agents': len(self.agents),
            'agents_ran': results['agents_ran'],
            'agents_skipped': results['agents_skipped'],
            'success_rate': f"{results['agents_ran']}/{len(self.agents)}"
        }

    def generate_cyclonedx_report(self, results: Dict, project_name: str = None,
                                  project_version: str = None) -> Dict:
        """
        Generate CycloneDX-style defense report using Pydantic models

        Args:
            results: Results from run_all_agents()
            project_name: Optional project name
            project_version: Optional project version

        Returns:
            Validated CycloneDX-style report dict
        """
        from sar.defense_report_schema import (
            DefenseReport, Metadata, Tool, Component, Property,
            AgentRecommendation, Summary
        )

        # Extract and validate recommendations from results
        recommendations = []
        for agent_id, agent_result in results['results_by_agent'].items():
            if agent_result.get('ran'):
                # Validate agent result against schema
                recommendations.append(AgentRecommendation(**agent_result))

        # Calculate overall coverage from agent defenses
        # Use RESTRICTIVENESS dimension - measures actual security, not just policy presence
        total_coverage = 0
        coverage_count = 0

        for rec in recommendations:
            if rec.defenses:
                for defense in rec.defenses:
                    if defense.metrics:
                        # Find the restrictiveness metric - this measures actual security
                        restrictiveness_metric = next(
                            (m for m in defense.metrics if m.dimension == 'restrictiveness'),
                            None
                        )
                        if restrictiveness_metric:
                            total_coverage += restrictiveness_metric.coverage
                            coverage_count += 1

        overall_coverage = round(total_coverage / coverage_count, 1) if coverage_count > 0 else 0

        # Build validated report using Pydantic models
        report = DefenseReport(
            bomFormat='CompassDefenseReport',
            specVersion='1.0',
            version=1,
            serialNumber=f'urn:uuid:{uuid.uuid4()}',
            metadata=Metadata(
                timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                tools=[
                    Tool(
                        vendor='Contrast Security',
                        name='Compass Defense Analyzer',
                        version='1.0.0'
                    )
                ],
                component=Component(
                    type='application',
                    name=project_name or 'Unknown Project',
                    version=project_version or '1.0.0',
                    properties=[
                        Property(name='project_directory', value=self.project_dir)
                    ]
                )
            ),
            recommendations=recommendations,
            summary=Summary(
                agents_ran=results['agents_ran'],
                agents_skipped=results['agents_skipped'],
                total_recommendations=len(recommendations),
                overall_coverage=overall_coverage
            )
        )

        # Return as dict for JSON serialization
        return report.model_dump(exclude_none=True)


if __name__ == '__main__':
    import sys
    import json
    from datetime import datetime

    if len(sys.argv) < 2:
        print("Usage: python defense_analyzer.py <project_dir>")
        print("Example: python defense_analyzer.py ../spring-petclinic")
        sys.exit(1)

    project_dir = os.path.abspath(sys.argv[1])
    reports_dir = os.path.join(os.path.dirname(__file__), 'output', 'reports')

    print(f"Target: {project_dir}")
    print(f"Reports: {reports_dir}\n")

    os.makedirs(reports_dir, exist_ok=True)

    print("Initializing CPG...")
    from sar.cpg_tool import CpgTool
    cpg_tool = CpgTool(cpg_path='auto', project_dir=project_dir, auto_generate=False)

    print("Initializing analyzer...\n")
    analyzer = DefenseAnalyzer(cpg_tool=cpg_tool, project_dir=project_dir, debug=True)

    print("\n" + "="*60)
    print("Running analysis...")
    print("="*60 + "\n")

    results = analyzer.run_all_agents()

    print("\n" + "="*60)
    print("Generating report...")
    report = analyzer.generate_cyclonedx_report(
        results,
        os.path.basename(project_dir),
        "1.0.0"
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(reports_dir, f"defense_report_{timestamp}.json")

    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"✓ Report saved: {report_path}")
    print(f"\nSummary: {results['summary']}")
    print(f"Recommendations: {len(report['recommendations'])}")
