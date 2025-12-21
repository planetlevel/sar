"""
Libraries Analysis Agent

Runs deptrast to identify all libraries (including transitive dependencies)
and checks which are supported by Compass (have matching .json files in
frameworks/ directory).

This is a test agent to verify the defense analysis pipeline is working.
"""

from typing import Dict, Any, List
import os
import glob
from sar.framework_tool import FrameworkTool


class LibrariesAgent:
    """Analyzes library dependencies and framework support"""

    def __init__(self,
                 cpg_tool,
                 project_dir: str,
                 ai_client,
                 debug: bool = False):
        self.cpg_tool = cpg_tool
        self.project_dir = project_dir
        self.ai = ai_client
        self.debug = debug

        # Initialize FrameworkTool for framework listing
        # FrameworkTool will auto-detect data/frameworks/ location
        self.framework_detector = FrameworkTool(project_dir=project_dir)

    def get_agent_id(self) -> str:
        return "libraries"

    def get_agent_name(self) -> str:
        return "Library & Framework Analysis"

    def get_category(self) -> str:
        return "infrastructure"

    def should_run(self) -> Dict[str, Any]:
        """Always run - this is a basic analysis"""
        return {
            'should_run': True,
            'reason': 'Basic library/framework analysis',
            'confidence': 1.0
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Run deptrast and check framework support

        Returns:
            {
                'agent_id': 'libraries',
                'agent_name': str,
                'defense_metadata': {...},
                'evidence': {
                    'total_libraries': int,
                    'supported_count': int,
                    'coverage_percentage': float
                },
                'metrics': {
                    'exposures': int,
                    'protected': int,
                    'unprotected': int,
                    'coverage': float
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
            print(f"[{self.get_agent_id().upper()}] Analyzing libraries...")

        # Run deptrast to get all dependencies (includes transitive)
        libraries = self._get_libraries()

        # Get list of supported frameworks (from frameworks/*.json)
        supported_frameworks = self._get_supported_frameworks()

        # Check which libraries are supported
        supported = []
        unsupported = []

        for lib in libraries:
            if self._is_supported(lib, supported_frameworks):
                supported.append(lib)
            else:
                unsupported.append(lib)

        support_pct = len(supported) / len(libraries) * 100 if libraries else 0

        # Build evidence - minimal, just counts (don't include the full library list)
        evidence = {
            'total_libraries': len(libraries),
            'supported_count': len(supported),
            'coverage_percentage': round(support_pct, 1)
        }

        # Defense metadata (framework support)
        defense_metadata = {
            'defense_name': 'Compass Framework Definitions',
            'defense_type': 'standard',
            'defense_mechanism': 'framework_json_definitions',
            'defense_patterns': [f'frameworks/{fw}.json' for fw in supported_frameworks[:5]]  # Sample
        }

        # Metrics (library coverage)
        metrics = {
            'exposures': len(libraries),
            'protected': len(supported),
            'unprotected': len(unsupported),
            'coverage': round(support_pct, 1)
        }

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

    def _get_libraries(self) -> List[Dict]:
        """
        Run deptrast to extract all dependencies (includes transitive)

        Returns list like:
        [
            {'group': 'org.springframework', 'artifact': 'spring-web', 'version': '5.3.20'},
            {'group': 'org.hibernate', 'artifact': 'hibernate-core', 'version': '5.6.0'}
        ]
        """
        try:
            from compass.deptrast_tool import DeptrastTool

            deptrast = DeptrastTool(debug=self.debug)

            # Look for build file in project directory
            build_file = self._find_build_file()
            if not build_file:
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] No build file found")
                return []

            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Found build file: {build_file}")

            # Extract dependencies (includes transitive)
            result = deptrast.extract_dependencies_from_build_file(
                build_file=build_file,
                format='list'
            )

            if not result.get('success'):
                if self.debug:
                    print(f"[{self.get_agent_id().upper()}] Deptrast failed: {result.get('error')}")
                return []

            # Parse dependencies
            dependencies = result.get('dependencies', [])
            libs = []

            for dep in dependencies:
                # Format: "maven:org.springframework:spring-web:5.3.20"
                parts = dep.split(':')
                if len(parts) >= 4:
                    libs.append({
                        'group': parts[1],
                        'artifact': parts[2],
                        'version': parts[3] if len(parts) > 3 else 'unknown'
                    })

            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Found {len(libs)} libraries")

            return libs

        except Exception as e:
            if self.debug:
                print(f"[{self.get_agent_id().upper()}] Error running deptrast: {e}")
            return []

    def _find_build_file(self) -> str:
        """Find build file (pom.xml, build.gradle, etc.)"""
        build_files = [
            'pom.xml',
            'build.gradle',
            'build.gradle.kts',
            'package.json',
            'requirements.txt',
            'go.mod'
        ]

        for bf in build_files:
            path = os.path.join(self.project_dir, bf)
            if os.path.exists(path):
                return path

        return None

    def _get_supported_frameworks(self) -> List[str]:
        """
        Get list of supported frameworks from FrameworkDetector

        Returns list of framework IDs
        """
        frameworks = list(self.framework_detector.available_frameworks.keys())

        if self.debug:
            print(f"[{self.get_agent_id().upper()}] Found {len(frameworks)} framework definitions")

        return frameworks

    def _is_supported(self, library: Dict, supported_frameworks: List[str]) -> bool:
        """
        Check if a library is supported by checking if its name matches
        any framework definition filename.

        Simple check: does group or artifact name appear in framework list?
        """
        group = library.get('group', '').lower()
        artifact = library.get('artifact', '').lower()

        # Check if any framework ID matches the library name
        for framework in supported_frameworks:
            framework_lower = framework.lower()
            if (framework_lower in group or
                framework_lower in artifact or
                group in framework_lower or
                artifact in framework_lower):
                return True

        return False

    def _generate_recommendation(self, evidence: Dict) -> Dict:
        """Generate recommendation based on framework support"""

        total = evidence['total_libraries']
        supported = evidence['supported_count']
        unsupported = total - supported
        pct = evidence['coverage_percentage']

        if supported == 0:
            title = "Consider Creating Framework Definitions"
            summary = f"Application uses {total} libraries (including transitive dependencies), but none match existing Compass framework definitions."
            design_rec = "Create framework definitions for your primary libraries to enable automated defense pattern detection."
            impl_rec = "Use compass-gen-framework tool to generate framework JSON definitions from library source code."
            rationale = "Without framework definitions, Compass cannot automatically detect standard defense patterns in these libraries."
        elif pct == 100.0:
            title = f"All {total} Libraries Supported"
            summary = f"All {total} libraries (including transitive dependencies) have Compass framework definitions, enabling comprehensive security analysis."
            design_rec = "Leverage existing framework definitions for automated defense discovery."
            impl_rec = "Run defense agents (authorization, input validation, injection defense) with confidence in coverage."
            rationale = "Complete framework coverage means Compass can detect both standard and custom defense patterns effectively."
        else:
            title = f"{supported}/{total} Libraries Supported ({pct}%)"
            summary = f"Application uses {total} libraries (including transitive dependencies). {supported} have Compass framework definitions, {unsupported} do not."

            design_rec = "Create framework definitions for unsupported libraries to improve defense pattern detection coverage."
            impl_rec = "Use compass-gen-framework on each unsupported library to generate framework definitions."
            rationale = f"With {pct}% coverage, some defense patterns may be missed. Complete coverage ensures comprehensive analysis."

        return {
            'title': title,
            'summary': summary,
            'design_recommendation': design_rec,
            'implementation_recommendation': impl_rec,
            'rationale': rationale
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
