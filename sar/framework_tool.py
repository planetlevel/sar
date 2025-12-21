#!/usr/bin/env python3
"""
Framework Tool - Centralized tool for framework detection and pattern searching

FrameworkTool acts as a database interface for framework patterns in code.
Agents ask simple questions (e.g., "find authorization patterns") and the tool
handles all complexity: loading frameworks, building queries, parsing results.

This encapsulates ALL pattern searching logic in one place, keeping agents simple.
"""

import yaml
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from sar.framework_schema import load_framework, FrameworkDefinition, PatternGroup


class FrameworkTool:
    """
    Centralized tool for framework detection and pattern searching.

    Acts as a database interface - agents ask what patterns exist in code,
    tool handles all complexity of searching, parsing, and returning results.
    """

    def __init__(self, project_dir: str, frameworks_dir: str = None, cpg_tool=None):
        """
        Initialize framework tool

        Args:
            project_dir: Directory containing the project
            frameworks_dir: Optional directory containing framework JSON files
            cpg_tool: Optional CPG tool instance (will create if not provided)
        """
        self.project_dir = Path(project_dir)

        if frameworks_dir is None:
            # Get the sar package directory, then go up to find data/frameworks/
            sar_dir = Path(__file__).parent
            project_root = sar_dir.parent  # Up to project root
            frameworks_dir = project_root / 'data' / 'frameworks'

            # Fallback: if data/frameworks/ doesn't exist, try old location
            if not frameworks_dir.exists():
                frameworks_dir = project_root / 'frameworks'

        self.frameworks_dir = Path(frameworks_dir)
        self.available_frameworks = self._load_frameworks()

        # Initialize tools for file and code operations
        from compass.file_tool import FileTool
        self.file_tool = FileTool(str(self.project_dir))

        # CPG tool for code pattern searching (lazy initialization)
        self._cpg_tool_instance = cpg_tool
        self._cpg_tool_initialized = cpg_tool is not None

    def _load_frameworks(self) -> Dict[str, FrameworkDefinition]:
        """Load all framework definitions from JSON files using Pydantic validation"""
        frameworks = {}

        # Load standard frameworks from frameworks/ directory
        if self.frameworks_dir.exists():
            for file_path in self.frameworks_dir.iterdir():
                # Load JSON files using Pydantic validation
                if file_path.suffix == '.json':
                    framework_id = file_path.stem
                    # Skip schema files and sample files
                    if not framework_id.endswith('.schema') and not framework_id.startswith('SAMPLE_'):
                        try:
                            framework_def = load_framework(str(file_path))
                            frameworks[framework_id] = framework_def
                        except Exception as e:
                            print(f"Warning: Failed to load {file_path.name}: {e}")

        # Load custom framework configs from project's .compass/ directory
        custom_config_dir = self.project_dir / '.compass'
        if custom_config_dir.exists():
            for file_path in custom_config_dir.iterdir():
                if file_path.name.endswith('-compass-config.json'):
                    try:
                        custom_def = load_framework(str(file_path))
                        # Use filename without extension as framework ID
                        framework_id = file_path.stem
                        frameworks[framework_id] = custom_def
                        print(f"[FRAMEWORK DETECTOR] Loaded custom framework: {custom_def.name}")
                    except Exception as e:
                        print(f"Warning: Failed to load custom config {file_path.name}: {e}")

        return frameworks

    @property
    def cpg_tool(self):
        """Lazy initialization of CPG tool"""
        if not self._cpg_tool_initialized:
            from compass.cpg_tool import CpgTool
            self._cpg_tool_instance = CpgTool('auto', str(self.project_dir), auto_generate=True, debug=False)
            self._cpg_tool_initialized = True
        return self._cpg_tool_instance

    def detect_frameworks(self) -> Dict[str, FrameworkDefinition]:
        """
        Detect frameworks present in project

        Returns:
            Dict mapping framework_id to FrameworkDefinition for detected frameworks
        """
        all_frameworks = self.detect_all_frameworks()
        if not all_frameworks:
            return {}

        return {fw_id: fw_def for fw_id, fw_def in all_frameworks}

    def detect_all_frameworks(self) -> List[tuple]:
        """
        Detect ALL frameworks/libraries used in the project

        Returns:
            List of matched frameworks as (framework_id, framework_config) tuples
            Frameworks are unordered - they will be ranked later based on actual behavior counts
        """
        matched_frameworks = []

        # Check all frameworks without priority ordering
        for framework_id, framework_def in self.available_frameworks.items():
            if self._matches_framework(framework_def):
                matched_frameworks.append((framework_id, framework_def))

        return matched_frameworks if matched_frameworks else None

    def detect_framework(self) -> Optional[tuple]:
        """
        Detect frameworks used in the project (legacy method for backward compatibility)

        Returns:
            Tuple of (first_framework_id, list_of_all_frameworks) or None
            The first_framework_id is arbitrary - frameworks should be ranked by behavior count in orchestrator
        """
        all_frameworks = self.detect_all_frameworks()
        if not all_frameworks:
            return None

        # Return first framework ID as placeholder (will be re-ranked by behavior count later)
        first_framework_id = all_frameworks[0][0]
        return (first_framework_id, all_frameworks)

    def _matches_framework(self, framework_def: FrameworkDefinition) -> bool:
        """Check if project matches framework detection patterns"""
        detection = framework_def.detection

        if not detection:
            return False

        # Check dependencies first (most definitive)
        dependencies = detection.dependencies if detection.dependencies else {}
        if dependencies:
            # Define build files to check in priority order
            build_files = [
                'pom.xml',
                'build.gradle',
                'requirements.txt',
                'pyproject.toml',
                'package.json',
                'go.mod'
            ]

            # Check each build file for matching dependencies
            for build_file in build_files:
                if build_file in dependencies:
                    if self._check_build_file_dependencies(build_file, dependencies[build_file]):
                        return True  # Definitive match based on dependency

            # Dependencies specified but none found
            return False

        # Check for required files (old detection method)
        files_def = detection.files
        if files_def:
            # PatternGroup has pattern field (list)
            file_patterns = files_def.pattern if files_def.pattern else []
        else:
            file_patterns = []

        files_found = 0
        for file_path in file_patterns:
            if self.file_tool.file_exists(file_path):
                files_found += 1

        # If files are specified but none found, not a match
        if file_patterns and files_found == 0:
            return False

        # Check for code_patterns - at least one must match
        code_patterns = detection.code_patterns
        if code_patterns and code_patterns.pattern:
            # This would be more complex - for now, skip this check
            # as it's not commonly used in the current framework definitions
            pass

        # If no specific detection criteria, only match if files were found
        return files_found > 0

    def _check_build_file_dependencies(self, build_file: str, dependencies: List) -> bool:
        """
        Helper method to check if any dependency pattern matches in a build file

        Args:
            build_file: Name of build file (e.g., 'pom.xml', 'build.gradle')
            dependencies: List of DependencyPattern objects

        Returns:
            True if any dependency matches, False otherwise
        """
        if not dependencies:
            return False

        file_content = self.file_tool.read_file(build_file)
        if not file_content:
            return False

        for dep in dependencies:
            # Check artifact (for pom.xml)
            if dep.artifact and f'<artifactId>{dep.artifact}</artifactId>' in file_content:
                return True
            # Check pattern (for other build files)
            if dep.pattern and dep.pattern in file_content:
                return True

        return False

    def get_framework_config(self, framework_id: str) -> Optional[FrameworkDefinition]:
        """Get configuration for a specific framework"""
        return self.available_frameworks.get(framework_id)

    def list_frameworks(self) -> List[str]:
        """List all available framework definitions"""
        return list(self.available_frameworks.keys())


def main():
    """Demo the framework tool"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: framework_tool.py <project_dir>")
        sys.exit(1)

    project_dir = sys.argv[1]
    tool = FrameworkTool(project_dir)

    print(f"Available frameworks: {', '.join(tool.list_frameworks())}")
    print()

    frameworks = tool.detect_frameworks()
    if frameworks:
        print(f"Detected {len(frameworks)} frameworks:")
        for fw_id, fw_def in list(frameworks.items())[:5]:  # Show first 5
            print(f"  - {fw_def.name} ({fw_id})")
            print(f"    Languages: {', '.join(fw_def.languages)}")
    else:
        print("No frameworks detected")


if __name__ == "__main__":
    main()
