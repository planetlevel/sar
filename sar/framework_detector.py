#!/usr/bin/env python3
"""
Framework Detector - Detects frameworks and loads framework-specific configurations
"""

import yaml
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from sar.framework_schema import load_framework, FrameworkDefinition


class FrameworkDetector:
    """Detects web frameworks and provides framework-specific patterns"""

    def __init__(self, project_dir: str, frameworks_dir: str = None):
        """
        Initialize framework detector

        Args:
            project_dir: Directory containing the project
            frameworks_dir: Directory containing framework YAML files
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

        # Initialize FileTool for file operations
        from compass.file_tool import FileTool
        self.file_tool = FileTool(str(self.project_dir))

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
    """Demo the framework detector"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: framework_detector.py <project_dir>")
        sys.exit(1)

    project_dir = sys.argv[1]
    detector = FrameworkDetector(project_dir)

    print(f"Available frameworks: {', '.join(detector.list_frameworks())}")
    print()

    result = detector.detect_framework()
    if result:
        framework_id, all_frameworks = result
        # all_frameworks is a list of (id, FrameworkDefinition) tuples
        # Get the first framework's definition
        first_fw_def = all_frameworks[0][1]
        print(f"Detected framework: {first_fw_def.name} ({framework_id})")
        print(f"Languages: {', '.join(first_fw_def.languages)}")
        print()
        print(f"Total frameworks detected: {len(all_frameworks)}")
        for fw_id, fw_def in all_frameworks[:5]:  # Show first 5
            print(f"  - {fw_def.name} ({fw_id})")
    else:
        print("No framework detected")


if __name__ == "__main__":
    main()
