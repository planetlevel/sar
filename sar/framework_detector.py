#!/usr/bin/env python3
"""
Framework Detector - Detects frameworks and loads framework-specific configurations
"""

import os
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
        self.project_dir = project_dir

        if frameworks_dir is None:
            # Get the sar package directory, then go up to find data/frameworks/
            sar_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(sar_dir)  # Up to project root
            frameworks_dir = os.path.join(project_root, 'data', 'frameworks')

            # Fallback: if data/frameworks/ doesn't exist, try old location
            if not os.path.exists(frameworks_dir):
                frameworks_dir = os.path.join(project_root, 'frameworks')

        self.frameworks_dir = frameworks_dir
        self.available_frameworks = self._load_frameworks()

        # Initialize FileTool for file operations
        from compass.file_tool import FileTool
        self.file_tool = FileTool(project_dir)

    def _load_frameworks(self) -> Dict[str, FrameworkDefinition]:
        """Load all framework definitions from JSON files using Pydantic validation"""
        frameworks = {}

        # Load standard frameworks from frameworks/ directory
        if os.path.exists(self.frameworks_dir):
            for file_name in os.listdir(self.frameworks_dir):
                # Load JSON files using Pydantic validation
                if file_name.endswith('.json'):
                    framework_path = os.path.join(self.frameworks_dir, file_name)
                    framework_id = file_name.replace('.json', '')
                    # Skip schema files and sample files
                    if not framework_id.endswith('.schema') and not framework_id.startswith('SAMPLE_'):
                        try:
                            framework_def = load_framework(framework_path)
                            frameworks[framework_id] = framework_def
                        except Exception as e:
                            print(f"Warning: Failed to load {file_name}: {e}")
                elif file_name.endswith('.yaml') or file_name.endswith('.yml'):
                    # Legacy YAML support (still using dict-based loading)
                    framework_path = os.path.join(self.frameworks_dir, file_name)
                    try:
                        with open(framework_path, 'r') as f:
                            framework_def = yaml.safe_load(f)
                            framework_id = file_name.replace('.yaml', '').replace('.yml', '')
                            # Convert dict to FrameworkDefinition (basic conversion, may need enhancement)
                            try:
                                frameworks[framework_id] = FrameworkDefinition.parse_obj(framework_def)
                            except Exception as parse_err:
                                print(f"Warning: Failed to parse YAML {file_name} as FrameworkDefinition: {parse_err}")
                    except Exception as e:
                        print(f"Warning: Failed to load {file_name}: {e}")

        # Load custom framework configs from project's .compass/ directory
        custom_config_dir = os.path.join(self.project_dir, '.compass')
        if os.path.exists(custom_config_dir):
            for file_name in os.listdir(custom_config_dir):
                if file_name.endswith('-compass-config.json'):
                    config_path = os.path.join(custom_config_dir, file_name)
                    try:
                        custom_def = load_framework(config_path)
                        # Use filename without extension as framework ID
                        framework_id = file_name.replace('.json', '')
                        frameworks[framework_id] = custom_def
                        print(f"[FRAMEWORK DETECTOR] Loaded custom framework: {custom_def.name}")
                    except Exception as e:
                        print(f"Warning: Failed to load custom config {file_name}: {e}")

        return frameworks

    def _merge_configs(self, base_config: Dict, extended_config: Dict, preserve_base_metadata: bool = False) -> Dict:
        """
        Merge extended framework config with base framework config

        Args:
            base_config: Base framework configuration (e.g., Java)
            extended_config: Extended framework configuration (e.g., Spring)
            preserve_base_metadata: If True, preserve base's name/languages/extends (for library merges)

        Returns:
            Merged configuration with extended config taking precedence
        """
        import copy
        merged = copy.deepcopy(base_config)

        # Metadata fields that should NOT be overwritten when merging libraries
        protected_fields = {'name', 'languages', 'extends', '$schema'} if preserve_base_metadata else set()

        # Recursively merge dictionaries
        def deep_merge(target, source):
            for key, value in source.items():
                # Skip protected metadata fields when merging libraries
                if key in protected_fields:
                    continue

                if key in target:
                    # If both are dicts, recursively merge
                    if isinstance(target[key], dict) and isinstance(value, dict):
                        # Special case: if dict contains 'signatures' key, merge the lists
                        if 'signatures' in target[key] and 'signatures' in value:
                            # Merge signature lists
                            target_sigs = target[key].get('signatures', [])
                            source_sigs = value.get('signatures', [])

                            # Handle both old format (strings) and new format (objects with 'signature' field)
                            if target_sigs and isinstance(target_sigs[0], dict):
                                # New format: deduplicate based on 'signature' field
                                existing_sigs = {sig['signature'] for sig in target_sigs if 'signature' in sig}
                                for sig in source_sigs:
                                    if isinstance(sig, dict) and 'signature' in sig:
                                        if sig['signature'] not in existing_sigs:
                                            target_sigs.append(sig)
                                            existing_sigs.add(sig['signature'])
                                merged_sigs = target_sigs
                            else:
                                # Old format: deduplicate strings directly
                                merged_sigs = target_sigs + [sig for sig in source_sigs if sig not in target_sigs]

                            target[key]['signatures'] = merged_sigs
                            # Merge other keys in the dict
                            for k, v in value.items():
                                if k != 'signatures':
                                    target[key][k] = v
                        else:
                            deep_merge(target[key], value)
                    # If both are lists, combine them
                    elif isinstance(target[key], list) and isinstance(value, list):
                        # Deduplicate list items
                        for item in value:
                            if item not in target[key]:
                                target[key].append(item)
                    else:
                        # Otherwise, source value takes precedence
                        target[key] = value
                else:
                    # Key doesn't exist in target, just add it
                    target[key] = copy.deepcopy(value)

        deep_merge(merged, extended_config)
        return merged

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

        # NEW: Check dependencies first (most definitive)
        dependencies = detection.dependencies if detection.dependencies else {}
        if dependencies:
            dependency_matched = False

            # Check pom.xml dependencies
            pom_deps = dependencies.get('pom.xml', [])
            if pom_deps:
                pom_content = self.file_tool.read_file('pom.xml')
                if pom_content:
                    # Check if any dependency artifact is present
                    for dep in pom_deps:
                        if dep.artifact and f'<artifactId>{dep.artifact}</artifactId>' in pom_content:
                            dependency_matched = True
                            break

            # Check build.gradle dependencies
            if not dependency_matched:
                gradle_deps = dependencies.get('build.gradle', [])
                if gradle_deps:
                    gradle_content = self.file_tool.read_file('build.gradle')
                    if gradle_content:
                        # Check if any dependency pattern is present
                        for dep in gradle_deps:
                            if dep.pattern and dep.pattern in gradle_content:
                                dependency_matched = True
                                break

            # Check requirements.txt dependencies (Python)
            if not dependency_matched:
                requirements_deps = dependencies.get('requirements.txt', [])
                if requirements_deps:
                    requirements_content = self.file_tool.read_file('requirements.txt')
                    if requirements_content:
                        # Check if any dependency pattern is present
                        for dep in requirements_deps:
                            if dep.pattern and dep.pattern in requirements_content:
                                dependency_matched = True
                                break

            # Check pyproject.toml dependencies (Python)
            if not dependency_matched:
                pyproject_deps = dependencies.get('pyproject.toml', [])
                if pyproject_deps:
                    pyproject_content = self.file_tool.read_file('pyproject.toml')
                    if pyproject_content:
                        # Check if any dependency pattern is present
                        for dep in pyproject_deps:
                            if dep.pattern and dep.pattern in pyproject_content:
                                dependency_matched = True
                                break

            # Check package.json dependencies (JavaScript/TypeScript)
            if not dependency_matched:
                package_deps = dependencies.get('package.json', [])
                if package_deps:
                    package_content = self.file_tool.read_file('package.json')
                    if package_content:
                        # Check if any dependency pattern is present
                        for dep in package_deps:
                            if dep.pattern and dep.pattern in package_content:
                                dependency_matched = True
                                break

            # Check go.mod dependencies (Go)
            if not dependency_matched:
                gomod_deps = dependencies.get('go.mod', [])
                if gomod_deps:
                    gomod_content = self.file_tool.read_file('go.mod')
                    if gomod_content:
                        # Check if any dependency pattern is present
                        for dep in gomod_deps:
                            if dep.pattern and dep.pattern in gomod_content:
                                dependency_matched = True
                                break

            # If dependencies are specified, at least one must match
            if dependency_matched:
                return True  # Definitive match based on dependency
            else:
                return False  # Dependencies specified but none found

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

    def detect_database(self, framework_def: Dict) -> Dict[str, Any]:
        """
        Detect database configuration using framework-specific patterns

        Args:
            framework_def: Framework definition from YAML

        Returns:
            Dict with 'databases', 'orm', and 'config_source' keys
        """
        result = {
            'databases': [],
            'orm': None,
            'config_source': None
        }

        db_config = framework_def.get('database', {})

        # Check configuration files
        config_files = db_config.get('config_files', [])
        for config_def in config_files:
            config_path = os.path.join(self.project_dir, config_def['path'])
            if os.path.exists(config_path):
                databases = self._extract_databases_from_config(config_path, config_def)
                for db in databases:
                    if db not in result['databases']:
                        result['databases'].append(db)
                        if not result['config_source']:
                            result['config_source'] = config_def['path']

        # Check dependencies in build files
        dependencies = db_config.get('dependencies', {})
        for build_file, dep_patterns in dependencies.items():
            build_path = os.path.join(self.project_dir, build_file)
            if os.path.exists(build_path):
                databases = self._extract_databases_from_dependencies(
                    build_path, dep_patterns, db_config
                )
                for db in databases:
                    if db not in result['databases']:
                        result['databases'].append(db)
                        if not result['config_source']:
                            result['config_source'] = build_file

        # Detect ORM
        orm_patterns = db_config.get('orm', [])
        for build_file in dependencies.keys():
            build_path = os.path.join(self.project_dir, build_file)
            if os.path.exists(build_path):
                orm = self._detect_orm(build_path, orm_patterns)
                if orm and not result['orm']:
                    result['orm'] = orm
                    break

        return result

    def _extract_databases_from_config(self, config_path: str, config_def: Dict) -> List[str]:
        """Extract database names from configuration file"""
        databases = []

        try:
            with open(config_path, 'r') as f:
                content = f.read()

                patterns = config_def.get('patterns', {})
                for pattern_type, pattern_list in patterns.items():
                    for pattern_def in pattern_list:
                        regex = pattern_def.get('regex')
                        group = pattern_def.get('group', 0)

                        matches = re.findall(regex, content)
                        for match in matches:
                            if isinstance(match, tuple) and group > 0:
                                db = match[group - 1] if group <= len(match) else match[0]
                            else:
                                db = match

                            if db and db not in databases:
                                databases.append(db)

        except Exception:
            pass

        return databases

    def _extract_databases_from_dependencies(
        self, build_path: str, dep_patterns: List[Dict], db_config: Dict
    ) -> List[str]:
        """Extract database names from build/dependency files"""
        databases = []

        try:
            with open(build_path, 'r') as f:
                content = f.read()

                for dep_def in dep_patterns:
                    if 'artifact' in dep_def:
                        # Check for artifact name
                        if dep_def['artifact'] in content:
                            databases.append(dep_def['database'])
                    elif 'pattern' in dep_def:
                        # Check for pattern match
                        if re.search(dep_def['pattern'], content):
                            databases.append(dep_def['database'])

        except Exception:
            pass

        return databases

    def _detect_orm(self, build_path: str, orm_patterns: List[Dict]) -> Optional[str]:
        """Detect ORM framework"""
        try:
            with open(build_path, 'r') as f:
                content = f.read().lower()

                for orm_def in orm_patterns:
                    pattern = orm_def['pattern'].lower()
                    if pattern in content:
                        return orm_def['name']

        except Exception:
            pass

        return None

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

        # Detect database
        db_info = detector.detect_database(first_fw_def)
        if db_info['databases']:
            print(f"Databases: {', '.join(db_info['databases'])}")
            print(f"ORM: {db_info['orm']}")
            print(f"Config source: {db_info['config_source']}")
        else:
            print("No database configuration detected")
    else:
        print("No framework detected")


if __name__ == "__main__":
    main()
