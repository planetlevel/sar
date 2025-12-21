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



    def search_patterns(
        self,
        frameworks: Union[Dict[str, FrameworkDefinition], FrameworkDefinition],
        category_path: str,
        filter_fn: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for patterns in specified architecture category

        Args:
            frameworks: Dict of frameworks or single FrameworkDefinition
            category_path: Dot-separated path like 'security.authorization' or 'routing.route_definitions'
            filter_fn: Optional function to filter patterns before searching

        Returns:
            List of Behavior dicts with standardized structure:
            {
                'framework': 'spring-security',
                'category': 'authorization',
                'type': 'authorization_annotation',
                'mechanism': 'PreAuthorize',
                'method': 'full.method.signature',
                'class': 'ClassName',
                'file': 'path/to/file.java',
                'line': 42,
                'location': 'ClassName (line 42)',
                'location_type': 'method',
                # Optional fields depending on pattern type:
                'roles': ['ADMIN', 'USER'],  # For authorization
                'httpMethod': 'POST',  # For routing
            }
        """
        # Normalize to dict
        if isinstance(frameworks, FrameworkDefinition):
            frameworks = {'framework': frameworks}

        behaviors = []

        for fw_id, fw_def in frameworks.items():
            # Extract patterns from category path
            patterns = self._extract_patterns_from_path(fw_def, category_path)

            if not patterns:
                continue

            # Apply filter if provided
            if filter_fn:
                patterns = [p for p in patterns if filter_fn(p)]

            # Search each pattern
            for pattern_group in patterns:
                pattern_behaviors = self._execute_pattern_search(
                    pattern_group,
                    fw_id,
                    category_path
                )
                behaviors.extend(pattern_behaviors)

        return behaviors


    def _extract_patterns_from_path(
        self,
        framework: FrameworkDefinition,
        category_path: str
    ) -> List[PatternGroup]:
        """
        Extract PatternGroup list from dot-separated category path

        Examples:
            'security.authorization' -> framework.architecture.security.authorization
            'routing.route_definitions' -> framework.architecture.routing.route_definitions
        """
        if not framework.architecture:
            return []

        # Navigate the path
        parts = category_path.split('.')
        current = framework.architecture

        for part in parts:
            if not hasattr(current, part):
                return []
            current = getattr(current, part)

        # current should now be a List[PatternGroup] or None
        if current is None:
            return []

        if not isinstance(current, list):
            return []

        return current


    def _execute_pattern_search(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """
        Execute search for a single PatternGroup

        Returns list of Behavior dicts
        """
        if not pattern_group.target or not pattern_group.search_type:
            return []

        # Route to appropriate search method based on target
        if pattern_group.target == 'joern':
            return self._search_joern_patterns(pattern_group, framework_id, category_path)
        elif pattern_group.target == 'filename':
            return self._search_filename_patterns(pattern_group, framework_id, category_path)
        elif pattern_group.target == 'filecontent':
            return self._search_filecontent_patterns(pattern_group, framework_id, category_path)
        else:
            return []


    def _search_joern_patterns(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """
        Search for patterns using Joern CPG queries

        Handles: annotation_name, method_signature, method_name_regex, etc.
        """
        search_type = pattern_group.search_type

        if search_type == 'annotation_name':
            return self._search_annotations(pattern_group, framework_id, category_path)
        elif search_type == 'method_signature':
            return self._search_method_signatures(pattern_group, framework_id, category_path)
        elif search_type == 'method_name_regex':
            return self._search_method_names(pattern_group, framework_id, category_path)
        elif search_type == 'class_name_regex':
            return self._search_class_names(pattern_group, framework_id, category_path)
        elif search_type == 'import':
            return self._search_imports(pattern_group, framework_id, category_path)
        else:
            # Unsupported search type
            return []


    def _search_annotations(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """
        Search for annotation patterns using Joern

        Builds query like:
            cpg.annotation.name("PreAuthorize|Secured").method.map(...)
        """
        patterns = pattern_group.pattern
        if not patterns:
            return []

        # Normalize to list
        if isinstance(patterns, str):
            patterns = [patterns]
        elif isinstance(patterns, dict):
            patterns = list(patterns.values())

        # Build Joern query
        pattern_regex = '|'.join(patterns)

        query = f'''
        cpg.annotation
          .name("({pattern_regex})")
          .method
          .map(m => {{
            val annot = m.annotation.name("({pattern_regex})").head
            val annotValue = annot.parameterAssign.headOption.map(_.value).getOrElse("")
            val className = m.typeDecl.headOption.map(_.name).getOrElse("Unknown")
            val httpMethod = m.annotation.name(".*Mapping").headOption.map(_.name.replace("Mapping", "").toUpperCase).getOrElse("UNKNOWN")
            s"${{m.fullName}}|${{className}}|${{m.filename}}|${{m.lineNumber.headOption.getOrElse(0)}}|${{annot.name}}|${{annotValue}}|${{httpMethod}}"
          }})
          .l
        '''

        try:
            results = self.cpg_tool.list_items(query)
            return self._parse_annotation_results(
                results,
                framework_id,
                category_path
            )
        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_TOOL] Error searching annotations: {e}")
            return []


    def _parse_annotation_results(
        self,
        results: List[str],
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Parse Joern annotation query results into Behavior dicts"""
        behaviors = []

        # Determine category from path (last part)
        category = category_path.split('.')[-1]

        for result in results:
            parts = result.split('|')
            if len(parts) < 7:
                continue

            method_full = parts[0]
            class_name = parts[1]
            file_path = parts[2]
            line_num = int(parts[3]) if parts[3].isdigit() else 0
            annot_name = parts[4]
            annot_value = parts[5]
            http_method = parts[6]

            # Determine location and location_type based on available context
            # Check if this is a controller class (endpoint layer)
            is_controller = class_name and (
                'Controller' in class_name or
                'Resource' in class_name or
                'Endpoint' in class_name or
                'Handler' in class_name
            )

            # Determine location_type: endpoint, service, code, or unknown
            if http_method and http_method != 'UNKNOWN':
                location = f"{http_method} {annot_value}"  # Will be refined below
                location_type = "endpoint"
            elif is_controller:
                location = f'{class_name} (line {line_num})'
                location_type = "endpoint"
            elif class_name:
                location = f'{class_name} (line {line_num})'
                location_type = "service"
            elif file_path:
                location = f'{file_path}:{line_num}'
                location_type = "code"
            else:
                location = "unknown"
                location_type = "unknown"

            behavior = {
                'framework': framework_id,
                'category': category,
                'type': f'{category}_annotation',
                'mechanism': annot_name,
                'method': method_full,
                'class': class_name,
                'file': file_path,
                'line': line_num,
                'location': location,
                'location_type': location_type
            }

            # Extract roles from annotation value for authorization
            if category == 'authorization' and annot_value:
                roles = self._extract_roles_from_annotation(annot_value)
                if roles:
                    behavior['roles'] = roles

            # Add HTTP method if available
            if http_method and http_method != 'UNKNOWN':
                behavior['httpMethod'] = http_method

            behaviors.append(behavior)

        return behaviors


    def _extract_roles_from_annotation(self, annot_value: str) -> List[str]:
        """
        Extract roles from annotation value

        Examples:
            "hasRole('ADMIN')" -> ['ADMIN']
            "hasAnyRole('USER', 'ADMIN')" -> ['USER', 'ADMIN']
            "hasAuthority('ROLE_USER')" -> ['USER']
        """
        roles = []

        import re

        # Pattern for single quotes
        matches = re.findall(r"['\"]([A-Z_]+)['\"]", annot_value)
        for match in matches:
            # Strip ROLE_ prefix if present
            role = match.replace('ROLE_', '')
            if role and role not in roles:
                roles.append(role)

        return roles


    def _search_method_signatures(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """
        Search for method signature patterns using Joern

        Builds query like:
            cpg.call.methodFullName("org.springframework.jdbc.core.JdbcTemplate.query.*")
        """
        signatures = pattern_group.signature or pattern_group.pattern
        if not signatures:
            return []

        # Normalize to list
        if isinstance(signatures, str):
            signatures = [signatures]

        # Build Joern query
        sig_regex = '|'.join(signatures)

        query = f'''
        cpg.call
          .methodFullName("({sig_regex})")
          .map(c => {{
            val methodOpt = c.method.headOption
            val className = methodOpt.flatMap(_.typeDecl.headOption).map(_.name).getOrElse("Unknown")
            val callerMethod = methodOpt.map(_.fullName).getOrElse("Unknown")
            s"${{c.code}}|${{c.methodFullName}}|${{className}}|${{callerMethod}}|${{c.filename}}|${{c.lineNumber.headOption.getOrElse(0)}}"
          }})
          .l
        '''

        try:
            results = self.cpg_tool.list_items(query)
            return self._parse_method_signature_results(
                results,
                framework_id,
                category_path
            )
        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_TOOL] Error searching method signatures: {e}")
            return []


    def _parse_method_signature_results(
        self,
        results: List[str],
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Parse Joern method signature query results into Behavior dicts"""
        behaviors = []

        category = category_path.split('.')[-1]

        for result in results:
            parts = result.split('|')
            if len(parts) < 6:
                continue

            code = parts[0]
            method_full = parts[1]
            class_name = parts[2]
            caller_method = parts[3]
            file_path = parts[4]
            line_num = int(parts[5]) if parts[5].isdigit() else 0

            # Determine location_type based on available context
            # Check if this is a controller class (endpoint layer)
            is_controller = class_name and (
                'Controller' in class_name or
                'Resource' in class_name or
                'Endpoint' in class_name or
                'Handler' in class_name
            )

            # Classify location_type: endpoint, service, code, or unknown
            if is_controller:
                location = f'{class_name} (line {line_num})'
                location_type = "endpoint"
            elif class_name:
                location = f'{class_name} (line {line_num})'
                location_type = "service"
            elif file_path:
                location = f'{file_path}:{line_num}'
                location_type = "code"
            else:
                location = "unknown"
                location_type = "unknown"

            behavior = {
                'framework': framework_id,
                'category': category,
                'type': f'{category}_method_call',
                'mechanism': method_full,
                'code': code,
                'method': caller_method,
                'class': class_name,
                'file': file_path,
                'line': line_num,
                'location': location,
                'location_type': location_type
            }

            behaviors.append(behavior)

        return behaviors


    def _search_filename_patterns(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Search for filename patterns (not yet implemented)"""
        return []


    def _search_filecontent_patterns(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Search for file content patterns (not yet implemented)"""
        return []


    def _search_method_names(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Search for method name regex patterns (not yet implemented)"""
        return []


    def _search_class_names(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Search for class name regex patterns (not yet implemented)"""
        return []


    def _search_imports(
        self,
        pattern_group: PatternGroup,
        framework_id: str,
        category_path: str
    ) -> List[Dict[str, Any]]:
        """Search for import patterns (not yet implemented)"""
        return []


    # Convenience methods


    def find_authorization_patterns(
        self,
        frameworks: Union[Dict[str, FrameworkDefinition], FrameworkDefinition]
    ) -> List[Dict[str, Any]]:
        """
        Find all authorization patterns (annotations, method calls, etc.)

        This is a convenience method that searches security.authorization patterns.

        Args:
            frameworks: Dict of frameworks or single FrameworkDefinition

        Returns:
            List of authorization Behavior dicts
        """
        return self.search_patterns(frameworks, 'security.authorization')


    def find_routing_patterns(
        self,
        frameworks: Union[Dict[str, FrameworkDefinition], FrameworkDefinition]
    ) -> List[Dict[str, Any]]:
        """
        Find all routing patterns (handler classes, route definitions, etc.)

        Searches routing.route_definitions patterns.

        Args:
            frameworks: Dict of frameworks or single FrameworkDefinition

        Returns:
            List of routing Behavior dicts
        """
        return self.search_patterns(frameworks, 'routing.route_definitions')


    def find_input_validation_patterns(
        self,
        frameworks: Union[Dict[str, FrameworkDefinition], FrameworkDefinition]
    ) -> List[Dict[str, Any]]:
        """
        Find all input validation patterns

        Searches security.input_validation patterns.

        Args:
            frameworks: Dict of frameworks or single FrameworkDefinition

        Returns:
            List of validation Behavior dicts
        """
        return self.search_patterns(frameworks, 'security.input_validation')


    def find_database_patterns(
        self,
        frameworks: Union[Dict[str, FrameworkDefinition], FrameworkDefinition]
    ) -> List[Dict[str, Any]]:
        """
        Find all database query patterns

        Searches database.sql_queries patterns.

        Args:
            frameworks: Dict of frameworks or single FrameworkDefinition

        Returns:
            List of database Behavior dicts
        """
        return self.search_patterns(frameworks, 'database.sql_queries')


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
