#!/usr/bin/env python3
"""
Pattern searching methods for FrameworkTool

These will be integrated into FrameworkTool to provide centralized
pattern searching capabilities.
"""

from typing import Dict, List, Optional, Any, Union
from sar.framework_schema import FrameworkDefinition, PatternGroup


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

        behavior = {
            'framework': framework_id,
            'category': category,
            'type': f'{category}_annotation',
            'mechanism': annot_name,
            'method': method_full,
            'class': class_name,
            'file': file_path,
            'line': line_num,
            'location': f'{class_name} (line {line_num})',
            'location_type': 'method'
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
            'location': f'{class_name} (line {line_num})',
            'location_type': 'method'
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
