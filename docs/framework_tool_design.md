# FrameworkTool Design Document

## Purpose
FrameworkTool is a centralized tool that encapsulates ALL complexity of searching for framework patterns in a codebase. It acts as a database interface - agents ask questions about what's present in the code, and FrameworkTool handles all the details.

## Design Principles

1. **Encapsulation** - Agents never build Joern queries, parse PatternGroups, or handle search complexity
2. **Centralization** - All pattern searching logic in ONE place
3. **Simplicity** - Agent code should be trivial: "give me auth patterns" → get results
4. **Maintainability** - Change search implementation once, all agents benefit

## Core API

### Initialization
```python
framework_tool = FrameworkTool(project_dir, cpg_tool=None)
# Optional: pass CPG tool to reuse, or tool creates its own
```

### Detection
```python
# Detect which frameworks are present
frameworks = framework_tool.detect_frameworks()
# Returns: Dict[str, FrameworkDefinition]

# Get specific framework
spring_security = framework_tool.get_framework('spring-security')
```

### Pattern Searching (Main API)

#### Generic Search
```python
# Search any architecture category path
behaviors = framework_tool.search_patterns(
    frameworks=frameworks,  # Dict[str, FrameworkDefinition] or single FrameworkDefinition
    category_path='security.authorization',  # Path like 'routing.route_definitions'
    filter_fn=None  # Optional: lambda pattern: pattern.search_type == 'annotation_name'
)

# Returns: List[Behavior]
# Behavior = {
#     'type': 'authorization_annotation',  # Derived from category
#     'mechanism': 'PreAuthorize',  # Pattern that matched
#     'method': 'full.method.signature',
#     'class': 'ClassName',
#     'file': 'path/to/file.java',
#     'line': 42,
#     'framework': 'spring-security',
#     'roles': ['ADMIN', 'USER'],  # Extracted from annotation value if applicable
#     'location': 'ClassName (line 42)',
#     'location_type': 'method'  # or 'class', 'file'
# }
```

#### Specialized Convenience Methods
```python
# Authorization patterns
auth_behaviors = framework_tool.find_authorization_patterns(frameworks)

# Routing patterns (handler classes, route definitions)
routing_behaviors = framework_tool.find_routing_patterns(frameworks)

# Input validation patterns
validation_behaviors = framework_tool.find_input_validation_patterns(frameworks)

# Output encoding patterns
encoding_behaviors = framework_tool.find_output_encoding_patterns(frameworks)

# Database query patterns
db_behaviors = framework_tool.find_database_patterns(frameworks)

# Command execution patterns
exec_behaviors = framework_tool.find_execution_patterns(frameworks)

# HTTP communication patterns
http_behaviors = framework_tool.find_http_patterns(frameworks)

# Serialization patterns
serialization_behaviors = framework_tool.find_serialization_patterns(frameworks)
```

### Pattern Analysis

```python
# Count patterns by type
counts = framework_tool.count_patterns_by_type(behaviors)
# Returns: {'annotation': 45, 'method_call': 23, ...}

# Group by framework
by_framework = framework_tool.group_by_framework(behaviors)
# Returns: {'spring-security': [...], 'hibernate': [...]}

# Filter behaviors
filtered = framework_tool.filter_behaviors(
    behaviors,
    lambda b: b.get('location_type') == 'method'
)
```

## Implementation Details

### PatternGroup Processing

The tool must handle ALL PatternGroup types:

**Search Types:**
- `annotation_name` → Joern: `cpg.annotation.name("pattern").method`
- `annotation_name_regex` → Joern: `cpg.annotation.name("regex").method`
- `method_signature` → Joern: `cpg.call.methodFullName("signature")`
- `method_name_regex` → Joern: `cpg.call.name("regex")`
- `class_name_regex` → Joern: `cpg.typeDecl.name("regex")`
- `import` → Joern: `cpg.imports.importedEntity("pattern")`
- `regex` → File search or Joern depending on target
- `xml_element` → XML parsing via file_tool
- `xpath` → XPath queries via file_tool
- `yaml_path` → YAML parsing
- `json_value` → JSON parsing

**Search Targets:**
- `joern` → Use CpgTool
- `filename` → Use file_tool.list_files() + pattern matching
- `filecontent` → Use file_tool.read_file() + parsing

### Internal Architecture

```
FrameworkTool
├── __init__(project_dir, cpg_tool)
├── _cpg_tool: CpgTool
├── _file_tool: FileTool
├── available_frameworks: Dict[str, FrameworkDefinition]
│
├── detect_frameworks() → Dict[str, FrameworkDefinition]
│   └── Uses dependency/file detection
│
├── search_patterns(frameworks, category_path, filter_fn) → List[Behavior]
│   ├── _extract_patterns_from_path(frameworks, category_path)
│   ├── _execute_pattern_search(pattern_group)
│   │   ├── _search_joern_patterns(pattern_group)
│   │   │   ├── _build_annotation_query(pattern)
│   │   │   ├── _build_method_signature_query(pattern)
│   │   │   ├── _build_method_name_query(pattern)
│   │   │   ├── _build_class_name_query(pattern)
│   │   │   └── _build_import_query(pattern)
│   │   ├── _search_file_patterns(pattern_group)
│   │   └── _search_filecontent_patterns(pattern_group)
│   └── _parse_results_to_behaviors(results, pattern_group, framework)
│
├── find_authorization_patterns(frameworks) → List[Behavior]
│   └── search_patterns(frameworks, 'security.authorization')
│
├── find_routing_patterns(frameworks) → List[Behavior]
│   └── search_patterns(frameworks, 'routing.route_definitions')
│
└── find_input_validation_patterns(frameworks) → List[Behavior]
    └── search_patterns(frameworks, 'security.input_validation')
```

### Query Building Logic

```python
def _build_joern_query(pattern_group: PatternGroup) -> str:
    """Build Joern query from PatternGroup"""

    if pattern_group.search_type == 'annotation_name':
        # Handle both single pattern and list
        patterns = pattern_group.pattern if isinstance(pattern_group.pattern, list) else [pattern_group.pattern]

        return f'''
        cpg.annotation
          .name("({'|'.join(patterns)})")
          .method
          .map(m => {{
            val annot = m.annotation.name("({'|'.join(patterns)})").head
            val annotValue = annot.parameterAssign.headOption.map(_.value).getOrElse("")
            s"${{m.fullName}}|${{m.typeDecl.head.name}}|${{m.filename}}|${{m.lineNumber.head}}|${{annotValue}}"
          }})
          .l
        '''

    elif pattern_group.search_type == 'method_signature':
        signatures = pattern_group.signature if isinstance(pattern_group.signature, list) else [pattern_group.signature]

        return f'''
        cpg.call
          .methodFullName("({'|'.join(signatures)})")
          .map(c => {{
            val methodOpt = c.method.headOption
            val callerMethodOpt = c.method.headOption
            s"${{c.code}}|${{c.methodFullName}}|${{c.filename}}|${{c.lineNumber.head}}"
          }})
          .l
        '''
```

### Behavior Extraction Logic

```python
def _parse_joern_result_to_behavior(result: str, pattern: str, framework_id: str, category: str) -> Dict:
    """Parse Joern query result into standardized Behavior dict"""

    parts = result.split('|')

    behavior = {
        'framework': framework_id,
        'category': category,
        'mechanism': pattern,
        'type': f'{category}_annotation',  # or method_call, import, etc.
    }

    if category == 'authorization' and len(parts) >= 5:
        # Parse annotation value for roles
        annot_value = parts[4]
        roles = extract_roles_from_annotation(annot_value)
        behavior['roles'] = roles

    # Extract location info
    behavior.update({
        'method': parts[0],
        'class': parts[1],
        'file': parts[2],
        'line': int(parts[3]),
        'location': f"{parts[1]} (line {parts[3]})",
        'location_type': 'method'
    })

    return behavior
```

## Migration Path

### Phase 1: Create FrameworkTool (rename + add search methods)
1. Rename `framework_detector.py` → `framework_tool.py`
2. Rename class `FrameworkDetector` → `FrameworkTool`
3. Add `search_patterns()` core method
4. Add specialized convenience methods
5. Keep all existing detection logic

### Phase 2: Migrate authorization_utils.py
1. Update to use `framework_tool.find_authorization_patterns()`
2. Remove pattern searching logic from agent
3. Test thoroughly

### Phase 3: Create additional agents
1. Input validation agent uses `find_input_validation_patterns()`
2. Injection defense agent uses `find_database_patterns()`, `find_execution_patterns()`
3. Each new agent just calls appropriate tool methods

### Phase 4: Handle all pattern types
1. Implement all search_type handlers (xml_element, xpath, yaml_path, etc.)
2. Add tests for each pattern type
3. Document pattern coverage

## Benefits

1. **Agent Simplicity** - Agent code becomes 5-10 lines instead of 100+
2. **Consistency** - All agents search patterns the same way
3. **Testability** - Test pattern searching once, thoroughly
4. **Maintainability** - Fix bugs once, all agents benefit
5. **Extensibility** - Add new pattern types without touching agents
6. **Performance** - Can optimize/cache at tool level

## Example Agent Code

### Before (Current Authorization Agent)
```python
# Agent must know:
# - How to access framework.architecture.security.authorization
# - How PatternGroup works
# - How to build Joern queries
# - How to parse results
# - How to extract roles from annotations
# ~200 lines of complex logic

for framework_name, framework in matched_frameworks.items():
    if not framework.architecture or not framework.architecture.security:
        continue

    auth_patterns = framework.architecture.security.authorization or []

    for pattern_group in auth_patterns:
        if pattern_group.search_type == 'annotation_name':
            patterns = pattern_group.pattern
            # Build query...
            # Execute query...
            # Parse results...
```

### After (With FrameworkTool)
```python
# Agent just asks for what it needs - ~10 lines

framework_tool = FrameworkTool(project_dir, cpg_tool)
frameworks = framework_tool.detect_frameworks()

# Get all authorization behaviors
auth_behaviors = framework_tool.find_authorization_patterns(frameworks)

# Use the results
for behavior in auth_behaviors:
    print(f"Found {behavior['mechanism']} at {behavior['location']}")
```

## Open Questions

1. **Caching** - Should tool cache CPG/framework detection results?
2. **Async** - Should searches be async for performance?
3. **Filtering** - How much filtering logic in tool vs agents?
4. **Custom patterns** - Should agents be able to define custom search patterns?

## Next Steps

1. Create `framework_tool.py` from `framework_detector.py`
2. Implement `search_patterns()` core method
3. Implement Joern query builders for main pattern types
4. Add convenience methods for common searches
5. Write comprehensive tests
6. Migrate authorization agent
7. Document API
