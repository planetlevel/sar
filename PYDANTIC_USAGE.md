# Using Pydantic Framework Schema

## Benefits

1. **Type Safety** - IDE autocomplete and type checking:
   ```python
   framework = load_framework("frameworks/spring-security.json")
   # IDE knows framework.architecture.security.authorization is List[PatternGroup]
   # Autocomplete works!
   for pattern in framework.architecture.security.authorization:
       print(pattern.target)  # IDE knows this field exists
       print(pattern.pattern)  # Type-checked!
   ```

2. **Automatic Validation** - Catches errors early:
   ```python
   # This will raise ValidationError if file is invalid
   framework = load_framework("frameworks/myframework.json")
   ```

3. **Easy Refactoring** - Change model, find all code that breaks:
   ```python
   # If you rename 'authorization' to 'auth' in Pydantic model:
   # - All code accessing .authorization will show type errors
   # - IDE will highlight every place that needs updating
   # - No need to grep/search - compiler tells you!
   ```

4. **Documentation** - Models serve as living documentation
   ```python
   class PatternGroup(BaseModel):
       target: Literal["filename", "filecontent", "joern"]  # Clear what values are allowed
       search_type: Literal["annotation_name", "method_signature", ...]  # All valid types listed
   ```

## Usage Examples

### Load and Validate a Framework

```python
from framework_schema import load_framework, FrameworkDefinition

try:
    framework = load_framework("frameworks/spring-security.json")
    print(f"Loaded: {framework.name}")
except ValidationError as e:
    print(f"Invalid framework file: {e}")
```

### Access with Type Safety

```python
# Old way (no type safety)
auth_patterns = framework_config.get('architecture', {}).get('security', {}).get('authorization', [])
if isinstance(auth_patterns, list):  # Need runtime check
    for pattern in auth_patterns:
        target = pattern.get('target')  # No autocomplete
        ...

# New way (with Pydantic)
if framework.architecture and framework.architecture.security:
    for pattern in framework.architecture.security.authorization:
        # IDE autocomplete works!
        # Type checker knows 'target' exists
        # Runtime guaranteed to be valid
        if pattern.target == "joern":
            print(f"Search type: {pattern.search_type}")
```

### Update Existing Code

Before (in authorization_utils.py):
```python
def extract_authorization_patterns(self, framework_config: Dict) -> List[Dict]:
    try:
        security = framework_config.get('architecture', {}).get('security', {})
        authorization = security.get('authorization', [])
        return authorization if isinstance(authorization, list) else []
    except (KeyError, AttributeError):
        return []
```

After (with Pydantic):
```python
from framework_schema import FrameworkDefinition

def extract_authorization_patterns(self, framework: FrameworkDefinition) -> List[PatternGroup]:
    """Now type-safe! IDE knows return type is List[PatternGroup]"""
    if framework.architecture and framework.architecture.security:
        return framework.architecture.security.authorization or []
    return []
```

### When Making Schema Changes

1. **Update Pydantic model** in `framework_schema.py`:
   ```python
   class PatternGroup(BaseModel):
       target: str  # Change from Literal to allow any string
   ```

2. **Run validation** to see what breaks:
   ```bash
   python3 framework_schema.py validate
   ```

3. **IDE highlights errors** - shows all code accessing the changed fields

4. **Update code** with confidence - type checker guides you

5. **Regenerate JSON schema** if needed:
   ```bash
   python3 framework_schema.py generate-schema
   ```

## Validation Commands

```bash
# Validate single file
python3 framework_schema.py frameworks/spring-security.json

# Validate all frameworks
python3 framework_schema.py validate

# Generate JSON schema from Pydantic models
python3 framework_schema.py generate-schema
```

## Integration with Existing Code

### Load Frameworks with Validation

Replace:
```python
def load_matching_frameworks(self, libraries: List[str]) -> Dict[str, Dict]:
    frameworks = {}
    for framework_file in Path('frameworks').glob('*.json'):
        with open(framework_file) as f:
            frameworks[name] = json.load(f)  # No validation!
    return frameworks
```

With:
```python
from framework_schema import load_all_frameworks, FrameworkDefinition

def load_matching_frameworks(self, libraries: List[str]) -> Dict[str, FrameworkDefinition]:
    return load_all_frameworks()  # Validated! Type-safe!
```

### Query Patterns Type-Safely

Replace:
```python
def execute_pattern_queries(self, framework: str, category: str, config: Dict) -> List[Dict]:
    target = config.get('target')
    search_type = config.get('search_type')
    pattern = config.get('pattern', [])
    # ... lots of get() calls and type checks
```

With:
```python
from framework_schema import PatternGroup

def execute_pattern_queries(self, framework: str, category: str, pattern: PatternGroup) -> List[Dict]:
    # No get() needed - fields guaranteed to exist (or None)
    # IDE autocomplete works!
    if pattern.target == "joern" and pattern.search_type == "annotation_name":
        patterns = pattern.pattern if isinstance(pattern.pattern, list) else [pattern.pattern]
        return self.query_authorization_annotations(patterns)
    ...
```

## When Schema and Files Get Out of Sync

Pydantic will immediately tell you:

```python
>>> framework = load_framework("frameworks/broken.json")
ValidationError: 2 validation errors for FrameworkDefinition
architecture.security.authorization.0.target
  Field required [type=missing, ...]
architecture.security.authorization.0.search_type
  Input should be 'annotation_name', 'method_signature', ... [type=literal_error, ...]
```

This is much better than:
- Runtime errors deep in your code
- Silent failures (accessing non-existent keys)
- Type confusion bugs

## Pro Tips

1. **Use validation in CI**:
   ```bash
   python3 framework_schema.py validate || exit 1
   ```

2. **Type hint everything**:
   ```python
   def process_framework(fw: FrameworkDefinition) -> None:
       # Now IDE and mypy can help you
   ```

3. **Generate schema automatically**:
   ```bash
   # After updating Pydantic models:
   python3 framework_schema.py generate-schema
   git diff schema/framework-schema.json  # See what changed
   ```

4. **Catch issues early**:
   ```python
   # Load frameworks at startup
   frameworks = load_all_frameworks()  # Validates ALL files
   # If any are broken, you know immediately
   ```
