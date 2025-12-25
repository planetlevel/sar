# Endpoint Extraction Issues - Critical Fixes Needed

## Status: BROKEN - Do Not Use in Production

The endpoint-centric refactoring has fundamental extraction bugs that make the reports unusable.

## Critical Issues

### 1. Empty Route Paths (CRITICAL)
**Problem:** Joern query returns `route: ""` for all endpoints
**Root Cause:** Lines 334-337 in `authorization_utils.py` - the parameter extraction logic fails
**Current Code:**
```scala
val route = ann.parameter.assignment
  .where(_.argument(1).code("value|path"))
  .argument(2).code.headOption.getOrElse("")
  .replaceAll("^\\\"|\\\"$", "")
```

**What's Happening:**
- Spring uses `@RequestMapping(value = "/owners/new")` format
- Query looks for parameter assignments but doesn't traverse AST correctly
- Returns empty string instead of "/owners/new"

**Fix Needed:**
```scala
val route = ann.parameter.name("value")
  .argument.code.headOption
  .orElse(ann.parameter.name("path").argument.code.headOption)
  .getOrElse("")
  .replaceAll("^\\\"|\\\"$", "")
```

### 2. Malformed Handler Names (CRITICAL)
**Problem:** Handler shows "util.Map)" instead of "OwnerController.initCreationForm"
**Root Cause:** `_format_handler()` in `endpoint_builder.py` incorrectly parses signatures
**Example Input:**
```
org.springframework.samples.petclinic.owner.OwnerController.initCreationForm:java.lang.String(java.util.Map)
```

**Current Logic:** Splits on `.` and takes last 2 parts → gets "Map)" from parameter list

**Fix Needed:**
```python
def _format_handler(self, method_sig: str) -> str:
    # Format: package.Class.method:returnType(params)
    # Split on colon to separate method from signature
    if ':' in method_sig:
        method_part = method_sig.split(':')[0]
    else:
        method_part = method_sig

    # Remove parameter list if present
    if '(' in method_part:
        method_part = method_part.split('(')[0]

    # Get ClassName.methodName
    parts = method_part.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return method_sig
```

### 3. Non-Unique Endpoint IDs (CRITICAL)
**Problem:** All endpoints have ID like "GET_" or "POST_" (not unique)
**Root Cause:** Empty path means `f"{method}_{path}"` becomes `f"GET_"`
**Fix Needed:** Use handler as fallback when path is empty:
```python
if route_path:
    endpoint_id = f"{http_method}_{route_path}"
else:
    # Fallback: use handler hash when path unavailable
    import hashlib
    handler_hash = hashlib.md5(handler.encode()).hexdigest()[:8]
    endpoint_id = f"{http_method}_{handler}_{handler_hash}"
```

### 4. Wrong HTTP Verbs (HIGH)
**Problem:** `processCreationForm` (POST handler) shows as GET
**Root Cause:** Not merging class + method level @RequestMapping
**Fix Needed:** Query must check method-level `method = RequestMethod.POST` parameter

### 5. Missing Class-Level @RequestMapping Prefix
**Problem:** Class-level `@RequestMapping("/owners")` not merged with method `@RequestMapping("/new")`
**Expected:** `/owners/new`
**Actual:** `/new` (or empty)
**Fix Needed:** Query class annotations and prepend to method routes

## Impact

- ❌ Reports are unusable (can't identify which endpoint is which)
- ❌ Domain inference fails (LLM sees no context, invents e-commerce roles for petclinic)
- ❌ Coverage calculations meaningless (can't match behaviors to endpoints)
- ❌ Developers can't action recommendations (no way to know which code to fix)

## Fix Priority

1. **CRITICAL:** Fix Joern query to extract route paths correctly
2. **CRITICAL:** Fix handler name parsing to show ClassName.methodName
3. **CRITICAL:** Generate unique IDs (use handler hash as fallback)
4. **HIGH:** Merge class + method level @RequestMapping
5. **HIGH:** Extract method parameter from RequestMethod.POST correctly

## Testing Checklist

After fixes, verify Spring PetClinic report shows:
- ✅ All 17 endpoints have unique IDs
- ✅ Paths like `/owners/new`, `/owners/{ownerId}`, `/vets`
- ✅ Handlers like `OwnerController.initCreationForm`, `OwnerController.processCreationForm`
- ✅ Correct HTTP verbs (GET/POST match actual annotations)
- ✅ Domain inference proposes VET/OWNER/RECEPTIONIST (not CUSTOMER/VENDOR/WAREHOUSE)

## Related Issues

- Schema drift: `authorization.rule` should be `description`
- HttpSecurity not represented as route_guard
- Duplication: mechanisms vs endpoints
- Null/empty conventions inconsistent
