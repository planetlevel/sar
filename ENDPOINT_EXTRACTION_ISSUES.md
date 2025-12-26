# Endpoint Extraction Issues - Fixed

## Status: ✅ COMPLETE - All Critical Issues Resolved

The endpoint-centric refactoring now correctly extracts endpoints with proper paths, handlers, and HTTP methods.

**Resolution Summary:**
- Issues 1-6: ✅ Fixed and committed (2ff2626)
- Issue 7: ✅ Not a bug - HttpSecurity correctly NOT represented as route_guard (uses permitAll)
- Issue 8: ⚠️ Optimization opportunity documented - acceptable for now

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

### 7. HttpSecurity Representation (NOT A BUG)
**Investigation Result:** Spring PetClinic's SecurityConfig.configure(HttpSecurity) uses `.anyRequest().permitAll()` - meaning there is NO HTTP-layer authorization. Everything is permitted at the route level, with authorization entirely at method level via @PreAuthorize.

**Current Behavior:** HttpSecurity detected as "code" behavior, not applied as route_guard
**Why Correct:** It shouldn't be represented as a route_guard because it doesn't guard anything (permitAll)
**Status:** ✅ Working as designed

### 8. Duplication: Mechanisms vs Endpoints (OPTIMIZATION OPPORTUNITY)
**Problem:** Evidence section contains both `mechanisms` and `endpoints`, with significant overlap
**Impact:** Increased token usage (~420 lines mechanisms + ~282 lines endpoints), harder to maintain

**Analysis:**
- `mechanisms`: Raw discovery evidence, detailed behaviors, framework patterns (used by report_utils.build_defense_metadata)
- `endpoints`: Clean user-facing view of "what protects each endpoint" (used by show_acm.py visualization)

**Current Status:** ⚠️ Acceptable duplication serving different purposes
- mechanisms = debugging/verification evidence
- endpoints = user presentation layer

**Future Optimization:** Could reduce by ~30% by:
1. Moving detailed behaviors to separate `evidence.observations` section
2. Having endpoints reference behaviors by ID rather than duplicating
3. Keeping only summary metadata in mechanisms

**Priority:** Low - works correctly, optimization can wait for token budget constraints
