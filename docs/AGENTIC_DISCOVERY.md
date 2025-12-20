# Agentic Authorization Discovery

## Philosophy

Instead of single-shot AI prompts, we use an **agentic exploration** approach where the AI:
- Has access to **tools** (Joern queries, file reads, grep)
- Formulates and tests **hypotheses** iteratively
- **Refines** understanding based on results
- **Decides** when confident it has found all mechanisms

This is a multi-turn conversation where the AI drives the investigation.

---

## Implementation Architecture

### Tool System

The AI agent has **direct access** to investigate:
- **Architecture report** (pre-analyzed data)
- **Joern CPG** (AI writes its own queries)
- **Filesystem** (AI reads source files directly)

**Philosophy:** Give AI the raw tools to pursue truth, not pre-digested summaries.

```python
class AgenticDiscoveryTools:
    """Tools available to AI agent during investigation"""

    # ==========================================
    # PRIMARY TOOLS - AI should use these first
    # ==========================================

    def joern_query(self, query: str) -> Dict:
        """
        Execute ANY Joern CPG query the AI writes

        The AI writes Scala queries to probe the CPG directly.
        Examples:
        - cpg.annotation.name.dedup.l
        - cpg.method.where(_.annotation.name("Superadmin")).fullName.l
        - cpg.typeDecl.name(".*Controller").annotation.name.l

        Returns: {'success': bool, 'data': [...], 'count': int}
        """
        result = self.cpg_tool.query(query)
        return {
            'success': result.success,
            'data': result.data[:100],  # Limit but show count
            'count': len(result.data),
            'query': query
        }

    def read_file(self, file_path: str, start_line: int = 1, end_line: Optional[int] = None) -> Dict:
        """
        Read source file directly from filesystem

        AI can read any file in the project directory.
        Use this to examine:
        - Annotation definitions
        - Controller implementations
        - Security configuration files
        - Custom authorization classes

        Returns: {'success': bool, 'content': str, 'path': str, 'lines': int}
        """
        try:
            full_path = os.path.join(self.project_dir, file_path)
            with open(full_path, 'r') as f:
                lines = f.readlines()

            if end_line is None:
                end_line = len(lines)

            content = ''.join(lines[start_line-1:end_line])

            return {
                'success': True,
                'content': content,
                'path': file_path,
                'lines': len(lines),
                'showing': f"{start_line}-{end_line}"
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_architecture_report(self) -> Dict:
        """
        Get the pre-analyzed architecture report

        Contains:
        - All endpoints discovered by Compass
        - Behaviors found (security operations, database ops, etc.)
        - Controllers and routes
        - Framework information
        - Package hierarchy

        Use this as STARTING POINT, then dig deeper with Joern/files.

        Returns: Full architecture report JSON
        """
        return self.architecture_report

    # ==========================================
    # CONVENIENCE TOOLS - Wrappers around primary tools
    # ==========================================

    def grep_code(self, pattern: str, file_pattern: str = "*.java", path: str = ".") -> Dict:
        """
        Search codebase for regex pattern

        Returns: {'matches': [{'file': '...', 'line': 123, 'content': '...'}], 'count': int}
        """
        # Implementation using ripgrep or grep

    def list_files(self, pattern: str = "*", directory: str = ".") -> List[str]:
        """
        List files matching pattern in directory

        Examples:
        - list_files("*.java", "src/main/java")
        - list_files("*Controller.java")
        - list_files("*Security*.java")
        """
        # Implementation

    def find_class_definition(self, class_name: str) -> Optional[Dict]:
        """
        Find source file for a class

        Returns: {'file': 'path/to/File.java', 'line': 42}
        """
        # Uses Joern to find class, returns file location
```

### Agent Loop

```python
def discover_with_agent(self, investigation_type: str) -> Dict[str, Any]:
    """
    Multi-turn agentic discovery

    investigation_type: 'custom_auth' | 'admin_auth'
    """

    # Initialize conversation context
    context = {
        'type': investigation_type,
        'framework': self.framework,
        'endpoints': len(self.endpoints),
        'standard_coverage': self.standard_coverage,
        'tools': AgenticDiscoveryTools(self.cpg_tool, self.project_dir, self.endpoints),
        'messages': [],
        'discovered_patterns': [],
        'confidence': 0.0
    }

    # System prompt explaining the investigation task
    system_prompt = self._build_system_prompt(investigation_type)
    context['messages'].append({"role": "system", "content": system_prompt})

    # Initial user message to start investigation
    initial_message = self._build_initial_message(context)
    context['messages'].append({"role": "user", "content": initial_message})

    # Investigation loop (max 10 turns)
    for turn in range(10):
        if self.debug:
            print(f"\n[AGENT] Turn {turn + 1}")

        # AI responds with tool calls or final answer
        response = self._call_agent(context['messages'])

        # Process response
        if response['type'] == 'tool_calls':
            # AI wants to use tools - execute them
            tool_results = self._execute_tool_calls(response['tool_calls'], context['tools'])

            # Add results to conversation
            context['messages'].append({"role": "assistant", "content": response['content'], "tool_calls": response['tool_calls']})
            context['messages'].append({"role": "user", "content": tool_results})

        elif response['type'] == 'final_answer':
            # AI is done investigating
            context['discovered_patterns'] = response['patterns']
            context['confidence'] = response['confidence']
            break

    return {
        'patterns': context['discovered_patterns'],
        'confidence': context['confidence'],
        'turns': turn + 1,
        'investigation_type': investigation_type
    }
```

---

## System Prompts

### Custom Authorization Investigation

```python
def _build_system_prompt_custom_auth(self) -> str:
    return """
You are a security analyst investigating CUSTOM AUTHORIZATION MECHANISMS in a codebase.

**Your Goal:**
Find authorization mechanisms that are NOT in the framework definitions (frameworks/*.json).
These could protect ANY endpoints with ANY roles (USER, MANAGER, ADMIN, etc.).

**Pattern Categories (examples only - be creative!):**
1. **Custom Annotations:** App-specific annotations for authorization
   - Could be named anything: @RequiresPermission, @CheckAccess, @Authorized, etc.
2. **Meta-Annotations:** Custom annotations wrapping framework patterns
   - Could wrap any standard pattern: @Superadmin → @PreAuthorize("isSuperadmin()")
3. **Custom Methods:** Authorization check methods called in code
   - Could be named anything: authService.checkAccess(), hasPermission(), validate(), etc.
4. **Interceptors/Filters:** AOP aspects, servlet filters, middleware doing authorization
   - Could be named anything: PermissionCheckInterceptor, AuthFilter, SecurityAspect, etc.

**IMPORTANT:** These are illustrative examples. Don't search only for these specific names.
Use your investigative skills to discover what THIS application actually uses.

**Available Tools:**

**PRIMARY TOOLS (use these for investigation):**
- `get_architecture_report()` - Start here: pre-analyzed endpoints, behaviors, controllers
- `joern_query(query)` - Write ANY Joern Scala query to probe the CPG
- `read_file(path, start_line, end_line)` - Read ANY source file directly
- `grep_code(pattern, file_pattern)` - Search codebase with regex
- `list_files(pattern, directory)` - Find files matching pattern

**CONVENIENCE TOOLS (optional helpers):**
- `find_class_definition(class_name)` - Locate source file for class

**Investigation Strategy:**
1. **Start with Architecture Report:** Review pre-analyzed data (endpoints, behaviors)
2. **Form Hypotheses:** Based on report + your security knowledge
3. **Write Joern Queries:** Probe CPG to test hypotheses
4. **Read Source Files:** Examine actual code when needed
5. **Refine Understanding:** Iterate based on findings
6. **Conclude:** When confident (>= 0.9), return patterns

**IMPORTANT:**
- You write your own Joern queries - be creative!
- Read source files when Joern results are unclear
- Use architecture report as starting point, not gospel
- Pursue truth through direct investigation

**Output Format:**
When done investigating, return:
{{
  "type": "final_answer",
  "confidence": 0.0-1.0,  // How confident you are
  "patterns": [
    {{
      "pattern_type": "custom_annotation|meta_annotation|custom_method|interceptor",
      "pattern_name": "Name (@Superadmin, AuthService.checkAccess, etc.)",
      "description": "What it does",
      "evidence": "Joern queries or file references that prove it exists",
      "usage_count": "Approximate number of usages",
      "applies_to": "all_endpoints|specific_controllers|specific_routes"
    }}
  ]
}}

**Important:**
- Be thorough - probe multiple angles
- Validate hypotheses with queries before concluding
- Don't focus only on admin - these mechanisms work for ANY roles
- Stop when confident (>= 0.9) or after exhausting investigation paths
"""
```

### Admin Authorization Investigation

```python
def _build_system_prompt_admin_auth(self) -> str:
    return """
You are a security analyst investigating ADMIN AUTHORIZATION ISOLATION in a codebase.

**Your Goal:**
Find authorization mechanisms that SPECIFICALLY protect administrative functions
and keep them SEPARATE from normal user authorization.

**What makes this different:**
This isn't just "authorization that protects admin routes."
This is about **isolation as a defense strategy** - admin functions use DIFFERENT
authorization than normal user functions to prevent privilege escalation.

**What you're looking for:**
1. **Separate Admin Mechanisms:** Different auth for admin vs normal users
   - Example: Admin portal uses OAuth2, normal app uses JWT
2. **Separate Admin Roles:** Admin roles checked independently
   - Example: SUPERADMIN role with separate validation logic
3. **Admin Annotations Different:** Admin-specific annotations
   - Example: @AdminOnly separate from @Authenticated
4. **Admin Route Isolation:** /admin/* routes with different protection
   - Example: Admin routes require 2FA, normal routes don't

**Key Questions to Answer:**
- Do admin routes use DIFFERENT authorization than normal routes?
- Are admin roles checked SEPARATELY from USER/MANAGER roles?
- Is there a clear SECURITY BOUNDARY between admin and user functions?

**Available Tools:**
[Same as custom auth investigation]

**Investigation Strategy:**
1. **Identify Admin Routes:** Find controllers/routes that are admin
2. **Identify Normal Routes:** Find controllers/routes that are normal user
3. **Compare:** Look for DIFFERENCES in authorization approach
4. **Validate:** Confirm the separation is intentional and consistent

**Output Format:**
When done investigating, return:
{{
  "type": "final_answer",
  "confidence": 0.0-1.0,
  "patterns": [
    {{
      "pattern_type": "admin_annotation|admin_role|admin_method|admin_portal",
      "pattern_name": "Name of admin-specific pattern",
      "description": "How admin authorization is separated",
      "isolation_strategy": "separate_mechanism|separate_roles|separate_portal|separate_checks",
      "evidence": "Proof this isolation exists",
      "admin_routes_count": "Number of admin routes using this"
    }}
  ],
  "isolation_exists": true|false  // Is there real admin isolation?
}}

**Important:**
- Look for DIFFERENCES between admin and normal authorization
- If admin routes use the same mechanism as normal routes, that's NOT isolation
- Admin roles (ADMIN, SUPERADMIN) alone aren't isolation unless checked separately
"""
```

---

## Initial Investigation Messages

### Custom Authorization

```python
def _build_initial_message_custom_auth(self, context: Dict) -> str:
    # Build framework context to share with AI
    frameworks_checked = context.get('framework_context', {}).get('frameworks_checked', [])
    frameworks_matched = context.get('framework_context', {}).get('frameworks_matched', [])
    standard_patterns = context.get('framework_context', {}).get('standard_patterns', [])

    framework_info = ""
    if frameworks_matched:
        framework_info = f"""
**Standard Frameworks Found:**
- Matched frameworks: {', '.join(frameworks_matched)}
- Standard patterns found: {', '.join(standard_patterns[:10])}
"""
    else:
        framework_info = f"""
**Standard Frameworks:**
- Checked {len(frameworks_checked)} framework definitions
- No standard authorization patterns matched
- Application may use completely custom authorization
"""

    return f"""
I need you to investigate custom authorization mechanisms in this application.

**Context:**
- Total endpoints: {context['endpoints']}
- Standard framework coverage: {context['standard_coverage']}%
{framework_info}

**The Problem:**
Standard framework patterns show only {context['standard_coverage']}% coverage.
This suggests custom authorization mechanisms exist.

**Your Mission:**
Find ALL authorization mechanisms not in frameworks/*.json. These could protect any endpoints
with any roles. Be thorough - probe multiple angles until confident.

**Remember:**
- You have access to the architecture report (starting point)
- You can write your own Joern queries to probe the CPG
- You can read source files directly when needed
- Standard frameworks checked: {', '.join(frameworks_checked[:5])}

**Start your investigation:**
What's your first step? What tools do you want to use to survey the codebase?
"""
```

### Admin Authorization

```python
def _build_initial_message_admin_auth(self, context: Dict) -> str:
    admin_routes = len([ep for ep in context['tools'].endpoints if context['tools']._is_admin_route(ep)])

    return f"""
I need you to investigate whether this application uses ADMIN AUTHORIZATION ISOLATION.

**Context:**
- Total endpoints: {context['endpoints']}
- Admin routes detected: {admin_routes}
- Framework: {context['framework']}

**The Question:**
Does this application separate admin authorization from normal user authorization as a defense strategy?

**What to Look For:**
- Do admin routes use DIFFERENT authorization than normal routes?
- Are admin roles checked SEPARATELY?
- Is there a security boundary preventing privilege escalation?

**Start your investigation:**
Begin by comparing admin routes to normal routes. What tools do you need?
"""
```

---

## Tool Execution

```python
def _execute_tool_calls(self, tool_calls: List[Dict], tools: AgenticDiscoveryTools) -> str:
    """Execute tools requested by AI and format results"""

    results = []

    for tool_call in tool_calls:
        tool_name = tool_call['name']
        arguments = tool_call['arguments']

        try:
            if tool_name == 'joern_query':
                result = tools.joern_query(arguments['query'])
                results.append({
                    'tool': tool_name,
                    'query': arguments['query'],
                    'result': result[:50],  # Limit results
                    'total_count': len(result)
                })

            elif tool_name == 'read_file':
                content = tools.read_file(arguments['path'], arguments.get('lines', 50))
                results.append({
                    'tool': tool_name,
                    'path': arguments['path'],
                    'content': content
                })

            elif tool_name == 'grep_code':
                matches = tools.grep_code(arguments['pattern'], arguments.get('file_pattern', '*.java'))
                results.append({
                    'tool': tool_name,
                    'pattern': arguments['pattern'],
                    'matches': matches[:20],  # Limit results
                    'total_matches': len(matches)
                })

            elif tool_name == 'list_annotations':
                annotations = tools.list_annotations()
                results.append({
                    'tool': tool_name,
                    'annotations': annotations
                })

            # ... other tools

        except Exception as e:
            results.append({
                'tool': tool_name,
                'error': str(e)
            })

    return json.dumps({'tool_results': results}, indent=2)
```

---

## Example Investigation Sessions

### Example 1: Discovering Meta-Annotations (Teamserver)

**Turn 1: Review Architecture Report**
```
AI: Let me start by examining the architecture report
Tool: get_architecture_report()
Result: {
  'endpoints': 1215,
  'security_operations': {
    'defense_auth': 8 behaviors,  // Only 8 out of 1215 = 0.66%!
    ...
  }
}

AI: Only 0.66% authorization coverage but 1215 endpoints? This application must
    have custom authorization. Let me probe with Joern to find annotations.

Tool: joern_query('cpg.annotation.name.dedup.l')
Result: ['PreAuthorize', 'Superadmin', 'SystemAdminNoServerAdmin', 'RequestMapping', ...]

AI: Interesting! 'Superadmin' and 'SystemAdminNoServerAdmin' aren't standard
    Spring Security annotations. These might be meta-annotations.
```

**Turn 2: Investigate Annotation Definitions**
```
AI: Let me read the Superadmin annotation source to see if it wraps @PreAuthorize
Tool: grep_code('@interface Superadmin', '*.java')
Result: [{'file': 'Superadmin.java', 'line': 34}]

Tool: read_file('src/main/java/contrast/teamserver/security/Superadmin.java', 30, 40)
Result:
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("isSuperadmin()")
    public @interface Superadmin {}

AI: Perfect! It's a meta-annotation wrapping @PreAuthorize("isSuperadmin()").
    Let me count usages and check the other one too.
```

**Turn 3: Count Usages**
```
AI: How many methods use @Superadmin?
Tool: joern_query('cpg.method.where(_.annotation.name("Superadmin")).count')
Result: 450

AI: And SystemAdminNoServerAdmin?
Tool: joern_query('cpg.method.where(_.annotation.name("SystemAdminNoServerAdmin")).count')
Result: 764

AI: Together that's 1214 methods protected. Let me verify these cover the endpoints.
Tool: joern_query('cpg.method.where(_.annotation.name("RequestMapping|GetMapping|PostMapping")).count')
Result: 1215

AI: Perfect! 1214 protected / 1215 total = 99.9% coverage. I'm confident now.
```

**Final Turn:**
```
AI: I've confirmed custom authorization through meta-annotations. High confidence.
{{
  "type": "final_answer",
  "confidence": 0.95,
  "patterns": [
    {{
      "pattern_type": "meta_annotation",
      "pattern_name": "@Superadmin",
      "description": "Meta-annotation wrapping @PreAuthorize('isSuperadmin()'). Applied at method level.",
      "evidence": "Definition at Superadmin.java:34 wraps @PreAuthorize. Used on 450 methods via Joern query.",
      "usage_count": 450,
      "applies_to": "specific_controllers",
      "joern_validation": "cpg.method.where(_.annotation.name(\"Superadmin\")).count"
    }},
    {{
      "pattern_type": "meta_annotation",
      "pattern_name": "@SystemAdminNoServerAdmin",
      "description": "Meta-annotation for system admin access (non-server admin). Applied at method level.",
      "evidence": "Joern query shows 764 usages. Combined with @Superadmin covers 99.9% of endpoints.",
      "usage_count": 764,
      "applies_to": "specific_controllers",
      "joern_validation": "cpg.method.where(_.annotation.name(\"SystemAdminNoServerAdmin\")).count"
    }}
  ]
}}
```

### Example 2: Finding No Admin Isolation

**Turn 1: Identify Admin vs Normal Routes**
```
AI: Let me first get the architecture report to see routes
Tool: get_architecture_report()
Result: 127 endpoints, including routes like /admin/users, /api/users, etc.

AI: Let me find all routes with 'admin' in the path
Tool: joern_query('cpg.method.where(_.annotation.name(".*Mapping")).where(_.annotation.parameterAssign.value(".*admin.*")).fullName.l')
Result: ['AdminController.listUsers', 'AdminController.deleteUser', ...] (12 methods)

AI: Now let me find normal user routes
Tool: joern_query('cpg.method.where(_.annotation.name(".*Mapping")).where(_.annotation.parameterAssign.value(".*api/users.*")).fullName.l')
Result: ['UserController.getProfile', 'UserController.updateProfile', ...] (8 methods)
```

**Turn 2: Compare Authorization Mechanisms**
```
AI: Let me check what authorization is on admin routes
Tool: read_file('src/main/java/com/app/AdminController.java', 1, 50)
Result:
    @RestController
    @RequestMapping("/admin")
    public class AdminController {
        @PreAuthorize("hasRole('ADMIN')")
        @GetMapping("/users")
        public List<User> listUsers() { ... }
    }

AI: And normal routes?
Tool: read_file('src/main/java/com/app/UserController.java', 1, 50)
Result:
    @RestController
    @RequestMapping("/api/users")
    public class UserController {
        @PreAuthorize("hasRole('USER')")
        @GetMapping("/profile")
        public User getProfile() { ... }
    }

AI: Both use the same @PreAuthorize mechanism, just different roles.
```

**Turn 3: Check for Separate Admin Authentication**
```
AI: Maybe admin portal has separate authentication? Let me search for SecurityConfig
Tool: grep_code('class.*SecurityConfig', '*.java')
Result: [{'file': 'SecurityConfig.java', 'line': 23}]

Tool: read_file('src/main/java/com/app/config/SecurityConfig.java')
Result:
    @Configuration
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) {
            http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").hasRole("USER");
        }
    }

AI: Same configuration for both admin and user routes. No separate auth mechanism.
    ADMIN is just another role in the same system.
```

**Final Turn:**
```
AI: I've thoroughly investigated and found NO admin authorization isolation.
{{
  "type": "final_answer",
  "confidence": 0.90,
  "patterns": [],
  "isolation_exists": false,
  "reasoning": "Admin routes and normal routes both use @PreAuthorize with Spring Security.
                The only difference is ADMIN vs USER role - both checked by the same mechanism.
                No separate authentication, no separate authorization logic, no security boundary.
                ADMIN is just another role, not a separate defense layer.",
  "evidence": [
    "AdminController and UserController both use @PreAuthorize (same mechanism)",
    "SecurityConfig treats admin and user routes identically (same httpSecurity chain)",
    "No separate admin authentication portal or filter found via grep/Joern",
    "Joern queries confirm no admin-specific authorization methods exist"
  ]
}}
```

### Example 3: Creative Query - Finding Custom Method Patterns

**Turn 1: Architecture Report Shows Low Coverage**
```
AI: Architecture report shows only 5% authorization coverage. Let me look for
    custom authorization methods that might have been missed.

Tool: joern_query('cpg.method.name(".*[Aa]uthoriz.*|.*[Pp]ermission.*|.*[Aa]ccess.*").whereNot(_.isExternal).fullName.l')
Result: [
  'AuthService.checkAccess',
  'PermissionValidator.hasPermission',
  'SecurityHelper.isAuthorized',
  ...
]

AI: Found several candidates! Let me check if these are actually used for authorization.
```

**Turn 2: Investigate Usage Patterns**
```
AI: Let me see where checkAccess is called
Tool: joern_query('cpg.call.name("checkAccess").file.name.dedup.l')
Result: ['UserController.java', 'DocumentController.java', 'ProjectController.java']

AI: Let me read one to see the pattern
Tool: read_file('src/main/java/com/app/UserController.java', 1, 100)
Result:
    public User getUser(Long id) {
        if (!authService.checkAccess(currentUser, "user:read")) {
            throw new AccessDeniedException();
        }
        return userRepo.findById(id);
    }

AI: This is authorization! Custom method pattern. Let me count total usages.

Tool: joern_query('cpg.call.name("checkAccess").count')
Result: 127

AI: 127 usages! This is the authorization mechanism. Coverage makes sense now.
```

**Final Turn:**
```
AI: Found custom authorization via method calls!
{{
  "type": "final_answer",
  "confidence": 0.92,
  "patterns": [
    {{
      "pattern_type": "custom_method",
      "pattern_name": "AuthService.checkAccess(user, permission)",
      "description": "Custom authorization method checking if user has permission string. Called at start of controller methods.",
      "evidence": "Found via Joern query for authorization-related methods. Validated by reading UserController showing pattern. 127 call sites confirmed.",
      "usage_count": 127,
      "applies_to": "all_endpoints",
      "joern_validation": "cpg.call.name(\"checkAccess\").count"
    }}
  ]
}}
```

---

## Benefits of Agentic Approach

1. **Adaptive:** AI adjusts investigation based on what it finds
2. **Thorough:** Can probe multiple angles until confident
3. **Evidence-Based:** Validates hypotheses before concluding
4. **Explainable:** Shows investigation path and reasoning
5. **Handles Complexity:** Can discover patterns we didn't anticipate

## Implementation Notes

- Use Claude's new function calling / tool use capability
- Set max_turns to prevent infinite loops
- Track confidence score - stop at >= 0.9
- Log all tool calls for debugging
- Handle tool errors gracefully
- Provide good initial context to guide investigation
