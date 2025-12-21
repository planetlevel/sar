"""
Authorization Analysis Utilities

Utility functions for framework detection, Joern query execution,
data parsing, and report building used by the endpoint authorization agent.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import os
import re
from sar.framework_schema import FrameworkDefinition, PatternGroup
from sar.framework_tool import FrameworkTool


class AuthorizationUtils:
    """
    Utility class for authorization analysis operations

    Handles:
    - Framework/library detection
    - Joern query execution
    - Data parsing and transformation
    - Report building
    """

    def __init__(self, cpg_tool, project_dir: str,
                 frameworks_dir: Path = None, ai_client=None, debug: bool = False):
        self.cpg_tool = cpg_tool
        self.project_dir = project_dir
        self.frameworks_dir = frameworks_dir
        self.ai_client = ai_client
        self.debug = debug

        # Initialize FrameworkTool for Pydantic-validated framework loading
        self.framework_detector = FrameworkTool(
            project_dir=project_dir,
            frameworks_dir=str(frameworks_dir) if frameworks_dir else None
        )

    # ========================================================================
    # JOERN QUERY EXECUTION
    # ========================================================================
    # NOTE: Framework detection and pattern searching now handled by FrameworkTool
    # (see sar/framework_tool.py)

    def query_authorization_annotations(self, annotation_names: List[str]) -> List[Dict]:
        """
        Query CPG for methods with authorization annotations

        Returns list of behaviors with endpoint context
        """
        behaviors = []

        if self.debug:
            print(f"[UTILS] Querying for annotations: {annotation_names}")

        # Build Joern query to find methods with these annotations
        # Use regex pattern to match any of the annotation names
        annotation_pattern = '|'.join(annotation_names)

        query = f'''
        cpg.method
          .where(_.annotation.name("{annotation_pattern}"))
          .map {{ m =>
            val annotation = m.annotation.name("{annotation_pattern}").head
            val annotCode = annotation.code

            // Try to extract route and HTTP method from mapping annotations on same method
            val mappingAnnotations = m.annotation.name(".*Mapping").l
            val routeInfo = mappingAnnotations.headOption.map {{ ann =>
              val httpMethod = ann.name match {{
                case n if n.contains("GetMapping") => "GET"
                case n if n.contains("PostMapping") => "POST"
                case n if n.contains("PutMapping") => "PUT"
                case n if n.contains("DeleteMapping") => "DELETE"
                case n if n.contains("PatchMapping") => "PATCH"
                case n if n.contains("RequestMapping") =>
                  // Try to extract method from annotation code
                  val codeStr = ann.code
                  if (codeStr.contains("method.*GET")) "GET"
                  else if (codeStr.contains("method.*POST")) "POST"
                  else if (codeStr.contains("method.*PUT")) "PUT"
                  else if (codeStr.contains("method.*DELETE")) "DELETE"
                  else "UNKNOWN"
                case _ => "UNKNOWN"
              }}

              val route = ann.parameter.assignment
                .where(_.argument(1).code("value|path"))
                .argument(2).code.headOption.getOrElse("")
                .replaceAll("^\\\"|\\\"$", "")

              Map("httpMethod" -> httpMethod, "route" -> route)
            }}.getOrElse(Map("httpMethod" -> "UNKNOWN", "route" -> ""))

            Map(
              "method" -> m.fullName,
              "file" -> m.file.name.headOption.getOrElse("unknown"),
              "line" -> m.lineNumber.getOrElse(0),
              "annotation" -> annotation.name,
              "roles" -> annotCode,
              "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
              "httpMethod" -> routeInfo.getOrElse("httpMethod", "UNKNOWN"),
              "route" -> routeInfo.getOrElse("route", "")
            )
          }}.toJson
        '''

        try:
            result = self.cpg_tool.query(query)

            if self.debug:
                print(f"[UTILS] Query success: {result.success}")
                if result.output:
                    print(f"[UTILS] Output length: {len(result.output)}")
                    print(f"[UTILS] Output preview: {result.output[:300]}")
                if result.error:
                    print(f"[UTILS] Error: {result.error}")

            if not result.success:
                if self.debug:
                    print(f"[UTILS] Query failed, returning empty")
                return []

            if not result.output:
                return []

            # Parse JSON result - handle Joern REPL wrapper
            # Output format: val res2: String = "[{...}]" OR val res2: String = """[{...}]"""
            output = result.output.strip()

            # Extract JSON from Scala REPL wrapper
            # Try triple-quote format first
            match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
            if match:
                json_str = match.group(1)
                data = json.loads(json_str)
            else:
                # Try single-quote format
                match = re.search(r'val \w+: \w+ = "(.*)"', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    # Unescape the string
                    json_str = json_str.replace('\\"', '"').replace('\\\\', '\\')
                    data = json.loads(json_str)
                else:
                    # Try direct JSON parse
                    data = json.loads(output)

            # BATCHED AI EXTRACTION: Collect unique role expressions and extract roles in batches
            unique_expressions = list(set([item.get('roles', '') for item in data if item.get('roles', '')]))

            if self.debug:
                print(f"[UTILS] Found {len(data)} annotations with {len(unique_expressions)} unique role expressions")

            # Extract roles using batched AI (20 expressions per batch)
            roles_cache = {}
            if self.ai_client and unique_expressions:
                batch_size = 20
                for i in range(0, len(unique_expressions), batch_size):
                    batch = unique_expressions[i:i+batch_size]
                    if self.debug:
                        print(f"[UTILS] Processing batch {i//batch_size + 1}/{(len(unique_expressions) + batch_size - 1)//batch_size} ({len(batch)} expressions)")

                    batch_results = self.parse_roles_with_ai_batch(batch, self.ai_client)
                    roles_cache.update(batch_results)

            # Convert to behavior format
            for item in data:
                # Determine location - could be route, service class, config file, etc.
                route = item.get('route', '')
                http_method = item.get('httpMethod', 'UNKNOWN')
                class_name = item.get('class', '')
                file_path = item.get('file', '')

                # Build location string based on what's available
                # Check if this is a controller class (endpoint layer)
                is_controller = class_name and (
                    'Controller' in class_name or
                    'Resource' in class_name or
                    'Endpoint' in class_name or
                    'Handler' in class_name
                )

                if route and http_method != 'UNKNOWN':
                    location = f"{http_method} {route}"
                    location_type = "endpoint"
                elif is_controller:
                    # Controller methods are endpoints even without explicit routes
                    location = f"{class_name} (line {item.get('line', 0)})"
                    location_type = "endpoint"
                elif class_name:
                    location = f"{class_name} (line {item.get('line', 0)})"
                    location_type = "service"
                elif file_path:
                    location = f"{file_path}:{item.get('line', 0)}"
                    location_type = "code"
                else:
                    location = "unknown"
                    location_type = "unknown"

                # Get roles from cache (or fallback to individual parsing if cache miss)
                roles_str = item.get('roles', '')
                if roles_str in roles_cache:
                    roles = roles_cache[roles_str]
                else:
                    # Fallback to individual parsing (shouldn't happen, but defensive)
                    roles = self.parse_roles(roles_str, self.ai_client)

                behavior = {
                    'type': 'authorization_annotation',
                    'mechanism': item.get('annotation', ''),  # Renamed from 'annotation' - can be annotation, method, config, filter
                    'method': item.get('method', ''),
                    'class': class_name,
                    'file': file_path,
                    'line': item.get('line', 0),
                    'roles': roles,
                    'location': location,
                    'location_type': location_type,
                    # Keep httpMethod for endpoint-level detection
                    'httpMethod': http_method
                }

                behaviors.append(behavior)

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Annotation query error: {e}")
                import traceback
                traceback.print_exc()

        return behaviors

    def query_authorization_method_calls(self, method_signatures: List[str]) -> List[Dict]:
        """
        Query CPG for calls to authorization check methods

        Returns list of behaviors with endpoint context
        """
        # TODO: Implement method call pattern matching
        return []

    def query_all_endpoint_methods(self, matched_frameworks: Dict[str, FrameworkDefinition] = None) -> List[Dict]:
        """
        Query CPG for ALL methods with routing annotations from detected frameworks (type-safe).

        This discovers ALL potential endpoints in the codebase, which can then
        be compared against protected endpoints to calculate coverage.

        Args:
            matched_frameworks: Dictionary of detected frameworks with their FrameworkDefinition
                                If None, falls back to hardcoded Spring patterns (legacy)

        Returns list of methods with endpoint context
        """
        methods = []

        # Extract routing patterns from frameworks
        routing_patterns = []
        http_method_mappings = {}

        if matched_frameworks:
            if self.debug:
                print(f"[UTILS] Loading routing patterns from {len(matched_frameworks)} framework(s)...")

            for framework_name, framework in matched_frameworks.items():
                if not framework.architecture or not framework.architecture.routing:
                    continue

                route_defs = framework.architecture.routing.route_definitions or []

                # route_defs is now a list of PatternGroup objects
                for pattern_group in route_defs:
                    if pattern_group.search_type == 'annotation_name':
                        # Extract pattern (can be string, list, or dict)
                        pattern = pattern_group.pattern
                        if isinstance(pattern, str):
                            routing_patterns.append(pattern)
                        elif isinstance(pattern, list):
                            routing_patterns.extend(pattern)
                        elif isinstance(pattern, dict):
                            # Dict patterns like {"get": "GetMapping", "post": "PostMapping"}
                            routing_patterns.extend(pattern.values())

                if self.debug and routing_patterns:
                    print(f"[UTILS]   {framework_name}: {len(routing_patterns)} routing patterns")
        if not matched_frameworks or not routing_patterns:
            if self.debug:
                print(f"[UTILS] ERROR: No routing patterns found in frameworks")
            return []

        # Build regex pattern from routing annotations
        # Pattern needs to match ANY of the routing annotations
        pattern = '|'.join(routing_patterns)
        if self.debug:
            print(f"[UTILS] Built routing pattern: {pattern}")

        # Build reverse mapping for HTTP method extraction
        # Map annotation name → HTTP method
        annotation_to_method = {}
        for http_method, annotation_name in http_method_mappings.items():
            annotation_to_method[annotation_name] = http_method.upper()

        if self.debug:
            print(f"[UTILS] Querying for ALL methods with routing annotations: {routing_patterns}")

        # Build dynamic Joern query using detected patterns
        query = '''
        cpg.method
          .where(_.annotation.name("({pattern})"))
          .map { m =>
            val routingAnnotations = m.annotation.name("({pattern})").l
            val routeInfo = routingAnnotations.headOption.map { ann =>
              val httpMethod = ann.name match {
                case n if n.contains("GetMapping") || n.contains("GET") => "GET"
                case n if n.contains("PostMapping") || n.contains("POST") => "POST"
                case n if n.contains("PutMapping") || n.contains("PUT") => "PUT"
                case n if n.contains("DeleteMapping") || n.contains("DELETE") => "DELETE"
                case n if n.contains("PatchMapping") || n.contains("PATCH") => "PATCH"
                case n if n.contains("RequestMapping") || n.contains("Path") =>
                  // Try to extract method from annotation code
                  val codeStr = ann.code
                  if (codeStr.contains("method.*GET")) "GET"
                  else if (codeStr.contains("method.*POST")) "POST"
                  else if (codeStr.contains("method.*PUT")) "PUT"
                  else if (codeStr.contains("method.*DELETE")) "DELETE"
                  else "GET"  // Default
                case _ => "UNKNOWN"
              }

              val route = ann.parameter.assignment
                .where(_.argument(1).code("value|path"))
                .argument(2).code.headOption.getOrElse("")
                .replaceAll("^\\\"|\\\"$", "")

              Map("httpMethod" -> httpMethod, "route" -> route)
            }.getOrElse(Map("httpMethod" -> "UNKNOWN", "route" -> ""))

            Map(
              "method" -> m.fullName,
              "file" -> m.file.name.headOption.getOrElse("unknown"),
              "line" -> m.lineNumber.getOrElse(0),
              "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
              "httpMethod" -> routeInfo.getOrElse("httpMethod", "UNKNOWN"),
              "route" -> routeInfo.getOrElse("route", "")
            )
          }.toJson
        '''.replace('{pattern}', pattern)

        try:
            result = self.cpg_tool.query(query)

            if self.debug:
                print(f"[UTILS] Endpoint query success: {result.success}")
                if result.output:
                    print(f"[UTILS] Output length: {len(result.output)}")
                    print(f"[UTILS] Output preview: {result.output[:300]}")

            if not result.success or not result.output:
                return []

            # Parse JSON result - handle Joern REPL wrapper
            output = result.output.strip()

            # Try triple-quote format first
            match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
            if match:
                json_str = match.group(1)
                data = json.loads(json_str)
            else:
                # Try single-quote format
                match = re.search(r'val \w+: \w+ = "(.*)"', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    json_str = json_str.replace('\\"', '"').replace('\\\\', '\\')
                    data = json.loads(json_str)
                else:
                    # Try direct JSON parse
                    data = json.loads(output)

            if self.debug:
                print(f"[UTILS] Found {len(data)} total endpoint methods with @RequestMapping")

            return data

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Endpoint query error: {e}")
                import traceback
                traceback.print_exc()

        return []

    def query_all_annotations_with_ai_filter(self) -> List[Dict]:
        """
        Query Joern for ALL annotations, then use AI to filter authorization-related ones

        This is more comprehensive than hardcoded patterns like "PreAuthorize|PostAuthorize|Secured|RolesAllowed"

        Returns list of authorization behaviors discovered
        """
        if self.debug:
            print(f"[UTILS] Querying for ALL annotations in codebase...")

        query = '''
        cpg.method
          .where(_.annotation)
          .map { m =>
            // Get all annotations on this method
            m.annotation.map { ann =>
              Map(
                "method" -> m.fullName,
                "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
                "file" -> m.file.name.headOption.getOrElse("unknown"),
                "line" -> m.lineNumber.getOrElse(0),
                "annotation" -> ann.name,
                "roles" -> ann.code
              )
            }
          }.flatten.toJson
        '''

        try:
            result = self.cpg_tool.query(query)

            if not result.success or not result.output:
                if self.debug:
                    print(f"[UTILS] Query failed or returned no results")
                return []

            # Parse JSON result
            output = result.output.strip()
            match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
            if match:
                json_str = match.group(1)
                data = json.loads(json_str)
            else:
                match = re.search(r'val \w+: \w+ = "(.*)\"', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    json_str = json_str.replace('\\"', '"').replace('\\\\', '\\')
                    data = json.loads(json_str)
                else:
                    data = json.loads(output)

            if self.debug:
                print(f"[UTILS] Found {len(data)} total annotations")

            # Get unique annotation names
            unique_annotations = list(set([item.get('annotation', '') for item in data]))
            if self.debug:
                print(f"[UTILS] Unique annotation types: {len(unique_annotations)}")
                print(f"[UTILS] Sample annotations: {unique_annotations[:20]}")

            # Use AI to filter for authorization-related annotations
            if not self.ai_client:
                if self.debug:
                    print(f"[UTILS] No AI client - falling back to hardcoded patterns")
                # Fallback to hardcoded patterns
                auth_patterns = ['PreAuthorize', 'PostAuthorize', 'Secured', 'RolesAllowed', 'Authorized']
                auth_annotations = [ann for ann in unique_annotations if any(pattern in ann for pattern in auth_patterns)]
            else:
                if self.debug:
                    print(f"[UTILS] Using AI to identify authorization-related annotations...")
                auth_annotations = self._filter_authorization_annotations_with_ai(unique_annotations)

            if self.debug:
                print(f"[UTILS] AI identified {len(auth_annotations)} authorization-related annotations")
                print(f"[UTILS] Authorization annotations: {auth_annotations}")

            # Filter data to only authorization annotations
            auth_data = [item for item in data if item.get('annotation', '') in auth_annotations]

            if self.debug:
                print(f"[UTILS] Filtered to {len(auth_data)} authorization annotation instances")

            # Convert to behavior format (reuse existing logic)
            # Extract roles using batched AI
            unique_expressions = list(set([item.get('roles', '') for item in auth_data if item.get('roles', '')]))
            roles_cache = {}
            if self.ai_client and unique_expressions:
                batch_size = 20
                for i in range(0, len(unique_expressions), batch_size):
                    batch = unique_expressions[i:i+batch_size]
                    if self.debug:
                        print(f"[UTILS] Extracting roles from batch {i//batch_size + 1}/{(len(unique_expressions) + batch_size - 1)//batch_size}")
                    batch_results = self.parse_roles_with_ai_batch(batch, self.ai_client)
                    roles_cache.update(batch_results)

            # Build behaviors
            behaviors = []
            for item in auth_data:
                route = item.get('route', '')
                http_method = item.get('httpMethod', 'UNKNOWN')
                class_name = item.get('class', '')
                file_path = item.get('file', '')

                # Check if this is a controller class (endpoint layer)
                is_controller = class_name and (
                    'Controller' in class_name or
                    'Resource' in class_name or
                    'Endpoint' in class_name or
                    'Handler' in class_name
                )

                # Determine location
                if route and http_method != 'UNKNOWN':
                    location = f"{http_method} {route}"
                    location_type = "endpoint"
                elif is_controller:
                    # Controller methods are endpoints even without explicit routes
                    location = f"{class_name} (line {item.get('line', 0)})"
                    location_type = "endpoint"
                elif class_name:
                    location = f"{class_name} (line {item.get('line', 0)})"
                    location_type = "service"
                elif file_path:
                    location = f"{file_path}:{item.get('line', 0)}"
                    location_type = "code"
                else:
                    location = "unknown"
                    location_type = "unknown"

                # Get roles
                roles_str = item.get('roles', '')
                if roles_str in roles_cache:
                    roles = roles_cache[roles_str]
                else:
                    roles = self.parse_roles(roles_str, self.ai_client)

                behavior = {
                    'type': 'authorization_annotation',
                    'mechanism': item.get('annotation', ''),
                    'method': item.get('method', ''),
                    'class': class_name,
                    'file': file_path,
                    'line': item.get('line', 0),
                    'roles': roles,
                    'location': location,
                    'location_type': location_type,
                    'httpMethod': http_method
                }
                behaviors.append(behavior)

            return behaviors

        except Exception as e:
            if self.debug:
                print(f"[UTILS] All-annotations query failed: {e}")
                import traceback
                traceback.print_exc()
            return []

    def _filter_authorization_annotations_with_ai(self, annotation_names: List[str]) -> List[str]:
        """
        Use AI to identify which annotations are authorization-related

        This handles novel/custom authorization annotations that aren't in our hardcoded list
        """
        if not annotation_names:
            return []

        # Build prompt with all unique annotation names
        annotations_text = "\n".join([f"{i+1}. {ann}" for i, ann in enumerate(annotation_names)])

        prompt = f"""You are analyzing Java/Spring annotations to identify authorization-related ones.

Here are ALL unique annotation names found in the codebase:

{annotations_text}

TASK: Identify which annotations are related to AUTHORIZATION (access control, permissions, roles).

Authorization annotations typically:
- Check if a user has permission to access a resource
- Verify user roles or authorities
- Enforce access control policies
- Examples: @PreAuthorize, @Secured, @RolesAllowed, @RequiresPermission, @CheckAccess

NOT authorization (exclude these):
- Validation: @Valid, @NotNull, @Size
- Transactions: @Transactional
- HTTP mapping: @GetMapping, @PostMapping
- Caching: @Cacheable
- Scheduling: @Scheduled
- Configuration: @Configuration, @Bean
- ORM: @Entity, @Column, @ManyToOne

Respond with ONLY the authorization-related annotation names, one per line:"""

        try:
            response = self.ai_client.call_claude(prompt, max_tokens=1000, temperature=0)
            if not response:
                return []

            # Parse response - one annotation name per line
            auth_annotations = []
            for line in response.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                # Remove leading numbers/bullets
                line = re.sub(r'^\d+\.\s*', '', line)
                line = re.sub(r'^[-*]\s*', '', line)
                # Extract annotation name
                if line:
                    auth_annotations.append(line)

            if self.debug:
                print(f"[UTILS] AI identified {len(auth_annotations)} authorization annotations from {len(annotation_names)} total")

            return auth_annotations

        except Exception as e:
            if self.debug:
                print(f"[UTILS] AI filtering failed: {e}")
            # Fallback to hardcoded patterns
            patterns = ['PreAuthorize', 'PostAuthorize', 'Secured', 'RolesAllowed', 'Authorized', 'RequiresPermission']
            return [ann for ann in annotation_names if any(pattern in ann for pattern in patterns)]

    # ========================================================================
    # DATA PARSING/TRANSFORMATION
    # ========================================================================

    def extract_route_info(self, method_data: Dict) -> Dict:
        """
        Extract route and HTTP method from method by cross-referencing with endpoints

        Matches method location to endpoint mapping
        """
        method_name = method_data.get('method', '')
        class_name = method_data.get('class', '')

        # Try to match with discovered endpoints
        for endpoint in self.endpoints:
            ep_method = endpoint.get('handler_method', '')
            ep_class = endpoint.get('controller', '')

            if ep_method and ep_method in method_name and ep_class in class_name:
                return {
                    'route': endpoint.get('route', ''),
                    'httpMethod': endpoint.get('httpMethod', 'UNKNOWN')
                }

        # No match - return empty (will show as unlinked authorization)
        return {'route': '', 'httpMethod': 'UNKNOWN'}

    def parse_roles_with_ai_batch(self, expressions_batch: List[str], ai_client) -> Dict[str, List[str]]:
        """
        BATCHED: Extract roles from multiple authorization expressions in one AI call

        This is 10-20x faster and cheaper than individual calls.
        Processes up to 20 expressions per call.

        Args:
            expressions_batch: List of role expression strings
            ai_client: AI client for Claude calls

        Returns:
            Dict mapping expression -> list of roles
        """
        if not expressions_batch or not ai_client:
            return {}

        # Build batch prompt with numbered expressions
        expressions_text = ""
        for i, expr in enumerate(expressions_batch, 1):
            expressions_text += f"\n{i}. {expr}"

        prompt = f"""Extract ALL role names from these Spring Security authorization expressions.

Authorization Expressions:{expressions_text}

Rules:
1. Extract role names from hasRole(), hasAnyRole(), hasAuthority(), etc.
2. Extract role names from custom methods like isSuperadmin() -> "superadmin"
3. Extract role names from method parameters like hasOrgAccess(#id, 'edit') -> "edit"
4. Strip ROLE_ prefix if present (ROLE_ADMIN -> ADMIN)
5. Return results in this format:
   1: role1, role2, role3
   2: NONE
   3: role4, role5

Example:
Input:
1. @PreAuthorize("hasAnyRole('USER','ADMIN')")
2. @PreAuthorize("isSuperadmin()")
3. @PreAuthorize("permitAll()")

Output:
1: USER, ADMIN
2: superadmin
3: NONE

Now extract roles from the expressions above:"""

        try:
            response = ai_client.call_claude(prompt, max_tokens=2000, temperature=0)
            if not response:
                return {}

            # Parse response - format: "1: role1, role2\n2: role3\n3: NONE"
            result = {}
            for line in response.strip().split('\n'):
                line = line.strip()
                if not line or ':' not in line:
                    continue

                # Parse "1: role1, role2, role3" format
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue

                try:
                    idx = int(parts[0].strip())
                    if idx < 1 or idx > len(expressions_batch):
                        continue

                    expr = expressions_batch[idx - 1]
                    roles_str = parts[1].strip()

                    if roles_str.upper() == 'NONE' or not roles_str:
                        result[expr] = []
                    else:
                        # Split by comma and clean
                        roles = [r.strip() for r in roles_str.split(',') if r.strip()]
                        result[expr] = roles

                except (ValueError, IndexError):
                    continue

            return result

        except Exception as e:
            if self.debug:
                print(f"[UTILS] AI batch extraction failed: {e}, falling back to individual calls")
            return {}

    def parse_roles_with_ai(self, roles_str: str, ai_client) -> List[str]:
        """
        Use AI to extract ALL roles from authorization expression

        This is the ONLY way to ensure we don't miss custom patterns.
        AI understands the semantics and extracts roles regardless of syntax.
        """
        if not roles_str or not ai_client:
            return []

        prompt = f"""Extract ALL role names from this Spring Security authorization expression.

Authorization Expression:
{roles_str}

Rules:
1. Extract role names from hasRole(), hasAnyRole(), hasAuthority(), etc.
2. Extract role names from custom methods like isSuperadmin() -> "superadmin"
3. Extract role names from method parameters like hasOrgAccess(#id, 'edit') -> "edit"
4. Strip ROLE_ prefix if present (ROLE_ADMIN -> ADMIN)
5. Return ONLY role names, one per line
6. If no roles found, return "NONE"

Example:
Input: @PreAuthorize("hasAnyRole('USER','ADMIN') or isSuperadmin()")
Output:
USER
ADMIN
superadmin

Now extract roles from the expression above:"""

        try:
            response = ai_client.call_claude(prompt, max_tokens=500, temperature=0)
            if not response or response.strip() == "NONE":
                return []

            # Parse response - one role per line
            roles = [line.strip() for line in response.strip().split('\n') if line.strip()]
            # Remove any explanatory text
            roles = [r for r in roles if not r.startswith('#') and not r.startswith('//')]
            return roles

        except Exception as e:
            if self.debug:
                print(f"[UTILS] AI role extraction failed: {e}, falling back to regex")
            return self.parse_roles_regex(roles_str)

    def parse_roles(self, roles_str: str, ai_client=None) -> List[str]:
        """
        Extract ALL roles from authorization expression

        Uses AI by default for comprehensive extraction.
        Falls back to regex if AI unavailable.
        """
        # Try AI first if available
        if ai_client:
            return self.parse_roles_with_ai(roles_str, ai_client)

        # Fallback to regex
        return self.parse_roles_regex(roles_str)

    def parse_roles_regex(self, roles_str: str) -> List[str]:
        """
        FALLBACK: Regex-based role extraction (used if AI unavailable)

        This is a best-effort fallback. It will miss novel patterns.
        AI extraction is preferred.
        """
        if not roles_str:
            return []

        roles = []
        original_count = 0  # Track if we found anything

        # Pattern 1: hasRole/hasAnyRole/hasAuthority patterns
        # Matches: hasRole('ADMIN'), hasAnyRole('USER','ADMIN'), hasAuthority('ROLE_USER')
        # Use global extraction of all quoted strings within these methods
        role_methods = ['hasRole', 'hasAnyRole', 'hasAuthority', 'hasAnyAuthority']

        for method in role_methods:
            # Find the method call
            method_match = re.search(rf"{method}\(([^)]+)\)", roles_str)
            if method_match:
                # Extract all quoted strings from within the parentheses
                args = method_match.group(1)
                quoted_values = re.findall(r"['\"]([^'\"]+)['\"]", args)
                roles.extend(quoted_values)

        # Pattern 2: Custom method calls that imply roles
        # Matches: isSuperadmin(), isObserver(), isCron(), isAdmin(), hasAdmin()
        # Extracts role name from method name (camelCase -> lowercase)
        # Supports both is* and has* prefixes
        method_patterns = [
            r"is([A-Z][a-zA-Z]+)\(\)",      # isSuperadmin() -> superadmin
            r"has([A-Z][a-zA-Z]+)Access\(\)",  # hasAdminAccess() -> admin
        ]

        for pattern in method_patterns:
            method_matches = re.findall(pattern, roles_str)
            if method_matches:
                # Convert camelCase to lowercase (Superadmin -> superadmin)
                roles.extend([m.lower() for m in method_matches])

        # Pattern 3: ALL string literals (comprehensive extraction)
        # This catches ANY quoted string that might be a role
        # Matches: 'edit', "admin", 'ROLE_USER'
        all_string_literals = re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\)", roles_str)
        roles.extend(all_string_literals)

        # Pattern 4: Method names with role-like parameters
        # Matches: hasOrganizationRoleAccess(#orgUuid,'edit')
        # This is already covered by Pattern 3 but kept for clarity

        # Warn if we couldn't extract anything from a non-empty expression
        if not roles and roles_str and self.debug:
            # Check if this is a complex expression we might miss
            if any(keyword in roles_str.lower() for keyword in ['access', 'permission', 'authorized']):
                print(f"[UTILS] WARNING: Could not extract roles from: {roles_str[:100]}")

        # Clean up: remove ROLE_ prefix if present (Spring Security convention)
        cleaned_roles = []
        for role in roles:
            role = role.strip()
            if not role:
                continue
            if role.startswith('ROLE_'):
                cleaned_roles.append(role[5:])  # Strip ROLE_ prefix
            else:
                cleaned_roles.append(role)

        # Remove duplicates while preserving order
        seen = set()
        unique_roles = []
        for role in cleaned_roles:
            if role not in seen:
                seen.add(role)
                unique_roles.append(role)

        return unique_roles

    def get_standard_pattern_summary(self, standard_mechanisms: List[Dict]) -> List[str]:
        """Get list of standard patterns found for AI context"""
        patterns = []
        for mechanism in standard_mechanisms:
            for pattern in mechanism.get('patterns', []):
                patterns.append(f"{mechanism['framework']}.{pattern}")
        return patterns[:20]  # Limit for context

    def find_location_authorization(self, location: str,
                                    all_mechanisms: List[Dict]) -> Dict:
        """
        Find authorization behaviors that protect a given location

        Args:
            location: Location string (e.g., "GET /path" for endpoints, "com.example.Service (line 42)" for services)
            all_mechanisms: List of discovered mechanisms with behaviors

        Returns:
            Dict with 'status' and 'behaviors' (list of matching behavior indices)
        """
        matching_behaviors = []

        for mech_idx, mechanism in enumerate(all_mechanisms):
            for behavior_idx, behavior in enumerate(mechanism.get('behaviors', [])):
                if behavior.get('location') == location:
                    matching_behaviors.append({
                        'mechanism_index': mech_idx,
                        'behavior_index': behavior_idx,
                        'framework': mechanism.get('framework', 'unknown'),
                        'category': mechanism.get('category', 'unknown')
                    })

        if matching_behaviors:
            return {
                'status': 'protected',
                'behaviors': matching_behaviors
            }
        else:
            return {
                'status': 'unprotected',
                'behaviors': []
            }

    # Legacy alias for backward compatibility
    def find_endpoint_authorization(self, endpoint: Dict,
                                    all_mechanisms: List[Dict]) -> Dict:
        """
        Legacy method - finds authorization for an endpoint
        Delegates to find_location_authorization
        """
        location = f"{endpoint.get('httpMethod', 'UNKNOWN')} {endpoint.get('route', '')}"
        result = self.find_location_authorization(location, all_mechanisms)

        # Convert to legacy format for backward compatibility
        if result['status'] == 'protected':
            # Get first matching behavior for roles/mechanism
            first_behavior_info = result['behaviors'][0]
            mech_idx = first_behavior_info['mechanism_index']
            behavior_idx = first_behavior_info['behavior_index']
            behavior = all_mechanisms[mech_idx]['behaviors'][behavior_idx]

            return {
                'status': 'protected',
                'roles': behavior.get('roles', []),
                'mechanism': f"{first_behavior_info['framework']}.{first_behavior_info['category']}"
            }
        else:
            return {'status': 'unprotected'}

    def analyze_roles(self, all_mechanisms: List[Dict]) -> Dict:
        """Analyze role usage patterns"""
        roles_used = set()

        for mechanism in all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                for role in behavior.get('roles', []):
                    roles_used.add(role)

        generic_roles = ['USER', 'ADMIN', 'GUEST', 'ANONYMOUS']
        generic = [r for r in roles_used if r.upper() in generic_roles]
        domain_specific = [r for r in roles_used if r.upper() not in generic_roles]

        return {
            'used': sorted(list(roles_used)),
            'generic': generic,
            'domain_specific': domain_specific,
            'generic_count': len(generic),
            'domain_specific_count': len(domain_specific)
        }

    # ========================================================================
    # EXPOSURE DISCOVERY
    # ========================================================================

    def discover_exposure_locations(self, matched_frameworks: Dict[str, Dict],
                                    location_type: str) -> List[str]:
        """
        FRAMEWORK-AGNOSTIC: Discover exposure locations by loading patterns from framework JSON files

        This method makes exposure discovery truly framework/language agnostic by:
        1. Loading exposure location patterns from framework JSON files
        2. Building Joern queries dynamically from those patterns
        3. Using AI to generalize what those locations represent

        Args:
            matched_frameworks: Dict of detected frameworks with their configs
            location_type: Type of exposure location ('endpoints', 'service_methods', 'repository_methods')

        Returns:
            List of discovered exposure locations (format depends on location_type)
        """
        if not matched_frameworks:
            if self.debug:
                print(f"[UTILS] No frameworks provided for exposure discovery")
            return []

        # Extract exposure location patterns from framework configs
        all_patterns = []
        for framework_name, framework_config in matched_frameworks.items():
            exposure_configs = framework_config.get('architecture', {}).get('exposure_locations', {})

            if location_type in exposure_configs:
                location_config = exposure_configs[location_type]
                patterns = location_config.get('patterns', [])

                if patterns:
                    if self.debug:
                        print(f"[UTILS] {framework_name} provides {len(patterns)} patterns for {location_type}")
                    all_patterns.extend(patterns)

        if not all_patterns:
            if self.debug:
                print(f"[UTILS] No patterns found for {location_type} in framework definitions")
            return []

        # Build Joern query dynamically from patterns
        pattern_regex = '|'.join(all_patterns)

        if self.debug:
            print(f"[UTILS] Querying for {location_type} with pattern: {pattern_regex}")

        # Query based on location type
        if location_type == 'endpoints':
            return self._query_endpoint_locations(pattern_regex)
        elif location_type in ['service_methods', 'repository_methods']:
            return self._query_annotated_class_methods(pattern_regex)
        else:
            if self.debug:
                print(f"[UTILS] Unknown location_type: {location_type}")
            return []

    def _query_endpoint_locations(self, pattern: str) -> List[str]:
        """Query for methods with routing annotations (HTTP endpoints)"""
        try:
            query = '''
            cpg.method
              .where(_.annotation.name("({pattern})"))
              .map { m =>
                val routingAnnotations = m.annotation.name("({pattern})").l
                val routeInfo = routingAnnotations.headOption.map { ann =>
                  val httpMethod = ann.name match {
                    case n if n.contains("GetMapping") || n.contains("GET") => "GET"
                    case n if n.contains("PostMapping") || n.contains("POST") => "POST"
                    case n if n.contains("PutMapping") || n.contains("PUT") => "PUT"
                    case n if n.contains("DeleteMapping") || n.contains("DELETE") => "DELETE"
                    case n if n.contains("PatchMapping") || n.contains("PATCH") => "PATCH"
                    case n if n.contains("RequestMapping") || n.contains("Path") => "GET"  // Default
                    case _ => "UNKNOWN"
                  }

                  val route = ann.parameter.assignment
                    .where(_.argument(1).code("value|path"))
                    .argument(2).code.headOption.getOrElse("")
                    .replaceAll("^\\\\\\\"|\\\\\\\"$", "")

                  Map("httpMethod" -> httpMethod, "route" -> route)
                }.getOrElse(Map("httpMethod" -> "UNKNOWN", "route" -> ""))

                s"${routeInfo.getOrElse("httpMethod", "UNKNOWN")} ${routeInfo.getOrElse("route", "")}"
              }.toJson
            '''.replace('{pattern}', pattern)

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                output = result.output.strip()
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return [endpoint for endpoint in data if endpoint and endpoint != "UNKNOWN "]

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Endpoint location query failed: {e}")

        return []

    def _query_annotated_class_methods(self, pattern: str) -> List[str]:
        """Query for public methods in classes with specific annotations"""
        try:
            query = '''
            cpg.typeDecl
              .where(_.annotation.name("({pattern})"))
              .method.isPublic
              .filter(!_.name.startsWith("<"))
              .map { m =>
                s"${m.typeDecl.fullName.headOption.getOrElse("unknown")}.${m.name}"
              }.toJson
            '''.replace('{pattern}', pattern)

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                output = result.output.strip()
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return data[:100]  # Limit to 100 methods

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Annotated class methods query failed: {e}")

        return []

    def _discover_exposures(self) -> List[str]:
        """
        Discover all exposures (places that need protection) using Joern queries

        Returns list of exposure locations based on common patterns:
        - HTTP endpoints: "GET /path"
        - Service methods: "com.example.UserService.getUserById"
        - Data accessors: "com.example.UserRepository.findById"
        - Admin functions: "com.example.AdminController.deleteUser"

        This discovers exposures WITHOUT requiring Compass reports.
        """
        exposures = set()

        # Pattern 1: HTTP endpoints (controllers with @GetMapping, @PostMapping, etc.)
        http_exposures = self._discover_http_endpoints()
        exposures.update(http_exposures)

        # Pattern 2: Service layer methods (public methods in @Service classes)
        service_exposures = self._discover_service_methods()
        exposures.update(service_exposures)

        # Pattern 3: Data accessors (Repository methods, DAO methods)
        data_exposures = self._discover_data_accessors()
        exposures.update(data_exposures)

        return sorted(list(exposures))

    def _discover_http_endpoints(self) -> List[str]:
        """Discover HTTP endpoints via Joern query"""
        try:
            query = '''
            cpg.method
              .where(_.annotation.name(".*Mapping"))
              .map { m =>
                val mappingAnnotations = m.annotation.name(".*Mapping").l
                val routeInfo = mappingAnnotations.headOption.map { ann =>
                  val httpMethod = ann.name match {
                    case n if n.contains("GetMapping") => "GET"
                    case n if n.contains("PostMapping") => "POST"
                    case n if n.contains("PutMapping") => "PUT"
                    case n if n.contains("DeleteMapping") => "DELETE"
                    case n if n.contains("PatchMapping") => "PATCH"
                    case n if n.contains("RequestMapping") => "GET"  // Default
                    case _ => "UNKNOWN"
                  }

                  val route = ann.parameter.assignment
                    .where(_.argument(1).code("value|path"))
                    .argument(2).code.headOption.getOrElse("")
                    .replaceAll("^\\\"|\\\"$", "")

                  Map("httpMethod" -> httpMethod, "route" -> route)
                }.getOrElse(Map("httpMethod" -> "UNKNOWN", "route" -> ""))

                s"${routeInfo.getOrElse("httpMethod", "UNKNOWN")} ${routeInfo.getOrElse("route", "")}"
              }.toJson
            '''

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                import json
                import re

                output = result.output.strip()
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return [endpoint for endpoint in data if endpoint and endpoint != "UNKNOWN "]

        except Exception as e:
            if self.debug:
                print(f"[UTILS] HTTP endpoint discovery failed: {e}")

        return []

    def _discover_exposure_classes(self) -> List[str]:
        """
        Discover ALL classes that could be exposure points by finding classes with web/controller annotations.
        This is architecture-agnostic - uses annotations not naming conventions.
        """
        try:
            # Query for classes with controller/web annotations
            # Covers Spring (@Controller, @RestController, @RequestMapping),
            # JAX-RS (@Path), and other common web framework annotations
            query = '''
            cpg.typeDecl
              .where(_.annotation.name(".*Controller|.*RestController|.*RequestMapping|.*Path|.*Resource|.*Service|.*Repository|.*Component"))
              .fullName.toJson
            '''

            if self.debug:
                print(f"[UTILS] Discovering exposure classes via annotations...")

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                import json
                import re

                output = result.output.strip()

                if self.debug:
                    print(f"[UTILS] Query returned output length: {len(output)}")
                    print(f"[UTILS] Output preview: {output[:200]}")

                # Extract JSON from Scala REPL wrapper
                # Try triple-quote format first
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    class_names = json.loads(json_str)
                    if self.debug:
                        print(f"[UTILS] Discovered {len(class_names)} exposure classes via annotations")
                    return [name for name in class_names if name]
                else:
                    # Try single-quote format
                    match = re.search(r'val \w+: \w+ = "(.*)\"', output, re.DOTALL)
                    if match:
                        json_str = match.group(1)
                        # Unescape the string
                        json_str = json_str.replace('\\\"', '"').replace('\\\\', '\\')
                        class_names = json.loads(json_str)
                        if self.debug:
                            print(f"[UTILS] Discovered {len(class_names)} exposure classes via annotations")
                        return [name for name in class_names if name]
                    else:
                        if self.debug:
                            print(f"[UTILS] Regex did not match Joern output format")
                            print(f"[UTILS] Output was: {output[:500]}")
                        return []
            else:
                if self.debug:
                    if not result.success:
                        print(f"[UTILS] Query failed: {result.error}")
                    elif not result.output:
                        print(f"[UTILS] Query succeeded but returned no output")
                return []

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Exposure class discovery failed: {e}")
                import traceback
                traceback.print_exc()

        return []

    def _discover_service_methods(self) -> List[str]:
        """Discover service layer methods via Joern query"""
        try:
            query = '''
            cpg.typeDecl
              .where(_.annotation.name(".*Service.*"))
              .method.isPublic
              .filter(!_.name.startsWith("<"))
              .map { m =>
                s"${m.typeDecl.fullName.headOption.getOrElse("unknown")}.${m.name}"
              }.toJson
            '''

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                import json
                import re

                output = result.output.strip()
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return data[:100]  # Limit to 100 services

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Service method discovery failed: {e}")

        return []

    def _discover_data_accessors(self) -> List[str]:
        """Discover data accessor methods via Joern query"""
        try:
            query = '''
            cpg.typeDecl
              .where(_.annotation.name(".*Repository.*|.*DAO.*"))
              .method.isPublic
              .filter(!_.name.startsWith("<"))
              .map { m =>
                s"${m.typeDecl.fullName.headOption.getOrElse("unknown")}.${m.name}"
              }.toJson
            '''

            result = self.cpg_tool.query(query)
            if result.success and result.output:
                import json
                import re

                output = result.output.strip()
                match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return data[:100]  # Limit to 100 data accessors

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Data accessor discovery failed: {e}")

        return []

    # ========================================================================
    # REPORT BUILDING
    # ========================================================================

    def build_defense_usage_matrix(self,
                                   exposures: List[Dict],
                                   all_mechanisms: List[Dict],
                                   defense_type: str = 'authorization') -> Dict:
        """
        Build matrix: exposures (rows) × defense options (columns)

        For authorization: rows = endpoints/routes, columns = roles
        Example: 17 endpoints × 2 roles (USER, ADMIN)

        Args:
            exposures: List of exposure dicts with 'method', 'route', 'httpMethod'
            all_mechanisms: List of discovered defense mechanisms
            defense_type: Type of defense being analyzed (for labeling)

        Returns:
            {
                'rows': ['GET /api/owners/{id}', 'POST /api/owners', ...],  # Exposure identifiers
                'columns': ['USER', 'ADMIN'],  # Defense options (roles)
                'matrix': [
                    [True, False],   # GET /api/owners/{id}: protected by USER only
                    [True, True],    # POST /api/owners: protected by USER and ADMIN
                    [False, False],  # DELETE /api/owners/{id}: UNPROTECTED
                ],
                'row_protected': [True, True, False],  # Which rows have any protection
            }
        """
        # Extract all unique roles (defense options) from mechanisms
        all_roles = set()
        for mechanism in all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                all_roles.update(behavior.get('roles', []))

        columns = sorted(list(all_roles))  # Defense options (roles)

        # Build row identifiers from exposures
        rows = []
        for exp in exposures:
            # Format: "GET /api/owners/{id}" or "GET OwnerController.getOwner"
            http_method = exp.get('httpMethod', 'UNKNOWN')
            route = exp.get('route', '')

            # If no route, use simplified method name
            if not route:
                method_full = exp.get('method', 'unknown')
                # Extract class.method from full signature
                # e.g., "org.example.Owner.Controller.getOwner:String(int)" -> "OwnerController.getOwner"
                if ':' in method_full:
                    method_full = method_full.split(':')[0]
                if '.' in method_full:
                    parts = method_full.split('.')
                    # Get last 2 parts (ClassName.methodName)
                    route = '.'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]
                else:
                    route = method_full

            rows.append(f"{http_method} {route}")

        # Build matrix: rows × columns
        matrix = []
        row_protected = []

        for exp in exposures:
            # Find which roles protect this exposure
            protecting_roles = set()
            exp_method = exp.get('method', '')
            exp_class = exp.get('class', '')

            # Search mechanisms for behaviors that match this exposure
            for mechanism in all_mechanisms:
                for behavior in mechanism.get('behaviors', []):
                    # Match by method signature or route
                    if (behavior.get('method') == exp_method and
                        behavior.get('class') == exp_class):
                        protecting_roles.update(behavior.get('roles', []))

            # Create row: True if role protects this exposure
            row = [role in protecting_roles for role in columns]
            matrix.append(row)
            row_protected.append(any(row))

        return {
            'rows': rows,
            'columns': columns,
            'matrix': matrix,
            'row_protected': row_protected
        }

    def build_defense_metadata(self, all_mechanisms: List[Dict]) -> Dict:
        """Build defense metadata section"""
        if not all_mechanisms:
            return {
                'defense_name': 'No Authorization Detected',
                'defense_type': 'N/A',
                'defense_mechanism': 'N/A',
                'defense_patterns': []
            }

        # Build defense name from mechanisms found
        mechanism_names = [f"{m.get('framework', 'unknown')}" for m in all_mechanisms]
        unique_mechanisms = list(set(mechanism_names))

        defense_name = ', '.join(unique_mechanisms[:3])
        if len(unique_mechanisms) > 3:
            defense_name += f" (+ {len(unique_mechanisms) - 3} more)"

        defense_type = 'standard' if all(m.get('type') == 'standard' for m in all_mechanisms) \
                      else 'custom' if all(m.get('type') == 'custom' for m in all_mechanisms) \
                      else 'mixed'

        # Get pattern examples - use actual PatternGroup metadata
        patterns = []
        for mechanism in all_mechanisms[:5]:
            for pattern in mechanism.get('patterns', [])[:2]:
                patterns.append({
                    'target': mechanism.get('pattern_group_target', 'unknown'),
                    'search_type': mechanism.get('pattern_group_search_type', 'unknown'),
                    'pattern': pattern,
                    'description': mechanism.get('pattern_group_description',
                                                 f"{mechanism.get('framework', 'unknown')} authorization pattern")
                })

        return {
            'defense_name': defense_name,
            'defense_type': defense_type,
            'defense_mechanism': 'annotation',  # Simplified
            'defense_patterns': patterns
        }

    def calculate_metrics(self, evidence: Dict) -> Dict:
        """Calculate coverage metrics"""
        coverage_metrics = evidence.get('coverage_metrics', {})

        return {
            'exposures': coverage_metrics.get('exposures', coverage_metrics.get('total_endpoints', 0)),
            'protected': coverage_metrics.get('protected', 0),
            'unprotected': coverage_metrics.get('unprotected', 0),
            'coverage': coverage_metrics.get('coverage', 0)
        }

    def generate_fallback_recommendation(self, coverage: float, unprotected: int,
                                        total: int, eval_result: Dict) -> Dict:
        """
        Minimal fallback when AI is unavailable

        Since every application is different, generic recommendations aren't very useful.
        This fallback just notes that AI analysis is recommended.
        """
        # Determine basic title
        if coverage == 0:
            title = "Authorization analysis requires AI-powered recommendation"
        elif coverage < 90:
            title = f"Authorization coverage at {coverage:.0f}% - AI analysis recommended"
        else:
            title = f"Strong authorization coverage ({coverage:.0f}%)"

        # Minimal summary
        if total == 0:
            summary = "No endpoints detected. If endpoints should exist, verify endpoint detection is working."
        else:
            summary = f"Application has {total} endpoints with {coverage:.0f}% authorization coverage. AI-powered analysis recommended for application-specific guidance."

        # Keep examples as fallback
        design_example = self._generate_design_guidance(coverage, eval_result, self._detect_primary_framework())
        implementation_example = self._generate_implementation_steps(coverage, unprotected, self._detect_primary_framework())
        rationale_example = self._generate_rationale(coverage, self._detect_primary_framework())

        return {
            'title': title,
            'summary': summary,
            'design_recommendation': f"AI-powered analysis recommended for tailored guidance.\n\nExample guidance:\n{design_example}",
            'implementation_recommendation': f"AI-powered analysis recommended for application-specific steps.\n\nExample steps:\n{implementation_example}",
            'rationale': f"AI analysis provides application-specific recommendations rather than generic advice.\n\nExample rationale:\n{rationale_example}"
        }

    def _detect_primary_framework(self) -> str:
        """Detect primary framework from project libraries"""
        libs = self._get_project_libraries_quick()

        # Framework priority order
        if 'spring' in libs or 'spring-security' in libs:
            return 'spring'
        elif 'django' in libs:
            return 'django'
        elif 'express' in libs:
            return 'express'
        elif 'flask' in libs:
            return 'flask'
        else:
            return 'generic'

    def _get_project_libraries_quick(self) -> set:
        """Quick library detection (cached from earlier analysis)"""
        # This was already detected in detect_project_libraries()
        # Return cached result if available
        return getattr(self, '_cached_libraries', set())

    def _generate_design_guidance(self, coverage: float, eval_result: Dict, framework: str) -> str:
        """Generate strategic design guidance"""
        if coverage < 50:
            return (
                "Start by defining roles that align with your business operations. "
                "Think about the actual job functions and responsibilities in your organization - "
                "avoid generic roles like USER and ADMIN. "
                "For example, a veterinary clinic might have roles like VETERINARIAN, RECEPTIONIST, PET_OWNER, and CLINIC_MANAGER. "
                "An enterprise application might have roles like DEVELOPER, SECURITY_ANALYST, COMPLIANCE_OFFICER, and APPLICATION_OWNER. "
                "\n\n"
                "Always create a PUBLIC role for endpoints that don't require authentication. "
                "This ensures every route follows the same pattern - all routes have explicit authorization, "
                "making it clear which endpoints are intentionally public versus accidentally unprotected. "
                "For example: @PreAuthorize(\"hasRole('PUBLIC')\") for public endpoints, "
                "@PreAuthorize(\"hasRole('VETERINARIAN')\") for protected ones. "
                "\n\n"
                "Once you have roles defined, map them to your business functions using an access control matrix. "
                "Look at each endpoint and ask: which roles should access this? "
                "For sensitive operations (delete, admin functions), restrict to specific roles. "
                "For read operations, consider which roles need visibility into that data. "
                "For truly public endpoints (health checks, login pages, static resources), use PUBLIC."
            )
        else:
            consistency = eval_result['consistency']['assessment']
            centralization = eval_result['centralization']['assessment']

            if consistency == 'inconsistent':
                return (
                    "Your authorization patterns are inconsistent across the application. "
                    "Standardize on a single authorization approach to improve maintainability. "
                    "Document which patterns to use for different endpoint types (read, write, delete, admin). "
                    "Ensure all developers follow the same patterns when adding new endpoints."
                )
            elif centralization != 'centralized':
                return (
                    "Your authorization logic is fragmented across multiple approaches. "
                    "Consolidate to a single, centralized authorization mechanism. "
                    "This makes it easier to audit, test, and maintain authorization rules. "
                    "Consider moving authorization checks to a consistent layer (annotations, middleware, or gateway)."
                )
            else:
                return (
                    f"Extend your existing {centralization} authorization approach to the remaining {100-coverage:.0f}% of endpoints. "
                    "Maintain consistency with current patterns to preserve architectural coherence. "
                    "Review unprotected endpoints to determine if they should be public or require authorization."
                )

    def _generate_implementation_steps(self, coverage: float, unprotected: int, framework: str) -> str:
        """Generate framework-specific implementation steps"""
        if framework == 'spring':
            if coverage == 0:
                return (
                    "For Spring Security implementation:\n\n"
                    "1. Add spring-security-web dependency to your pom.xml or build.gradle\n"
                    "2. Create a SecurityConfig class that extends WebSecurityConfigurerAdapter\n"
                    "3. Enable method-level security with @EnableGlobalMethodSecurity(prePostEnabled = true)\n"
                    "4. Define your roles and role hierarchy in the security configuration\n"
                    "5. Apply @PreAuthorize annotations to controller methods (e.g., @PreAuthorize(\"hasRole('ADMIN')\"))\n"
                    "6. For complex expressions, use @PreAuthorize(\"hasRole('ADMIN') or hasRole('MANAGER')\")\n"
                    "7. Test authorization with both positive and negative test cases"
                )
            else:
                return (
                    f"You already have Spring Security configured. To protect the remaining {unprotected} endpoints:\n\n"
                    "1. Review each unprotected endpoint to determine required roles\n"
                    "2. Add @PreAuthorize annotations following existing patterns\n"
                    "3. For read operations: consider hasRole('USER') or more specific roles\n"
                    "4. For write operations: require specific roles like hasRole('EDITOR')\n"
                    "5. For delete/admin operations: restrict to hasRole('ADMIN')\n"
                    "6. Update tests to verify authorization is enforced"
                )

        elif framework == 'django':
            if coverage == 0:
                return (
                    "For Django implementation:\n\n"
                    "1. Use Django's built-in permissions system (django.contrib.auth)\n"
                    "2. Define custom permissions in your models' Meta class\n"
                    "3. Apply @permission_required decorators to views\n"
                    "4. For class-based views, use PermissionRequiredMixin\n"
                    "5. Create groups for role-based access control\n"
                    "6. Assign permissions to groups, users to groups\n"
                    "7. Test with Django's test client and permission checking"
                )
            else:
                return (
                    f"You already have Django permissions configured. To protect the remaining {unprotected} endpoints:\n\n"
                    "1. Add @permission_required decorators to unprotected views\n"
                    "2. For class-based views, add PermissionRequiredMixin to base classes\n"
                    "3. Follow existing permission naming conventions\n"
                    "4. Update tests to verify permissions are checked"
                )

        elif framework == 'express':
            if coverage == 0:
                return (
                    "For Express.js implementation:\n\n"
                    "1. Install authorization middleware (e.g., express-jwt, passport)\n"
                    "2. Create role-checking middleware functions\n"
                    "3. Apply middleware to routes: app.get('/admin', requireRole('admin'), handler)\n"
                    "4. Store user roles in JWT claims or session\n"
                    "5. Define role hierarchy if needed (admin includes editor, etc.)\n"
                    "6. Test with supertest and mock authentication"
                )
            else:
                return (
                    f"You already have authorization middleware. To protect the remaining {unprotected} endpoints:\n\n"
                    "1. Apply existing role-checking middleware to unprotected routes\n"
                    "2. Follow existing patterns for role requirements\n"
                    "3. Update route definitions to include authorization checks\n"
                    "4. Test with both authorized and unauthorized requests"
                )

        else:  # generic
            if coverage == 0:
                return (
                    "For general implementation:\n\n"
                    "1. Choose an authorization framework appropriate for your stack\n"
                    "2. Define roles that map to business functions\n"
                    "3. Implement authorization checks at route/controller entry points\n"
                    "4. Use declarative patterns (annotations, decorators, middleware) rather than imperative checks\n"
                    "5. Store user roles in secure session or token\n"
                    "6. Test authorization with both positive and negative cases"
                )
            else:
                return (
                    f"To protect the remaining {unprotected} endpoints:\n\n"
                    "1. Apply existing authorization patterns consistently\n"
                    "2. Review unprotected endpoints to determine if public access is intentional\n"
                    "3. Add authorization checks using the same mechanism as protected endpoints\n"
                    "4. Update tests to verify authorization"
                )

    def _generate_rationale(self, coverage: float, framework: str) -> str:
        """Generate rationale with trade-offs and alternatives"""
        if framework == 'spring':
            base = (
                "Using Spring Security is the best choice for this application because it's the standard, "
                "well-tested authorization framework for Spring applications. It integrates seamlessly with "
                "Spring MVC and provides both declarative (annotations) and programmatic authorization."
            )
        elif framework == 'django':
            base = (
                "Using Django's built-in permissions system is the best choice because it's integrated with "
                "Django's authentication system and provides a straightforward model for role-based access control."
            )
        elif framework == 'express':
            base = (
                "Using Express middleware for authorization provides flexibility and composability. "
                "Popular options include Passport.js for authentication and custom middleware for role checking."
            )
        else:
            base = (
                "Implementing route-level authorization using your framework's recommended approach ensures "
                "security best practices and maintainability."
            )

        alternatives = (
            "\n\n"
            "Alternative approaches include:\n"
            "- Custom authorization schemes: Provides maximum flexibility but requires careful design and testing. "
            "Can be complex and error-prone. Only recommended if framework solutions don't meet requirements.\n"
            "- Upstream authorization gateway: Large enterprises sometimes use API gateways (Kong, Apigee) "
            "to separate authorization logic from applications. Good for microservices but adds infrastructure complexity.\n"
            "- Attribute-Based Access Control (ABAC): More flexible than role-based, but significantly more complex. "
            "Consider only for applications with complex authorization requirements."
        )

        urgency = (
            f"\n\n"
            f"Current coverage of {coverage:.1f}% indicates "
            f"{'immediate action is needed' if coverage < 50 else 'continued improvement is important' if coverage < 90 else 'the application is well-protected'}. "
            "Authorization prevents unauthorized access to application functionality and protects sensitive data from exposure."
        )

        return base + alternatives + urgency

    # ========================================================================
    # ARCHITECTURAL PATTERN DETECTION HELPERS
    # ========================================================================

    def extract_class_pattern(self, class_name: str) -> str:
        """
        Extract pattern from class name (e.g., UserController → *Controller)

        This helps identify architectural layers by class naming conventions
        """
        if not class_name:
            return "unknown"

        # Get simple class name (last part after dots)
        simple_name = class_name.split('.')[-1]

        # Extract suffix pattern
        common_patterns = [
            'Controller', 'Service', 'Repository', 'DAO', 'Manager',
            'Handler', 'Processor', 'Filter', 'Interceptor', 'Aspect',
            'Config', 'Configuration', 'Gateway', 'Proxy', 'Store'
        ]

        for pattern in common_patterns:
            if simple_name.endswith(pattern):
                return f'*{pattern}'

        # No common pattern found
        return simple_name

    def extract_package(self, class_name: str) -> str:
        """
        Extract package from fully-qualified class name

        Example: com.example.controller.UserController → com.example.controller
        """
        if not class_name or '.' not in class_name:
            return "unknown"

        parts = class_name.split('.')
        # Remove class name, keep package
        return '.'.join(parts[:-1])

    def classify_package(self, package: str) -> str:
        """
        Classify package as controller/service/repository/security/etc.

        Looks for architectural layer indicators in package names
        """
        if not package:
            return "unknown"

        package_lower = package.lower()

        # Check for architectural layer keywords
        if 'controller' in package_lower or 'endpoint' in package_lower or 'resource' in package_lower:
            return "controller"
        elif 'service' in package_lower or 'business' in package_lower:
            return "service"
        elif 'repository' in package_lower or 'dao' in package_lower or 'data' in package_lower:
            return "repository"
        elif 'security' in package_lower or 'auth' in package_lower:
            return "security"
        elif 'filter' in package_lower or 'interceptor' in package_lower:
            return "filter"
        elif 'config' in package_lower or 'configuration' in package_lower:
            return "config"
        elif 'aspect' in package_lower or 'aop' in package_lower:
            return "aspect"
        else:
            return "other"

    def query_interface_implementations(self, class_names: List[str]) -> Dict[str, int]:
        """
        Query Joern for which interfaces these classes implement

        Returns dict mapping interface names to counts
        """
        if not class_names:
            return {}

        # Build query to get interfaces for these classes
        class_filter = '|'.join([f'"{name}"' for name in class_names[:100]])  # Limit to 100 classes

        query = f'''
        cpg.typeDecl
          .fullNameExact({class_filter})
          .inheritsFromTypeFullName
          .dedup
          .toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if not result.success:
                return {}

            output = result.output
            if not output or output.strip() == '[]':
                return {}

            # Parse JSON
            import json
            interfaces = json.loads(output)

            # Count interface implementations
            interface_counts = {}
            for interface_name in interfaces:
                # Extract simple interface name
                simple_name = interface_name.split('.')[-1] if '.' in interface_name else interface_name
                interface_counts[simple_name] = interface_counts.get(simple_name, 0) + 1

            return interface_counts

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Interface query failed: {e}")
            return {}

    def query_architectural_markers(self, class_names: List[str]) -> Dict[str, int]:
        """
        Query Joern for other annotations on these classes (@Service, @Component, etc.)

        Returns dict mapping annotation names to counts
        """
        if not class_names:
            return {}

        # Build query to get all annotations on these classes
        class_filter = '|'.join([f'"{name}"' for name in class_names[:100]])

        query = f'''
        cpg.typeDecl
          .fullNameExact({class_filter})
          .where(_.annotation)
          .annotation
          .name
          .dedup
          .toJson
        '''

        try:
            result = self.cpg_tool.query(query)
            if not result.success:
                return {}

            output = result.output
            if not output or output.strip() == '[]':
                return {}

            # Parse JSON
            import json
            annotations = json.loads(output)

            # Count annotation occurrences
            annotation_counts = {}
            for ann_name in annotations:
                annotation_counts[ann_name] = annotation_counts.get(ann_name, 0) + 1

            return annotation_counts

        except Exception as e:
            if self.debug:
                print(f"[UTILS] Architectural markers query failed: {e}")
            return {}

    def query_caller_relationships(self, method_signatures: List[str]) -> Dict[str, List[str]]:
        """
        Query Joern for who calls these authorized methods

        Returns dict mapping method signature to list of caller class names
        """
        if not method_signatures:
            return {}

        # For performance, sample up to 50 methods
        sample_methods = method_signatures[:50]

        caller_map = {}
        for method_sig in sample_methods:
            try:
                query = f'''
                cpg.method.fullName("{method_sig}")
                  .caller
                  .typeDecl.fullName
                  .dedup
                  .l.take(10)
                  .toJson
                '''

                result = self.cpg_tool.query(query)
                if result.success and result.output:
                    output = result.output
                    if output and output.strip() != '[]':
                        import json
                        callers = json.loads(output)
                        caller_map[method_sig] = callers

            except json.JSONDecodeError:
                # Empty or invalid output from Joern - method probably has no callers
                continue
            except Exception as e:
                if self.debug:
                    print(f"[UTILS] Caller query failed for {method_sig}: {e}")
                continue

        return caller_map
