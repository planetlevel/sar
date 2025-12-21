#!/usr/bin/env python3
"""
Framework Generator - AI-powered framework definition generator

Analyzes a framework/library using Joern CPG and Claude AI to automatically
generate framework JSON definitions for Compass architecture analysis.

Output: frameworks/<framework-name>.json

Usage:
    framework_generator.py <library_path_or_url> <framework_name> [options]

Examples:
    # Local path
    framework_generator.py ~/spring-framework "Spring Framework" --validate frameworks/spring.json
    # Output: frameworks/spring-framework.json

    # GitHub URL (clones to temp directory)
    framework_generator.py https://github.com/apache/commons-exec "Apache Commons Exec" --debug
    # Output: frameworks/apache-commons-exec.json

    # Specific branch/tag
    framework_generator.py https://github.com/apache/commons-exec --branch rel/commons-exec-1.4.0 "Apache Commons Exec 1.4.0" --debug
    # Output: frameworks/apache-commons-exec-1.4.0.json

    # Keep cloned repo for inspection
    framework_generator.py https://github.com/apache/commons-exec "Apache Commons Exec" --keep-clone ~/git/commons-exec --debug

    # Use cached clone if available (faster)
    framework_generator.py https://github.com/apache/commons-exec "Apache Commons Exec" --cache-dir ~/git --debug

Options:
    --validate <json>     Validate against existing framework JSON
    --cpg <path>          CPG file path (default: auto)
    --branch <name>       Git branch to clone (for GitHub URLs)
    --tag <name>          Git tag to clone (for GitHub URLs)
    --keep-clone <dir>    Keep cloned repo at specified directory
    --cache-dir <dir>     Use existing clone from cache directory if available
    --force               Regenerate framework definitions even if they already exist
    --debug               Enable debug output
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from compass.cpg_tool import CpgTool
from compass.project_overview_generator import ProjectOverviewGenerator
from sar.framework_schema import FrameworkDefinition, PatternGroup, Detection, Architecture


class FrameworkGenerator:
    """Generate framework definitions from library source code"""

    # Categories we want to populate
    ARCHITECTURE_CATEGORIES = {
        'routing': {
            'route_definitions': 'Methods or annotations that define HTTP routes/endpoints (e.g., @GetMapping, @Route)',
            'parameters': 'Methods or annotations for extracting route parameters, query params, request bodies',
            'handler_classes': 'Classes or annotations that handle HTTP requests (controllers, servlets, @Controller, etc.)'
        },
        'database': {
            'sql_queries': 'Methods or annotations that execute SQL queries (JDBC, query builders, @Query)',
            'orm_operations': 'ORM methods or annotations (find, save, delete, merge, persist)',
            'jpa_operations': 'JPA-specific operations or annotations (@Entity, @Table, @Column)',
            'repository_pattern': 'Repository/DAO pattern methods or annotations',
            'xpath_queries': 'Methods or annotations for XPath query execution',
            'ldap_queries': 'Methods or annotations for LDAP queries',
            'nosql_operations': 'NoSQL database operations or annotations (MongoDB, Redis, etc.)'
        },
        'execution': {
            'native': 'Methods or annotations that execute native/system commands',
            'expression': 'Methods or annotations that evaluate expressions (OGNL, SpEL, JEXL)',
            'reflection': 'Reflection APIs or annotations that can invoke methods dynamically'
        },
        'data_flow': {
            'input_sources': 'Methods or annotations that read user input (request params, files, streams, @RequestBody)',
            'serialization': 'Serialization/deserialization methods or annotations',
            'xml_parsing': 'XML parsing operations or annotations',
            'file_operations': 'File read/write operations or annotations',
            'data_accessors': {
                'read_by_id': 'Methods that retrieve resources by identifier (findById, getById, loadById, fetchById, queryById, retrieveById, selectById, lookupById, etc.). Typical patterns: Repository/DAO/Service classes with methods containing find/get/load/fetch/query/retrieve/select/lookup/search/read + identifier parameter + returns data object. Also includes methods with @PathVariable, @RequestParam, @Param annotations on ID parameters.',
                'delete_by_id': 'Methods that delete resources by identifier (deleteById, removeById, destroyById, etc.). Typical patterns: Repository/DAO/Service classes with methods containing delete/remove/destroy/purge/erase + identifier parameter.',
                'check_existence': 'Methods that check resource existence by identifier (existsById, containsId, hasId, etc.). Typical patterns: Repository/DAO/Service classes with methods containing exists/contains/has/check/verify + identifier parameter.'
            }
        },
        'defense': {
            'authentication': 'Authentication-related methods, security context access, and annotations. Includes: authenticate() methods, SecurityContextHolder.getContext/setContext/clearContext(), SecurityContext.getAuthentication/setAuthentication(), Principal access, login/logout operations, and annotations like @Authenticated, @WithUser',
            'authorization': 'Authorization/permission checking methods and annotations. Includes: authorize() methods, permission checks, role checks, access control decisions, allowed/disallowed checks, and annotations like @PreAuthorize, @Secured, @RolesAllowed',
            'crypto': 'Cryptographic operations (encryption, hashing, key generation)',
            'input_validation': 'Input validation methods or annotations (@Valid, @Validated)',
            'output_encoding': 'Output encoding/escaping methods or annotations',
            'sanitization': 'Data sanitization methods or annotations',
            'cookie_security': 'Secure cookie handling methods or annotations',
            'secrets': 'Secrets management operations. Includes: credential storage (password hashing, BCrypt, PBKDF2), API key management, token handling (JWT creation/validation), secrets managers (Vault, AWS Secrets Manager, Azure Key Vault), configuration encryption, secure storage methods. Excludes hardcoded secrets detection (that is architectural analysis, not framework API)',
            'privacy': 'Privacy and PII/PHI handling operations. Includes: data anonymization/masking, PII protection methods, consent management, data retention controls, personally identifiable information (PII) handling, protected health information (PHI) handling, financial data protection. Focus on methods that implement privacy controls, not generic getters/setters'
        },
        'presentation': {
            'response_output': 'Methods or annotations that write HTTP responses',
            'redirects': 'Methods or annotations for HTTP redirects',
            'cookies': 'Cookie manipulation methods or annotations',
            'headers': 'HTTP header manipulation methods or annotations'
        },
        'integration': {
            'filesystem': 'Filesystem access methods or annotations',
            'email': 'Email sending methods or annotations',
            'http_clients': 'HTTP client methods or annotations for making requests',
            'messaging': 'Message queue/pub-sub operations or annotations'
        },
        'communication': {
            'http': 'HTTP client methods or annotations',
            'socket': 'Socket operations or annotations',
            'http_server': 'HTTP server methods or annotations'
        },
        'logging': {
            'operations': 'Logging methods or annotations'
        }
    }

    def __init__(self, use_bedrock: bool = True, debug: bool = False):
        """
        Initialize the framework generator

        Args:
            use_bedrock: If True, use AWS Bedrock for AI (default: True)
            debug: Enable debug output
        """
        self.debug = debug
        self.overview_generator = ProjectOverviewGenerator(debug=debug)

    def is_parent_project(self, project_path: str) -> bool:
        """
        Detect if a directory is a parent/aggregator project (has modules but no source code)

        Returns:
            True if this is a parent project that should be skipped
        """
        project_path = os.path.abspath(project_path)

        # Check for Maven parent
        pom_file = os.path.join(project_path, 'pom.xml')
        if os.path.exists(pom_file):
            try:
                with open(pom_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Parent if has <modules> section or packaging=pom
                    if '<modules>' in content or '<packaging>pom</packaging>' in content:
                        return True
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Warning: Could not read {pom_file}: {e}")

        # Check for Gradle multi-project
        settings_gradle = os.path.join(project_path, 'settings.gradle')
        if os.path.exists(settings_gradle):
            # Gradle project with settings.gradle is typically a parent
            return True

        return False

    def enumerate_child_modules(self, parent_path: str, include_test: bool = False) -> List[Dict[str, str]]:
        """
        Find all child modules in a parent project

        Args:
            parent_path: Path to parent project
            include_test: If True, include test modules (default: False)

        Returns:
            List of dicts with keys: 'path', 'artifact_name'
        """
        parent_path = os.path.abspath(parent_path)
        modules = []

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Enumerating child modules in {parent_path}")

        # Maven: Look for <module> entries in parent pom.xml
        pom_file = os.path.join(parent_path, 'pom.xml')
        if os.path.exists(pom_file):
            modules.extend(self._enumerate_maven_modules(parent_path, pom_file))

        # Gradle: Look for subdirectories with build.gradle and src/
        settings_gradle = os.path.join(parent_path, 'settings.gradle')
        if os.path.exists(settings_gradle):
            modules.extend(self._enumerate_gradle_modules(parent_path))

        # Filter out test/docs modules unless explicitly requested
        if not include_test:
            filtered_modules = []
            for module in modules:
                if self._is_production_module(module, parent_path):
                    filtered_modules.append(module)
                elif self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Filtered out: {module['artifact_name']} (test/docs module)")
            modules = filtered_modules

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Found {len(modules)} child modules")

        return modules

    def _is_production_module(self, module: Dict[str, str], parent_path: str) -> bool:
        """Check if a module is a production module (not test fixtures/docs)"""
        name = module['artifact_name'].lower()
        path = module['path']
        rel_path = path.replace(parent_path, '').lower()

        # Filter out docs modules
        if 'docs' in name or 'documentation' in name:
            return False

        # Filter out integration test fixtures (but keep production test utilities like spring-security-test)
        if '/itest/' in rel_path or rel_path.startswith('itest/'):
            return False

        # Filter out test fixtures/embedded test utilities (but not production test JARs)
        if 'embedded-ldap' in name or 'kerberos-test' in name:
            return False

        # Filter out sample/example projects
        if 'sample' in name or 'example' in name:
            return False

        return True

    def _enumerate_maven_modules(self, parent_path: str, pom_file: str) -> List[Dict[str, str]]:
        """Enumerate Maven modules from parent pom.xml"""
        modules = []

        try:
            with open(pom_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract module names from <modules> section
            import re
            modules_match = re.search(r'<modules>(.*?)</modules>', content, re.DOTALL)
            if modules_match:
                module_entries = re.findall(r'<module>([^<]+)</module>', modules_match.group(1))

                for module_rel_path in module_entries:
                    module_path = os.path.join(parent_path, module_rel_path.strip())
                    if os.path.isdir(module_path):
                        # Check if it's a leaf module (not another parent)
                        if not self.is_parent_project(module_path):
                            artifact_name = self._extract_artifact_name(module_path)
                            if artifact_name:
                                modules.append({
                                    'path': module_path,
                                    'artifact_name': artifact_name
                                })
                        else:
                            # Recursively enumerate sub-modules
                            sub_modules = self.enumerate_child_modules(module_path)
                            modules.extend(sub_modules)

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error enumerating Maven modules: {e}")

        return modules

    def _enumerate_gradle_modules(self, parent_path: str) -> List[Dict[str, str]]:
        """Enumerate Gradle subprojects by scanning directories"""
        modules = []

        try:
            # Find all subdirectories with gradle files and src/
            for root, dirs, files in os.walk(parent_path):
                # Skip hidden directories and common non-module dirs
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                          ['build', 'bin', 'out', 'target', 'gradle', 'buildSrc']]

                # Check if this directory has gradle files and is not the parent
                if root != parent_path:
                    # Look for any .gradle file (handles both standard build.gradle and custom module files)
                    gradle_files = [f for f in files if f.endswith('.gradle') or f.endswith('.gradle.kts')]
                    has_gradle_file = len(gradle_files) > 0
                    has_src = 'src' in dirs

                    if has_gradle_file and has_src:
                        # This is a potential module
                        if not self.is_parent_project(root):
                            artifact_name = self._extract_artifact_name(root)
                            if artifact_name:
                                modules.append({
                                    'path': root,
                                    'artifact_name': artifact_name
                                })
                                # Don't recurse into this module's subdirectories
                                dirs.clear()

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error enumerating Gradle modules: {e}")

        return modules

    def _extract_artifact_name(self, module_path: str) -> Optional[str]:
        """
        Extract artifact name from module's build file

        Returns:
            Artifact name (e.g., 'spring-security-core') or None
        """
        # Try Maven pom.xml first
        pom_file = os.path.join(module_path, 'pom.xml')
        if os.path.exists(pom_file):
            try:
                with open(pom_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract artifactId
                    import re
                    match = re.search(r'<artifactId>([^<]+)</artifactId>', content)
                    if match:
                        return match.group(1)
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Warning: Could not parse {pom_file}: {e}")

        # Try Gradle build files
        for gradle_file in ['build.gradle', 'build.gradle.kts']:
            gradle_path = os.path.join(module_path, gradle_file)
            if os.path.exists(gradle_path):
                try:
                    with open(gradle_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Look for archiveBaseName or similar
                        import re
                        match = re.search(r'archivesBaseName\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            return match.group(1)
                except Exception as e:
                    if self.debug:
                        print(f"[FRAMEWORK_GENERATOR] Warning: Could not parse {gradle_path}: {e}")

        # Fallback: Use directory name or look for specific Gradle file
        # Spring Security uses <dirname>/spring-security-<dirname>.gradle naming
        dir_name = os.path.basename(module_path)
        specific_gradle = os.path.join(module_path, f'spring-security-{dir_name}.gradle')
        if os.path.exists(specific_gradle):
            return f'spring-security-{dir_name}'

        # Final fallback: just use directory name
        return dir_name if dir_name else None

    def generate_framework_json_from_shared_cpg(self, parent_cpg, module_path: str,
                                                 framework_name: str, parent_path: str,
                                                 languages: List[str] = None,
                                                 extends: str = None) -> Dict[str, Any]:
        """
        Generate framework JSON for a module using a shared parent CPG

        Args:
            parent_cpg: CpgTool instance for the entire parent project
            module_path: Path to the specific module
            framework_name: Name of the framework/module
            parent_path: Path to the parent project
            languages: Programming languages (auto-detected if None)
            extends: Parent framework to extend

        Returns:
            Framework JSON dictionary
        """
        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Analyzing module {framework_name} from shared CPG")

        # Calculate relative path for filtering
        rel_module_path = os.path.relpath(module_path, parent_path)

        # Discover methods from the shared CPG, filtered by module path
        discovered_methods = self._discover_interesting_methods_from_cpg_filtered(
            parent_cpg, framework_name, rel_module_path
        )

        if not discovered_methods:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Warning: No methods discovered for module {framework_name}")
            architecturally_significant = []
        else:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Discovered {len(discovered_methods)} methods for {framework_name}")
            architecturally_significant = discovered_methods

        # Categorize methods using AI
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Categorizing methods with AI...")

        categorized = self._categorize_methods_with_ai(architecturally_significant, framework_name)

        # Extract data accessor patterns (under data_flow.data_accessors)
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Extracting data accessor patterns...")

        data_accessor_candidates = self._extract_data_accessors_broad(parent_cpg)
        data_accessors = self._filter_data_accessors_with_ai(data_accessor_candidates, framework_name)

        # Build framework JSON
        framework_json = self._build_framework_json(
            framework_name=framework_name,
            languages=languages or ['java'],  # Default to Java for Spring Security
            extends=extends,
            categorized_methods=categorized,
            data_accessors=data_accessors,
            library_path=module_path,
            joern=parent_cpg
        )

        return framework_json

    def generate_framework_json(self, library_path: str, framework_name: str,
                                languages: List[str] = None,
                                extends: str = None,
                                cpg_path: str = 'auto') -> Dict[str, Any]:
        """
        Generate a framework JSON definition

        Args:
            library_path: Path to the framework/library source code
            framework_name: Human-readable name of the framework
            languages: Programming languages supported (auto-detected if None)
            extends: Parent framework to extend (e.g., "java" for Spring)
            cpg_path: CPG file path (default: auto)

        Returns:
            Framework JSON dictionary
        """
        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Analyzing {framework_name} at {library_path}")

        # Create Joern tool and generate CPG
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Generating CPG...")

        # For framework analysis, we don't need to fetch dependencies since we're only
        # analyzing the framework's own source code, not building it as an application
        joern = CpgTool(cpg_path, library_path, auto_generate=(cpg_path == 'auto'), fetch_dependencies=False)

        # Detect languages if not provided
        if languages is None:
            detected = joern.detect_languages()
            languages = list(detected.keys()) if detected else ['java']
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Detected languages: {languages}")

        # Step 1: Discover interesting methods directly from the CPG
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Discovering architecturally interesting methods from CPG...")

        discovered_methods = self._discover_interesting_methods_from_cpg(joern, framework_name)

        if not discovered_methods:
            if self.debug:
                print("[FRAMEWORK_GENERATOR] Warning: No interesting methods discovered from CPG")
            architecturally_significant = []
        else:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Discovered {len(discovered_methods)} interesting methods from CPG")
            architecturally_significant = discovered_methods

        # Categorize methods using AI
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Categorizing methods with AI...")

        categorized = self._categorize_methods_with_ai(architecturally_significant, framework_name)

        # Extract data accessor patterns (under data_flow.data_accessors)
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Extracting data accessor patterns...")

        data_accessor_candidates = self._extract_data_accessors_broad(joern)
        data_accessors = self._filter_data_accessors_with_ai(data_accessor_candidates, framework_name)

        # Build framework JSON
        framework_json = self._build_framework_json(
            framework_name=framework_name,
            languages=languages,
            extends=extends,
            categorized_methods=categorized,
            data_accessors=data_accessors,
            library_path=library_path,
            joern=joern
        )

        return framework_json

    def _discover_interesting_methods_from_cpg(self, joern: CpgTool, framework_name: str) -> List[Dict[str, str]]:
        """
        Discover architecturally interesting methods directly from the CPG

        Uses pattern-based queries to find public methods that are likely to be
        architecturally significant based on:
        - Method names (execute, query, authenticate, etc.)
        - Package names (security, database, http, etc.)
        - Public visibility in public packages

        Returns:
            List of method info dicts with keys: fullSignature, paramNames, paramTypes, className, filename
        """
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Step 1: Finding methods by naming patterns...")

        # Architectural method name patterns - expanded to catch more APIs
        method_patterns = [
            # Execution patterns
            r'.*execute.*', r'.*invoke.*', r'.*eval.*', r'.*run.*', r'.*call.*',
            # Database patterns
            r'.*query.*', r'.*find.*', r'.*save.*', r'.*delete.*', r'.*insert.*',
            r'.*update.*', r'.*persist.*', r'.*merge.*',
            # Security patterns
            r'.*authenticate.*', r'.*authorize.*', r'.*encrypt.*', r'.*decrypt.*',
            r'.*hash.*', r'.*sign.*', r'.*verify.*', r'.*validate.*',
            # HTTP/Communication patterns
            r'.*request.*', r'.*response.*', r'.*send.*', r'.*receive.*',
            r'.*get.*', r'.*post.*', r'.*put.*', r'.*patch.*',
            # Parsing/Transformation
            r'.*parse.*', r'.*transform.*', r'.*convert.*', r'.*serialize.*',
            r'.*deserialize.*', r'.*encode.*', r'.*decode.*',
            # HTTP Client methods (RestTemplate, WebClient)
            r'.*ForObject.*', r'.*ForEntity.*', r'.*exchange.*', r'.*retrieve.*',
            # File operations
            r'.*getBytes.*', r'.*getInputStream.*', r'.*getOriginalFilename.*',
            r'.*transferTo.*', r'.*getResource.*',
            # Mail operations
            r'.*setFrom.*', r'.*setTo.*', r'.*setSubject.*', r'.*setText.*', r'.*setCc.*',
            # Encoding/Escaping (security utilities)
            r'.*escape.*', r'.*unescape.*', r'.*htmlEscape.*', r'.*javaScriptEscape.*',
            r'.*encodeUri.*', r'.*encodePath.*', r'.*encodeQuery.*',
            # Context access
            r'.*getContext.*', r'.*getAuthentication.*', r'.*getRequest.*', r'.*getResponse.*',
            r'.*getRequestAttributes.*',
            # JWT/Token operations
            r'.*withJwkSetUri.*', r'.*withPublicKey.*', r'.*withSecretKey.*',
            # Factory/Builder patterns (important APIs)
            r'.*create.*', r'.*build.*', r'.*with.*',
            # Redirect operations
            r'.*setUrl.*', r'.*redirect.*',
        ]

        methods_by_pattern = {}

        # Query for each pattern
        for pattern in method_patterns:
            query = f'''
            cpg.method
              .isPublic
              .filterNot(_.isExternal)
              .whereNot(_.file.name(".*/test/.*"))
              .whereNot(_.file.name(".*/tests/.*"))
              .whereNot(_.file.name(".*Test\\\\.java"))
              .whereNot(_.file.name(".*Tests\\\\.java"))
              .filter(m => m.name.matches("{pattern}"))
              .filter(m => {{
                // Exclude simple getters/setters unless they have interesting keywords or are from key APIs
                val name = m.name
                if (name.startsWith("get") || name.startsWith("set") || name.startsWith("is")) {{
                  // Keep if it has interesting keywords OR is a multipart/file/mail/context API
                  name.matches(".*execute.*|.*query.*|.*find.*|.*save.*|.*delete.*|.*authenticate.*|.*authorize.*|.*encrypt.*|.*decrypt.*|.*parse.*|.*Bytes.*|.*InputStream.*|.*OriginalFilename.*|.*Resource.*|.*Context.*|.*Authentication.*|.*Request.*|.*Response.*|.*From.*|.*Subject.*|.*Text.*")
                }} else {{
                  true
                }}
              }})
              .map {{ m =>
                val paramNames = m.parameter.name.l.mkString(",")
                val paramTypes = m.parameter.typeFullName.l.mkString(",")
                val pkg = m.typeDecl.fullName
                s"${{m.fullName}}:${{m.signature}}|||${{paramNames}}|||${{paramTypes}}|||${{pkg}}|||${{m.filename}}"
              }}
              .l
              .foreach(println)
            '''

            try:
                results = joern.list_items(query)
                if results:
                    for item in results:
                        parts = item.split('|||')
                        if len(parts) >= 5:
                            sig = parts[0]
                            if sig not in methods_by_pattern:
                                methods_by_pattern[sig] = {
                                    'fullSignature': sig,
                                    'paramNames': parts[1],
                                    'paramTypes': parts[2],
                                    'className': parts[3],
                                    'filename': parts[4]
                                }
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Error searching pattern {pattern}: {e}")

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Found {len(methods_by_pattern)} methods matching naming patterns")

        # Step 2: Find public annotations
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Step 2: Finding public annotations...")

        annotations = self._discover_public_annotations(joern)

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Found {len(annotations)} public annotations")

        # Combine methods and annotations
        all_methods = list(methods_by_pattern.values())

        # Add annotations as special "method" entries so AI can categorize them
        for annot in annotations:
            all_methods.append({
                'fullSignature': annot['full_name'],
                'paramNames': '',
                'paramTypes': '',
                'className': '',
                'filename': '',
                'is_annotation': True,
                'short_name': annot['short_name']
            })

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Total discovered items: {len(all_methods)} ({len(methods_by_pattern)} methods + {len(annotations)} annotations)")

        return all_methods

    def _discover_interesting_methods_from_cpg_filtered(self, joern: CpgTool, framework_name: str,
                                                        module_rel_path: str) -> List[Dict[str, str]]:
        """
        Discover methods from a shared CPG, filtered by module path

        Args:
            joern: Shared CPG tool
            framework_name: Name of the framework/module
            module_rel_path: Relative path to module from parent (e.g., "core", "oauth2/oauth2-jose")

        Returns:
            List of method info dicts for this specific module
        """
        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Finding methods in module path: {module_rel_path}")

        # Normalize module path for regex matching
        # Handle both forward and back slashes, escape dots
        module_path_pattern = module_rel_path.replace('/', '/').replace('\\', '/')

        # Pattern matches paths that either start with module path OR have it after a slash
        # e.g., "core/src/..." or ".../core/src/..."
        path_filter_pattern = f"(^{module_path_pattern}/.*|.*/{module_path_pattern}/.*)"

        # Architectural method name patterns (same as unfiltered version)
        method_patterns = [
            r'.*execute.*', r'.*invoke.*', r'.*eval.*', r'.*run.*', r'.*call.*',
            r'.*query.*', r'.*find.*', r'.*save.*', r'.*delete.*', r'.*insert.*',
            r'.*update.*', r'.*persist.*', r'.*merge.*',
            r'.*authenticate.*', r'.*authorize.*', r'.*encrypt.*', r'.*decrypt.*',
            r'.*hash.*', r'.*sign.*', r'.*verify.*', r'.*validate.*',
            r'.*request.*', r'.*response.*', r'.*send.*', r'.*receive.*',
            r'.*get.*', r'.*post.*', r'.*put.*', r'.*patch.*',
            r'.*parse.*', r'.*transform.*', r'.*convert.*', r'.*serialize.*',
            r'.*deserialize.*', r'.*encode.*', r'.*decode.*',
            r'.*ForObject.*', r'.*ForEntity.*', r'.*exchange.*', r'.*retrieve.*',
            r'.*getBytes.*', r'.*getInputStream.*', r'.*getOriginalFilename.*',
            r'.*transferTo.*', r'.*getResource.*',
            r'.*setFrom.*', r'.*setTo.*', r'.*setSubject.*', r'.*setText.*', r'.*setCc.*',
            r'.*escape.*', r'.*unescape.*', r'.*htmlEscape.*', r'.*javaScriptEscape.*',
            r'.*encodeUri.*', r'.*encodePath.*', r'.*encodeQuery.*',
            r'.*getContext.*', r'.*getAuthentication.*', r'.*getRequest.*', r'.*getResponse.*',
            r'.*getRequestAttributes.*',
            r'.*withJwkSetUri.*', r'.*withPublicKey.*', r'.*withSecretKey.*',
            r'.*create.*', r'.*build.*', r'.*with.*',
            r'.*setUrl.*', r'.*redirect.*',
        ]

        methods_by_pattern = {}

        # Query for each pattern, filtered by module path
        for pattern in method_patterns:
            query = f'''
            cpg.method
              .isPublic
              .filterNot(_.isExternal)
              .where(_.file.name("{path_filter_pattern}"))
              .whereNot(_.file.name(".*/test/.*"))
              .whereNot(_.file.name(".*/tests/.*"))
              .whereNot(_.file.name(".*Test\\\\.java"))
              .whereNot(_.file.name(".*Tests\\\\.java"))
              .filter(m => m.name.matches("{pattern}"))
              .filter(m => {{
                val name = m.name
                if (name.startsWith("get") || name.startsWith("set") || name.startsWith("is")) {{
                  name.matches(".*execute.*|.*query.*|.*find.*|.*save.*|.*delete.*|.*authenticate.*|.*authorize.*|.*encrypt.*|.*decrypt.*|.*parse.*|.*Bytes.*|.*InputStream.*|.*OriginalFilename.*|.*Resource.*|.*Context.*|.*Authentication.*|.*Request.*|.*Response.*|.*From.*|.*Subject.*|.*Text.*")
                }} else {{
                  true
                }}
              }})
              .map {{ m =>
                val paramNames = m.parameter.name.l.mkString(",")
                val paramTypes = m.parameter.typeFullName.l.mkString(",")
                val pkg = m.typeDecl.fullName
                s"${{m.fullName}}:${{m.signature}}|||${{paramNames}}|||${{paramTypes}}|||${{pkg}}|||${{m.filename}}"
              }}
              .l
              .foreach(println)
            '''

            try:
                results = joern.list_items(query)
                if results:
                    for item in results:
                        parts = item.split('|||')
                        if len(parts) >= 5:
                            sig = parts[0]
                            if sig not in methods_by_pattern:
                                methods_by_pattern[sig] = {
                                    'fullSignature': sig,
                                    'paramNames': parts[1],
                                    'paramTypes': parts[2],
                                    'className': parts[3],
                                    'filename': parts[4]
                                }
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Error searching pattern {pattern}: {e}")

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Found {len(methods_by_pattern)} methods in module {framework_name}")

        return list(methods_by_pattern.values())

    def _discover_public_annotations(self, joern: CpgTool) -> List[Dict[str, str]]:
        """
        Discover all public annotations defined in the framework

        Returns:
            List of annotation dicts with keys: full_name, short_name
        """
        # Detect the main source directory
        source_dir = self._detect_main_source_directory(joern)

        # Java annotations are interfaces with @interface keyword
        # Look for types that have @Retention annotation (marker for Java annotations)
        query = f'''
        cpg.annotation
          .name(".*Retention")
          .typeDecl
          .isPublic
          .filter(t =>
            t.filename != "<unknown>" &&
            t.filename != "<empty>" &&
            t.filename.contains("{source_dir}") &&
            !t.filename.contains("/test/") &&
            !t.filename.contains("/tests/") &&
            !t.filename.contains("Test.java") &&
            !t.filename.contains("Tests.java")
          )
          .map(t => s"${{t.fullName}}|||${{t.name}}")
          .l
          .dedup
          .foreach(println)
        '''

        try:
            results = joern.list_items(query)
            annotations = []
            for item in results:
                parts = item.split('|||')
                if len(parts) >= 2:
                    annotations.append({
                        'full_name': parts[0],
                        'short_name': parts[1]
                    })

            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Annotation query returned {len(annotations)} annotations")

            return annotations
        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error discovering annotations: {e}")
            return []

    def _get_commonly_used_methods_from_ai(self, framework_name: str, library_path: str) -> List[str]:
        """
        Ask AI for the most commonly used methods in the framework

        This avoids analyzing tens of thousands of methods by going straight to
        the ones developers actually use in practice.

        Returns:
            List of method signatures (format depends on language)
        """
        # Get some context about the library
        repo_info = self._extract_repository_info(library_path)
        repo_url = repo_info.get('url', 'unknown') if repo_info else 'unknown'

        # Detect language to customize prompt
        from compass.file_tool import FileTool
        file_tool = FileTool(library_path)
        language = file_tool.detect_primary_language()

        if language == 'python':
            prompt = f"""You are analyzing the {framework_name} Python library to identify its most commonly used API methods.

Framework: {framework_name}
Repository: {repo_url}

Based on common usage patterns in real-world Python applications, list the most frequently used functions and methods from this framework that developers actually call in their code.

**Guidelines:**
- Include entry points and commonly called functions
- Include core operations developers must call
- Focus on methods that would appear in typical code examples and tutorials
- For a library like requests, include: get, post, put, delete, request, Session.get, Session.post, etc.
- The number of methods depends on the library's size:
  - Small focused libraries: 10-20 methods
  - Medium libraries: 30-60 methods
  - Large frameworks: 60-100 methods

**Format:**
Return a JSON array of simple method/function names (NOT full signatures):

**Examples for Python:**
[
  "get",
  "post",
  "put",
  "delete",
  "request",
  "Session.get",
  "Session.post",
  "Session.request"
]

**Important:**
- Return ONLY the JSON array
- No markdown code blocks
- No explanatory text
- Just simple method names

Output:"""
        else:
            # Java/JVM languages
            prompt = f"""You are analyzing the {framework_name} library to identify its most commonly used API methods.

Framework: {framework_name}
Repository: {repo_url}

Based on common usage patterns in real-world applications, list the most frequently used classes and methods from this framework that developers actually call in their code.

**Guidelines:**
- Include entry points (constructors, factory methods, builders)
- Include core operations developers must call (execute, save, find, query, commit)
- Include common configuration/setup methods
- Focus on methods that would appear in typical code examples and tutorials
- The number of methods depends on the framework's size and complexity:
  - Small focused libraries: 10-20 methods
  - Medium frameworks: 30-60 methods
  - Large complex frameworks: 60-100 methods
- Do NOT include internal/implementation methods
- Do NOT include simple getters/setters UNLESS they clearly belong to one of these framework categories:
  - Security: authentication, authorization, cryptography, access control
  - Database: persistence, queries, transactions, sessions
  - HTTP: requests, responses, routing, communication
  - Execution: command execution, expression evaluation
  - Integration: external system interaction, messaging
  If a getter/setter is for security context, database session, HTTP request, etc. - include it

**Format:**
Return a JSON array of fully qualified method signatures in this exact format:
fullMethodName:returnType(paramType1,paramType2,...)

**Examples:**
[
  "org.hibernate.SessionFactory.openSession:org.hibernate.Session()",
  "org.hibernate.Session.save:void(java.lang.Object)",
  "org.hibernate.Session.find:java.lang.Object(java.lang.Class,java.lang.Object)",
  "org.hibernate.Query.getResultList:java.util.List()",
  "org.hibernate.Transaction.commit:void()",
  "org.apache.commons.exec.DefaultExecutor.execute:int(org.apache.commons.exec.CommandLine)",
  "org.springframework.web.bind.annotation.RequestMapping.value:java.lang.String[]"
]

**Important:**
- Return ONLY the JSON array
- No markdown code blocks
- No explanatory text
- Just the raw JSON array

Output:"""

        try:
            if self.overview_generator.ai_client.is_available():
                response = self.overview_generator.ai_client.call_claude(prompt)
            else:
                if self.debug:
                    print("[FRAMEWORK_GENERATOR] No AI client available, cannot get common methods")
                return []

            # Parse JSON response
            response = response.strip()

            # Remove markdown code blocks if present
            if response.startswith('```'):
                lines = response.split('\n')
                # Find first line that starts with [ and last line that ends with ]
                start_idx = 0
                end_idx = len(lines)
                for i, line in enumerate(lines):
                    if line.strip().startswith('['):
                        start_idx = i
                        break
                for i in range(len(lines) - 1, -1, -1):
                    if lines[i].strip().endswith(']'):
                        end_idx = i + 1
                        break
                response = '\n'.join(lines[start_idx:end_idx])

            if response.startswith('json'):
                response = response[4:].strip()

            method_signatures = json.loads(response)

            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] AI identified {len(method_signatures)} commonly used methods")

            return method_signatures

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error getting common methods from AI: {e}")
                import traceback
                traceback.print_exc()
            return []

    def _extract_specific_methods(self, joern: CpgTool, target_signatures: List[str]) -> List[Dict[str, str]]:
        """
        Extract only specific methods that match the target signatures

        This is much faster than extracting all 50k methods - we only query for what we need
        """
        if not target_signatures:
            return []

        methods = []

        # Detect language to handle signatures differently
        from compass.file_tool import FileTool
        file_tool = FileTool(joern.project_dir)
        language = file_tool.detect_primary_language()

        if language == 'python':
            # Python: target_signatures are simple method names like "get", "Session.get"
            # Build a pattern to match method names at the end of fullName
            for method_name in target_signatures:
                # Escape special characters for Scala regex
                safe_name = method_name.replace('.', '\\\\.')

                # Query for methods matching this name
                # Python CPG format: filename:<module>.MethodName or filename:<module>.ClassName.MethodName
                # We match the end of the fullName string: .methodName
                query = f"""
                cpg.method
                  .fullName(".*\\\\.{safe_name}$")
                  .filterNot(_.filename.contains("test"))
                  .filterNot(_.filename.contains("Test"))
                  .map {{ m =>
                    val paramNames = m.parameter.name.l.mkString(",")
                    val paramTypes = m.parameter.typeFullName.l.mkString(",")
                    val pkg = m.typeDecl.fullName
                    s"${{m.fullName}}:${{m.signature}}|||${{paramNames}}|||${{paramTypes}}|||${{pkg}}|||${{m.filename}}"
                  }}
                  .l
                """

                result = joern.list_items(query)

                for item in result:
                    parts = item.split('|||')
                    if len(parts) >= 5:
                        method_info = {
                            'fullSignature': parts[0],
                            'paramNames': parts[1],
                            'paramTypes': parts[2],
                            'className': parts[3],
                            'filename': parts[4]
                        }

                        # Extract docstring from Python source
                        method_info['docComment'] = self._extract_python_docstring(
                            method_info['filename'],
                            method_name
                        )

                        methods.append(method_info)
                        break  # Only need one match per method name
        else:
            # Java/JVM: Parse the signature: fullName:returnType(params)
            for sig in target_signatures:
                if ':' not in sig:
                    continue

                full_name = sig.split(':')[0]

                # Escape special characters for Joern query
                safe_name = full_name.replace('"', '\\"')

                # Query for this specific method
                query = f"""
                cpg.method
                  .fullName("{safe_name}")
                  .map {{ m =>
                    val paramNames = m.parameter.name.l.mkString(",")
                    val paramTypes = m.parameter.typeFullName.l.mkString(",")
                    val pkg = m.typeDecl.fullName
                    s"${{m.fullName}}:${{m.signature}}|||${{paramNames}}|||${{paramTypes}}|||${{pkg}}|||${{m.filename}}"
                  }}
                  .l
                """

                result = joern.list_items(query)

                for item in result:
                    parts = item.split('|||')
                    if len(parts) >= 5:
                        method_info = {
                            'fullSignature': parts[0],
                            'paramNames': parts[1],
                            'paramTypes': parts[2],
                            'className': parts[3],
                            'filename': parts[4]
                        }

                        # Try to extract JavaDoc
                        method_info['docComment'] = self._extract_javadoc_from_source(
                            method_info['filename'],
                            method_info['fullSignature'].split(':')[0].split('.')[-1]
                        )

                        methods.append(method_info)
                        break  # Only need one match per signature

        if self.debug:
            print(f"[FRAMEWORK_GENERATOR] Found {len(methods)} of {len(target_signatures)} target methods in CPG")

        return methods

    def _extract_javadoc_from_source(self, filename: str, method_name: str) -> str:
        """Extract JavaDoc comment from source file using file_tool"""
        try:
            # Use file_tool's read_file_lines for better handling
            from compass.file_tool import FileTool
            file_tool = FileTool(os.path.dirname(filename))

            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Look for method declaration
            for i, line in enumerate(lines):
                if f' {method_name}(' in line and ('public' in line or 'protected' in line):
                    # Look backwards for JavaDoc comment
                    javadoc_lines = []
                    j = i - 1
                    in_javadoc = False

                    while j >= 0 and j > i - 30:  # Look up to 30 lines back
                        line_stripped = lines[j].strip()

                        if line_stripped.endswith('*/'):
                            in_javadoc = True
                            j -= 1
                            continue

                        if in_javadoc:
                            if line_stripped.startswith('/**') or line_stripped.startswith('/*'):
                                # Found start of JavaDoc
                                javadoc_lines.reverse()
                                # Remove leading * and whitespace
                                cleaned = []
                                for doc_line in javadoc_lines:
                                    cleaned_line = doc_line.strip().lstrip('*').strip()
                                    if cleaned_line and not cleaned_line.startswith('@'):
                                        cleaned.append(cleaned_line)

                                doc_text = ' '.join(cleaned)
                                # Return first sentence or 300 chars
                                if '.' in doc_text:
                                    first_sentence = doc_text.split('.')[0] + '.'
                                    return first_sentence[:300]
                                return doc_text[:300]
                            else:
                                javadoc_lines.append(line_stripped)

                        j -= 1
                    break

            return ""
        except Exception:
            return ""

    def _extract_python_docstring(self, filename: str, method_name: str) -> str:
        """Extract Python docstring from source file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Handle both "function_name" and "ClassName.method_name" formats
            if '.' in method_name:
                parts = method_name.split('.')
                class_name = parts[0]
                method_name = parts[-1]
                in_class = False
            else:
                class_name = None
                in_class = True  # Looking for module-level function

            # Look for function/method declaration
            for i, line in enumerate(lines):
                # Check if we're entering the right class
                if class_name and f'class {class_name}' in line:
                    in_class = True
                    continue

                # Check if we left the class
                if class_name and in_class and line.startswith('class ') and class_name not in line:
                    in_class = False
                    continue

                # Look for the method/function definition
                if in_class and f'def {method_name}(' in line:
                    # Found the method, look for docstring in next few lines
                    for j in range(i + 1, min(i + 20, len(lines))):
                        doc_line = lines[j].strip()

                        # Check for docstring start (""" or ''')
                        if doc_line.startswith('"""') or doc_line.startswith("'''"):
                            quote = '"""' if doc_line.startswith('"""') else "'''"
                            docstring_lines = []

                            # Single-line docstring
                            if doc_line.count(quote) >= 2:
                                doc_text = doc_line.strip(quote).strip()
                                return doc_text[:300] if doc_text else ""

                            # Multi-line docstring
                            for k in range(j + 1, min(j + 30, len(lines))):
                                if quote in lines[k]:
                                    # Found end of docstring
                                    docstring_lines.append(lines[k].split(quote)[0].strip())
                                    doc_text = ' '.join(docstring_lines).strip()
                                    # Return first sentence or 300 chars
                                    if '.' in doc_text:
                                        first_sentence = doc_text.split('.')[0] + '.'
                                        return first_sentence[:300]
                                    return doc_text[:300]
                                else:
                                    docstring_lines.append(lines[k].strip())

                            # Docstring found but no end found
                            doc_text = ' '.join(docstring_lines).strip()
                            return doc_text[:300] if doc_text else ""

                        # If we hit non-docstring code, stop looking
                        if doc_line and not doc_line.startswith('#'):
                            break

                    return ""

            return ""
        except Exception:
            return ""

    def _get_method_snippet(self, joern: CpgTool, method_fullname: str) -> str:
        """Get first 10 lines of method body"""
        # Escape special characters in method name for query
        safe_name = method_fullname.replace('"', '\\"')

        query = f"""
        cpg.method.fullName("{safe_name}").code.l.headOption.getOrElse("")
        """

        result = joern.query(query)
        if result['success'] and result['output']:
            # Extract code from the result and get first 10 lines
            code = result['output']
            lines = code.split('\n')[:10]
            return '\n'.join(lines)
        return ""

    def _filter_relevant_methods(self, methods: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Filter out noise methods (getters, setters, toString, etc.)"""
        # Common patterns to exclude
        exclude_patterns = [
            'toString', 'hashCode', 'equals', 'clone', 'finalize',
            'wait', 'notify', 'notifyAll',  # Object methods
            'compareTo', 'compare',  # Comparator methods
        ]

        filtered = []
        for method in methods:
            # Extract method name from fullSignature (format: full.name:returnType(params))
            full_sig = method['fullSignature']
            if ':' not in full_sig:
                continue

            method_fullname = full_sig.split(':')[0]
            name = method_fullname.split('.')[-1]

            # Skip if it's a simple getter/setter (getName, setName, isValid, hasValue)
            if (name.startswith('get') or name.startswith('set') or
                name.startswith('is') or name.startswith('has')):
                # But keep if it has interesting keywords
                interesting = ['execute', 'query', 'find', 'save', 'delete', 'create',
                              'send', 'receive', 'connect', 'authenticate', 'validate',
                              'encode', 'decode', 'encrypt', 'decrypt', 'parse', 'load']
                if not any(keyword in name.lower() for keyword in interesting):
                    continue

            # Skip common utility methods
            if any(pattern in name for pattern in exclude_patterns):
                continue

            # Skip test methods
            if 'test' in method['filename'].lower():
                continue

            filtered.append(method)

        return filtered

    def _filter_architecturally_significant_methods(self, methods: List[Dict[str, str]],
                                                   framework_name: str) -> List[Dict[str, str]]:
        """
        Use AI to filter methods, keeping only those that are architecturally significant
        for understanding the framework's behavior and patterns.
        """
        if not methods:
            return []

        # Process in batches to avoid token limits
        batch_size = 100
        all_significant = []

        for i in range(0, len(methods), batch_size):
            batch = methods[i:i + batch_size]

            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Reviewing batch {i//batch_size + 1} ({len(batch)} methods)...")

            significant = self._review_architectural_significance_batch(batch, framework_name)
            all_significant.extend(significant)

        return all_significant

    def _review_architectural_significance_batch(self, methods: List[Dict[str, str]],
                                                 framework_name: str) -> List[Dict[str, str]]:
        """Review a batch of methods for architectural significance"""
        # Build method descriptions
        method_descriptions = []
        for i, method in enumerate(methods):
            desc = f"{i+1}. {method['fullSignature']}\n"
            if method.get('className'):
                desc += f"   Class: {method['className']}\n"
            if method.get('docComment') and method['docComment'].strip():
                doc_lines = method['docComment'].strip().split('\n')[:2]
                desc += f"   Doc: {' '.join(doc_lines)}\n"
            method_descriptions.append(desc)

        prompt = f"""You are reviewing the {framework_name} library to identify architecturally significant methods.

**Your Task:**
Review the following {len(methods)} public methods and identify which ones are architecturally significant for understanding how applications use this framework.

**Keep methods that:**
- Perform data access or persistence (database, file I/O, network)
- Execute queries or commands (SQL, HQL, native queries)
- Handle security operations (authentication, authorization, encryption)
- Manage transactions or sessions
- Process or transform data in business-meaningful ways
- Integrate with external systems (HTTP, messaging, APIs)
- Define application structure (routing, controllers, handlers)
- Execute code dynamically (reflection, scripting, expression evaluation)

**Skip methods that:**
- Are simple utilities (formatters, converters, validators)
- Just manipulate in-memory data structures (lists, maps, sets)
- Are getters/setters for simple configuration properties UNLESS they access:
  * Security contexts (authentication, authorization, principal)
  * Database sessions or transactions
  * HTTP requests or responses
  * Execution contexts or runtime state
- Are builders or factories for simple objects
- Handle logging, debugging, or monitoring
- Manage internal framework state
- Are simple delegates or wrappers

**Methods to Review:**
```
{chr(10).join(method_descriptions)}
```

**Output Format:**
Return a JSON array of method indices (1-based) that are architecturally significant.

**Example:**
[1, 3, 5, 7, 12, 15]

**Important:**
- Only include method numbers that are truly architecturally significant
- Be selective - it's better to skip borderline cases
- Focus on methods that reveal important patterns in application architecture

**Output only the JSON array, no other text.**
"""

        try:
            # Call AI
            if self.overview_generator.ai_client.is_available():
                response_text = self.overview_generator.ai_client.call_claude(prompt)
            else:
                if self.debug:
                    print("[FRAMEWORK_GENERATOR] No AI client available, keeping all methods")
                return methods

            # Parse JSON response
            response_text = response_text.strip()
            if response_text.startswith('```'):
                lines = response_text.split('\n')
                response_text = '\n'.join(lines[1:-1])
            if response_text.startswith('json'):
                response_text = response_text[4:].strip()

            indices = json.loads(response_text)

            # Filter methods based on AI response
            significant_methods = []
            for idx in indices:
                if 1 <= idx <= len(methods):
                    significant_methods.append(methods[idx - 1])

            return significant_methods

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error reviewing batch: {e}")
            # On error, keep all methods to be safe
            return methods

    def _categorize_methods_with_ai(self, methods: List[Dict[str, str]],
                                   framework_name: str) -> Dict[str, List[str]]:
        """Use AI to categorize methods into architecture categories"""
        if not methods:
            return {}

        # Process in batches to avoid token limits
        # Reduced from 200 to 100 to help AI focus better and follow instructions more carefully
        batch_size = 100
        all_categorized = {}

        for i in range(0, len(methods), batch_size):
            batch = methods[i:i + batch_size]

            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Processing batch {i//batch_size + 1} ({len(batch)} methods)...")

            categorized = self._categorize_batch(batch, framework_name)

            # Merge results
            for category, method_list in categorized.items():
                if category not in all_categorized:
                    all_categorized[category] = []
                all_categorized[category].extend(method_list)

        return all_categorized

    def _categorize_batch(self, methods: List[Dict[str, str]],
                         framework_name: str) -> Dict[str, List[str]]:
        """Categorize a batch of methods and annotations using AI"""
        # Build rich descriptions for methods and annotations
        item_descriptions = []
        for i, item in enumerate(methods):
            # Check if this is an annotation
            if item.get('is_annotation'):
                desc = f"\n--- Annotation {i+1} ---\n"
                desc += f"@{item.get('short_name', 'Unknown')}\n"
                desc += f"Full name: {item['fullSignature']}\n"
            else:
                # Regular method
                desc = f"\n--- Method {i+1} ---\n"
                desc += f"Signature: {item['fullSignature']}\n"
                if item.get('className'):
                    desc += f"Class: {item['className']}\n"

                # Add parameter names with types
                if item.get('paramNames') and item.get('paramTypes'):
                    param_names = item['paramNames'].split(',')
                    param_types = item['paramTypes'].split(',')
                    if len(param_names) == len(param_types) and param_names[0]:
                        params = [f"{name}: {ptype}" for name, ptype in zip(param_names, param_types)]
                        desc += f"Parameters: {', '.join(params)}\n"

                # Add JavaDoc if available
                if item.get('docComment') and item['docComment'].strip():
                    doc_lines = item['docComment'].strip().split('\n')[:5]  # First 5 lines
                    desc += f"Documentation: {' '.join(doc_lines)}\n"

                # Add code snippet if available
                if item.get('codeSnippet') and item['codeSnippet'].strip():
                    snippet_lines = item['codeSnippet'].strip().split('\n')[:5]  # First 5 lines
                    desc += f"Code snippet:\n{chr(10).join(snippet_lines)}\n"

            item_descriptions.append(desc)

        prompt = f"""You are analyzing the {framework_name} library to categorize its public API methods and annotations.

**CRITICAL RULE #1 - PATTERN TYPE DISTINCTION:**
There are TWO types of patterns you MUST distinguish:

**ANNOTATION PATTERNS** (for categories like routing.route_definitions, defense.authorization):
- Format: Simple names or short qualified names
- Examples: "GetMapping", "PostMapping", "@RequestMapping", "@PreAuthorize", "@Secured"
- These are annotation names used to match `@GetMapping` in user code
- MUST NOT contain colons (:) or method signatures
- NEVER include method signatures here - only annotation names!

**METHOD SIGNATURES** (for most other categories like database.sql_queries, execution.expression):
- Format: class.method:returnType(params)
- Examples: "org.springframework.jdbc.core.JdbcTemplate.query:java.util.List(java.lang.String)"
- These are method calls used to match actual method invocations in user code
- MUST contain colons (:) and full signature format

**CRITICAL: NEVER mix these types!**
- If you see "org.springframework.web.reactive.result.method.RequestMappingInfo.hashCode:int():int()"
  → This is a METHOD SIGNATURE, NOT an annotation
  → If you want to add it, put it in a method-signature-based category
  → NEVER put it in routing.route_definitions or other annotation-based categories

**CRITICAL RULE #2 - GETTER/SETTER INCLUSION:**
When you see a getter or setter method (getX, setX, isX), DO NOT automatically exclude it. Instead:
1. Look at the CLASS name first - if it contains "Security", "Context", "Authentication", "Session", "Request", "Response", "Connection", "Transaction" → INCLUDE the method
2. Look at the return type - if it returns Security/Auth/Session/Connection/Transaction types → INCLUDE the method
3. Only exclude getters/setters from utility classes like StringUtils, CollectionUtils, NumberUtils

Example: SecurityContextHolder.getContext() MUST be included (returns SecurityContext, class has "Security")
Example: SecurityContext.getAuthentication() MUST be included (returns Authentication, class has "Security")
Example: SessionFactory.getSession() MUST be included (returns Session, class has "Session")
Example: StringUtils.getValue() can be excluded (generic utility class)

Below are {len(methods)} items (methods and annotations) from the framework. Your task is to categorize each into one or more of the following architecture categories:

{self._format_categories_for_prompt()}

**Items to Analyze:**
```
{chr(10).join(item_descriptions[:100])}
```

**Task:**
For each item, analyze ALL available information to determine if it CLEARLY MATCHES one or more categories above:
- **Package name**: Does it contain keywords like "security", "database", "web", "crypto", "auth", etc.?
- **Class name**: What does the class represent (SecurityContext, SessionManager, QueryRunner, etc.)?
- **Method name**: What action does it describe (execute, query, authenticate, getContext, etc.)?
- **Parameters and return types**: What types of objects does it work with (Authentication, SecurityContext, Connection, Session, etc.)?
- **Documentation**: What does the JavaDoc say it does?

**Matching Guidelines:**
- Be INCLUSIVE - include items if they have clear semantic connection to a category
- Match based on the SEMANTIC PURPOSE evident from package/class/method names:
  - If package contains "security" OR class name contains "Security/Auth" OR method works with Authentication/Principal/Context → likely defense category
  - If package contains "database/persistence" OR class name contains "Query/Session/Transaction" OR method works with Connection/ResultSet → likely database category
  - If package contains "web/http/servlet" OR class name contains "Request/Response/Controller" OR method works with HTTP types → likely routing/communication category
  - If method name contains "execute/invoke/eval/run" AND works with commands/expressions → likely execution category

**For Annotations:**
- Match based on what they DECLARE, CONFIGURE, or ENABLE
- Look at annotation name keywords: if it contains "Security", "Authorize", "Allowed", "Authenticated", "Validated", "Mapping", "Route" → match to corresponding category

**For Methods (including getters/setters):**
- Match based on what they ACCESS or MANIPULATE
- **CRITICAL**: Review the CRITICAL RULE at the top of this prompt again before excluding any getter/setter
- Look at CLASS name, return type, and parameter types to determine if the getter/setter is architecturally significant
- Only exclude getters/setters if they're from generic utility classes (String/Collection/Number/File/Path utils)

**Key Principle:**
If the method's package, class name, method name, parameters, or return types clearly indicate it belongs to a tracked architectural category, INCLUDE it. When in doubt, look at the CLASS the method belongs to - if the class is architecturally significant, its public methods likely are too.

**Output Format:**
Return a JSON object where:
- Keys are in "category.subcategory" format (e.g., "database.sql_queries")
- Values are arrays of objects with "signature" and "description" fields

**Example Output:**
{{
  "database.sql_queries": [
    {{
      "signature": "org.example.QueryRunner.execute:int(java.sql.Connection,java.lang.String)",
      "description": "Executes a SQL INSERT, UPDATE, or DELETE statement and returns the number of affected rows"
    }},
    {{
      "signature": "org.example.QueryRunner.query:java.lang.Object(java.sql.Connection,java.lang.String,org.example.ResultHandler)",
      "description": "Executes a SQL SELECT query and processes results with a ResultHandler"
    }}
  ],
  "routing.route_definitions": [
    {{
      "signature": "GetMapping",
      "description": "Annotation that defines HTTP GET endpoint mapping"
    }},
    {{
      "signature": "RequestMapping",
      "description": "Annotation that defines HTTP endpoint mapping with configurable methods and paths"
    }},
    {{
      "signature": "PostMapping",
      "description": "Annotation that defines HTTP POST endpoint mapping"
    }}
  ],
  "defense.authorization": [
    {{
      "signature": "PreAuthorize",
      "description": "Annotation that declares authorization requirements before method execution"
    }},
    {{
      "signature": "Secured",
      "description": "Annotation that specifies security roles required to access a method or class"
    }},
    {{
      "signature": "RolesAllowed",
      "description": "Annotation that specifies which roles are permitted to access a method"
    }}
  ]
}}

**COMMON MISTAKE TO AVOID:**
WRONG:
{{
  "routing.route_definitions": [
    {{
      "signature": "org.springframework.web.reactive.result.method.RequestMappingInfo.hashCode:int():int()",
      "description": "..."
    }}
  ]
}}
This is WRONG because RequestMappingInfo.hashCode is a METHOD SIGNATURE, not an annotation name.

RIGHT:
{{
  "routing.route_definitions": [
    {{
      "signature": "RequestMapping",
      "description": "..."
    }}
  ]
}}

**Important Rules:**
1. For annotations: Copy EXACTLY as shown (e.g., "@GetMapping", "@Controller")
2. For methods: Copy the signature EXACTLY as shown after "Signature:" - format is "fullName:returnType(params)"
3. Do NOT duplicate the signature part (e.g., NOT "name:sig:sig" - just "name:sig")
4. Write clear, concise descriptions (1 sentence) explaining what each item does
5. An item can appear in multiple categories if appropriate
6. Be INCLUSIVE - when unsure, include the item rather than skipping it

**Output only valid JSON, no other text.**
"""

        try:
            # Call AI
            if self.overview_generator.ai_client.is_available():
                response_text = self.overview_generator.ai_client.call_claude(prompt)
            else:
                if self.debug:
                    print("[FRAMEWORK_GENERATOR] No AI client available, skipping categorization")
                return {}

            # Parse JSON response
            # Remove markdown code blocks if present
            response_text = response_text.strip()
            if response_text.startswith('```'):
                lines = response_text.split('\n')
                response_text = '\n'.join(lines[1:-1])
            if response_text.startswith('json'):
                response_text = response_text[4:].strip()

            categorized = json.loads(response_text)

            # VALIDATION: Filter out method signatures from annotation-based categories
            # NOTE: routing.handler_classes is NOT included here because it should contain
            # CLASS-level patterns (e.g., @RestController, @Controller), not method annotations
            annotation_categories = [
                'routing.route_definitions',
                'defense.authorization',
                'defense.authentication',
                'defense.input_validation',
                'database.repository_pattern'
            ]

            filtered_count = 0
            for category in annotation_categories:
                if category in categorized:
                    original_items = categorized[category]
                    filtered_items = []

                    for item in original_items:
                        sig = item.get('signature', '')
                        # Method signature detection: has ':' and '(' and multiple '.'
                        is_method_signature = (':' in sig and '(' in sig and sig.count('.') > 2)

                        if is_method_signature:
                            filtered_count += 1
                            if self.debug:
                                print(f"[FRAMEWORK_GENERATOR] WARNING: Filtered method signature from {category}: {sig}")
                        else:
                            filtered_items.append(item)

                    categorized[category] = filtered_items

            if filtered_count > 0 and self.debug:
                print(f"[FRAMEWORK_GENERATOR] Filtered {filtered_count} method signatures from annotation-based categories")

            # Debug: Check how many items the AI returned and if security context methods are present
            if self.debug:
                total_returned = sum(len(items) for items in categorized.values())
                print(f"[FRAMEWORK_GENERATOR] DEBUG: AI returned {total_returned} items out of {len(methods)} sent")

                # Check for specific methods we expect
                found_context_methods = {}
                for category, items in categorized.items():
                    for item in items:
                        sig = item.get('signature', '')
                        if 'SecurityContextHolder' in sig or 'SecurityContext.get' in sig:
                            if category not in found_context_methods:
                                found_context_methods[category] = []
                            found_context_methods[category].append(sig.split(':')[0].split('.')[-1])

                if found_context_methods:
                    print(f"[FRAMEWORK_GENERATOR] DEBUG: SecurityContext methods found:")
                    for cat, methods_list in found_context_methods.items():
                        print(f"  {cat}: {', '.join(methods_list)}")
                else:
                    print(f"[FRAMEWORK_GENERATOR] DEBUG: NO SecurityContextHolder methods in AI response!")

            return categorized

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error categorizing batch: {e}")
            return {}

    def _extract_data_accessors_broad(self, joern: CpgTool) -> List[Dict]:
        """
        Extract data accessor candidates using BROAD Joern query.
        Cast a wide net - AI will filter down to true data accessor methods.

        Returns:
            List of candidate method dicts with signature, method name, class name, etc.
        """
        if self.debug:
            print("\n[FRAMEWORK_GENERATOR] Extracting data accessor candidates with broad query...")

        # Broad keyword list - ANY of these in method name = candidate
        read_keywords = [
            'find', 'get', 'load', 'fetch', 'query', 'retrieve',
            'select', 'lookup', 'search', 'read', 'obtain', 'access'
        ]

        delete_keywords = [
            'delete', 'remove', 'destroy', 'purge', 'erase', 'drop'
        ]

        check_keywords = [
            'exists', 'contains', 'has', 'check', 'verify', 'validate', 'test'
        ]

        all_keywords = read_keywords + delete_keywords + check_keywords

        # Class name patterns - suggest data access layer
        datastore_keywords = [
            'repository', 'dao', 'service', 'manager', 'store', 'access',
            'persistence', 'data', 'crud', 'jpa', 'entity', 'model',
            'gateway', 'adapter', 'provider', 'handler', 'controller'
        ]

        # Parameter name patterns - suggest ID-like parameters
        id_param_patterns = [
            'id', 'identifier', 'key', 'uuid', 'guid',
            'userid', 'accountid', 'recordid', 'entityid', 'objectid',
            'user_id', 'account_id', 'record_id', 'entity_id', 'object_id'
        ]

        # Build Scala conditions
        keyword_conditions = ' || '.join([f'name.contains("{kw}")' for kw in all_keywords])
        class_conditions = ' || '.join([f'className.contains("{kw}")' for kw in datastore_keywords])
        param_conditions = ' || '.join([f'paramName.contains("{pat}")' for pat in id_param_patterns])

        query = f'''
cpg.method
  .filter {{ m =>
    val name = m.name.toLowerCase
    val className = m.typeDecl.name.headOption.getOrElse("").toLowerCase
    val returnTypeFull = m.methodReturn.typeFullName.toLowerCase
    val paramNames = m.parameter.name.map(_.toLowerCase).l

    // Method name contains ANY data accessor keyword
    val hasAccessorKeyword = {keyword_conditions}

    // Class name suggests data access layer
    val isDatastoreClass = {class_conditions}

    // At least one parameter name suggests an identifier
    val hasIdParam = paramNames.exists {{ paramName =>
      {param_conditions}
    }}

    // Check if method/parameters have data accessor annotations
    val hasAccessorAnnotation = {{
      val methodAnnotations = m.annotation.name.map(_.toLowerCase).l
      val paramAnnotations = m.parameter.annotation.name.map(_.toLowerCase).l

      // Annotations that suggest ID parameters
      methodAnnotations.exists(a =>
        a.contains("pathvariable") || a.contains("requestparam") ||
        a.contains("param") || a.contains("query")
      ) ||
      paramAnnotations.exists(a =>
        a.contains("pathvariable") || a.contains("requestparam") ||
        a.contains("param")
      )
    }}

    // Return type suggests a data object
    val returnsDataObject = {{
      val rt = returnTypeFull
      !rt.contains("void") &&
      (rt.contains(".") || rt.contains("optional") || rt.contains("list") ||
       rt.contains("set") || rt.contains("collection") || rt.contains("iterable") ||
       rt.contains("stream") || rt.contains("map")) &&
      !rt.matches(".*(java\\\\.lang\\\\.(integer|long|string|boolean|double|float))")
    }}

    // Must be public and have at least one parameter
    val isPublic = m.modifier.modifierType.contains("PUBLIC")
    val hasParams = m.parameter.size > 0

    // Match if: (has keyword OR has annotation) AND other criteria
    (hasAccessorKeyword || hasAccessorAnnotation) && isDatastoreClass && isPublic && hasParams && hasIdParam && returnsDataObject
  }}
  .whereNot(_.file.name(".*/test/.*"))
  .whereNot(_.file.name(".*/tests/.*"))
  .map {{ m =>
    val fullSig = m.fullName
    val methodName = m.name
    val className = m.typeDecl.name.headOption.getOrElse("Unknown")
    val packageName = m.typeDecl.fullName.headOption.getOrElse("").split("\\\\.").dropRight(1).mkString(".")
    val returnType = m.methodReturn.typeFullName
    val paramTypes = m.parameter.typeFullName.l.mkString(",")
    val paramNames = m.parameter.name.l.mkString(",")
    s"$fullSig|||$methodName|||$className|||$packageName|||$returnType|||$paramTypes|||$paramNames"
  }}
  .dedup
  .l
'''

        try:
            results = joern.list_items(query)
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Broad query found {len(results)} candidate data accessor methods")

            # Parse results
            candidates = []
            for result in results:
                parts = result.split('|||')
                if len(parts) >= 7:
                    candidates.append({
                        'fullSignature': parts[0],
                        'methodName': parts[1],
                        'className': parts[2],
                        'packageName': parts[3],
                        'returnType': parts[4],
                        'paramTypes': parts[5],
                        'paramNames': parts[6]
                    })

            return candidates

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error in broad data accessor query: {e}")
            return []

    def _filter_data_accessors_with_ai(self, candidates: List[Dict], framework_name: str) -> Dict[str, List[Dict]]:
        """
        Use AI to filter broad candidates down to true data accessor methods.

        Args:
            candidates: Broad list of candidate methods
            framework_name: Name of the framework

        Returns:
            Dict with categorized data accessor patterns: {read_by_id: [...], delete_by_id: [...], check_existence: [...]}
        """
        if not candidates:
            return {'read_by_id': [], 'delete_by_id': [], 'check_existence': []}

        # Process in batches (100 methods at a time)
        batch_size = 100
        all_categorized = {'read_by_id': [], 'delete_by_id': [], 'check_existence': []}

        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]

            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Processing data accessor batch {i//batch_size + 1} ({len(batch)} methods)...")

            # Build method descriptions
            descriptions = []
            for idx, method in enumerate(batch):
                desc = f"\n--- Method {idx+1} ---\n"
                desc += f"Package: {method['packageName']}\n"
                desc += f"Class: {method['className']}\n"
                desc += f"Method: {method['methodName']}\n"
                desc += f"Returns: {method['returnType']}\n"

                if method['paramTypes']:
                    param_types = method['paramTypes'].split(',')
                    param_names = method['paramNames'].split(',') if method['paramNames'] else []
                    if param_names and len(param_names) == len(param_types):
                        params = [f"{name}: {ptype}" for name, ptype in zip(param_names, param_types)]
                    else:
                        params = param_types
                    desc += f"Parameters: {', '.join(params)}\n"

                desc += f"Full signature: {method['fullSignature']}\n"
                descriptions.append(desc)

            prompt = f"""You are analyzing the {framework_name} library to identify data accessor patterns that could be vulnerable to unauthorized access when identifiers are controlled by users.

**What is a data accessor pattern?**
A method that accesses a resource (database record, entity, file, object) using an identifier parameter where the identifier could potentially come from user input (HTTP requests, API calls, external sources). These are potential Direct Object Reference (DOR) vulnerability sinks if the identifier comes from untrusted input without proper authorization checks.

**CRITICAL FOCUS:**
We want methods where the ID parameter is LIKELY TO COME FROM USER INPUT:
- Methods in Controllers, REST endpoints, API handlers (user-facing layer)
- Methods in Services that are called from controllers (business logic layer)
- Methods in Repositories/DAOs that accept simple IDs (data access layer)
- Methods with annotations like @PathVariable, @RequestParam, @Param (ID from HTTP)

**Your Task:**
Analyze {len(batch)} candidate methods and identify data accessor patterns where the identifier is LIKELY CONTROLLED BY A USER. Be STRICT - only include methods that are typically in the path from user input to data access.

**What to INCLUDE:**
✓ Repository/DAO methods accessed by user-facing code: UserRepository.findById(id), OrderDAO.getById(orderId)
✓ Service methods that take simple IDs: UserService.getUser(userId), OrderService.deleteOrder(orderId)
✓ Controller/API methods with ID parameters: getUser(@PathVariable userId), deleteOrder(@PathVariable orderId)
✓ Methods that look up resources by user-supplied keys: findByApiKey(key), getByToken(token)
✓ Methods in public APIs of the library (likely called from application code that handles user input)

**What to EXCLUDE:**
✗ Internal caching methods: CacheManager.get(key) - IDs are system-generated
✗ Internal helper methods: Helper.lookup(id) - not user-facing
✗ Configuration loaders: ConfigLoader.findById(id) - IDs are predefined
✗ System/background task methods: Scheduler.findTask(id) - IDs are internal
✗ Utility/builder methods: Builder.get(), Factory.create() - not data access
✗ Methods in internal/implementation packages that are unlikely to be called from user-facing code
✗ Methods that take complex objects or domain entities (not simple IDs)

**Categories:**
1. **read_by_id**: Retrieves/reads resource by identifier (find, get, load, fetch, query, retrieve, select, lookup, read)
2. **delete_by_id**: Deletes/removes resource by identifier (delete, remove, destroy, purge, erase)
3. **check_existence**: Checks if resource exists by identifier (exists, contains, has, check)

**Decision Guidelines:**

Ask yourself for each method:
1. **Is this method part of a public API?** (Repository, Service, Controller interfaces)
2. **Would application code call this with user-supplied IDs?** (from HTTP requests, API calls)
3. **Is the class in a user-facing layer?** (Controllers, Services, Repositories - NOT internal helpers)
4. **Does the method name suggest user data access?** (findUser, getOrder, deleteAccount)

If YES to most of these → INCLUDE
If NO to most of these → EXCLUDE

**Examples:**
- ✓ INCLUDE: `UserRepository.findById(Long id)` - public repo method, called from services with user IDs
- ✓ INCLUDE: `OrderService.getOrder(String orderId)` - service method taking user-supplied order ID
- ✗ EXCLUDE: `CacheManager.get(String key)` - internal caching, keys are system-generated
- ✗ EXCLUDE: `ConfigLoader.findById(String id)` - configuration loading, IDs are predefined

**Candidates:**
```
{chr(10).join(descriptions)}
```

**Output JSON:**
{{
  "read_by_id": [
    {{"signature": "org.example.UserRepository.findById:User(Long)", "description": "Retrieves user by ID"}},
    ...
  ],
  "delete_by_id": [...],
  "check_existence": [...]
}}

Return ONLY valid JSON, no markdown or other text.
"""

            try:
                if self.overview_generator.ai_client.is_available():
                    response = self.overview_generator.ai_client.call_claude(prompt)
                else:
                    if self.debug:
                        print("[FRAMEWORK_GENERATOR] No AI client available for data accessor filtering")
                    continue

                # Extract JSON
                json_str = response.strip()
                if '```json' in json_str:
                    json_str = json_str.split('```json')[1].split('```')[0]
                elif '```' in json_str:
                    json_str = json_str.split('```')[1].split('```')[0]

                batch_categorized = json.loads(json_str)

                # Merge batch results
                for category in ['read_by_id', 'delete_by_id', 'check_existence']:
                    if category in batch_categorized:
                        all_categorized[category].extend(batch_categorized[category])

            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Error in AI filtering batch: {e}")

        if self.debug:
            total = sum(len(v) for v in all_categorized.values())
            print(f"[FRAMEWORK_GENERATOR] AI filtered to {total} true data accessor patterns:")
            for category, methods in all_categorized.items():
                print(f"[FRAMEWORK_GENERATOR]   {category}: {len(methods)}")

        return all_categorized

    def _format_categories_for_prompt(self) -> str:
        """Format categories for the AI prompt"""
        lines = []
        for category, subcategories in self.ARCHITECTURE_CATEGORIES.items():
            lines.append(f"\n**{category}:**")
            for subcat, description in subcategories.items():
                lines.append(f"  - {category}.{subcat}: {description}")
        return '\n'.join(lines)

    def _build_framework_json(self, framework_name: str, languages: List[str],
                             extends: Optional[str], categorized_methods: Dict[str, List[str]],
                             data_accessors: Dict[str, List[Dict]],
                             library_path: str, joern: CpgTool) -> Dict[str, Any]:
        """Build the framework JSON structure"""
        # Generate detection rules
        detection = self._generate_detection_rules(library_path, framework_name, joern, languages)

        # Build architecture section
        architecture = {}
        for category_path, items in categorized_methods.items():
            if not items:
                continue

            parts = category_path.split('.')
            if len(parts) != 2:
                continue

            category, subcategory = parts

            if category not in architecture:
                architecture[category] = {}

            # Separate methods and annotations
            methods = []
            annotations = []

            for item in items:
                # Extract signature from dict (AI returns {"signature": "...", "description": "..."})
                if isinstance(item, dict):
                    signature = item.get("signature", "")
                else:
                    # Legacy support: item might be a plain string
                    signature = item

                if not signature:
                    continue

                # Check if this is an annotation
                if signature.startswith("@"):
                    # Remove @ prefix for annotation_name patterns
                    clean_sig = signature[1:]  # "@GetMapping" -> "GetMapping"
                    annotations.append(clean_sig)
                elif ':' not in signature:
                    # No colon and no @, likely an annotation without @ prefix
                    annotations.append(signature)
                else:
                    # Has colon, it's a method signature
                    methods.append(signature)

            # Create entries based on what we found
            if methods and annotations:
                # Both - need to create separate entries or combine intelligently
                # For now, prioritize methods
                architecture[category][subcategory] = {
                    "target": "joern",
                    "search_type": "method_signature",
                    "signature": methods
                }
                # Add annotations with a different key if needed
                if annotations:
                    annotation_key = f"{subcategory}_annotations"
                    architecture[category][annotation_key] = {
                        "annotations": {
                            "target": "joern",
                            "search_type": "annotation_name",
                            "pattern": annotations
                        }
                    }
            elif annotations:
                # Only annotations
                architecture[category][subcategory] = {
                    "annotations": {
                        "target": "joern",
                        "search_type": "annotation_name",
                        "pattern": annotations
                    }
                }
            else:
                # Only methods
                architecture[category][subcategory] = {
                    "target": "joern",
                    "search_type": "method_signature",
                    "signature": methods
                }

        # Add data accessor patterns to data_flow category
        if any(data_accessors.values()):
            if 'data_flow' not in architecture:
                architecture['data_flow'] = {}

            architecture['data_flow']['data_accessors'] = {}

            for category, patterns in data_accessors.items():
                if patterns:
                    architecture['data_flow']['data_accessors'][category] = {
                        'target': 'joern',
                        'search_type': 'method_signature',
                        'description': f"Methods that {category.replace('_', ' ')}",
                        'signature': patterns
                    }

        # Build final JSON
        framework_json = {
            "$schema": "../schema/framework-schema.json",
            "name": framework_name,
            "languages": languages
        }

        if extends:
            framework_json["extends"] = extends

        # Add repository information if available
        repo_info = self._extract_repository_info(library_path)
        if repo_info:
            framework_json["repository"] = repo_info
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Repository: {repo_info.get('url')}")
                if 'commit' in repo_info:
                    print(f"[FRAMEWORK_GENERATOR] Commit: {repo_info['commit']}")
                if 'branch' in repo_info:
                    print(f"[FRAMEWORK_GENERATOR] Branch: {repo_info['branch']}")

        framework_json["detection"] = detection
        framework_json["architecture"] = architecture

        return framework_json

    def _extract_repository_info(self, library_path: str) -> Optional[Dict[str, str]]:
        """
        Extract comprehensive Git repository information including URL, branch, commit, and tags

        Args:
            library_path: Path to the library/framework source code

        Returns:
            Dict with repository info:
            {
                'url': 'https://github.com/spring-projects/spring-framework',
                'branch': 'main',
                'commit': 'abc123def456...',
                'tag': 'v5.3.20',  # if on a tag
                'date': '2023-05-15'  # commit date
            }
            or None if not found
        """
        import subprocess
        import re

        try:
            repo_info = {}

            # Get remote URL
            result = subprocess.run(
                ['git', '-C', library_path, 'remote', 'get-url', 'origin'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                remote_url = result.stdout.strip()

                # Convert SSH URLs to HTTPS format
                # git@github.com:user/repo.git -> https://github.com/user/repo
                if remote_url.startswith('git@'):
                    ssh_pattern = r'git@([^:]+):([^/]+)/(.+?)(?:\.git)?$'
                    match = re.match(ssh_pattern, remote_url)
                    if match:
                        host = match.group(1)
                        user = match.group(2)
                        repo = match.group(3)
                        repo_info['url'] = f"https://{host}/{user}/{repo}"
                    else:
                        repo_info['url'] = remote_url
                # Clean up HTTPS URLs (remove .git suffix)
                elif remote_url.startswith('https://') or remote_url.startswith('http://'):
                    repo_info['url'] = remote_url.rstrip('/').removesuffix('.git')
                else:
                    repo_info['url'] = remote_url

            # Get current branch
            result = subprocess.run(
                ['git', '-C', library_path, 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                if branch and branch != 'HEAD':  # Skip detached HEAD state
                    repo_info['branch'] = branch

            # Get current commit hash
            result = subprocess.run(
                ['git', '-C', library_path, 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                commit = result.stdout.strip()
                if commit:
                    repo_info['commit'] = commit

            # Get commit date
            result = subprocess.run(
                ['git', '-C', library_path, 'log', '-1', '--format=%ci'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                commit_date = result.stdout.strip().split()[0]  # Extract just the date part
                if commit_date:
                    repo_info['date'] = commit_date

            # Check if on a tag
            result = subprocess.run(
                ['git', '-C', library_path, 'describe', '--exact-match', '--tags', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tag = result.stdout.strip()
                if tag:
                    repo_info['tag'] = tag

            # If we got at least a URL, return the info
            if 'url' in repo_info:
                return repo_info

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Could not extract repository info: {e}")

        return None

    def _generate_jar_pattern(self, library_path: str, framework_name: str) -> Optional[str]:
        """
        Generate JAR file pattern for the framework based on pom.xml or build.gradle

        Returns:
            JAR pattern like "commons-exec*.jar" or "apache-commons-exec*.jar"
        """
        # Try to extract artifactId from pom.xml
        pom_path = os.path.join(library_path, 'pom.xml')
        if os.path.exists(pom_path):
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(pom_path)
                root = tree.getroot()

                # Get namespace
                ns = {'mvn': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

                # Extract artifactId
                artifact_id = root.find('.//mvn:artifactId', ns)
                if artifact_id is not None and artifact_id.text:
                    # Create pattern: artifact-id*.jar
                    pattern = f"{artifact_id.text}*.jar"
                    return pattern

            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Could not parse pom.xml for JAR pattern: {e}")

        # Try to extract from build.gradle
        gradle_path = os.path.join(library_path, 'build.gradle')
        if os.path.exists(gradle_path):
            try:
                with open(gradle_path, 'r') as f:
                    content = f.read()

                # Look for archivesBaseName or project.name
                import re

                # Try archivesBaseName
                match = re.search(r"archivesBaseName\s*[=:]\s*['\"]([^'\"]+)['\"]", content)
                if match:
                    artifact_name = match.group(1)
                    return f"{artifact_name}*.jar"

                # Try rootProject.name or project.name
                match = re.search(r"(?:rootProject\.)?name\s*[=:]\s*['\"]([^'\"]+)['\"]", content)
                if match:
                    artifact_name = match.group(1)
                    return f"{artifact_name}*.jar"

            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Could not parse build.gradle for JAR pattern: {e}")

        # Fallback: derive from framework name
        # "Apache Commons Exec" -> "commons-exec*.jar"
        # "Spring Framework" -> "spring*.jar"
        fallback_name = framework_name.lower()
        fallback_name = fallback_name.replace(' framework', '')
        fallback_name = fallback_name.replace(' library', '')
        fallback_name = fallback_name.replace('apache ', '')
        fallback_name = fallback_name.strip()
        fallback_name = fallback_name.replace(' ', '-')

        if fallback_name:
            return f"{fallback_name}*.jar"

        return None

    def _generate_detection_rules(self, library_path: str, framework_name: str, joern: CpgTool, languages: List[str]) -> Dict[str, Any]:
        """Generate detection rules for the framework"""
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Generating detection rules...")

        detection = {
            "files": {
                "target": "filename",
                "pattern": []
            },
            "dependencies": {}
        }

        # Find config files
        config_patterns = self._find_config_files(library_path, framework_name)
        if config_patterns:
            detection["files"]["pattern"] = config_patterns

        # Add JAR file pattern based on framework name
        jar_pattern = self._generate_jar_pattern(library_path, framework_name)
        if jar_pattern:
            if jar_pattern not in detection["files"]["pattern"]:
                detection["files"]["pattern"].append(jar_pattern)
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Added JAR pattern: {jar_pattern}")

        # Extract dependency information (language-specific)
        dependencies = self._extract_dependencies(library_path, framework_name, languages)
        if dependencies:
            detection["dependencies"] = dependencies

        # Get import patterns from Joern
        import_patterns = self._extract_import_patterns(joern, framework_name)
        if import_patterns:
            detection["imports"] = {
                "target": "joern",
                "search_type": "import",
                "pattern": import_patterns
            }

        # Extract package hierarchy at multiple depth levels
        if self.debug:
            print("[FRAMEWORK_GENERATOR] Extracting package hierarchy...")
        package_hierarchy = self._extract_package_hierarchy(joern, framework_name)
        if package_hierarchy:
            detection["package_hierarchy"] = {
                "type": "analysis",
                "description": "Packages used in the framework organized by depth level",
                "levels": package_hierarchy
            }
            if self.debug:
                for depth, packages in package_hierarchy.items():
                    print(f"[FRAMEWORK_GENERATOR]   {depth}: {len(packages)} packages")

        return detection

    def _find_config_files(self, library_path: str, framework_name: str) -> List[str]:
        """Find framework-specific configuration files"""
        config_files = []

        # Common framework config file patterns
        search_patterns = [
            "*.xml", "*.properties", "*.yml", "*.yaml", "*.json", "*.config", "*.conf"
        ]

        # Scan for config files in the library root and src directories
        for root, dirs, files in os.walk(library_path):
            # Skip test directories
            if 'test' in root.lower():
                continue
            # Only look in key directories
            if not any(x in root for x in ['src/main/resources', 'src/resources', 'resources']):
                if root != library_path:  # Allow root directory
                    continue

            for file in files:
                # Check if it matches our patterns
                for pattern in search_patterns:
                    import fnmatch
                    if fnmatch.fnmatch(file.lower(), pattern):
                        # Add if it looks framework-specific (not generic like application.properties)
                        if not any(generic in file.lower() for generic in ['application', 'test', 'example', 'sample']):
                            config_files.append(file)
                        break

        # Use AI to filter to framework-relevant files
        if config_files and len(config_files) < 50:
            filtered = self._filter_framework_config_files(config_files, framework_name)
            return filtered[:10]  # Limit to 10 most relevant

        return config_files[:10]  # Limit to first 10

    def _filter_framework_config_files(self, files: List[str], framework_name: str) -> List[str]:
        """Use AI to identify framework-specific config files"""
        prompt = f"""Given these configuration files found in the {framework_name} library, identify which ones are framework-specific configuration files that would indicate the framework is being used in a project.

**Files:**
{chr(10).join([f"- {f}" for f in files])}

**Keep files that:**
- Are specific to {framework_name} framework
- Would typically be present in projects using this framework
- Contain framework-specific configuration

**Skip files that:**
- Are generic (e.g., log4j.properties, application.yml)
- Are examples or samples
- Are internal to the framework itself

**Output Format:**
Return a JSON array of framework-specific filenames.

**Example:**
["struts.xml", "struts-config.xml", "hibernate.cfg.xml"]

**Output only the JSON array, no other text.**
"""

        try:
            if self.overview_generator.ai_client.is_available():
                response_text = self.overview_generator.ai_client.call_claude(prompt)
            else:
                return files

            # Parse JSON response
            response_text = response_text.strip()
            if response_text.startswith('```'):
                lines = response_text.split('\n')
                response_text = '\n'.join(lines[1:-1])
            if response_text.startswith('json'):
                response_text = response_text[4:].strip()

            filtered_files = json.loads(response_text)
            return filtered_files if isinstance(filtered_files, list) else files

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error filtering config files: {e}")
            return files

    def _extract_dependencies(self, library_path: str, framework_name: str, languages: List[str]) -> Dict[str, Any]:
        """Extract dependency information from build files (language-specific)"""
        dependencies = {}

        # Check for pom.xml (Java/Kotlin)
        pom_path = os.path.join(library_path, 'pom.xml')
        if os.path.exists(pom_path):
            pom_deps = self._parse_pom_dependencies(pom_path, framework_name)
            if pom_deps:
                dependencies["pom.xml"] = pom_deps

        # Check for build.gradle (Java/Kotlin)
        gradle_path = os.path.join(library_path, 'build.gradle')
        if os.path.exists(gradle_path):
            gradle_deps = self._parse_gradle_dependencies(gradle_path, framework_name)
            if gradle_deps:
                dependencies["build.gradle"] = gradle_deps

        # Check for Python package files (Python only)
        if 'python' in [lang.lower() for lang in languages]:
            python_deps = self._parse_python_dependencies(library_path, framework_name)
            if python_deps:
                dependencies.update(python_deps)

        return dependencies

    def _parse_pom_dependencies(self, pom_path: str, framework_name: str) -> List[Dict[str, str]]:
        """Parse Maven dependencies from pom.xml"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Get namespace
            ns = {'mvn': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

            # Extract artifactId and groupId
            artifact_id = root.find('.//mvn:artifactId', ns)
            group_id = root.find('.//mvn:groupId', ns)

            if artifact_id is not None and group_id is not None:
                return [{
                    "artifact": artifact_id.text,
                    "library": framework_name
                }]
        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error parsing pom.xml: {e}")

        return []

    def _parse_gradle_dependencies(self, gradle_path: str, framework_name: str) -> List[Dict[str, str]]:
        """Parse Gradle dependencies from build.gradle"""
        try:
            with open(gradle_path, 'r') as f:
                content = f.read()

            # Look for group pattern in the file
            # Try to extract group ID from common patterns
            import re
            group_pattern = re.search(r"group\s*[=:]\s*['\"]([^'\"]+)['\"]", content)

            if group_pattern:
                group_id = group_pattern.group(1)
                return [{
                    "pattern": group_id,
                    "library": framework_name
                }]
        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error parsing build.gradle: {e}")

        return []

    def _parse_python_dependencies(self, library_path: str, framework_name: str) -> Dict[str, List[Dict[str, str]]]:
        """Parse Python package name from setup.py, pyproject.toml, or infer from directory"""
        dependencies = {}

        # Try setup.py first
        setup_path = os.path.join(library_path, 'setup.py')
        if os.path.exists(setup_path):
            try:
                with open(setup_path, 'r') as f:
                    content = f.read()

                # Look for name='package-name' or name="package-name"
                import re
                match = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", content)
                if match:
                    package_name = match.group(1)
                    dep_entry = [{
                        "artifact": package_name,
                        "library": framework_name
                    }]
                    dependencies["requirements.txt"] = dep_entry
                    dependencies["pyproject.toml"] = dep_entry
                    dependencies["setup.py"] = dep_entry
                    return dependencies
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Error parsing setup.py: {e}")

        # Try pyproject.toml
        pyproject_path = os.path.join(library_path, 'pyproject.toml')
        if os.path.exists(pyproject_path):
            try:
                with open(pyproject_path, 'r') as f:
                    content = f.read()

                # Look for name = "package-name" in [project] section
                import re
                match = re.search(r'\[project\].*?name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
                if match:
                    package_name = match.group(1)
                    dep_entry = [{
                        "artifact": package_name,
                        "library": framework_name
                    }]
                    dependencies["requirements.txt"] = dep_entry
                    dependencies["pyproject.toml"] = dep_entry
                    dependencies["setup.py"] = dep_entry
                    return dependencies
            except Exception as e:
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] Error parsing pyproject.toml: {e}")

        # Fallback: derive package name from directory name or framework name
        # e.g., "requests" directory -> "requests" package
        # e.g., "Python Requests Library" -> "requests" package
        dir_name = os.path.basename(library_path)

        # Try directory name first
        if dir_name and dir_name not in ['.', '..', '/', 'tmp']:
            package_name = dir_name.lower().replace('-', '_')
            dep_entry = [{
                "artifact": package_name,
                "library": framework_name
            }]
            dependencies["requirements.txt"] = dep_entry
            dependencies["pyproject.toml"] = dep_entry
            dependencies["setup.py"] = dep_entry
            return dependencies

        return dependencies

    def _detect_main_source_directory(self, joern: CpgTool) -> str:
        """
        Detect the main source directory by analyzing file paths

        Returns:
            Path pattern for main source directory (e.g., "src/main/java/")
        """
        # Get all filenames from typeDecls
        query = "cpg.typeDecl.filename.l.distinct"
        filenames = joern.list_items(query)

        # Filter to only .java files, excluding <unknown>, <empty>, jars, class files, and test files
        java_files = []
        test_patterns = ['test/', 'tests/', 'testing/', '/test/', '/tests/', '/testing/',
                        'Test.java', 'Tests.java', 'IT.java', 'demo/', 'example/', 'sample/',
                        'intTest/', 'jakartaData/', 'quarkusHrPanache/', 'documentation/', 'src/it/']

        for filename in filenames:
            if not filename or filename in ['<unknown>', '<empty>']:
                continue
            if not filename.endswith('.java'):
                continue
            # Skip test files
            if any(pattern in filename for pattern in test_patterns):
                continue
            java_files.append(filename)

        if not java_files:
            return "src/main/java/"  # Default fallback

        # Look for common source directory patterns
        from collections import Counter
        patterns = Counter()

        # Common Java source patterns
        common_patterns = [
            'src/main/java/',
            'src/java/',
            'src/',
            'main/java/',
            'java/',
        ]

        for filepath in java_files:
            # Check which pattern exists in this file
            for pattern in common_patterns:
                if pattern in filepath:
                    patterns[pattern] += 1
                    break

        if patterns:
            # Return most common pattern
            most_common = patterns.most_common(1)[0][0]
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Detected main source pattern: {most_common} ({patterns[most_common]} files)")
            return most_common

        # Ultimate fallback
        return "src/main/java/"

    def _extract_package_hierarchy(self, joern: CpgTool, framework_name: str) -> Dict[str, Any]:
        """
        Extract package hierarchy at multiple depth levels (2, 3, 4 levels deep)
        This identifies the packages DEFINED BY this framework/library (not packages it imports)

        Returns:
            Dict with packages grouped by depth level:
            {
                'depth_2': ['org.hibernate', 'org.springframework', ...],
                'depth_3': ['org.hibernate.sql', 'org.hibernate.query', ...],
                'depth_4': ['org.hibernate.sql.ast', 'org.hibernate.query.sqm', ...]
            }
        """
        try:
            # Detect the main source directory
            source_dir = self._detect_main_source_directory(joern)

            # Query for type declarations in the main source directory only
            # Exclude <unknown>, <empty>, non-.java files, and test files
            query = f"""
            cpg.typeDecl
              .filter(t =>
                t.filename != "<unknown>" &&
                t.filename != "<empty>" &&
                t.filename.endsWith(".java") &&
                t.filename.contains("{source_dir}") &&
                !t.filename.contains("/test/") &&
                !t.filename.contains("/tests/") &&
                !t.filename.contains("/testing/") &&
                !t.filename.contains("Test.java") &&
                !t.filename.contains("Tests.java") &&
                !t.filename.contains("/demo/") &&
                !t.filename.contains("/example/") &&
                !t.filename.contains("/sample/") &&
                !t.filename.contains("src/it/") &&
                !t.filename.contains("/documentation/")
              )
              .fullName.l
            """
            result = joern.list_items(query)

            if not result:
                return {}

            from collections import Counter

            # Track packages at different depth levels
            packages_by_depth = {
                'depth_2': Counter(),
                'depth_3': Counter(),
                'depth_4': Counter()
            }

            for class_name in result:
                if '.' not in class_name:
                    continue

                # Extract package from fully qualified class name
                # e.g., "org.hibernate.query.Query" -> "org.hibernate.query"
                parts = class_name.split('.')

                # Skip if it's not a proper package structure
                if len(parts) < 2:
                    continue

                # Extract packages at different depths
                if len(parts) >= 2:
                    pkg_2 = '.'.join(parts[:2])  # e.g., org.hibernate
                    packages_by_depth['depth_2'][pkg_2] += 1

                if len(parts) >= 3:
                    pkg_3 = '.'.join(parts[:3])  # e.g., org.hibernate.query
                    packages_by_depth['depth_3'][pkg_3] += 1

                if len(parts) >= 4:
                    pkg_4 = '.'.join(parts[:4])  # e.g., org.hibernate.query.sqm
                    packages_by_depth['depth_4'][pkg_4] += 1

            # Build result with top packages at each depth
            result_hierarchy = {}

            for depth_key, counter in packages_by_depth.items():
                # Get top 20 packages at this depth, sorted by frequency
                top_packages = [pkg for pkg, count in counter.most_common(20)]
                if top_packages:
                    result_hierarchy[depth_key] = top_packages

            return result_hierarchy

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error extracting package hierarchy: {e}")
            return {}

    def _extract_import_patterns(self, joern: CpgTool, framework_name: str) -> List[str]:
        """
        Extract import patterns by finding the first level where package tree diverges

        Algorithm:
        1. For each depth level (2, 3, 4...), count unique packages
        2. Find first depth where there are multiple packages (tree diverges)
        3. Take top 5 most frequent packages at that level

        Examples:
        - org.hibernate.query, org.hibernate.sql → depth 2 has 1 package (org.hibernate),
          depth 3 has 2+ packages, so use patterns from depth 3:
          ["org.hibernate.query.*", "org.hibernate.sql.*"]

        - org.contrastsecurity.project1, org.contrastsecurity.project2 →
          depth 3 diverges: ["org.contrastsecurity.project1.*", "org.contrastsecurity.project2.*"]
        """
        try:
            # Detect the main source directory
            source_dir = self._detect_main_source_directory(joern)

            # Query for public type declarations in the main source directory only
            # Exclude test files, documentation, examples
            query = f"""
            cpg.typeDecl
              .isPublic
              .filter(t =>
                t.filename != "<unknown>" &&
                t.filename != "<empty>" &&
                t.filename.endsWith(".java") &&
                t.filename.contains("{source_dir}") &&
                !t.filename.contains("/test/") &&
                !t.filename.contains("/tests/") &&
                !t.filename.contains("/testing/") &&
                !t.filename.contains("Test.java") &&
                !t.filename.contains("Tests.java") &&
                !t.filename.contains("/demo/") &&
                !t.filename.contains("/example/") &&
                !t.filename.contains("/sample/") &&
                !t.filename.contains("src/it/") &&
                !t.filename.contains("/documentation/")
              )
              .fullName.l
            """
            result = joern.list_items(query)

            if not result:
                return []

            from collections import Counter

            # Analyze each depth level (2 through 6)
            max_depth = 6
            depth_analysis = {}

            for depth in range(2, max_depth + 1):
                packages_at_depth = Counter()

                for class_name in result:
                    if '.' not in class_name:
                        continue

                    parts = class_name.split('.')
                    if len(parts) >= depth:
                        # Extract package at this depth
                        pkg = '.'.join(parts[:depth])
                        packages_at_depth[pkg] += 1

                depth_analysis[depth] = packages_at_depth

            # Find first depth with multiple unique packages (divergence point)
            divergence_depth = None
            for depth in range(2, max_depth + 1):
                if len(depth_analysis[depth]) > 1:
                    divergence_depth = depth
                    if self.debug:
                        print(f"[FRAMEWORK_GENERATOR] Package tree diverges at depth {depth} ({len(depth_analysis[depth])} packages)")
                    break

            if not divergence_depth:
                # No divergence found, use depth 2 as fallback
                divergence_depth = 2
                if self.debug:
                    print(f"[FRAMEWORK_GENERATOR] No divergence found, using depth 2 as fallback")

            # Get top 5 packages at divergence depth
            packages = depth_analysis[divergence_depth]
            top_packages = [pkg for pkg, count in packages.most_common(5)]

            # Convert to wildcard patterns
            patterns = [f"{pkg}.*" for pkg in top_packages]

            if self.debug and patterns:
                print(f"[FRAMEWORK_GENERATOR] Import patterns: {patterns}")

            return patterns

        except Exception as e:
            if self.debug:
                print(f"[FRAMEWORK_GENERATOR] Error extracting import patterns: {e}")
            return []
    # ========================================================================
    # INTERNAL MODE: Generate framework from application code (not library)
    # ========================================================================

    def generate_internal_framework(self, joern: 'CpgTool', project_dir: str,
                                   project_info: Dict[str, Any],
                                   endpoints: List[Dict],
                                   app_packages: List[str]) -> Optional[Dict[str, Any]]:
        """
        Generate internal framework definition from application code

        Uses two approaches:
        1. Common path analysis - find methods used across multiple routes
        2. Semantic name matching - find methods with security-relevant names

        Args:
            joern: CpgTool instance (CPG already loaded)
            project_dir: Application directory
            project_info: Project metadata (name, version, languages)
            endpoints: List of endpoint dicts from analyze_endpoints()
            app_packages: List of application package prefixes (e.g., ['com.contrastsecurity', 'org.springframework.samples'])

        Returns:
            Framework JSON dict or None if insufficient data
        """
        if self.debug:
            print(f"[INTERNAL_FRAMEWORK] Generating internal framework for {project_info.get('name', 'application')}")
            print(f"[INTERNAL_FRAMEWORK] Application packages: {app_packages}")

        if len(endpoints) < 3:
            if self.debug:
                print("[INTERNAL_FRAMEWORK] Not enough endpoints (need at least 3)")
            return None

        # Approach 1: Find methods common across sampled routes
        common_methods = self._find_common_methods(joern, endpoints, app_packages)

        # Approach 2: Find methods with semantically interesting names
        semantic_methods = self._find_semantic_methods(joern, app_packages)

        # Approach 3: Find security and architecture-relevant annotations
        annotation_patterns = self._find_internal_annotations(joern, app_packages)

        # Merge all three approaches
        all_methods = self._merge_internal_methods(common_methods, semantic_methods)

        # Merge in annotations (as a separate category since they're not method signatures)
        if annotation_patterns:
            for category, patterns in annotation_patterns.items():
                if category not in all_methods:
                    all_methods[category] = []
                all_methods[category].extend(patterns)

        if not all_methods:
            if self.debug:
                print("[INTERNAL_FRAMEWORK] No internal methods found")
            return None

        # Build framework JSON
        framework_json = self._build_internal_framework_json(
            all_methods,
            project_info,
            len(endpoints)
        )

        if self.debug:
            total_sigs = sum(len(sigs) for sigs in all_methods.values())
            print(f"[INTERNAL_FRAMEWORK] Generated internal framework with {total_sigs} signatures across {len(all_methods)} categories")

        return framework_json

    def _find_common_methods(self, joern: 'CpgTool', endpoints: List[Dict],
                            app_packages: List[str]) -> Dict[str, List[str]]:
        """
        Find internal methods that are common across multiple sampled routes

        Args:
            joern: CpgTool instance
            endpoints: List of endpoints
            app_packages: Application package prefixes

        Returns:
            Dict mapping category -> list of method signatures
        """
        if self.debug:
            print(f"[INTERNAL_FRAMEWORK] Finding common methods across {len(endpoints)} endpoints")

        # Sample up to 10 random endpoints
        import random
        sample_size = min(10, len(endpoints))
        sampled = random.sample(endpoints, sample_size)

        if self.debug:
            print(f"[INTERNAL_FRAMEWORK] Sampled {sample_size} endpoints for common path analysis")

        # Get internal calls for each sampled endpoint
        endpoint_calls = {}
        for ep in sampled:
            controller = ep.get('controller', '')
            method_name = ep.get('method_name', '')

            if not controller or not method_name:
                continue

            calls = self._get_internal_calls_for_endpoint(joern, controller, method_name, app_packages)
            if calls:
                key = f"{controller}.{method_name}"
                endpoint_calls[key] = set(calls)

        if self.debug:
            print(f"[INTERNAL_FRAMEWORK] Got call graphs for {len(endpoint_calls)} endpoints")

        # Find methods called by at least 3 endpoints (common threshold)
        from collections import Counter
        call_counter = Counter()

        for endpoint_key, calls in endpoint_calls.items():
            for call in calls:
                call_counter[call] += 1

        # Filter to methods called by at least 3 endpoints
        threshold = min(3, max(2, sample_size // 3))  # At least 2, max 3
        common_calls = [call for call, count in call_counter.items() if count >= threshold]

        if self.debug:
            print(f"[INTERNAL_FRAMEWORK] Found {len(common_calls)} common methods (threshold: {threshold}/{sample_size})")

        # Categorize by naming patterns
        return self._categorize_internal_methods(common_calls)

    def _get_internal_calls_for_endpoint(self, joern: 'CpgTool', controller: str,
                                        method_name: str, app_packages: List[str]) -> List[str]:
        """
        Get all internal method calls from an endpoint using call graph traversal

        Args:
            joern: CpgTool instance
            controller: Controller class name
            method_name: Method name
            app_packages: Application package prefixes

        Returns:
            List of internal method signatures
        """
        # Build package filter for Scala
        package_filters = ' || '.join(f'pkg.startsWith("{pkg}")' for pkg in app_packages)

        # DEBUG: Investigate isExternal flag behavior
        query = f'''
    // Find the endpoint method
    val entryMethod = cpg.method
      .fullName(".*{controller}.*{method_name}.*")
      .headOption

    // Traverse call graph to find internal calls
    def getInternalCalls(m: io.shiftleft.codepropertygraph.generated.nodes.Method,
                     visited: Set[String] = Set(),
                     depth: Int = 0): Set[String] = {{
      if (visited.contains(m.fullName) || depth > 15) {{
    Set()
      }} else {{
    val newVisited = visited + m.fullName

    // Get all calls from this method
    val directCalls = m.ast.isCall
      .callee
      .map(c => {{
        val fname = c.fullName
        val isExt = c.isExternal
        val pkg = fname

        // DEBUG: Print first 20 calls to see isExternal values
        if (depth < 2) {{
          println(s"DEBUG_CALL: method=$fname | isExternal=$isExt | package_match=${{({package_filters})}}")
        }}

        (fname, isExt)
      }})
      .filter {{ case (fname, isExt) =>
        // Filter by BOTH isExternal AND package prefix
        val matchesPackage = {package_filters}
        !isExt && matchesPackage
      }}
      .map(_._1)  // Extract just the fullName
      .l
      .toSet

    // Recursively get calls from callees (also filter by isExternal)
    val transitiveCalls = m.ast.isCall
      .callee
      .filterNot(_.isExternal)  // Filter external at the callee level too
      .filter(c => {{
        val pkg = c.fullName
        {package_filters}
      }})
      .l
      .flatMap(callee => getInternalCalls(callee, newVisited, depth + 1))
      .toSet

    directCalls ++ transitiveCalls
      }}
    }}

    entryMethod.map {{ m =>
      getInternalCalls(m).foreach(println)
    }}.getOrElse(List())
    '''

        try:
            return joern.list_items(query)
        except Exception as e:
            if self.debug:
                print(f"[INTERNAL_FRAMEWORK] Error getting calls for {controller}.{method_name}: {e}")
            return []

    def _find_semantic_methods(self, joern: 'CpgTool', app_packages: List[str]) -> Dict[str, List[str]]:
        """
        Find internal methods with semantically interesting names

        Args:
            joern: CpgTool instance
            app_packages: Application package prefixes

        Returns:
            Dict mapping category -> list of method signatures
        """
        if self.debug:
            print("[INTERNAL_FRAMEWORK] Finding methods with semantic patterns")

        # Semantic patterns organized by category (using existing ARCHITECTURE_CATEGORIES)
        semantic_patterns = {
            'defense.authentication': [
                r'.*authenticate.*',
                r'.*login.*',
                r'.*signin.*',
                r'.*isAuthenticated.*',
                r'.*checkAuth.*',
                r'.*verifyUser.*',
                r'.*validateToken.*',
                r'.*verifyToken.*',
            ],
            'defense.authorization': [
                r'.*authorize.*',
                r'.*hasPermission.*',
                r'.*canAccess.*',
                r'.*isAllowed.*',
                r'.*allowed.*',
                r'.*disallowed.*',
                r'.*checkAccess.*',
                r'.*hasRole.*',
                r'.*requireRole.*',
            ],
            'defense.crypto': [
                r'.*encrypt.*',
                r'.*decrypt.*',
                r'.*hash.*',
                r'.*sign.*',
                r'.*generateKey.*',
            ],
            'defense.sanitization': [
                r'.*sanitize.*',
                r'.*escape.*',
                r'.*escapeHtml.*',
                r'.*escapeSql.*',
                r'.*clean.*',
            ],
            'defense.input_validation': [
                r'.*validate.*',
                r'.*isValid.*',
                r'.*check.*',
            ],
            'data_flow.file_operations': [
                r'.*loadFile.*',
                r'.*readFile.*',
                r'.*writeFile.*',
                r'.*saveFile.*',
                r'.*uploadFile.*',
                r'.*downloadFile.*',
                r'.*deleteFile.*',
            ],
            'execution.native': [
                r'.*execute.*',
                r'.*exec.*',
                r'.*invoke.*',
                r'.*spawn.*',
                r'.*run.*Command.*',
            ],
            'execution.reflection': [
                r'.*invoke.*',
                r'.*callMethod.*',
                r'.*newInstance.*',
                r'.*forName.*',
            ],
        }

        results = {}
        # CRITICAL: Only include methods whose fullName STARTS WITH app packages
        package_filters = ' || '.join(f'pkg.startsWith("{pkg}")' for pkg in app_packages)

        for category, patterns in semantic_patterns.items():
            category_methods = []

            for pattern in patterns:
                query = f'''
    cpg.method
      .whereNot(_.file.name(".*/test/.*"))      // Exclude test directories
      .whereNot(_.file.name(".*/tests/.*"))
      .whereNot(_.file.name(".*Test\\\\.java"))
      .whereNot(_.file.name(".*Tests\\\\.java"))
      .whereNot(_.file.name(".*_test\\\\.py"))
      .filter(m => m.name.matches("{pattern}"))  // Match pattern
      .filter(m => {{
    val pkg = m.fullName
    {package_filters}  // ONLY application packages
      }})
      .fullName
      .l
      .foreach(println)
    '''

                try:
                    methods = joern.list_items(query)
                    category_methods.extend(methods)
                except Exception as e:
                    if self.debug:
                        print(f"[INTERNAL_FRAMEWORK] Error searching pattern {pattern}: {e}")

            if category_methods:
                results[category] = list(set(category_methods))  # Deduplicate

        if self.debug:
            total = sum(len(methods) for methods in results.values())
            print(f"[INTERNAL_FRAMEWORK] Found {total} methods via semantic matching across {len(results)} categories")

        return results

    def _find_internal_annotations(self, joern: 'CpgTool', app_packages: List[str]) -> Dict[str, List[str]]:
        """
        Find security and architecture-relevant annotations in application code using AI classification

        Two-step approach:
        1. Extract ALL annotations from application packages using Joern
        2. Use AI to classify which are architecturally significant and categorize them

        Args:
            joern: CpgTool instance
            app_packages: Application package prefixes

        Returns:
            Dict mapping category -> list of annotation patterns
        """
        if self.debug:
            print("[INTERNAL_FRAMEWORK] Extracting all annotations from application packages...")

        # Step 1: Extract ALL annotations from application packages
        package_filters = ' || '.join(f'pkg.startsWith("{pkg}")' for pkg in app_packages)

        query = f'''
    cpg.annotation
      .filter(a => {{
        // Get the method or class this annotation is attached to
        val annotatedMethod = a.method.headOption
        val annotatedClass = a.typeDecl.headOption

        // Check if either is in application packages
        val methodInApp = annotatedMethod.exists(m => {{
          val pkg = m.fullName
          {package_filters}
        }})

        val classInApp = annotatedClass.exists(c => {{
          val pkg = c.fullName
          {package_filters}
        }})

        methodInApp || classInApp
      }})
      .whereNot(_.file.name(".*/test/.*"))      // Exclude test files
      .whereNot(_.file.name(".*/tests/.*"))
      .whereNot(_.file.name(".*Test\\\\.java"))
      .whereNot(_.file.name(".*Tests\\\\.java"))
      .whereNot(_.file.name(".*_test\\\\.py"))
      .map(a => {{
        val annotatedMethod = a.method.headOption.map(_.fullName).getOrElse("")
        val annotatedClass = a.typeDecl.headOption.map(_.fullName).getOrElse("")
        val annotatedElement = if (annotatedMethod.nonEmpty) annotatedMethod else annotatedClass
        s"${{a.fullName}}|||${{a.name}}|||${{annotatedElement}}"
      }})
      .l
      .dedup
      .foreach(println)
    '''

        try:
            results_raw = joern.list_items(query)

            # Parse results into structured format
            annotations = []
            seen = set()
            for item in results_raw:
                parts = item.split('|||')
                if len(parts) >= 3:
                    full_name = parts[0]
                    short_name = parts[1]
                    annotated_element = parts[2]

                    # Deduplicate by full name
                    if full_name not in seen:
                        seen.add(full_name)
                        annotations.append({
                            'full_name': full_name,
                            'short_name': short_name,
                            'annotated_element': annotated_element
                        })

            if self.debug:
                print(f"[INTERNAL_FRAMEWORK] Found {len(annotations)} unique annotations in application code")

            if not annotations:
                return {}

            # Step 2: Use AI to classify annotations
            if self.debug:
                print("[INTERNAL_FRAMEWORK] Asking AI to classify annotations...")

            categorized = self._classify_annotations_with_ai(annotations)

            if self.debug:
                total = sum(len(annots) for annots in categorized.values())
                print(f"[INTERNAL_FRAMEWORK] AI classified {total} annotations as architecturally significant across {len(categorized)} categories")

            return categorized

        except Exception as e:
            if self.debug:
                print(f"[INTERNAL_FRAMEWORK] Error extracting annotations: {e}")
                import traceback
                traceback.print_exc()
            return {}

    def _classify_annotations_with_ai(self, annotations: List[Dict[str, str]]) -> Dict[str, List[str]]:
        """
        Use AI to classify annotations into architecture categories

        Args:
            annotations: List of annotation dicts with keys: full_name, short_name, annotated_element

        Returns:
            Dict mapping category -> list of annotation full names
        """
        if not annotations:
            return {}

        # Build annotation descriptions for AI
        annotation_descriptions = []
        for i, annot in enumerate(annotations):
            desc = f"{i+1}. @{annot['short_name']} ({annot['full_name']})"
            if annot['annotated_element']:
                # Show what it's attached to
                element = annot['annotated_element'].split('.')[-1] if '.' in annot['annotated_element'] else annot['annotated_element']
                desc += f" - used on: {element}"
            annotation_descriptions.append(desc)

        prompt = f"""You are analyzing custom application-defined annotations to identify which are architecturally significant.

**Annotations Found:**
```
{chr(10).join(annotation_descriptions)}
```

**Your Task:**
Review these annotations and identify which are architecturally significant (security, data access, routing, validation, etc.). SKIP framework annotations like Spring's @Controller, @Autowired - we only want custom application-defined annotations.

**Categorize into:**
- **defense.authorization**: Custom authorization/permission checking (@RequireRole, @CheckPermission, @Authorize)
- **defense.authentication**: Custom authentication (@RequireAuth, @Authenticated, @CheckAuth)
- **defense.input_validation**: Custom validation (@ValidateInput, @CheckFormat)
- **routing.route_definitions**: Custom routing/endpoint METHOD annotations (@PublicEndpoint, @InternalOnly, @AdminOnly)
- **database.repository_pattern**: Custom data access markers (@ReadOnlyTransaction, @WriteTransaction)
- **integration.caching**: Custom caching annotations

**NOTE**: Do NOT categorize as routing.handler_classes - that category is for CLASS-level patterns only, not method annotations.

**Output Format:**
Return a JSON object where keys are "category.subcategory" and values are arrays of annotation indices (1-based).

**Example:**
{{
  "defense.authorization": [1, 3, 5],
  "defense.authentication": [2, 7]
}}

**Important:**
- ONLY include custom application-defined annotations (not framework annotations)
- ONLY include architecturally significant annotations
- Return empty object {{}} if no significant annotations found
- Output ONLY valid JSON, no other text

Output:"""

        try:
            # Call AI
            if self.overview_generator.ai_client.is_available():
                response_text = self.overview_generator.ai_client.call_claude(prompt)
            else:
                if self.debug:
                    print("[INTERNAL_FRAMEWORK] No AI client available, skipping annotation classification")
                return {}

            # Parse JSON response
            response_text = response_text.strip()
            if response_text.startswith('```'):
                lines = response_text.split('\n')
                # Find first line that starts with { and last line that ends with }
                start_idx = 0
                end_idx = len(lines)
                for i, line in enumerate(lines):
                    if line.strip().startswith('{'):
                        start_idx = i
                        break
                for i in range(len(lines) - 1, -1, -1):
                    if lines[i].strip().endswith('}'):
                        end_idx = i + 1
                        break
                response_text = '\n'.join(lines[start_idx:end_idx])

            if response_text.startswith('json'):
                response_text = response_text[4:].strip()

            classification = json.loads(response_text)

            # Convert indices back to annotation full names
            categorized = {}
            for category, indices in classification.items():
                annotation_names = []
                for idx in indices:
                    if 1 <= idx <= len(annotations):
                        annotation_names.append(annotations[idx - 1]['full_name'])

                if annotation_names:
                    categorized[category] = annotation_names

            return categorized

        except Exception as e:
            if self.debug:
                print(f"[INTERNAL_FRAMEWORK] Error classifying annotations with AI: {e}")
                import traceback
                traceback.print_exc()
            return {}

    def _merge_internal_methods(self, common_methods: Dict[str, List[str]],
                                semantic_methods: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Merge methods from common path and semantic analyses

        Args:
            common_methods: Methods from common path analysis
            semantic_methods: Methods from semantic name matching

        Returns:
            Merged dict with all unique methods per category
        """
        merged = {}

        # Add semantic methods
        for category, methods in semantic_methods.items():
            if methods:
                merged[category] = methods

        # Merge common methods (categorized)
        for category, methods in common_methods.items():
            if category in merged:
                # Merge with existing
                existing = set(merged[category])
                new_methods = set(methods)
                merged[category] = list(existing | new_methods)
            else:
                merged[category] = methods

        return merged

    def _categorize_internal_methods(self, method_signatures: List[str]) -> Dict[str, List[str]]:
        """
        Categorize internal methods by naming/package patterns

        Args:
            method_signatures: List of method fullName signatures

        Returns:
            Dict mapping category -> list of signatures
        """
        categorized = {}

        for sig in method_signatures:
            # Extract package, class, method name
            parts = sig.split('.')
            if len(parts) < 2:
                continue

            package = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            class_name = parts[-2] if len(parts) >= 2 else ''
            method_name = parts[-1].split(':')[0] if len(parts) >= 1 else ''

            # Categorization rules (map to existing ARCHITECTURE_CATEGORIES)
            category = None

            # Check package-based categorization first
            if 'security' in package.lower() or 'auth' in package.lower():
                if 'auth' in method_name.lower() or 'login' in method_name.lower():
                    category = 'defense.authentication'
                else:
                    category = 'defense.authorization'
            elif 'validation' in package.lower() or 'validator' in package.lower():
                category = 'defense.input_validation'

            # Check class-based categorization
            elif 'Service' in class_name or 'Manager' in class_name or 'Processor' in class_name:
                category = 'business_logic.service'
            elif 'Utils' in class_name or 'Helper' in class_name:
                if 'valid' in method_name.lower():
                    category = 'defense.input_validation'
                elif 'sanitize' in method_name.lower() or 'escape' in method_name.lower():
                    category = 'defense.sanitization'
                else:
                    category = 'utilities.helpers'
            elif 'Repository' in class_name or 'DAO' in class_name or 'Dao' in class_name:
                category = 'database.repository_pattern'

            # Default fallback
            if not category:
                category = 'business_logic.service'

            if category not in categorized:
                categorized[category] = []
            categorized[category].append(sig)

        return categorized

    def _build_internal_framework_json(self, categorized_methods: Dict[str, List[str]],
                                      project_info: Dict[str, Any],
                                      sample_size: int) -> Dict[str, Any]:
        """
        Build framework JSON for internal application methods

        Args:
            categorized_methods: Dict mapping category -> list of method signatures
            project_info: Project metadata
            sample_size: Number of endpoints sampled

        Returns:
            Framework JSON dict
        """
        from datetime import datetime

        # Build architecture section (nested structure)
        architecture = {}
        for category_path, signatures in categorized_methods.items():
            if not signatures:
                continue

            parts = category_path.split('.')
            if len(parts) < 2:
                continue

            # Navigate/create nested structure
            current = architecture
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Add leaf node
            leaf_name = parts[-1]

            # Determine if these are annotations or method signatures
            # Annotations typically have full qualified names like "org.springframework.security.access.prepost.PreAuthorize"
            # Method signatures have format "package.Class.method:returnType(params)"
            is_annotation = signatures and not any(':' in sig for sig in signatures)

            if is_annotation:
                current[leaf_name] = {
                    "target": "joern",
                    "search_type": "annotation_name",
                    "pattern": sorted(signatures)
                }
            else:
                current[leaf_name] = {
                    "target": "joern",
                    "search_type": "method_signature",
                    "signature": sorted(signatures)
                }

        # Build framework JSON
        framework_name = project_info.get('name', 'Application')
        version = project_info.get('version', 'unknown')

        # Ensure languages is an array (schema requires array, not dict)
        languages_raw = project_info.get('languages', ['unknown'])
        if isinstance(languages_raw, dict):
            # Convert dict like {"java": 999, "python": 1} to array like ["java", "python"]
            # Sort by value (descending) to put primary language first
            languages = [lang for lang, _ in sorted(languages_raw.items(), key=lambda x: x[1], reverse=True)]
        elif isinstance(languages_raw, list):
            languages = languages_raw
        else:
            languages = ['unknown']

        framework_json = {
            "$schema": "../schema/framework-schema.json",
            "name": f"{framework_name} Internal API",
            "version": version,
            "languages": languages,
            "generated": datetime.now().isoformat(),
            "detection": {
                "note": "Auto-generated from application code analysis",
                "methods": [
                    "Common path analysis (methods used across multiple routes)",
                    "Semantic name matching (security/architecture-relevant names)",
                    "Annotation detection (security and architecture-relevant annotations)"
                ],
                "sample_size": sample_size
            },
            "architecture": architecture
        }

        return framework_json


def _is_github_url(url: str) -> bool:
    """Check if the URL is a GitHub repository URL"""
    return url.startswith('https://github.com/') or url.startswith('git@github.com:')


def _clone_github_repo(url: str, branch: Optional[str] = None, tag: Optional[str] = None,
                       keep_clone: Optional[str] = None, cache_dir: Optional[str] = None,
                       debug: bool = False) -> Tuple[str, bool]:
    """
    Clone a GitHub repository

    Args:
        url: GitHub URL (https or SSH)
        branch: Branch to checkout
        tag: Tag to checkout
        keep_clone: Directory to keep the clone
        cache_dir: Directory to check for existing clone
        debug: Enable debug output

    Returns:
        Tuple of (clone_path, should_cleanup)
    """
    import subprocess

    # Extract repo name from URL
    if url.startswith('https://github.com/'):
        repo_name = url.replace('https://github.com/', '').rstrip('.git').rstrip('/')
    elif url.startswith('git@github.com:'):
        repo_name = url.replace('git@github.com:', '').rstrip('.git').rstrip('/')
    else:
        raise ValueError(f"Invalid GitHub URL: {url}")

    # Get just the repository name (last part)
    repo_dir_name = repo_name.split('/')[-1]

    # Check cache directory first
    if cache_dir:
        cached_path = os.path.join(os.path.expanduser(cache_dir), repo_dir_name)
        if os.path.exists(cached_path):
            if debug:
                print(f"[FRAMEWORK_GENERATOR] Using cached clone at {cached_path}")
            return (cached_path, False)

    # Determine clone destination
    if keep_clone:
        clone_path = os.path.expanduser(keep_clone)
        should_cleanup = False
    elif cache_dir:
        clone_path = os.path.join(os.path.expanduser(cache_dir), repo_dir_name)
        should_cleanup = False
    else:
        clone_path = tempfile.mkdtemp(prefix='framework_gen_')
        should_cleanup = True

    # Build clone command
    clone_cmd = ['git', 'clone', '--depth', '1']

    if branch:
        clone_cmd.extend(['--branch', branch])
    elif tag:
        clone_cmd.extend(['--branch', tag])

    clone_cmd.extend([url, clone_path])

    if debug:
        print(f"[FRAMEWORK_GENERATOR] Cloning repository: {' '.join(clone_cmd)}")

    # Execute clone
    result = subprocess.run(clone_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        if should_cleanup and os.path.exists(clone_path):
            shutil.rmtree(clone_path, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repository: {result.stderr}")

    return (clone_path, should_cleanup)


def main():
    """Main entry point"""
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    library_path_or_url = sys.argv[1]
    framework_name = sys.argv[2]

    # Parse optional flags
    validate_against = None
    if '--validate' in sys.argv:
        idx = sys.argv.index('--validate')
        if idx + 1 < len(sys.argv):
            validate_against = sys.argv[idx + 1]

    cpg_path = 'auto'
    if '--cpg' in sys.argv:
        idx = sys.argv.index('--cpg')
        if idx + 1 < len(sys.argv):
            cpg_path = sys.argv[idx + 1]

    branch = None
    if '--branch' in sys.argv:
        idx = sys.argv.index('--branch')
        if idx + 1 < len(sys.argv):
            branch = sys.argv[idx + 1]

    tag = None
    if '--tag' in sys.argv:
        idx = sys.argv.index('--tag')
        if idx + 1 < len(sys.argv):
            tag = sys.argv[idx + 1]

    keep_clone = None
    if '--keep-clone' in sys.argv:
        idx = sys.argv.index('--keep-clone')
        if idx + 1 < len(sys.argv):
            keep_clone = sys.argv[idx + 1]

    cache_dir = None
    if '--cache-dir' in sys.argv:
        idx = sys.argv.index('--cache-dir')
        if idx + 1 < len(sys.argv):
            cache_dir = sys.argv[idx + 1]

    debug = '--debug' in sys.argv
    force = '--force' in sys.argv

    # Handle GitHub URLs
    should_cleanup = False
    library_path = library_path_or_url

    if _is_github_url(library_path_or_url):
        try:
            if debug:
                print(f"[FRAMEWORK_GENERATOR] Detected GitHub URL: {library_path_or_url}")

            library_path, should_cleanup = _clone_github_repo(
                url=library_path_or_url,
                branch=branch,
                tag=tag,
                keep_clone=keep_clone,
                cache_dir=cache_dir,
                debug=debug
            )

            if keep_clone:
                print(f"✓ Repository cloned to {library_path}")
            elif not cache_dir:
                print(f"✓ Repository cloned to temporary directory")

        except Exception as e:
            print(f"\n✗ Error cloning repository: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Generate framework JSON
    generator = FrameworkGenerator(use_bedrock=True, debug=debug)

    # Create frameworks directory if it doesn't exist
    frameworks_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frameworks')
    if not os.path.exists(frameworks_dir):
        # If not in package structure, try current directory
        frameworks_dir = 'frameworks'
        os.makedirs(frameworks_dir, exist_ok=True)

    try:
        # Check if this is a multi-module project
        if generator.is_parent_project(library_path):
            print(f"\n✓ Detected multi-module project at {library_path}")
            print("  Enumerating child modules...")

            # Enumerate all child modules
            modules = generator.enumerate_child_modules(library_path)

            if not modules:
                print("\n✗ Error: No child modules found in parent project")
                sys.exit(1)

            print(f"\n  Found {len(modules)} modules:")
            for module in modules:
                print(f"    - {module['artifact_name']}")

            # Generate ONE CPG for the entire parent project (more efficient and handles inter-module dependencies)
            print(f"\n  Generating CPG for entire parent project (handles inter-module dependencies)...")
            from compass.cpg_tool import CpgTool
            try:
                parent_cpg = CpgTool('auto', library_path, auto_generate=True, fetch_dependencies=False, debug=debug)
                print(f"  ✓ Parent CPG generated successfully")
            except Exception as e:
                print(f"\n✗ Error generating parent CPG: {e}")
                if debug:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)

            # Generate framework JSON for each module using the shared CPG
            generated_files = []
            skipped_files = []
            for i, module in enumerate(modules, 1):
                # Check if file already exists
                filename = f"{module['artifact_name']}.json"
                output_file = os.path.join(frameworks_dir, filename)

                if os.path.exists(output_file) and not force:
                    print(f"\n[{i}/{len(modules)}] Skipping {module['artifact_name']} (already exists)")
                    skipped_files.append(output_file)
                    continue

                status = "Regenerating" if os.path.exists(output_file) else "Generating"
                print(f"\n[{i}/{len(modules)}] {status} {module['artifact_name']}...")

                try:
                    # Generate framework JSON using the shared parent CPG, but filter by module path
                    framework_json = generator.generate_framework_json_from_shared_cpg(
                        parent_cpg=parent_cpg,
                        module_path=module['path'],
                        framework_name=module['artifact_name'],
                        parent_path=library_path
                    )

                    with open(output_file, 'w') as f:
                        json.dump(framework_json, f, indent=2)

                    print(f"  ✓ Generated: {output_file}")
                    generated_files.append(output_file)

                except Exception as e:
                    print(f"  ✗ Error generating {module['artifact_name']}: {e}")
                    if debug:
                        import traceback
                        traceback.print_exc()
                    # Continue with next module instead of failing completely

            # Stop the shared CPG server
            parent_cpg._stop_server()

            print(f"\n✓ Successfully generated {len(generated_files)}/{len(modules)} framework definitions")
            if skipped_files:
                print(f"  Skipped {len(skipped_files)} existing files (use --force to regenerate)")
            if generated_files:
                print(f"\n  Generated:")
                for file in generated_files:
                    print(f"    - {os.path.basename(file)}")
            if skipped_files:
                print(f"\n  Skipped:")
                for file in skipped_files:
                    print(f"    - {os.path.basename(file)}")

        else:
            # Single module project - existing behavior
            framework_json = generator.generate_framework_json(
                library_path=library_path,
                framework_name=framework_name,
                cpg_path=cpg_path
            )

            # Output JSON to frameworks/ directory by default
            # Slugify framework name: lowercase, replace spaces/special chars with dashes, collapse multiple dashes
            filename = framework_name.lower()
            filename = re.sub(r'[^a-z0-9]+', '-', filename)  # Replace non-alphanumeric with dashes
            filename = re.sub(r'-+', '-', filename)  # Collapse multiple dashes
            filename = filename.strip('-')  # Remove leading/trailing dashes
            filename = f"{filename}.json"

            output_file = os.path.join(frameworks_dir, filename)

            with open(output_file, 'w') as f:
                json.dump(framework_json, f, indent=2)

            print(f"\n✓ Framework JSON generated: {output_file}")

            # Validate if requested
            if validate_against:
                print(f"\n=== Validation against {validate_against} ===")
                with open(validate_against, 'r') as f:
                    existing = json.load(f)

                compare_frameworks(framework_json, existing)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Clean up temporary directory if needed
        if should_cleanup and os.path.exists(library_path):
            if debug:
                print(f"[FRAMEWORK_GENERATOR] Cleaning up temporary directory: {library_path}")
            try:
                shutil.rmtree(library_path, ignore_errors=True)
            except Exception as e:
                if debug:
                    print(f"[FRAMEWORK_GENERATOR] Warning: Could not cleanup temp directory: {e}")

        # Always print AI usage summary at the end
        from compass.ai_client import print_ai_usage_summary
        print_ai_usage_summary("Framework Generator")


def compare_frameworks(generated: Dict[str, Any], existing: Dict[str, Any]):
    """Compare generated framework JSON with existing one"""
    print("\nComparison:")
    print(f"  Name: {generated.get('name')} vs {existing.get('name')}")
    print(f"  Languages: {generated.get('languages')} vs {existing.get('languages')}")

    # Compare architecture categories
    gen_arch = generated.get('architecture', {})
    exist_arch = existing.get('architecture', {})

    print("\nArchitecture Categories:")
    all_categories = set(gen_arch.keys()) | set(exist_arch.keys())

    for category in sorted(all_categories):
        gen_subcats = set(gen_arch.get(category, {}).keys())
        exist_subcats = set(exist_arch.get(category, {}).keys())

        print(f"\n  {category}:")
        print(f"    Generated: {', '.join(sorted(gen_subcats)) if gen_subcats else '(none)'}")
        print(f"    Existing:  {', '.join(sorted(exist_subcats)) if exist_subcats else '(none)'}")

        # Show overlap
        common = gen_subcats & exist_subcats
        only_gen = gen_subcats - exist_subcats
        only_exist = exist_subcats - gen_subcats

        if common:
            print(f"    ✓ Common:  {', '.join(sorted(common))}")
        if only_gen:
            print(f"    + New:     {', '.join(sorted(only_gen))}")
        if only_exist:
            print(f"    - Missing: {', '.join(sorted(only_exist))}")

        # Compare method counts for common subcategories
        for subcat in common:
            gen_sigs = gen_arch[category][subcat].get('signatures', [])
            exist_sigs = exist_arch[category][subcat].get('signatures', [])
            print(f"      {subcat}: {len(gen_sigs)} generated vs {len(exist_sigs)} existing signatures")


if __name__ == "__main__":
    main()
