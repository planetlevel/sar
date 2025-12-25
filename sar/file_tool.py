#!/usr/bin/env python3
"""
File System Tool - Generic filesystem utilities for project analysis

This module provides filesystem utilities that are independent of any
specific analysis tool (like Joern). It handles language detection,
build system detection, version extraction, and other file-based queries.
"""

import os
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import Counter


class FileTool:
    """Filesystem utilities for project analysis"""

    # Language detection mappings
    LANGUAGE_EXTENSIONS = {
        'java': ['.java'],
        'javascript': ['.js', '.jsx', '.mjs', '.cjs'],
        'typescript': ['.ts', '.tsx'],
        'python': ['.py'],
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.cxx', '.cc', '.hpp', '.hxx', '.hh'],
        'go': ['.go'],
        'kotlin': ['.kt', '.kts'],
        'php': ['.php'],
        'ruby': ['.rb'],
        'swift': ['.swift'],
        'csharp': ['.cs'],
        'rust': ['.rs'],
        'scala': ['.scala'],
        'r': ['.r', '.R'],
        'perl': ['.pl', '.pm'],
        'lua': ['.lua'],
        'shell': ['.sh', '.bash', '.zsh'],
    }

    # Build system file mappings
    BUILD_FILES = {
        'maven': 'pom.xml',
        'gradle': 'build.gradle',
        'gradle_kts': 'build.gradle.kts',
        'npm': 'package.json',
        'yarn': 'yarn.lock',
        'pnpm': 'pnpm-lock.yaml',
        'pip': 'requirements.txt',
        'pipenv': 'Pipfile',
        'poetry': 'pyproject.toml',
        'go_mod': 'go.mod',
        'cargo': 'Cargo.toml',
        'sbt': 'build.sbt',
        'ant': 'build.xml',
        'cmake': 'CMakeLists.txt',
        'make': 'Makefile',
    }

    # Directories to skip during scanning
    SKIP_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv', 'env',
        'target', 'build', 'dist', '.idea', '.vscode', 'bin',
        'obj', 'out', '.gradle', '.mvn', 'vendor', 'site-packages',
    }

    def __init__(self, project_dir: str):
        """
        Initialize the File Tool

        Args:
            project_dir: Directory containing the project to analyze
        """
        self.project_dir = project_dir

    def detect_languages(self, max_files: int = 1000) -> Dict[str, int]:
        """
        Detect programming languages in the project by file extension

        Args:
            max_files: Maximum number of files to scan

        Returns:
            Dict mapping language names to file counts
        """
        language_counts = Counter()

        # Walk the project directory
        file_count = 0
        for root, dirs, files in os.walk(self.project_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file in files:
                if file_count >= max_files:
                    break

                file_path = Path(file)
                ext = file_path.suffix.lower()

                # Check which language this extension belongs to
                for language, extensions in self.LANGUAGE_EXTENSIONS.items():
                    if ext in extensions:
                        language_counts[language] += 1
                        file_count += 1
                        break

            if file_count >= max_files:
                break

        return dict(language_counts)

    def count_source_files(self, max_files: int = 10000) -> int:
        """
        Count total source files in the project (all recognized languages)

        Args:
            max_files: Maximum number of files to count

        Returns:
            Total count of source files
        """
        languages = self.detect_languages(max_files=max_files)
        return sum(languages.values())

    def detect_primary_language(self) -> Optional[str]:
        """
        Detect the primary language of the project

        Returns:
            Language name or None if no files found
        """
        languages = self.detect_languages()
        if not languages:
            return None

        # Return language with most files
        return max(languages.items(), key=lambda x: x[1])[0]

    def detect_build_files(self) -> Dict[str, bool]:
        """
        Detect build/dependency files in the project

        Returns:
            Dict of build file types found (name -> bool)
        """
        found = {}
        for build_type, filename in self.BUILD_FILES.items():
            path = os.path.join(self.project_dir, filename)
            found[build_type] = os.path.exists(path)

        return found

    def detect_version(self) -> Optional[str]:
        """
        Detect application version from build files

        Returns:
            Version string or None if not found
        """

        # Try Maven pom.xml
        pom_path = os.path.join(self.project_dir, 'pom.xml')
        if os.path.exists(pom_path):
            try:
                tree = ET.parse(pom_path)
                root = tree.getroot()

                # Handle XML namespaces if present
                ns = {'mvn': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

                # Try to get project version (not parent version)
                # Look for version element that's a direct child of root, not inside <parent>
                if ns:
                    # With namespace
                    version_elem = root.find('./mvn:version', ns)
                    if version_elem is not None and version_elem.text:
                        version = version_elem.text.strip()
                        # Skip property references like ${revision}
                        if not version.startswith('${'):
                            return version
                else:
                    # Without namespace
                    version_elem = root.find('./version')
                    if version_elem is not None and version_elem.text:
                        version = version_elem.text.strip()
                        # Skip property references like ${revision}
                        if not version.startswith('${'):
                            return version

                # Fallback: try any version tag (might be parent version)
                # This is better than nothing
                if ns:
                    all_versions = root.findall('.//mvn:version', ns)
                else:
                    all_versions = root.findall('.//version')

                for elem in all_versions:
                    if elem.text:
                        version = elem.text.strip()
                        if not version.startswith('${'):
                            return version
            except Exception:
                pass

        # Try package.json
        package_path = os.path.join(self.project_dir, 'package.json')
        if os.path.exists(package_path):
            try:
                with open(package_path, 'r') as f:
                    data = json.load(f)
                    if 'version' in data:
                        return data['version']
            except Exception:
                pass

        # Try Gradle build.gradle
        gradle_path = os.path.join(self.project_dir, 'build.gradle')
        if os.path.exists(gradle_path):
            try:
                with open(gradle_path, 'r') as f:
                    content = f.read()
                    # Look for version = "..." or version '...'
                    match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        return match.group(1)
            except Exception:
                pass

        # Try pyproject.toml
        pyproject_path = os.path.join(self.project_dir, 'pyproject.toml')
        if os.path.exists(pyproject_path):
            try:
                with open(pyproject_path, 'r') as f:
                    content = f.read()
                    match = re.search(r'version\s*=\s*"([^"]+)"', content)
                    if match:
                        return match.group(1)
            except Exception:
                pass

        # Try Cargo.toml
        cargo_path = os.path.join(self.project_dir, 'Cargo.toml')
        if os.path.exists(cargo_path):
            try:
                with open(cargo_path, 'r') as f:
                    content = f.read()
                    match = re.search(r'version\s*=\s*"([^"]+)"', content)
                    if match:
                        return match.group(1)
            except Exception:
                pass

        # Try go.mod
        gomod_path = os.path.join(self.project_dir, 'go.mod')
        if os.path.exists(gomod_path):
            try:
                with open(gomod_path, 'r') as f:
                    content = f.read()
                    # Go modules use module path with version tags
                    match = re.search(r'module\s+.+/v(\d+)', content)
                    if match:
                        return f"v{match.group(1)}"
            except Exception:
                pass

        return None

    def file_exists(self, relative_path: str) -> bool:
        """Check if a file exists relative to project directory"""
        full_path = os.path.join(self.project_dir, relative_path)
        return os.path.exists(full_path)

    def read_file(self, relative_path: str) -> Optional[str]:
        """Read a file's contents relative to project directory"""
        full_path = os.path.join(self.project_dir, relative_path)
        if not os.path.exists(full_path):
            return None

        try:
            with open(full_path, 'r') as f:
                return f.read()
        except Exception:
            return None

    def extract_code_snippet(self, file_path: str, line_number: int, context_before: int = 2, context_after: int = 2) -> str:
        """
        Extract a code snippet from a source file with context

        Args:
            file_path: Relative path to the file from project directory
            line_number: Line number where the issue occurs (1-indexed)
            context_before: Number of lines to include before the target line
            context_after: Number of lines to include after the target line

        Returns:
            Code snippet as a string with line numbers, or empty string if file not found
        """
        # Construct full path
        full_path = os.path.join(self.project_dir, file_path)

        if not os.path.exists(full_path):
            return ""

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Calculate line range (convert to 0-indexed)
            start_line = max(0, line_number - context_before - 1)
            end_line = min(len(lines), line_number + context_after)

            # Extract the lines for the snippet
            snippet_raw_lines = [lines[i].rstrip() for i in range(start_line, end_line)]

            # Find minimum indentation (ignoring empty lines)
            min_indent = float('inf')
            for line in snippet_raw_lines:
                if line.strip():  # Skip empty lines
                    leading_spaces = len(line) - len(line.lstrip())
                    min_indent = min(min_indent, leading_spaces)

            # If all lines were empty, set min_indent to 0
            if min_indent == float('inf'):
                min_indent = 0

            # Build snippet with line numbers, removing common leading whitespace
            snippet_lines = []
            for i, raw_line in enumerate(snippet_raw_lines):
                actual_line_num = start_line + i + 1
                # Remove common leading whitespace
                if len(raw_line) >= min_indent:
                    line_content = raw_line[min_indent:]
                else:
                    line_content = raw_line
                # Mark the target line with >>>
                marker = ">>> " if actual_line_num == line_number else "    "
                snippet_lines.append(f"{marker}{actual_line_num:4d} | {line_content}")

            return "\n".join(snippet_lines)
        except Exception:
            return ""

    def find_files(self, pattern: str, max_results: int = 100) -> List[str]:
        """
        Find files matching a pattern (simple glob)

        Args:
            pattern: Simple pattern like "*.xml" or "**/*.java"
            max_results: Maximum number of results to return

        Returns:
            List of relative file paths
        """
        import fnmatch

        results = []
        pattern_parts = pattern.split('/')

        for root, dirs, files in os.walk(self.project_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file in files:
                if len(results) >= max_results:
                    return results

                # Get relative path
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.project_dir)

                # Simple pattern matching
                if fnmatch.fnmatch(file, pattern_parts[-1]):
                    results.append(rel_path)

        return results

    def get_project_fingerprint(self) -> Dict[str, Any]:
        """
        Calculate a fingerprint of the project's source files

        This scans source files and creates a signature based on:
        - Most recent modification time of any source file
        - Count of source files by extension
        - Total size of source files

        Returns:
            Dict with 'last_modified', 'file_counts', 'total_size'
        """
        latest_mtime = 0
        file_counts = Counter()
        total_size = 0

        for root, dirs, files in os.walk(self.project_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file in files:
                file_path = Path(file)
                ext = file_path.suffix.lower()

                # Only track source files we know about
                is_source_file = False
                for language, extensions in self.LANGUAGE_EXTENSIONS.items():
                    if ext in extensions:
                        file_counts[ext] += 1
                        is_source_file = True
                        break

                if is_source_file:
                    full_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(full_path)
                        mtime = stat_info.st_mtime
                        size = stat_info.st_size

                        if mtime > latest_mtime:
                            latest_mtime = mtime

                        total_size += size
                    except (OSError, IOError):
                        # Skip files we can't access
                        pass

        return {
            'last_modified': latest_mtime,
            'file_counts': dict(file_counts),
            'total_size': total_size
        }

    def has_project_changed(self, cpg_path: str) -> bool:
        """
        Check if project has changed since CPG was generated

        Args:
            cpg_path: Path to CPG file

        Returns:
            True if project has changed, False if CPG is up to date
        """
        # Check if CPG exists
        if not os.path.exists(cpg_path):
            return True  # CPG doesn't exist, needs generation

        # Get CPG modification time
        try:
            cpg_mtime = os.path.getmtime(cpg_path)
        except OSError:
            return True  # Can't read CPG, regenerate

        # Get project fingerprint
        fingerprint = self.get_project_fingerprint()

        # If any source file is newer than CPG, project has changed
        if fingerprint['last_modified'] > cpg_mtime:
            return True

        return False

    def extract_xml_data(self, xml_file: str, xpath_patterns: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract data from XML file using XPath-like patterns

        Args:
            xml_file: Path to XML file (relative to project_dir)
            xpath_patterns: Dictionary defining what to extract
                {
                    "element": "action",  # XML element to find
                    "parent": "package",  # Optional parent element
                    "attributes": ["name", "class", "method"],  # Attributes to extract
                    "namespace_attr": "namespace"  # Optional: get namespace from parent
                }

        Returns:
            List of dictionaries with extracted data
        """
        xml_path = os.path.join(self.project_dir, xml_file)
        if not os.path.exists(xml_path):
            return []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            results = []
            element_name = xpath_patterns.get('element')
            parent_name = xpath_patterns.get('parent')
            attributes = xpath_patterns.get('attributes', [])
            namespace_attr = xpath_patterns.get('namespace_attr')

            # Handle XML namespaces if present
            # Strip namespace prefix from element names for matching
            def strip_namespace(tag):
                return tag.split('}')[-1] if '}' in tag else tag

            # Find elements
            if parent_name:
                # Find elements within parent elements
                for parent in root.iter():
                    if strip_namespace(parent.tag) == parent_name:
                        # Get namespace from parent if specified
                        parent_namespace = parent.get(namespace_attr, '') if namespace_attr else ''

                        for elem in parent.iter():
                            if strip_namespace(elem.tag) == element_name:
                                data = {}

                                # Add namespace if present
                                if parent_namespace:
                                    data['namespace'] = parent_namespace

                                # Extract attributes
                                for attr in attributes:
                                    value = elem.get(attr)
                                    if value:
                                        data[attr] = value

                                if data:  # Only add if we extracted something
                                    results.append(data)
            else:
                # Find elements anywhere in the document
                for elem in root.iter():
                    if strip_namespace(elem.tag) == element_name:
                        data = {}

                        # Extract attributes
                        for attr in attributes:
                            value = elem.get(attr)
                            if value:
                                data[attr] = value

                        if data:  # Only add if we extracted something
                            results.append(data)

            return results

        except Exception as e:
            print(f"Error parsing XML file {xml_file}: {e}")
            return []


def main():
    """Demo the File Tool"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: file_tool.py <project_dir>")
        print("\nExample:")
        print("  file_tool.py ~/my-project")
        sys.exit(1)

    project_dir = sys.argv[1]
    tool = FileTool(project_dir)

    print(f"Analyzing project: {project_dir}\n")

    # Detect languages
    languages = tool.detect_languages()
    if languages:
        print("Languages detected:")
        for lang, count in sorted(languages.items(), key=lambda x: -x[1]):
            print(f"  {lang}: {count} files")

        primary = tool.detect_primary_language()
        print(f"\nPrimary language: {primary}")
    else:
        print("No recognized source files found")

    # Detect build files
    print("\nBuild files detected:")
    build_files = tool.detect_build_files()
    found_any = False
    for build_type, found in build_files.items():
        if found:
            print(f"  ✓ {build_type}")
            found_any = True
    if not found_any:
        print("  (none)")

    # Detect version
    version = tool.detect_version()
    if version:
        print(f"\nVersion: {version}")
    else:
        print("\nVersion: Not found")


if __name__ == "__main__":
    main()
