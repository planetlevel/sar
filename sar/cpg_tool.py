#!/usr/bin/env python3
"""
CPG Tool - A clean interface to CPG queries

This provides a simple, focused tool for executing CPG queries
against a Code Property Graph.  The tool automatically starts
a CPG server on an ephemeral port and cleans it up when done.
"""

# Standard library imports
import atexit
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

# Third-party imports
import requests

# Local imports
from sar.file_tool import FileTool

# Set up module logger
logger = logging.getLogger(__name__)


@dataclass
class CpgConfig:
    """Configuration for CPG Tool behavior"""
    workspace_dir: str = field(default_factory=lambda: os.path.expanduser('~/git/compass/workspace'))
    large_cpg_threshold_mb: float = 10.0
    medium_cpg_threshold_mb: float = 5.0
    large_cpg_timeout_seconds: int = 180  # 3 minutes
    medium_cpg_timeout_seconds: int = 60  # 1 minute
    small_cpg_timeout_seconds: int = 30   # 30 seconds (joern server needs ~10-20s to initialize HTTP endpoint)
    generation_timeout_seconds: int = 600  # 10 minutes
    server_startup_retry_interval: float = 0.5  # seconds
    test_exclusions: List[str] = field(default_factory=lambda: [
        'src/test',           # Maven test directory
        'test',               # Generic test directory
        'tests',              # Generic tests directory
        '**/test/**',         # Nested test directories
        '**/tests/**',        # Nested tests directories
        '**/*Test.java',      # Test files by naming convention
        '**/*Tests.java',     # Test files by naming convention
        '**/*IT.java',        # Integration test files
        '**/target/test-classes',  # Maven compiled test classes
    ])


@dataclass
class QueryResult:
    """Result of a CPG query execution"""
    success: bool
    output: str
    error: Optional[str] = None


@dataclass
class CpgGenerationResult:
    """Result of CPG generation"""
    success: bool
    language: Optional[str]
    command: Optional[str]
    cpg_path: Optional[str] = None
    size: Optional[int] = None
    error: Optional[str] = None
    stderr: Optional[str] = None


class CpgTool:
    """Simple tool interface to make CPG queries

    Automatically manages a CPG server instance on an ephemeral port.
    The server is started on initialization and cleaned up on exit.
    """

    # Language-specific CPG generators - use dedicated frontends for better support
    LANGUAGE_GENERATORS = {
        'java': {
            'command': 'javasrc2cpg',
            'options': ['--fetch-dependencies', '--enable-type-recovery']
        },
        'javascript': {
            'command': 'jssrc2cpg',
            'options': []
        },
        'typescript': {
            'command': 'jssrc2cpg',
            'options': ['--ts']
        },
        'python': {
            'command': 'pysrc2cpg',
            'options': []
        },
        'c': {
            'command': 'c2cpg',
            'options': []
        },
        'cpp': {
            'command': 'c2cpg',
            'language_flag': 'C',  # C frontend handles C++
            'options': []
        },
        'go': {
            'command': 'go2cpg',
            'options': []
        },
        'kotlin': {
            'command': 'kotlin2cpg',
            'options': []
        },
        'php': {
            'command': 'php2cpg',
            'options': []
        },
        'ruby': {
            'command': 'rubysrc2cpg',
            'options': []
        },
        'swift': {
            'command': 'swiftsrc2cpg',
            'options': []
        },
        'csharp': {
            'command': 'csharpsrc2cpg',
            'options': []
        },
    }

    def __init__(self, cpg_path: str, project_dir: str, auto_generate: bool = True,
                 force_regenerate: bool = False, debug: bool = False, config: Optional[CpgConfig] = None,
                 ignore_cpg_size: bool = False, fetch_dependencies: bool = True):
        """
        Initialize the CPG Tool

        Automatically manages CPG lifecycle:
        - Checks if CPG exists and is up to date
        - Generates new CPG if needed or out of date
        - Cleans up old CPG files
        - Starts internal CPG server

        Args:
            cpg_path: Path to CPG file or 'auto' for automatic naming (default: 'auto')
            project_dir: Directory containing the project
            auto_generate: If True, automatically manage CPG (default: True)
            force_regenerate: If True, force CPG regeneration even if up to date (default: False)
            debug: If True, enable debug logging (default: False)
            config: CPG configuration (uses defaults if None)
            ignore_cpg_size: If True, skip CPG size validation (use for projects with parser issues)
            fetch_dependencies: If True, fetch project dependencies during CPG generation (default: True)
                               Set to False for framework source analysis
        """
        # Normalize project_dir to absolute path to handle relative paths correctly
        self.project_dir = os.path.abspath(os.path.expanduser(project_dir))
        self.server_process = None
        self.server_url = None
        self.server_port = None
        self.debug = debug
        self.config = config or CpgConfig()
        self.ignore_cpg_size = ignore_cpg_size
        self.fetch_dependencies = fetch_dependencies
        self._cleanup_registered = False

        # Initialize FileTool for filesystem operations
        self.file_tool = FileTool(project_dir)

        # Set up workspace directory for CPG storage
        self.workspace_dir = self.config.workspace_dir
        os.makedirs(self.workspace_dir, exist_ok=True)

        # Use GAV-style naming (group-artifact-version.bin) for auto mode
        if cpg_path is None or cpg_path == 'auto':
            self.cpg_path = self._generate_cpg_name()
            logger.debug(f"Using auto-generated CPG name: {self.cpg_path}")
        else:
            self.cpg_path = cpg_path

        # Store CPG in workspace directory
        cpg_full_path = os.path.join(self.workspace_dir, self.cpg_path)
        logger.debug(f"CPG location: {cpg_full_path}")

        # Check if CPG needs regeneration
        needs_regeneration = False
        if force_regenerate:
            needs_regeneration = True
            # Delete existing CPG to force regeneration
            if os.path.exists(cpg_full_path):
                try:
                    os.remove(cpg_full_path)
                    logger.info(f"Forcing CPG regeneration - deleted {cpg_full_path}")
                    if not self.debug:
                        print("Clearing analysis cache...")
                except (OSError, PermissionError) as e:
                    logger.warning(f"Could not delete existing CPG: {e}")
        elif not os.path.exists(cpg_full_path):
            needs_regeneration = True
        elif auto_generate and self.file_tool.has_project_changed(cpg_full_path):
            needs_regeneration = True
            # Delete outdated CPG
            try:
                os.remove(cpg_full_path)
            except (OSError, PermissionError) as e:
                logger.warning(f"Could not delete outdated CPG: {e}")

        # Generate CPG if needed
        # IMPORTANT: Generate to a temporary location first, NOT directly to workspace
        # The workspace expects a project directory structure, not a raw .bin file
        self.temp_cpg_path = None
        if needs_regeneration:
            if auto_generate:
                # Generate to temp location first
                import tempfile
                temp_dir = tempfile.gettempdir()
                self.temp_cpg_path = os.path.join(temp_dir, f"compass-temp-{os.getpid()}.bin")
                result = self.generate_cpg(output_path=self.temp_cpg_path, fetch_dependencies=self.fetch_dependencies)
                if not result.success:
                    raise RuntimeError(f"Failed to generate CPG: {result.error}")
            else:
                raise RuntimeError(f"CPG not found and auto_generate is disabled: {cpg_full_path}")

        # Start CPG server automatically
        self._start_server()
        # Register cleanup handler only once
        if not self._cleanup_registered:
            atexit.register(self._stop_server)
            self._cleanup_registered = True

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup"""
        self._stop_server()
        return False  # Don't suppress exceptions

    def _generate_cpg_name(self) -> str:
        """
        Generate a smart CPG filename based on project name and version

        Returns:
            CPG filename like 'spring-petclinic-1.5.1.bin' or 'myproject-20250929.bin'
        """
        from datetime import datetime

        # Get project name from directory
        project_name = os.path.basename(os.path.abspath(self.project_dir))

        # Try to get version
        version = self.detect_version()

        if version:
            # Clean version string (remove special chars)
            clean_version = version.replace('/', '-').replace(' ', '-')
            cpg_name = f"{project_name}-{clean_version}.bin"
        else:
            # Use date if no version found
            date_str = datetime.now().strftime('%Y%m%d')
            cpg_name = f"{project_name}-{date_str}.bin"

        return cpg_name

    def _find_free_port(self) -> int:
        """Find an available port on localhost"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _start_server(self):
        """Start CPG server on an ephemeral port"""
        # Find available port
        self.server_port = self._find_free_port()
        self.server_url = f"http://localhost:{self.server_port}"

        # Determine which CPG file to use
        # If we just generated a new one, use the temp path; otherwise use workspace path
        if self.temp_cpg_path and os.path.exists(self.temp_cpg_path):
            cpg_full_path = self.temp_cpg_path
        else:
            cpg_full_path = os.path.join(self.workspace_dir, self.cpg_path)
            if not os.path.isfile(cpg_full_path):
                raise RuntimeError(f"CPG not found at {cpg_full_path}")

        # Get CPG size for timeout calculation
        cpg_size_mb = os.path.getsize(cpg_full_path) / (1024 * 1024)

        # Determine timeout based on CPG size
        if cpg_size_mb > self.config.large_cpg_threshold_mb:
            timeout_seconds = self.config.large_cpg_timeout_seconds
            logger.info(f"Large CPG detected ({cpg_size_mb:.1f} MB), waiting up to {timeout_seconds // 60} minutes for server to load...")
            if not self.debug:
                print(f"Large CPG detected ({cpg_size_mb:.1f} MB), waiting up to {timeout_seconds // 60} minutes for server to load...")
        elif cpg_size_mb > self.config.medium_cpg_threshold_mb:
            timeout_seconds = self.config.medium_cpg_timeout_seconds
            logger.info(f"Medium CPG detected ({cpg_size_mb:.1f} MB), waiting up to {timeout_seconds} seconds for server to load...")
            if not self.debug:
                print(f"Medium CPG detected ({cpg_size_mb:.1f} MB), waiting up to {timeout_seconds} seconds for server to load...")
        else:
            timeout_seconds = self.config.small_cpg_timeout_seconds
            logger.debug(f"Small CPG ({cpg_size_mb:.1f} MB), waiting up to {timeout_seconds} seconds for server")

        max_retries = int(timeout_seconds / self.config.server_startup_retry_interval)

        # Start server WITH CPG path - this loads it with default overlays automatically
        cmd = [
            'joern',
            '--server',
            '--server-host', 'localhost',
            '--server-port', str(self.server_port),
            cpg_full_path  # Pass CPG directly - joern applies overlays automatically!
        ]

        try:
            # Start server in background
            self.server_process = subprocess.Popen(
                cmd,
                cwd=self.project_dir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True  # Detach from parent process group
            )

            # Wait for server to be ready (try a simple query)
            for i in range(max_retries):
                try:
                    # Try a simple query to check if server is ready
                    response = requests.post(
                        f"{self.server_url}/query-sync",
                        json={"query": "1 + 1"},
                        timeout=1
                    )
                    if response.status_code == 200:
                        elapsed = i * self.config.server_startup_retry_interval
                        logger.info(f"CPG server ready after {elapsed:.1f} seconds")

                        # Clean up temp CPG file if it was used
                        if self.temp_cpg_path and os.path.exists(self.temp_cpg_path):
                            try:
                                # Move temp CPG to workspace
                                workspace_path = os.path.join(self.workspace_dir, self.cpg_path)
                                import shutil
                                shutil.move(self.temp_cpg_path, workspace_path)
                                logger.debug(f"Moved temp CPG to workspace: {workspace_path}")
                            except OSError as e:
                                logger.warning(f"Could not move temp CPG to workspace: {e}")

                        return  # Server is ready!
                except requests.RequestException:
                    pass

                # Log progress every 10 seconds for large CPGs
                if cpg_size_mb > self.config.large_cpg_threshold_mb and i > 0 and i % 20 == 0:
                    elapsed = i * self.config.server_startup_retry_interval
                    logger.debug(f"Still waiting for server... ({elapsed:.0f}s elapsed)")
                    if not self.debug:
                        print(f"Analyzing... ({elapsed:.0f}s elapsed)")

                time.sleep(self.config.server_startup_retry_interval)

            raise RuntimeError(f"CPG server failed to start after {timeout_seconds} seconds")

        except subprocess.SubprocessError as e:
            self._stop_server()
            raise RuntimeError(f"Failed to start CPG server process: {e}")
        except Exception as e:
            self._stop_server()
            raise RuntimeError(f"Failed to start CPG server: {e}")

    def _stop_server(self):
        """Stop the CPG server if it's running"""
        if not self.server_process:
            return

        try:
            pid = self.server_process.pid
            logger.debug(f"Stopping CPG server (PID: {pid})")

            # Since we used start_new_session=True, we need to kill the process group
            # to ensure all child processes are terminated
            try:
                # Kill the entire process group
                os.killpg(pid, signal.SIGTERM)

                # Wait for graceful shutdown
                try:
                    self.server_process.wait(timeout=5)
                    logger.debug("CPG server stopped gracefully")
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    logger.warning("CPG server did not stop gracefully, force killing")
                    os.killpg(pid, signal.SIGKILL)
                    self.server_process.wait()
                    logger.debug("CPG server force killed")
            except ProcessLookupError:
                # Process already terminated
                logger.debug("CPG server process already terminated")
            except (PermissionError, OSError) as e:
                # Fallback to regular terminate/kill if process group approach fails
                logger.warning(f"Could not kill process group, trying regular termination: {e}")
                try:
                    self.server_process.terminate()
                    try:
                        self.server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.server_process.kill()
                        self.server_process.wait()
                except (ProcessLookupError, PermissionError, OSError) as e:
                    logger.warning(f"Error during fallback termination: {e}")
        except Exception as e:
            # Log but don't raise - cleanup should be best-effort
            logger.error(f"Unexpected error stopping server: {e}", exc_info=True)
        finally:
            self.server_process = None
            self.server_url = None
            self.server_port = None

    def query(self, scala_query: str, timeout: int = 60) -> QueryResult:
        """
        Execute a CPG query

        Args:
            scala_query: Scala code to execute in CPG
            timeout: Maximum execution time in seconds

        Returns:
            QueryResult with success status, output, and error message
        """
        if not self.server_url:
            return QueryResult(
                success=False,
                output='',
                error='CPG server not running'
            )

        return self._query_server(scala_query, timeout)

    def _query_server(self, scala_query: str, timeout: int = 60) -> QueryResult:
        """Execute query via CPG HTTP server (synchronous)"""
        import re

        # Transform query for server mode
        # Server mode doesn't capture println() output, so we need to return values directly
        # Convert .foreach(println) to .l to return the list
        # Convert .l.foreach(println) to .l
        transformed_query = re.sub(r'\.l\s*\.foreach\(println\)', '.l', scala_query)
        transformed_query = re.sub(r'\.foreach\(println\)', '.l', transformed_query)

        try:
            # Use synchronous endpoint
            response = requests.post(
                f"{self.server_url}/query-sync",
                json={"query": transformed_query},
                timeout=timeout
            )
            response.raise_for_status()
            result_data = response.json()

            # Extract output from stdout, removing ANSI color codes
            stdout = result_data.get('stdout', '')
            stderr = result_data.get('stderr', '')

            # Remove ANSI escape sequences
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_output = ansi_escape.sub('', stdout)

            # Check for errors in stderr or API response
            if stderr or not result_data.get('success', True):
                return QueryResult(
                    success=False,
                    output=clean_output,
                    error=stderr or 'Query failed'
                )

            # Check for Scala syntax errors in output
            # CPG queries return syntax errors with HTTP 200, so we need to detect them
            if 'Syntax Error:' in clean_output or '-- [E0' in clean_output:
                return QueryResult(
                    success=False,
                    output=clean_output.strip(),
                    error='Scala syntax error in query'
                )

            return QueryResult(
                success=True,
                output=clean_output.strip(),
                error=None
            )

        except requests.Timeout as e:
            logger.warning(f"Query timed out after {timeout}s: {str(e)}")
            return QueryResult(
                success=False,
                output='',
                error=f'Query timed out after {timeout} seconds'
            )
        except requests.HTTPError as e:
            logger.error(f"HTTP error during query: {e}")
            return QueryResult(
                success=False,
                output='',
                error=f'HTTP error: {str(e)}'
            )
        except requests.RequestException as e:
            logger.error(f"Request failed during query: {e}")
            return QueryResult(
                success=False,
                output='',
                error=f'Server request failed: {str(e)}'
            )

    def list_items(self, query: str) -> List[str]:
        """
        Execute a query that returns a list of items

        Args:
            query: Scala query that returns a list (.l)

        Returns:
            List of items from the output
        """
        result = self.query(query)
        if result.success:
            output = result.output.strip()

            # Parse Scala List output: List("item1", "item2", ...)
            # The output format is: val resN: List[Type] = List(...)
            if 'List(' in output:
                # Extract the list content between List( and the last )
                start = output.find('List(')
                if start != -1:
                    start += 5  # Skip 'List('
                    # Find matching closing paren
                    depth = 1
                    i = start
                    while i < len(output) and depth > 0:
                        if output[i] == '(':
                            depth += 1
                        elif output[i] == ')':
                            depth -= 1
                        i += 1

                    if depth == 0:
                        list_content = output[start:i-1]
                        # Parse quoted strings, handling both """ and " quotes
                        items = []
                        in_quote = False
                        in_triple_quote = False
                        escaped = False
                        current = []
                        idx = 0

                        while idx < len(list_content):
                            # Check for triple quote
                            if idx + 2 < len(list_content) and list_content[idx:idx+3] == '"""':
                                if in_triple_quote:
                                    # Ending triple quote
                                    items.append(''.join(current))
                                    current = []
                                    in_triple_quote = False
                                    idx += 3
                                elif not in_quote:
                                    # Starting triple quote
                                    in_triple_quote = True
                                    idx += 3
                                else:
                                    # Inside regular quote, treat as content
                                    current.append(list_content[idx])
                                    idx += 1
                            elif in_triple_quote:
                                # Inside triple quote - add everything
                                current.append(list_content[idx])
                                idx += 1
                            elif escaped:
                                current.append(list_content[idx])
                                escaped = False
                                idx += 1
                            elif list_content[idx] == '\\':
                                escaped = True
                                current.append(list_content[idx])
                                idx += 1
                            elif list_content[idx] == '"':
                                if in_quote:
                                    items.append(''.join(current))
                                    current = []
                                in_quote = not in_quote
                                idx += 1
                            elif in_quote:
                                current.append(list_content[idx])
                                idx += 1
                            else:
                                # Outside any quote, skip whitespace and commas
                                idx += 1

                        return items

            # Fallback: try line-based parsing for backward compatibility
            return [line.strip() for line in output.split('\n') if line.strip()]
        return []

    def count(self, query: str) -> int:
        """
        Execute a query that returns a count

        Args:
            query: Scala query that outputs a number

        Returns:
            Integer count (0 if query fails)
        """
        result = self.query(query)
        if result.success:
            try:
                output = result.output
                # In server mode, output is like: "val count: Int = 17"
                # In CLI mode, it might be just "17"
                # Try to parse as direct integer first
                first_line = output.split('\n')[0].strip()
                try:
                    return int(first_line)
                except ValueError:
                    # Try to extract from "val name: Type = value" format
                    import re
                    # Remove ANSI codes first
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', first_line)
                    # Extract number from "val ... = NUMBER"
                    match = re.search(r'=\s*(\d+)', clean_line)
                    if match:
                        return int(match.group(1))
                    return 0
            except (ValueError, IndexError):
                return 0
        return 0

    def parse_json_result(self, output: str) -> Any:
        """
        Parse JSON from Joern Scala REPL output

        Handles multiple output formats:
        - val res: String = \"\"\"[...]\"\"\"  (triple-quote)
        - val res: String = "[...]"       (escaped quotes)
        - [...]                           (direct JSON)

        Args:
            output: Raw output from Joern query

        Returns:
            Parsed JSON (dict, list, or primitive)

        Raises:
            json.JSONDecodeError: If output is not valid JSON

        Example:
            result = cpg.query('cpg.method.name.l.toJson')
            data = cpg.parse_json_result(result.output)
        """
        import re

        output = output.strip()

        # Try triple-quote format: val res: String = """[...]"""
        match = re.search(r'val \w+: \w+ = """(.*)"""', output, re.DOTALL)
        if match:
            json_str = match.group(1)
            return json.loads(json_str)

        # Try single-quote format: val res: String = "[...]"
        match = re.search(r'val \w+: \w+ = "(.*)"', output, re.DOTALL)
        if match:
            json_str = match.group(1)
            # Unescape the string
            json_str = json_str.replace('\\"', '"').replace('\\\\', '\\')
            return json.loads(json_str)

        # Try direct JSON parse
        return json.loads(output)

    def detect_languages(self, max_files: int = 1000) -> Dict[str, int]:
        """
        Detect programming languages in the project

        Args:
            max_files: Maximum number of files to scan

        Returns:
            Dict mapping language names to file counts
        """
        return self.file_tool.detect_languages(max_files)

    def detect_primary_language(self) -> Optional[str]:
        """
        Detect the primary language of the project

        Returns:
            Language name or None if no files found
        """
        return self.file_tool.detect_primary_language()

    def detect_build_files(self) -> Dict[str, bool]:
        """
        Detect build/dependency files in the project

        Returns:
            Dict of build file types found
        """
        return self.file_tool.detect_build_files()

    def detect_version(self) -> Optional[str]:
        """
        Detect application version from build files

        Returns:
            Version string or None if not found
        """
        return self.file_tool.detect_version()

    def generate_cpg(self, language: Optional[str] = None,
                     output_path: Optional[str] = None,
                     fetch_dependencies: bool = True) -> CpgGenerationResult:
        """
        Generate a CPG for the project

        Args:
            language: Language to use (auto-detected if None)
            output_path: Output path for CPG (uses self.cpg_path if None)
            fetch_dependencies: Whether to fetch project dependencies (default: True)
                               Set to False for framework source analysis

        Returns:
            CpgGenerationResult with success status and details
        """
        # Detect language if not specified
        if language is None:
            language = self.detect_primary_language()
            if language is None:
                return CpgGenerationResult(
                    success=False,
                    error='Could not detect project language',
                    language=None,
                    command=None
                )

        # Check if we support this language
        if language not in self.LANGUAGE_GENERATORS:
            return CpgGenerationResult(
                success=False,
                error=f'Unsupported language: {language}',
                language=language,
                command=None
            )

        # Use unified joern-parse command - it auto-detects language from file extensions
        command = 'joern-parse'

        # Determine output path
        if output_path:
            target_name = output_path
        else:
            # Use self.cpg_path (which may be auto-generated name)
            target_name = self.cpg_path

        # Convert to absolute path - store in workspace directory
        if not os.path.isabs(target_name):
            target_path = os.path.join(self.workspace_dir, target_name)
        else:
            target_path = target_name

        # Delete existing CPG file to ensure clean generation
        if os.path.exists(target_path):
            try:
                os.remove(target_path)
                logger.debug(f"Removed existing CPG file: {target_path}")
            except (OSError, PermissionError) as e:
                error_msg = f'Cannot remove existing CPG file: {e}. It may be in use by a CPG server.'
                logger.error(error_msg)
                return CpgGenerationResult(
                    success=False,
                    language=language,
                    command=None,
                    error=error_msg,
                    stderr=str(e)
                )

        # Always use project root (.) so joern-parse can find all source files
        # and build files (pom.xml, build.gradle, etc.)
        source_path = '.'

        # Build exclusion patterns for test directories from config
        # These go after --frontend-args to be passed to the specific frontend
        exclude_options = []
        for pattern in self.config.test_exclusions:
            exclude_options.extend(['--exclude', pattern])

        generator = self.LANGUAGE_GENERATORS[language]
        command = generator['command']
        options = generator['options'].copy()

        # Filter out --fetch-dependencies if requested
        if not fetch_dependencies:
            options = [opt for opt in options if opt != '--fetch-dependencies']

        # Add language-specific options based on detected build files
        if language == 'java':
            build_files = self.detect_build_files()
            if build_files.get('maven') or build_files.get('gradle'):
                # Already have --fetch-dependencies in options if needed
                pass

        # Build the command with explicit output path and source directory
        cmd_parts = [command] + options + exclude_options + ['-o', target_path, source_path]

        logger.info(f"Generating CPG for {language} project...")
        logger.debug(f"Command: {' '.join(cmd_parts)}")
        logger.debug(f"Working directory: {self.project_dir}")
        logger.debug(f"Source directory: {source_path}")
        print(f"Generating CPG for {language} project...")
        print(f"Command: {' '.join(cmd_parts)}")
        print(f"Working directory: {self.project_dir}")
        print(f"Source directory: {source_path}")

        try:
            result = subprocess.run(
                cmd_parts,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=self.config.generation_timeout_seconds
            )

            if result.returncode == 0:
                # Check if CPG was created at target path
                if os.path.exists(target_path):
                    file_size = os.path.getsize(target_path)

                    # Log stderr even on success to capture warnings
                    if result.stderr and result.stderr.strip():
                        logger.warning(f"CPG generation stderr: {result.stderr[:500]}")
                        if self.debug:
                            print(f"⚠ CPG generation warnings:\n{result.stderr[:500]}")

                    # Validate CPG size - use dynamic threshold based on source file count
                    # A 30-file project typically produces ~150KB CPG
                    # Larger projects scale proportionally (300 files → ~1.5MB)
                    # Only flag as suspicious if CPG is < 1KB per source file
                    file_size_mb = file_size / (1024 * 1024)
                    file_size_kb = file_size / 1024

                    if not self.ignore_cpg_size:
                        # Count source files in project (rough estimate)
                        source_count = self.file_tool.count_source_files()
                        if source_count > 0:
                            kb_per_file = file_size_kb / source_count
                            # Flag if less than 1KB per source file (suspiciously small)
                            if kb_per_file < 1.0:
                                error_msg = f'CPG suspiciously small ({file_size} bytes, {file_size_mb:.2f} MB) for {source_count} source files ({kb_per_file:.1f} KB/file). Generation may have failed.'
                                logger.error(error_msg)
                                logger.error(f"stderr: {result.stderr[:1000]}")
                                print(f"✗ {error_msg}")
                                if result.stderr:
                                    print(f"Error details:\n{result.stderr[:1000]}")
                                return CpgGenerationResult(
                                    success=False,
                                    language=language,
                                    command=' '.join(cmd_parts),
                                    error=error_msg,
                                    stderr=result.stderr
                                )
                            else:
                                logger.debug(f"CPG size check passed: {kb_per_file:.1f} KB/file for {source_count} files")
                        else:
                            logger.warning("Could not count source files for CPG size validation")

                    logger.info(f"CPG generated successfully: {target_path} ({file_size} bytes)")
                    print(f"✓ CPG generated successfully: {target_path} ({file_size} bytes)")

                    # Update self.cpg_path to reflect actual location
                    if not os.path.isabs(target_name):
                        self.cpg_path = target_name

                    return CpgGenerationResult(
                        success=True,
                        language=language,
                        command=' '.join(cmd_parts),
                        cpg_path=target_path,
                        size=file_size,
                        error=None,
                        stderr=result.stderr if result.stderr else None
                    )
                else:
                    error_msg = f'CPG file not created at {target_path}'
                    logger.error(error_msg)
                    return CpgGenerationResult(
                        success=False,
                        language=language,
                        command=' '.join(cmd_parts),
                        error=error_msg,
                        stderr=result.stderr
                    )
            else:
                # CPG generation failed
                error_msg = f'Command failed with exit code {result.returncode}'
                logger.error(f"{error_msg}: {result.stderr[:200]}")
                return CpgGenerationResult(
                    success=False,
                    language=language,
                    command=' '.join(cmd_parts),
                    error=error_msg,
                    stderr=result.stderr
                )

        except subprocess.TimeoutExpired:
            timeout_minutes = self.config.generation_timeout_seconds // 60
            error_msg = f'CPG generation timed out after {timeout_minutes} minutes'
            logger.error(error_msg)
            return CpgGenerationResult(
                success=False,
                language=language,
                command=' '.join(cmd_parts),
                error=error_msg
            )
        except FileNotFoundError:
            error_msg = f'Command not found: {command}. Is CPG installed and in PATH?'
            logger.error(error_msg)
            return CpgGenerationResult(
                success=False,
                language=language,
                command=' '.join(cmd_parts),
                error=error_msg
            )
        except subprocess.SubprocessError as e:
            error_msg = f'Subprocess error: {str(e)}'
            logger.error(error_msg, exc_info=True)
            return CpgGenerationResult(
                success=False,
                language=language,
                command=' '.join(cmd_parts),
                error=error_msg
            )
        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            logger.error(error_msg, exc_info=True)
            return CpgGenerationResult(
                success=False,
                language=language,
                command=' '.join(cmd_parts),
                error=error_msg
            )


def main():
    """Demo the CPG Tool"""
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  cpg_tool.py <command> [options]")
        print("\nCommands:")
        print("  detect <project_dir>              - Detect languages in project")
        print("  generate <project_dir>            - Generate CPG for project")
        print("  query <cpg_path> <project_dir> <query>  - Execute CPG query")
        print("\nExamples:")
        print("  cpg_tool.py detect ~/my-project")
        print("  cpg_tool.py generate ~/my-project")
        print("  cpg_tool.py query cpg.bin ~/project 'cpg.typeDecl.name.l.size'")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'detect':
        if len(sys.argv) < 3:
            print("Usage: cpg_tool.py detect <project_dir>")
            sys.exit(1)

        project_dir = sys.argv[2]
        tool = CpgTool('cpg.bin', project_dir)

        print(f"Detecting languages in {project_dir}...\n")

        languages = tool.detect_languages()
        if languages:
            print("Languages detected:")
            for lang, count in sorted(languages.items(), key=lambda x: -x[1]):
                print(f"  {lang}: {count} files")

            primary = tool.detect_primary_language()
            print(f"\nPrimary language: {primary}")
        else:
            print("No recognized source files found")

        print("\nBuild files detected:")
        build_files = tool.detect_build_files()
        found_any = False
        for build_type, found in build_files.items():
            if found:
                print(f"  ✓ {build_type}")
                found_any = True
        if not found_any:
            print("  (none)")

    elif command == 'generate':
        if len(sys.argv) < 3:
            print("Usage: cpg_tool.py generate <project_dir> [language]")
            sys.exit(1)

        project_dir = sys.argv[2]
        language = sys.argv[3] if len(sys.argv) > 3 else None

        tool = CpgTool('cpg.bin', project_dir)

        # Show what we detected
        if language is None:
            detected = tool.detect_languages()
            primary = tool.detect_primary_language()
            print(f"Detected languages: {detected}")
            print(f"Primary language: {primary}\n")

        result = tool.generate_cpg(language=language)

        if result.success:
            print(f"\n✓ Successfully generated CPG")
            print(f"  Language: {result.language}")
            print(f"  Size: {result.size} bytes")
            print(f"  Path: {result.cpg_path}")
        else:
            print(f"\n✗ Failed to generate CPG")
            print(f"  Error: {result.error}")
            if result.stderr:
                print(f"  Details: {result.stderr[:500]}")
            sys.exit(1)

    elif command == 'query':
        if len(sys.argv) < 5:
            print("Usage: cpg_tool.py query <cpg_path> <project_dir> <query>")
            sys.exit(1)

        cpg_path = sys.argv[2]
        project_dir = sys.argv[3]
        query = sys.argv[4]

        tool = CpgTool(cpg_path, project_dir)
        result = tool.query(query)

        if result.success:
            print(result.output)
        else:
            print(f"Error: {result.error}", file=sys.stderr)
            sys.exit(1)

    else:
        print(f"Unknown command: {command}")
        print("Valid commands: detect, generate, query")
        sys.exit(1)


if __name__ == "__main__":
    main()
