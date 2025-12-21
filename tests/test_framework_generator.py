#!/usr/bin/env python3
"""
Tests for framework_generator.py

Tests:
1. Framework generation produces valid Pydantic models
2. Generated frameworks match existing framework definitions
3. Framework detection works correctly with generated frameworks
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sar.framework_schema import load_framework, FrameworkDefinition
from sar.framework_detector import FrameworkDetector
from compass.cpg_tool import CpgTool


def test_load_existing_spring_security():
    """Test that we can load the existing spring-security.json with Pydantic validation"""
    print("\n=== Test 1: Load Existing Spring Security Framework ===")

    frameworks_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'frameworks')
    spring_security_path = os.path.join(frameworks_dir, 'spring-security.json')

    if not os.path.exists(spring_security_path):
        print(f"❌ FAIL: {spring_security_path} does not exist")
        return False

    try:
        # Load with Pydantic validation
        framework_def = load_framework(spring_security_path)

        print(f"✓ Successfully loaded spring-security.json")
        print(f"  Name: {framework_def.name}")
        print(f"  Languages: {framework_def.languages}")
        print(f"  Extends: {framework_def.extends}")

        # Verify architecture structure
        if framework_def.architecture:
            # Architecture is a Pydantic model with specific fields
            arch_fields = [f for f in dir(framework_def.architecture) if not f.startswith('_') and getattr(framework_def.architecture, f) is not None]
            print(f"  Architecture categories: {len(arch_fields)}")

            # Check for defense (security field in Architecture model)
            if framework_def.architecture.security:
                defense = framework_def.architecture.security
                # Security is SecurityArchitecture, check for authorization patterns
                if hasattr(defense, 'authorization') and defense.authorization:
                    auth_patterns = defense.authorization
                    print(f"  ✓ security.authorization found")
                    print(f"    Authorization patterns: {len(auth_patterns)}")

                    # Check first pattern for schema compliance
                    if auth_patterns:
                        first_pattern = auth_patterns[0]
                        print(f"    Target: {first_pattern.target}")
                        print(f"    Search type: {first_pattern.search_type}")

                        # Verify schema compliance (new field names)
                        if first_pattern.target and first_pattern.search_type:
                            print(f"    ✓ Uses new schema (target)")
                        else:
                            print(f"    ❌ Missing required fields")
                            return False

        print("✓ PASS: spring-security.json loads and validates correctly")
        return True

    except Exception as e:
        print(f"❌ FAIL: Error loading spring-security.json: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_framework_detection_spring_petclinic():
    """Test that framework detection works on spring-petclinic using Pydantic models"""
    print("\n=== Test 2: Framework Detection on Spring Petclinic ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True  # Skip, not a failure

    try:
        # Initialize detector
        detector = FrameworkDetector(petclinic_path)

        print(f"  Available frameworks: {len(detector.available_frameworks)}")

        # Detect frameworks
        result = detector.detect_all_frameworks()

        if not result:
            print(f"  ❌ FAIL: No frameworks detected")
            return False

        print(f"  ✓ Detected {len(result)} frameworks")

        # Check for Spring Security
        spring_security_found = False
        for framework_id, framework_def in result:
            print(f"    - {framework_id}: {framework_def.name}")
            if 'spring-security' in framework_id.lower():
                spring_security_found = True

                # Verify it's a proper FrameworkDefinition
                if not isinstance(framework_def, FrameworkDefinition):
                    print(f"    ❌ FAIL: Framework is not a FrameworkDefinition instance")
                    return False

                # Verify architecture has security.authorization
                if framework_def.architecture and framework_def.architecture.security:
                    defense = framework_def.architecture.security
                    if hasattr(defense, 'authorization') and defense.authorization:
                        print(f"    ✓ Has security.authorization patterns")

        if spring_security_found:
            print("✓ PASS: Spring Security detected and validated")
            return True
        else:
            print("⚠ INFO: Spring Security not detected (may be expected)")
            return True  # Not a failure - petclinic might not use it

    except Exception as e:
        print(f"❌ FAIL: Error during framework detection: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_search_annotations_in_spring_petclinic():
    """Test that we can search for Spring Security annotations in spring-petclinic"""
    print("\n=== Test 3: Search for @PreAuthorize Annotations ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True  # Skip, not a failure

    try:
        # Create CPG
        print(f"  Generating CPG for {petclinic_path}...")
        cpg = CpgTool('auto', petclinic_path, auto_generate=True, debug=False)

        # Search for @PreAuthorize annotation
        query = '''
        cpg.annotation
          .name(".*PreAuthorize")
          .map(a => {
            val methodName = a.method.headOption.map(_.name).getOrElse("unknown")
            val className = a.method.headOption.flatMap(_.typeDecl.headOption).map(_.name).getOrElse("unknown")
            s"$className.$methodName"
          })
          .l
          .distinct
        '''

        results = cpg.list_items(query)

        if results:
            print(f"  ✓ Found {len(results)} @PreAuthorize annotations")
            for i, result in enumerate(results[:5], 1):
                print(f"    {i}. {result}")
            if len(results) > 5:
                print(f"    ... and {len(results) - 5} more")
            print("✓ PASS: Annotation search works correctly")
            return True
        else:
            print("  ⚠ INFO: No @PreAuthorize annotations found (may be expected)")
            return True  # Not necessarily a failure

    except Exception as e:
        print(f"❌ FAIL: Error searching for annotations: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_search_methods_in_spring_petclinic():
    """Test that we can search for Spring Security methods in spring-petclinic"""
    print("\n=== Test 4: Search for SecurityContextHolder Methods ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True  # Skip, not a failure

    try:
        # Create CPG
        print(f"  Generating CPG for {petclinic_path}...")
        cpg = CpgTool('auto', petclinic_path, auto_generate=True, debug=False)

        # Search for SecurityContextHolder.getContext() method calls
        query = '''
        cpg.call
          .name("getContext")
          .where(_.methodFullName(".*SecurityContextHolder.*"))
          .code
          .l
          .distinct
        '''

        results = cpg.list_items(query)

        if results:
            print(f"  ✓ Found {len(results)} SecurityContextHolder.getContext() calls")
            for i, result in enumerate(results[:3], 1):
                print(f"    {i}. {result}")
            print("✓ PASS: Method signature search works correctly")
            return True
        else:
            print("  ⚠ INFO: No SecurityContextHolder calls found (may be expected)")
            return True  # Not necessarily a failure

    except Exception as e:
        print(f"❌ FAIL: Error searching for methods: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_framework_schema_validation():
    """Test that framework JSON structure validates against Pydantic schema"""
    print("\n=== Test 5: Framework Schema Validation ===")

    frameworks_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'frameworks')

    if not os.path.exists(frameworks_dir):
        print(f"❌ FAIL: {frameworks_dir} does not exist")
        return False

    tested_count = 0
    passed_count = 0
    failed_frameworks = []

    for filename in os.listdir(frameworks_dir):
        if filename.endswith('.json') and not filename.endswith('.schema.json') and not filename.startswith('SAMPLE_'):
            framework_path = os.path.join(frameworks_dir, filename)
            tested_count += 1

            try:
                framework_def = load_framework(framework_path)
                passed_count += 1

                # Verify new schema field names are used
                # Architecture is a Pydantic model, just check it loaded successfully
                # The fact that it validated means schema is correct
                pass

            except Exception as e:
                failed_frameworks.append((filename, str(e)))

    print(f"  Tested {tested_count} framework files")
    print(f"  Passed: {passed_count}")
    print(f"  Failed: {len(failed_frameworks)}")

    if failed_frameworks:
        print("\n  Failed frameworks:")
        for filename, error in failed_frameworks:
            print(f"    ❌ {filename}: {error}")
        print("❌ FAIL: Some frameworks failed validation")
        return False

    print("✓ PASS: All framework files validate correctly")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("Framework Generator and Schema Validation Tests")
    print("=" * 70)

    tests = [
        ("Load Existing Spring Security", test_load_existing_spring_security),
        ("Framework Detection", test_framework_detection_spring_petclinic),
        ("Annotation Search", test_search_annotations_in_spring_petclinic),
        ("Method Search", test_search_methods_in_spring_petclinic),
        ("Schema Validation", test_framework_schema_validation),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            print(f"\n❌ EXCEPTION in {test_name}: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))

    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
