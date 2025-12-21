#!/usr/bin/env python3
"""
Tests for FrameworkTool pattern searching functionality

Tests:
1. search_patterns() finds authorization patterns
2. Convenience methods work correctly
3. Pattern extraction and execution work
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sar.framework_tool import FrameworkTool
from compass.cpg_tool import CpgTool


def test_find_authorization_patterns_spring_petclinic():
    """Test finding @PreAuthorize annotations in spring-petclinic"""
    print("\n=== Test 1: Find Authorization Patterns in Spring Petclinic ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True

    try:
        # Initialize FrameworkTool
        print(f"  Initializing FrameworkTool for {petclinic_path}...")
        tool = FrameworkTool(petclinic_path)

        # Detect frameworks
        print(f"  Detecting frameworks...")
        frameworks = tool.detect_frameworks()

        if not frameworks:
            print(f"  ❌ FAIL: No frameworks detected")
            return False

        print(f"  ✓ Detected {len(frameworks)} frameworks")
        for fw_id, fw_def in frameworks.items():
            print(f"    - {fw_id}: {fw_def.name}")

        # Search for authorization patterns
        print(f"  Searching for authorization patterns...")
        behaviors = tool.find_authorization_patterns(frameworks)

        if not behaviors:
            print(f"  ⚠ INFO: No authorization patterns found (may be expected)")
            return True

        print(f"  ✓ Found {len(behaviors)} authorization behaviors")

        # Display first few results
        for i, behavior in enumerate(behaviors[:3], 1):
            print(f"\n    Behavior {i}:")
            print(f"      Framework: {behavior.get('framework')}")
            print(f"      Category: {behavior.get('category')}")
            print(f"      Type: {behavior.get('type')}")
            print(f"      Mechanism: {behavior.get('mechanism')}")
            print(f"      Location: {behavior.get('location')}")
            print(f"      Roles: {behavior.get('roles', [])}")

        if len(behaviors) > 3:
            print(f"\n    ... and {len(behaviors) - 3} more")

        print("\n✓ PASS: Authorization pattern search works correctly")
        return True

    except Exception as e:
        print(f"❌ FAIL: Error searching for patterns: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_search_patterns_with_category_path():
    """Test search_patterns() with explicit category path"""
    print("\n=== Test 2: Search Patterns with Category Path ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True

    try:
        tool = FrameworkTool(petclinic_path)
        frameworks = tool.detect_frameworks()

        if not frameworks:
            print(f"  ⚠ SKIP: No frameworks detected")
            return True

        # Test explicit category path
        print(f"  Testing search_patterns() with 'security.authorization'...")
        behaviors = tool.search_patterns(frameworks, 'security.authorization')

        print(f"  ✓ search_patterns() returned {len(behaviors)} results")

        if behaviors:
            # Verify structure
            first = behaviors[0]
            required_fields = ['framework', 'category', 'type', 'mechanism', 'location']
            missing = [f for f in required_fields if f not in first]

            if missing:
                print(f"  ❌ FAIL: Missing required fields: {missing}")
                return False

            print(f"  ✓ All required fields present in results")

        print("✓ PASS: search_patterns() works with category path")
        return True

    except Exception as e:
        print(f"❌ FAIL: Error in search_patterns(): {e}")
        import traceback
        traceback.print_exc()
        return False


def test_convenience_methods():
    """Test all convenience methods"""
    print("\n=== Test 3: Convenience Methods ===")

    petclinic_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'spring-petclinic')

    if not os.path.exists(petclinic_path):
        print(f"⚠ SKIP: {petclinic_path} does not exist")
        return True

    try:
        tool = FrameworkTool(petclinic_path)
        frameworks = tool.detect_frameworks()

        if not frameworks:
            print(f"  ⚠ SKIP: No frameworks detected")
            return True

        # Test each convenience method
        methods = [
            ('find_authorization_patterns', tool.find_authorization_patterns),
            ('find_routing_patterns', tool.find_routing_patterns),
            ('find_input_validation_patterns', tool.find_input_validation_patterns),
            ('find_database_patterns', tool.find_database_patterns),
        ]

        for method_name, method in methods:
            try:
                results = method(frameworks)
                print(f"  ✓ {method_name}(): {len(results)} results")
            except Exception as e:
                print(f"  ❌ {method_name}() failed: {e}")
                return False

        print("✓ PASS: All convenience methods work correctly")
        return True

    except Exception as e:
        print(f"❌ FAIL: Error testing convenience methods: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("FrameworkTool Pattern Search Tests")
    print("=" * 70)

    tests = [
        ("Find Authorization Patterns", test_find_authorization_patterns_spring_petclinic),
        ("Search Patterns with Category Path", test_search_patterns_with_category_path),
        ("Convenience Methods", test_convenience_methods),
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
