#!/usr/bin/env python3
"""
Comprehensive test suite for framework_detector.py

Tests framework loading, detection, helper methods, and edge cases.
"""

import json
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sar.framework_tool import FrameworkTool
from sar.framework_schema import FrameworkDefinition

# Backward compatibility alias
FrameworkDetector = FrameworkTool


class TestFrameworkLoading:
    """Test framework loading from JSON/YAML files"""

    @staticmethod
    def test_load_json_frameworks():
        """Test loading JSON framework files with Pydantic validation"""
        print("\n=== Test: Load JSON Frameworks ===")

        # Use actual frameworks directory
        sar_root = Path(__file__).parent.parent
        project_dir = sar_root / 'tests'  # Dummy project dir

        detector = FrameworkDetector(str(project_dir))

        # Should load at least 100+ frameworks from data/frameworks/
        assert len(detector.available_frameworks) >= 100, \
            f"Expected 100+ frameworks, got {len(detector.available_frameworks)}"

        # Check that spring-security is loaded and is a FrameworkDefinition
        assert 'spring-security' in detector.available_frameworks
        spring_security = detector.available_frameworks['spring-security']
        assert isinstance(spring_security, FrameworkDefinition)
        assert spring_security.name == "Spring Security"

        print(f"✓ Loaded {len(detector.available_frameworks)} frameworks")
        print(f"✓ Spring Security: {spring_security.name} ({', '.join(spring_security.languages)})")
        return True

    @staticmethod
    def test_skip_schema_and_sample_files():
        """Test that .schema.json and SAMPLE_ files are skipped"""
        print("\n=== Test: Skip Schema and Sample Files ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()

            # Create test files
            valid_framework = {
                "name": "Test Framework",
                "languages": ["java"],
                "detection": {"files": {"pattern": ["test.txt"]}}
            }

            # Valid framework
            with open(frameworks_dir / 'test-framework.json', 'w') as f:
                json.dump(valid_framework, f)

            # Schema file (should be skipped)
            with open(frameworks_dir / 'framework.schema.json', 'w') as f:
                json.dump({"type": "object"}, f)

            # Sample file (should be skipped)
            with open(frameworks_dir / 'SAMPLE_framework.json', 'w') as f:
                json.dump(valid_framework, f)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))

            # Should only load test-framework
            assert len(detector.available_frameworks) == 1
            assert 'test-framework' in detector.available_frameworks
            assert 'framework.schema' not in detector.available_frameworks
            assert 'SAMPLE_framework' not in detector.available_frameworks

        print("✓ Correctly skipped .schema and SAMPLE_ files")
        return True

    @staticmethod
    def test_load_custom_frameworks():
        """Test loading custom frameworks from project's .compass/ directory"""
        print("\n=== Test: Load Custom Frameworks ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            compass_dir = project_dir / '.compass'
            compass_dir.mkdir()

            # Create custom framework config
            custom_framework = {
                "name": "Custom Framework",
                "languages": ["java"],
                "detection": {"files": {"pattern": ["custom.txt"]}}
            }

            with open(compass_dir / 'my-framework-compass-config.json', 'w') as f:
                json.dump(custom_framework, f)

            # Use empty frameworks dir to isolate test
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))

            # Should load custom framework
            assert len(detector.available_frameworks) == 1
            assert 'my-framework-compass-config' in detector.available_frameworks

        print("✓ Successfully loaded custom framework from .compass/")
        return True

    @staticmethod
    def test_handle_invalid_json():
        """Test graceful handling of invalid JSON files"""
        print("\n=== Test: Handle Invalid JSON ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()

            # Create invalid JSON file
            with open(frameworks_dir / 'invalid.json', 'w') as f:
                f.write("{invalid json}")

            # Create valid framework
            valid_framework = {
                "name": "Valid Framework",
                "languages": ["java"],
                "detection": {"files": {"pattern": ["test.txt"]}}
            }
            with open(frameworks_dir / 'valid.json', 'w') as f:
                json.dump(valid_framework, f)

            # Should load valid framework and skip invalid
            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))

            assert len(detector.available_frameworks) == 1
            assert 'valid' in detector.available_frameworks

        print("✓ Gracefully handled invalid JSON")
        return True


class TestFrameworkDetection:
    """Test framework detection using various methods"""

    @staticmethod
    def test_detect_by_pom_xml():
        """Test detecting frameworks by pom.xml dependencies"""
        print("\n=== Test: Detect by pom.xml ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create framework definition
            framework = {
                "name": "Spring Boot",
                "languages": ["java"],
                "detection": {
                    "dependencies": {
                        "pom.xml": [
                            {"artifact": "spring-boot-starter", "library": "Spring Boot"}
                        ]
                    }
                }
            }
            with open(frameworks_dir / 'spring-boot.json', 'w') as f:
                json.dump(framework, f)

            # Create pom.xml with dependency
            pom_content = """
            <project>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter</artifactId>
                    </dependency>
                </dependencies>
            </project>
            """
            with open(project_dir / 'pom.xml', 'w') as f:
                f.write(pom_content)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is not None
            assert len(result) == 1
            assert result[0][0] == 'spring-boot'

        print("✓ Detected framework by pom.xml artifact")
        return True

    @staticmethod
    def test_detect_by_build_gradle():
        """Test detecting frameworks by build.gradle dependencies"""
        print("\n=== Test: Detect by build.gradle ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create framework definition
            framework = {
                "name": "Kotlin",
                "languages": ["kotlin"],
                "detection": {
                    "dependencies": {
                        "build.gradle": [
                            {"pattern": "org.jetbrains.kotlin:kotlin-stdlib", "library": "Kotlin"}
                        ]
                    }
                }
            }
            with open(frameworks_dir / 'kotlin.json', 'w') as f:
                json.dump(framework, f)

            # Create build.gradle with dependency
            gradle_content = """
            dependencies {
                implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.0'
            }
            """
            with open(project_dir / 'build.gradle', 'w') as f:
                f.write(gradle_content)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is not None
            assert len(result) == 1
            assert result[0][0] == 'kotlin'

        print("✓ Detected framework by build.gradle pattern")
        return True

    @staticmethod
    def test_detect_by_requirements_txt():
        """Test detecting frameworks by requirements.txt"""
        print("\n=== Test: Detect by requirements.txt ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create framework definition
            framework = {
                "name": "Django",
                "languages": ["python"],
                "detection": {
                    "dependencies": {
                        "requirements.txt": [
                            {"pattern": "django", "library": "Django"}
                        ]
                    }
                }
            }
            with open(frameworks_dir / 'django.json', 'w') as f:
                json.dump(framework, f)

            # Create requirements.txt
            with open(project_dir / 'requirements.txt', 'w') as f:
                f.write("django==4.2.0\nrequests==2.31.0\n")

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is not None
            assert len(result) == 1
            assert result[0][0] == 'django'

        print("✓ Detected framework by requirements.txt")
        return True

    @staticmethod
    def test_detect_by_package_json():
        """Test detecting frameworks by package.json"""
        print("\n=== Test: Detect by package.json ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create framework definition
            framework = {
                "name": "React",
                "languages": ["javascript"],
                "detection": {
                    "dependencies": {
                        "package.json": [
                            {"pattern": "react", "library": "React"}
                        ]
                    }
                }
            }
            with open(frameworks_dir / 'react.json', 'w') as f:
                json.dump(framework, f)

            # Create package.json
            package = {
                "dependencies": {
                    "react": "^18.2.0",
                    "react-dom": "^18.2.0"
                }
            }
            with open(project_dir / 'package.json', 'w') as f:
                json.dump(package, f)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is not None
            assert len(result) == 1
            assert result[0][0] == 'react'

        print("✓ Detected framework by package.json")
        return True

    @staticmethod
    def test_detect_multiple_frameworks():
        """Test detecting multiple frameworks in same project"""
        print("\n=== Test: Detect Multiple Frameworks ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create multiple framework definitions
            spring = {
                "name": "Spring",
                "languages": ["java"],
                "detection": {
                    "dependencies": {
                        "pom.xml": [
                            {"artifact": "spring-core", "library": "Spring"}
                        ]
                    }
                }
            }
            hibernate = {
                "name": "Hibernate",
                "languages": ["java"],
                "detection": {
                    "dependencies": {
                        "pom.xml": [
                            {"artifact": "hibernate-core", "library": "Hibernate"}
                        ]
                    }
                }
            }

            with open(frameworks_dir / 'spring.json', 'w') as f:
                json.dump(spring, f)
            with open(frameworks_dir / 'hibernate.json', 'w') as f:
                json.dump(hibernate, f)

            # Create pom.xml with both dependencies
            pom_content = """
            <dependencies>
                <dependency><artifactId>spring-core</artifactId></dependency>
                <dependency><artifactId>hibernate-core</artifactId></dependency>
            </dependencies>
            """
            with open(project_dir / 'pom.xml', 'w') as f:
                f.write(pom_content)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is not None
            assert len(result) == 2
            framework_ids = [fw[0] for fw in result]
            assert 'spring' in framework_ids
            assert 'hibernate' in framework_ids

        print("✓ Detected multiple frameworks")
        return True

    @staticmethod
    def test_no_frameworks_detected():
        """Test when no frameworks match"""
        print("\n=== Test: No Frameworks Detected ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create framework that won't match
            framework = {
                "name": "Test",
                "languages": ["java"],
                "detection": {
                    "dependencies": {
                        "pom.xml": [
                            {"artifact": "nonexistent", "library": "Test"}
                        ]
                    }
                }
            }
            with open(frameworks_dir / 'test.json', 'w') as f:
                json.dump(framework, f)

            # Empty project
            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_all_frameworks()

            assert result is None

        print("✓ Correctly returned None when no frameworks detected")
        return True


class TestHelperMethods:
    """Test private helper methods"""

    @staticmethod
    def test_check_build_file_dependencies():
        """Test _check_build_file_dependencies helper"""
        print("\n=== Test: _check_build_file_dependencies ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create pom.xml
            pom_content = '<dependencies><artifactId>test-artifact</artifactId></dependencies>'
            with open(project_dir / 'pom.xml', 'w') as f:
                f.write(pom_content)

            # Create dummy framework (not used for detection)
            framework = {
                "name": "Test",
                "languages": ["java"],
                "detection": {}
            }
            with open(frameworks_dir / 'test.json', 'w') as f:
                json.dump(framework, f)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))

            # Test with matching artifact
            from sar.framework_schema import DependencyPattern
            deps = [DependencyPattern(artifact="test-artifact", library="Test")]
            result = detector._check_build_file_dependencies('pom.xml', deps)
            assert result is True

            # Test with non-matching artifact
            deps = [DependencyPattern(artifact="other-artifact", library="Test")]
            result = detector._check_build_file_dependencies('pom.xml', deps)
            assert result is False

            # Test with missing file
            result = detector._check_build_file_dependencies('nonexistent.xml', deps)
            assert result is False

            # Test with empty dependencies
            result = detector._check_build_file_dependencies('pom.xml', [])
            assert result is False

        print("✓ Helper method works correctly")
        return True


class TestPublicMethods:
    """Test public API methods"""

    @staticmethod
    def test_get_framework_config():
        """Test get_framework_config method"""
        print("\n=== Test: get_framework_config ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            framework = {
                "name": "Test Framework",
                "languages": ["java"],
                "detection": {}
            }
            with open(frameworks_dir / 'test-fw.json', 'w') as f:
                json.dump(framework, f)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))

            # Get existing framework
            config = detector.get_framework_config('test-fw')
            assert config is not None
            assert isinstance(config, FrameworkDefinition)
            assert config.name == "Test Framework"

            # Get non-existent framework
            config = detector.get_framework_config('nonexistent')
            assert config is None

        print("✓ get_framework_config works correctly")
        return True

    @staticmethod
    def test_list_frameworks():
        """Test list_frameworks method"""
        print("\n=== Test: list_frameworks ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            # Create multiple frameworks
            for name in ['fw1', 'fw2', 'fw3']:
                framework = {
                    "name": f"Framework {name}",
                    "languages": ["java"],
                    "detection": {}
                }
                with open(frameworks_dir / f'{name}.json', 'w') as f:
                    json.dump(framework, f)

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            frameworks = detector.list_frameworks()

            assert len(frameworks) == 3
            assert 'fw1' in frameworks
            assert 'fw2' in frameworks
            assert 'fw3' in frameworks

        print("✓ list_frameworks works correctly")
        return True

    @staticmethod
    def test_detect_framework_backward_compatibility():
        """Test detect_framework (legacy method) for backward compatibility"""
        print("\n=== Test: detect_framework Backward Compatibility ===")

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()
            frameworks_dir = Path(tmpdir) / 'frameworks'
            frameworks_dir.mkdir()

            framework = {
                "name": "Test",
                "languages": ["java"],
                "detection": {
                    "dependencies": {
                        "pom.xml": [{"artifact": "test", "library": "Test"}]
                    }
                }
            }
            with open(frameworks_dir / 'test.json', 'w') as f:
                json.dump(framework, f)

            # Create matching pom.xml
            with open(project_dir / 'pom.xml', 'w') as f:
                f.write('<artifactId>test</artifactId>')

            detector = FrameworkDetector(str(project_dir), str(frameworks_dir))
            result = detector.detect_framework()

            # Should return tuple of (first_framework_id, all_frameworks_list)
            assert result is not None
            assert isinstance(result, tuple)
            assert len(result) == 2
            assert result[0] == 'test'  # First framework ID
            assert isinstance(result[1], list)  # All frameworks list
            assert len(result[1]) == 1

        print("✓ detect_framework backward compatibility maintained")
        return True


class TestIntegration:
    """Integration tests with real frameworks"""

    @staticmethod
    def test_spring_petclinic_detection():
        """Test detection on real spring-petclinic project"""
        print("\n=== Test: Spring Petclinic Detection (Integration) ===")

        petclinic_path = Path(__file__).parent.parent.parent / 'spring-petclinic'

        if not petclinic_path.exists():
            print("⚠ SKIP: spring-petclinic not found")
            return True

        detector = FrameworkDetector(str(petclinic_path))
        result = detector.detect_all_frameworks()

        if result:
            print(f"✓ Detected {len(result)} frameworks:")
            for fw_id, fw_def in result[:5]:
                print(f"  - {fw_def.name} ({fw_id})")

            # Spring should be detected
            framework_ids = [fw[0] for fw in result]
            assert 'spring' in framework_ids or 'spring-boot' in framework_ids
        else:
            print("⚠ No frameworks detected (unexpected)")
            return False

        return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("Framework Detector Comprehensive Test Suite")
    print("=" * 70)

    test_classes = [
        ("Framework Loading", TestFrameworkLoading, [
            ("Load JSON Frameworks", TestFrameworkLoading.test_load_json_frameworks),
            ("Skip Schema/Sample Files", TestFrameworkLoading.test_skip_schema_and_sample_files),
            ("Load Custom Frameworks", TestFrameworkLoading.test_load_custom_frameworks),
            ("Handle Invalid JSON", TestFrameworkLoading.test_handle_invalid_json),
        ]),
        ("Framework Detection", TestFrameworkDetection, [
            ("Detect by pom.xml", TestFrameworkDetection.test_detect_by_pom_xml),
            ("Detect by build.gradle", TestFrameworkDetection.test_detect_by_build_gradle),
            ("Detect by requirements.txt", TestFrameworkDetection.test_detect_by_requirements_txt),
            ("Detect by package.json", TestFrameworkDetection.test_detect_by_package_json),
            ("Detect Multiple Frameworks", TestFrameworkDetection.test_detect_multiple_frameworks),
            ("No Frameworks Detected", TestFrameworkDetection.test_no_frameworks_detected),
        ]),
        ("Helper Methods", TestHelperMethods, [
            ("_check_build_file_dependencies", TestHelperMethods.test_check_build_file_dependencies),
        ]),
        ("Public API", TestPublicMethods, [
            ("get_framework_config", TestPublicMethods.test_get_framework_config),
            ("list_frameworks", TestPublicMethods.test_list_frameworks),
            ("detect_framework (legacy)", TestPublicMethods.test_detect_framework_backward_compatibility),
        ]),
        ("Integration Tests", TestIntegration, [
            ("Spring Petclinic Detection", TestIntegration.test_spring_petclinic_detection),
        ]),
    ]

    results = []

    for category_name, test_class, tests in test_classes:
        print(f"\n{'=' * 70}")
        print(f"{category_name}")
        print('=' * 70)

        for test_name, test_func in tests:
            try:
                passed = test_func()
                results.append((f"{category_name}: {test_name}", passed))
            except Exception as e:
                print(f"\n❌ EXCEPTION in {test_name}: {e}")
                import traceback
                traceback.print_exc()
                results.append((f"{category_name}: {test_name}", False))

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
