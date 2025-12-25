#!/usr/bin/env python3
"""
Test script for AI enrichment feature in FrameworkTool
"""

import sys
from pathlib import Path
from sar.framework_tool import FrameworkTool
from compass.ai_client import AIClient

def main():
    # Setup
    project_dir = Path("../spring-petclinic").resolve()
    print(f"Testing AI enrichment on: {project_dir}")
    print()

    # Initialize AI client
    ai_client = AIClient()

    # Initialize framework tool with AI client
    tool = FrameworkTool(
        project_dir=str(project_dir),
        ai_client=ai_client,
        debug=True
    )

    # Detect frameworks
    print("=" * 80)
    print("DETECTING FRAMEWORKS")
    print("=" * 80)
    frameworks = tool.detect_frameworks()
    print(f"Detected {len(frameworks)} frameworks:")
    for fw_id, fw_def in frameworks.items():
        print(f"  - {fw_def.name} ({fw_id})")
    print()

    # Search for authorization patterns (includes HttpSecurity with ai_interpret=true)
    print("=" * 80)
    print("SEARCHING AUTHORIZATION PATTERNS WITH AI ENRICHMENT")
    print("=" * 80)
    behaviors = tool.search_patterns(frameworks, 'security.authorization')

    print(f"\nFound {len(behaviors)} authorization behaviors")
    print()

    # Display behaviors with AI interpretation
    print("=" * 80)
    print("BEHAVIORS WITH AI INTERPRETATION")
    print("=" * 80)
    for i, behavior in enumerate(behaviors, 1):
        print(f"\n--- Behavior {i} ---")
        print(f"Framework: {behavior.get('framework')}")
        print(f"Type: {behavior.get('type')}")
        print(f"Mechanism: {behavior.get('mechanism')}")
        print(f"Location: {behavior.get('location')}")
        print(f"File: {behavior.get('file')}:{behavior.get('line')}")

        # Show AI interpretation if present
        if 'ai_interpretation' in behavior:
            print(f"\n🤖 AI INTERPRETATION:")
            ai = behavior['ai_interpretation']
            print(f"   Severity: {ai.get('severity', 'unknown')}")
            print(f"   Impact: {ai.get('impact', 'No impact provided')}")
            if 'rules' in ai and ai['rules']:
                print(f"   Rules:")
                for rule in ai['rules']:
                    print(f"     - {rule}")
        else:
            print("\n(No AI interpretation)")

    # Focus on HttpSecurity behaviors
    print("\n" + "=" * 80)
    print("HTTP SECURITY CONFIGURATIONS (with AI analysis)")
    print("=" * 80)
    http_security_behaviors = [
        b for b in behaviors
        if 'HttpSecurity' in b.get('mechanism', '') or 'http_security' in b.get('type', '')
    ]

    if http_security_behaviors:
        for behavior in http_security_behaviors:
            print(f"\n📄 {behavior.get('file')}:{behavior.get('line')}")
            print(f"   Mechanism: {behavior.get('mechanism')}")

            if 'ai_interpretation' in behavior:
                ai = behavior['ai_interpretation']
                print(f"\n   ⚠️  SEVERITY: {ai.get('severity', 'unknown').upper()}")
                print(f"   💥 IMPACT: {ai.get('impact')}")
                print(f"\n   📋 Security Rules:")
                for rule in ai.get('rules', []):
                    print(f"      • {rule}")
            else:
                print("   ⚠️  No AI interpretation available")
    else:
        print("No HttpSecurity configurations found")

if __name__ == "__main__":
    main()
