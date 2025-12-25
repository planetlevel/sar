#!/usr/bin/env python3
"""Diagnose why custom annotation queries are failing on TeamServer"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sar.cpg_tool import CpgTool

# Initialize CPG for TeamServer
project_dir = os.path.expanduser('~/git/teamserver-3.12.7/teamserver-app')
cpg_path = os.path.join(project_dir, 'workspace/teamserver-app-10.0.0.bin/cpg.bin')
cpg_tool = CpgTool(cpg_path=cpg_path, project_dir=project_dir, auto_generate=False)

# Test queries for custom annotations
annotations = ['Superadmin', 'OnlySaaS', 'FreemiumAvailable']

for annotation in annotations:
    print(f"\n{'='*80}")
    print(f"Testing annotation: @{annotation}")
    print('='*80)

    query = f'''
        cpg.method
          .where(_.annotation.name("{annotation}"))
          .map {{ m =>
            Map(
              "method" -> m.fullName,
              "file" -> m.file.name.headOption.getOrElse("unknown"),
              "line" -> m.lineNumber.getOrElse(0),
              "class" -> m.typeDecl.fullName.headOption.getOrElse("unknown"),
              "annotation" -> "{annotation}"
            )
          }}.toJson
    '''

    print(f"\nQuery:\n{query}")

    result = cpg_tool.query(query)
    print(f"\nSuccess: {result.success}")
    print(f"Output length: {len(result.output) if result.output else 0}")
    print(f"Error: {result.error if result.error else 'None'}")

    if result.output:
        print(f"\nRaw output (first 500 chars):")
        print(result.output[:500])

        # Try to parse as JSON
        import json
        try:
            data = cpg_tool.parse_json_result(result.output)
            print(f"\n✓ Valid JSON - {len(data)} results")
            if data:
                print(f"\nFirst result:")
                print(json.dumps(data[0], indent=2))
        except json.JSONDecodeError as e:
            print(f"\n✗ Invalid JSON: {e}")
            print(f"\nTrying to find where JSON breaks...")
            for i in range(min(len(result.output), 1000), 0, -100):
                try:
                    json.loads(result.output[:i])
                    print(f"JSON is valid up to character {i}")
                    break
                except:
                    pass
