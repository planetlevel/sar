#!/usr/bin/env python3
"""
Convert framework JSON files from old schema to new schema

Old schema:
  "authorization": {
    "annotations": {
      "type": "joern",
      "search_type": "annotation_name",
      "patterns": [...]
    }
  }

New schema:
  "authorization": [
    {
      "target": "joern",
      "search_type": "annotation_name",
      "pattern": [...],
      "description": "..."
    }
  ]

Changes:
1. Flatten nested structure - remove "annotations", "methods" sub-groups
2. Rename "type" to "target"
3. Rename "patterns" to "pattern" (singular)
4. Rename "signatures" to "signature" (for method_signature search_type)
5. Convert pattern groups to array of pattern objects
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any


def convert_pattern_group(group: Dict, group_name: str = None) -> List[Dict]:
    """
    Convert a pattern group from old schema to new schema

    Returns a list of pattern objects
    """
    patterns = []

    # Handle old "type" -> new "target"
    target = group.get('target') or group.get('type')
    search_type = group.get('search_type')

    if not target or not search_type:
        print(f"  WARNING: Missing target or search_type in group: {group_name}")
        return patterns

    # Handle different pattern formats
    if 'patterns' in group:
        # Old format: "patterns" array or object
        old_patterns = group['patterns']

        if isinstance(old_patterns, list):
            # Array of patterns (could be strings or objects)
            if old_patterns and isinstance(old_patterns[0], dict):
                # Array of objects with "signature" field (wrong schema!)
                for item in old_patterns:
                    pattern_obj = {
                        'target': target,
                        'search_type': search_type
                    }

                    if 'signature' in item:
                        # This should be "pattern" or "signature" depending on search_type
                        if search_type == 'method_signature':
                            pattern_obj['signature'] = item['signature']
                        else:
                            pattern_obj['pattern'] = item['signature']

                    if 'description' in item:
                        pattern_obj['description'] = item['description']

                    patterns.append(pattern_obj)
            else:
                # Array of strings - combine into single pattern with array
                pattern_obj = {
                    'target': target,
                    'search_type': search_type,
                    'pattern': old_patterns
                }
                if group_name:
                    pattern_obj['description'] = f"{group_name} patterns"
                patterns.append(pattern_obj)

        elif isinstance(old_patterns, dict):
            # Named patterns (like http methods)
            # Keep as single pattern with dict
            pattern_obj = {
                'target': target,
                'search_type': search_type,
                'pattern': old_patterns
            }
            if group_name:
                pattern_obj['description'] = f"{group_name} named patterns"
            patterns.append(pattern_obj)

    elif 'signatures' in group:
        # Old format: "signatures" array
        old_signatures = group['signatures']

        for sig_item in old_signatures:
            pattern_obj = {
                'target': target,
                'search_type': search_type
            }

            if isinstance(sig_item, dict):
                pattern_obj['signature'] = sig_item['signature']
                if 'description' in sig_item:
                    pattern_obj['description'] = sig_item['description']
            else:
                # String signature
                pattern_obj['signature'] = sig_item

            patterns.append(pattern_obj)

    elif 'pattern' in group:
        # Already new format (single pattern)
        pattern_obj = {
            'target': target,
            'search_type': search_type,
            'pattern': group['pattern']
        }
        if 'description' in group:
            pattern_obj['description'] = group['description']
        patterns.append(pattern_obj)

    elif 'signature' in group:
        # Already new format (single signature)
        pattern_obj = {
            'target': target,
            'search_type': search_type,
            'signature': group['signature']
        }
        if 'description' in group:
            pattern_obj['description'] = group['description']
        patterns.append(pattern_obj)

    return patterns


def convert_architecture_category(category: Dict, category_name: str) -> Dict:
    """
    Convert an architecture category (like "authorization", "authentication")
    from old nested structure to new flat array structure

    Returns converted category
    """
    # Check if already an array (new format)
    if isinstance(category, list):
        print(f"  {category_name}: Already in new format (array)")
        return category

    # Check if it's a direct pattern group (not nested)
    if 'target' in category or 'type' in category:
        # Single pattern group - convert to array
        patterns = convert_pattern_group(category, category_name)
        print(f"  {category_name}: Converted direct pattern group -> {len(patterns)} patterns")
        return patterns

    # Nested structure - flatten it
    all_patterns = []
    for sub_key, sub_value in category.items():
        if isinstance(sub_value, dict) and ('target' in sub_value or 'type' in sub_value):
            # This is a pattern group
            patterns = convert_pattern_group(sub_value, f"{category_name}.{sub_key}")
            all_patterns.extend(patterns)
            print(f"  {category_name}.{sub_key}: Converted -> {len(patterns)} patterns")
        else:
            # Not a pattern group - keep as-is (like "public_access" guidance)
            print(f"  {category_name}.{sub_key}: Skipping non-pattern data")

    return all_patterns


def convert_framework_file(input_path: Path, dry_run: bool = True) -> Dict:
    """
    Convert a framework JSON file from old to new schema

    Returns the converted framework dict
    """
    print(f"\n{'='*70}")
    print(f"Converting: {input_path.name}")
    print(f"{'='*70}")

    with open(input_path) as f:
        framework = json.load(f)

    converted = framework.copy()

    # Convert architecture categories
    if 'architecture' in framework:
        converted['architecture'] = {}

        for top_category, top_value in framework['architecture'].items():
            print(f"\n{top_category}:")

            if not isinstance(top_value, dict):
                print(f"  Skipping non-dict: {type(top_value)}")
                converted['architecture'][top_category] = top_value
                continue

            # Convert each sub-category
            converted_top = {}
            for sub_category, sub_value in top_value.items():
                if isinstance(sub_value, dict) or isinstance(sub_value, list):
                    converted_sub = convert_architecture_category(sub_value, sub_category)
                    converted_top[sub_category] = converted_sub
                else:
                    converted_top[sub_category] = sub_value

            converted['architecture'][top_category] = converted_top

    return converted


def print_comparison(original: Dict, converted: Dict, category_path: str = ""):
    """Print a comparison of original vs converted to verify no data loss"""
    pass  # TODO: implement if needed


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 convert_framework_schema.py <framework_dir> [--write]")
        print("  Defaults to dry-run mode (show changes without writing)")
        print("  Use --write to actually write converted files")
        sys.exit(1)

    frameworks_dir = Path(sys.argv[1])
    dry_run = '--write' not in sys.argv

    if not frameworks_dir.exists():
        print(f"Error: Directory not found: {frameworks_dir}")
        sys.exit(1)

    print(f"Mode: {'DRY RUN (no changes)' if dry_run else 'WRITE MODE (will modify files)'}")
    print(f"Directory: {frameworks_dir}")

    # Convert all JSON files
    for framework_file in sorted(frameworks_dir.glob('*.json')):
        converted = convert_framework_file(framework_file, dry_run)

        if dry_run:
            # Show preview
            print(f"\n--- Preview of converted structure ---")
            if 'architecture' in converted:
                for top_cat, top_val in converted['architecture'].items():
                    if isinstance(top_val, dict):
                        for sub_cat, sub_val in top_val.items():
                            if isinstance(sub_val, list):
                                print(f"{top_cat}.{sub_cat}: {len(sub_val)} patterns")
        else:
            # Write converted file (overwrite original)
            with open(framework_file, 'w') as f:
                json.dump(converted, f, indent=2)
            print(f"\nWrote: {framework_file}")

    if dry_run:
        print(f"\n{'='*70}")
        print("DRY RUN COMPLETE - No files were modified")
        print("Review the output above, then run with --write to apply changes")
        print(f"{'='*70}")


if __name__ == '__main__':
    main()
