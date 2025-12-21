#!/usr/bin/env python3
"""
Migrate deprecated fields in framework JSON files.

Replaces:
- "type" -> "target"
- "patterns" -> "pattern"
- "signatures" -> "signature"
"""

import json
from pathlib import Path


def migrate_pattern_group(obj):
    """Recursively migrate deprecated fields in pattern groups"""
    if isinstance(obj, dict):
        # Migrate type -> target
        if 'type' in obj and 'target' not in obj:
            obj['target'] = obj.pop('type')

        # Migrate patterns -> pattern
        if 'patterns' in obj and 'pattern' not in obj:
            obj['pattern'] = obj.pop('patterns')

        # Migrate signatures -> signature
        if 'signatures' in obj and 'signature' not in obj:
            obj['signature'] = obj.pop('signatures')

        # Recursively process nested objects
        for key, value in obj.items():
            if isinstance(value, dict):
                migrate_pattern_group(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        migrate_pattern_group(item)

    return obj


def migrate_framework_file(filepath: Path, dry_run: bool = False):
    """Migrate a single framework file"""
    with open(filepath, 'r') as f:
        data = json.load(f)

    # Track if we made any changes
    original_json = json.dumps(data, indent=2)

    # Migrate the data
    migrated_data = migrate_pattern_group(data)

    migrated_json = json.dumps(migrated_data, indent=2)

    if original_json != migrated_json:
        if not dry_run:
            with open(filepath, 'w') as f:
                f.write(migrated_json + '\n')
        return True  # Changed

    return False  # No changes


def main():
    import sys

    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv

    frameworks_dir = Path('frameworks')
    changed_files = []
    unchanged_files = []

    print(f"{'DRY RUN: ' if dry_run else ''}Migrating deprecated fields in framework files...")

    for json_file in sorted(frameworks_dir.glob('*.json')):
        try:
            changed = migrate_framework_file(json_file, dry_run=dry_run)
            if changed:
                changed_files.append(json_file.name)
                print(f"  {'WOULD MIGRATE' if dry_run else 'MIGRATED'}: {json_file.name}")
            else:
                unchanged_files.append(json_file.name)
        except Exception as e:
            print(f"  ERROR: {json_file.name}: {e}")

    print(f"\n{'Would change' if dry_run else 'Changed'}: {len(changed_files)} files")
    print(f"Unchanged: {len(unchanged_files)} files")

    if dry_run and changed_files:
        print(f"\nRun without --dry-run to apply changes")


if __name__ == '__main__':
    main()
