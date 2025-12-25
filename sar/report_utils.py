#!/usr/bin/env python3
"""
Report Utilities - Generic report building and formatting functions

Provides standardized report structure and formatting utilities used across
all defense analysis agents. These functions ensure consistent report format
regardless of which agent generates the recommendation.
"""

from typing import Dict, List, Any


def build_defense_usage_matrix(exposures: List[Dict],
                                all_mechanisms: List[Dict],
                                defense_type: str = 'authorization') -> Dict:
    """
    Build matrix: exposures (rows) × defense options (columns)

    Generic matrix builder that works for any defense type. Agents choose
    what the rows and columns represent based on their analysis:
    - Authorization: rows = endpoints/routes, columns = roles
    - Input validation: rows = endpoints, columns = validation types
    - Output encoding: rows = endpoints, columns = encoding mechanisms

    Args:
        exposures: List of exposure dicts with 'method', 'route', 'httpMethod', 'class'
        all_mechanisms: List of discovered defense mechanisms with 'behaviors'
        defense_type: Type of defense being analyzed (for documentation)

    Returns:
        {
            'rows': ['GET /api/owners/{id}', 'POST /api/owners', ...],  # Exposure identifiers
            'columns': ['USER', 'ADMIN'],  # Defense options (roles, validation types, etc.)
            'matrix': [
                [True, False],   # GET /api/owners/{id}: protected by USER only
                [True, True],    # POST /api/owners: protected by USER and ADMIN
                [False, False],  # DELETE /api/owners/{id}: UNPROTECTED
            ],
            'row_protected': [True, True, False],  # Which rows have any protection
        }

    Example (Authorization):
        17 endpoints × 2 roles (USER, ADMIN)
        Matrix[i][j] = True if endpoint i requires role j

    Example (Input Validation):
        15 endpoints × 3 validation types (PARAM, BODY, HEADER)
        Matrix[i][j] = True if endpoint i validates input type j
    """
    # Extract all unique defense options from mechanisms
    # For authorization: roles, mechanisms, expressions; for validation: validation types; etc.
    all_options = set()
    for mechanism in all_mechanisms:
        for behavior in mechanism.get('behaviors', []):
            # Extract explicit options (roles, validation types, etc.)
            all_options.update(behavior.get('roles', []))
            all_options.update(behavior.get('validation_types', []))
            all_options.update(behavior.get('encoding_types', []))

            # FALLBACK: If no explicit options, use mechanism name itself
            # This captures @PreAuthorize (SpEL), @Superadmin, @OnlySaaS, etc.
            has_explicit_options = (behavior.get('roles') or
                                   behavior.get('validation_types') or
                                   behavior.get('encoding_types'))
            if not has_explicit_options:
                mech_name = behavior.get('mechanism', 'UNKNOWN')
                # Abbreviate long mechanism names for display
                if len(mech_name) > 20:
                    # Take first + last parts: "SuperAdminCalifragilisticExpialidocious" -> "SuperAdmin...cious"
                    mech_name = mech_name[:12] + '...' + mech_name[-5:]
                all_options.add(mech_name)

    columns = sorted(list(all_options))  # Defense options

    # Build row identifiers from exposures
    rows = []
    for exp in exposures:
        # Format: "GET /api/owners/{id}" or "GET OwnerController.getOwner"
        http_method = exp.get('httpMethod', 'UNKNOWN')
        route = exp.get('route', '')

        # If no route, use simplified method name
        if not route:
            method_full = exp.get('method', 'unknown')
            # Extract class.method from full signature
            # e.g., "org.example.Owner.Controller.getOwner:String(int)" -> "OwnerController.getOwner"
            if ':' in method_full:
                method_full = method_full.split(':')[0]
            if '.' in method_full:
                parts = method_full.split('.')
                # Get last 2 parts (ClassName.methodName)
                route = '.'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]
            else:
                route = method_full

        rows.append(f"{http_method} {route}")

    # Build matrix: rows × columns
    matrix = []
    row_protected = []

    for exp in exposures:
        # Find which defense options protect this exposure
        protecting_options = set()
        exp_method = exp.get('method', '')
        exp_class = exp.get('class', '')

        # Search mechanisms for behaviors that match this exposure
        for mechanism in all_mechanisms:
            for behavior in mechanism.get('behaviors', []):
                # Match by method signature and class
                if (behavior.get('method') == exp_method and
                    behavior.get('class') == exp_class):
                    # Collect all defense options from this behavior
                    protecting_options.update(behavior.get('roles', []))
                    protecting_options.update(behavior.get('validation_types', []))
                    protecting_options.update(behavior.get('encoding_types', []))

                    # FALLBACK: If no explicit options, add mechanism name
                    has_explicit_options = (behavior.get('roles') or
                                           behavior.get('validation_types') or
                                           behavior.get('encoding_types'))
                    if not has_explicit_options:
                        mech_name = behavior.get('mechanism', 'UNKNOWN')
                        # Apply same abbreviation as column building
                        if len(mech_name) > 20:
                            mech_name = mech_name[:12] + '...' + mech_name[-5:]
                        protecting_options.add(mech_name)

        # Create row: True if defense option protects this exposure
        row = [option in protecting_options for option in columns]
        matrix.append(row)
        row_protected.append(any(row))

    return {
        'rows': rows,
        'columns': columns,
        'matrix': matrix,
        'row_protected': row_protected
    }


def build_defense_metadata(all_mechanisms: List[Dict], defense_type: str = 'authorization') -> Dict:
    """
    Build defense metadata section for report

    Summarizes which defense mechanisms were found and what patterns they use.

    Args:
        all_mechanisms: List of discovered defense mechanisms
        defense_type: Type of defense (e.g., 'authorization', 'validation')

    Returns:
        {
            'defense_name': 'spring-security, custom',
            'defense_type': 'standard' | 'custom' | 'mixed',
            'defense_mechanism': 'annotation' | 'middleware' | 'code',
            'defense_patterns': [...]
        }
    """
    if not all_mechanisms:
        return {
            'defense_name': f'No {defense_type.title()} Detected',
            'defense_type': 'N/A',
            'defense_mechanism': 'N/A',
            'defense_patterns': []
        }

    # Build defense name from mechanisms found
    mechanism_names = [f"{m.get('framework', 'unknown')}" for m in all_mechanisms]
    unique_mechanisms = list(set(mechanism_names))

    defense_name = ', '.join(unique_mechanisms[:3])
    if len(unique_mechanisms) > 3:
        defense_name += f" (+ {len(unique_mechanisms) - 3} more)"

    defense_type_classification = 'standard' if all(m.get('type') == 'standard' for m in all_mechanisms) \
                  else 'custom' if all(m.get('type') == 'custom' for m in all_mechanisms) \
                  else 'mixed'

    # Get pattern examples - use actual PatternGroup metadata
    patterns = []
    for mechanism in all_mechanisms[:5]:
        for pattern in mechanism.get('patterns', [])[:2]:
            patterns.append({
                'target': mechanism.get('pattern_group_target', 'unknown'),
                'search_type': mechanism.get('pattern_group_search_type', 'unknown'),
                'pattern': pattern,
                'description': mechanism.get('pattern_group_description',
                                             f"{mechanism.get('framework', 'unknown')} {defense_type} pattern")
            })

    return {
        'defense_name': defense_name,
        'defense_type': defense_type_classification,
        'defense_mechanism': 'annotation',  # Simplified - could be inferred from patterns
        'defense_patterns': patterns
    }


def calculate_metrics(evidence: Dict) -> Dict:
    """
    Calculate standardized coverage metrics from evidence

    Extracts and formats coverage metrics in standard format used across all agents.

    Args:
        evidence: Evidence dict containing 'coverage_metrics'

    Returns:
        {
            'exposures': 17,      # Total exposures analyzed
            'protected': 5,        # Exposures with defense
            'unprotected': 12,     # Exposures without defense
            'coverage': 29.4       # Percentage protected
        }
    """
    coverage_metrics = evidence.get('coverage_metrics', {})

    return {
        'exposures': coverage_metrics.get('exposures', coverage_metrics.get('total_endpoints', 0)),
        'protected': coverage_metrics.get('protected', 0),
        'unprotected': coverage_metrics.get('unprotected', 0),
        'coverage': coverage_metrics.get('coverage', 0)
    }
