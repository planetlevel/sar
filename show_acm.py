#!/usr/bin/env python3
import json
import sys

report_file = sys.argv[1] if len(sys.argv) > 1 else 'output/reports/defense_report_20251221_204954.json'

with open(report_file) as f:
    data = json.load(f)

# Check if proposed_access_matrix exists in the report
if 'proposed_access_matrix' not in data['recommendations'][1]['evidence']:
    print(f"ERROR: Report {report_file} does not contain proposed_access_matrix")
    print("This report was generated with an older version of the analyzer.")
    print("Run the analyzer again to generate a new report with the access control matrix.")
    sys.exit(1)

matrix = data['recommendations'][1]['evidence']['proposed_access_matrix']
current_matrix = data['recommendations'][1]['evidence']['defense_usage_matrix']

# ANSI color codes
RESET = '\033[0m'
BOLD = '\033[1m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BLUE = '\033[94m'

# =============================================================================
# CURRENT ACCESS CONTROL MATRIX
# =============================================================================
print(f'\n{BOLD}{YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}')
print(f'{BOLD}{YELLOW}║                     CURRENT ACCESS CONTROL MATRIX                            ║{RESET}')
print(f'{BOLD}{YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}\n')

# Current matrix data
current_rows = current_matrix['rows']
current_columns = current_matrix['columns']
current_data = current_matrix['matrix']
current_protected = current_matrix['row_protected']

# Calculate column widths for current matrix
current_endpoint_width = max(len(row) for row in current_rows) + 2
current_col_width = 8

# Print current matrix header
current_header = f"{BOLD}{'Endpoint':<{current_endpoint_width}}"
for col in current_columns:
    current_header += f"{col:^{current_col_width}}"
current_header += f"{RESET}"
print(current_header)
print('─' * (current_endpoint_width + len(current_columns) * current_col_width))

# Print current matrix rows
for i, row_name in enumerate(current_rows):
    ep_name = row_name
    if len(ep_name) > current_endpoint_width - 2:
        ep_name = ep_name[:current_endpoint_width-5] + '...'

    line = f"{ep_name:<{current_endpoint_width}}"
    if i < len(current_data):
        for j, val in enumerate(current_data[i]):
            if val:
                line += f"{GREEN}{'✓':^{current_col_width}}{RESET}"
            else:
                line += f"{' ':^{current_col_width}}"
    else:
        for _ in current_columns:
            line += f"{' ':^{current_col_width}}"

    # Add protection indicator
    if i < len(current_protected):
        if not current_protected[i]:
            line += f" {RED}(UNPROTECTED){RESET}"

    print(line)

print(f'\n{BOLD}Current Summary:{RESET}')
protected_count = sum(current_protected)
print(f"  Protected: {protected_count}/{len(current_rows)} ({protected_count/len(current_rows)*100:.1f}%)")
print(f"  Unprotected: {len(current_rows) - protected_count}\n")

# =============================================================================
# PROPOSED ACCESS CONTROL MATRIX
# =============================================================================
print(f'\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}')
print(f'{BOLD}{CYAN}║                    PROPOSED ACCESS CONTROL MATRIX                            ║{RESET}')
print(f'{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}\n')

# Role Structure
print(f'{BOLD}Role Structure:{RESET}')
print(f"  Current:  {YELLOW}{', '.join(matrix['role_structure']['current_roles'])}{RESET}")
print(f"  Proposed: {GREEN}{', '.join(matrix['role_structure']['proposed_roles'])}{RESET}")
print(f"  Rationale: {matrix['role_structure']['rationale']}\n")

# Summary
print(f'{BOLD}Summary:{RESET}')
print(f"  Total endpoints:       {matrix['total_endpoints']}")
print(f"  Currently protected:   {matrix['currently_protected']} ({matrix['currently_protected']/matrix['total_endpoints']*100:.1f}%)")
print(f"  Suggested PUBLIC:      {matrix['suggested_public']}")
print(f"  Suggested AUTHENTICATED: {matrix['suggested_authenticated']}")
print(f"  Suggested ROLE_SPECIFIC: {matrix['suggested_role_specific']}\n")

# Build the matrix
proposed_roles = matrix['role_structure']['proposed_roles']
classifications = matrix['endpoint_classifications']

# Add special columns for PUBLIC and AUTHENTICATED
all_columns = ['PUBLIC', 'AUTH'] + proposed_roles

# Build matrix data
matrix_data = []
for ep in classifications:
    row = {'endpoint': ep['endpoint'], 'rationale': ep['rationale']}

    # Check what auth is suggested
    if ep['suggested_auth'] == 'PUBLIC':
        row['PUBLIC'] = '✓'
        row['AUTH'] = ''
        for role in proposed_roles:
            row[role] = ''
    elif ep['suggested_auth'] == 'AUTHENTICATED':
        row['PUBLIC'] = ''
        row['AUTH'] = '✓'
        for role in proposed_roles:
            row[role] = ''
    elif ep['suggested_auth'] == 'ROLE_SPECIFIC':
        row['PUBLIC'] = ''
        row['AUTH'] = '✓'  # Role checks require authentication
        suggested_role = ep['suggested_role']
        # Handle both single role (string) and multiple roles (list)
        if isinstance(suggested_role, list):
            suggested_roles_list = suggested_role
        else:
            suggested_roles_list = [suggested_role] if suggested_role else []

        for role in proposed_roles:
            row[role] = '✓' if role in suggested_roles_list else ''

    matrix_data.append(row)

# Calculate column widths
endpoint_width = max(len(ep['endpoint']) for ep in classifications) + 2
col_width = 8
rationale_width = 60

# Print matrix header
header = f"{BOLD}{'Endpoint':<{endpoint_width}}"
for col in all_columns:
    header += f"{col:^{col_width}}"
header += f"{'Rationale':<{rationale_width}}{RESET}"
print(header)
print('─' * (endpoint_width + len(all_columns) * col_width + rationale_width))

# Print matrix rows
for i, row in enumerate(matrix_data):
    ep_name = row['endpoint']
    # Truncate long endpoint names
    if len(ep_name) > endpoint_width - 2:
        ep_name = ep_name[:endpoint_width-5] + '...'

    # Truncate rationale if needed
    rationale = row['rationale']
    if len(rationale) > rationale_width - 2:
        rationale = rationale[:rationale_width-5] + '...'

    line = f"{ep_name:<{endpoint_width}}"
    for col in all_columns:
        val = row.get(col, '')
        if val == '✓':
            line += f"{GREEN}{val:^{col_width}}{RESET}"
        else:
            line += f"{val:^{col_width}}"
    line += f"{rationale:<{rationale_width}}"
    print(line)

# Legend
print(f'\n{BOLD}Legend:{RESET}')
print(f"  {GREEN}✓{RESET} = Access granted")
print(f"  PUBLIC = No authentication required (use permitAll() in HTTP config)")
print(f"  AUTH = Any authenticated user (use isAuthenticated())")
print(f"  Role columns = Specific role required (use hasRole())\n")
