#!/usr/bin/env python3
import json
import sys

report_file = sys.argv[1] if len(sys.argv) > 1 else 'output/reports/defense_report_20251221_204954.json'

with open(report_file) as f:
    data = json.load(f)

# Find endpoint_authorization agent
auth_agent = None
for rec in data['recommendations']:
    if rec.get('agent_id') == 'endpoint_authorization':
        auth_agent = rec
        break

if not auth_agent:
    print(f"ERROR: Report {report_file} does not contain endpoint_authorization agent")
    sys.exit(1)

# Check if proposed_access_matrix exists in the report
if 'proposed_access_matrix' not in auth_agent['evidence']:
    print(f"ERROR: Report {report_file} does not contain proposed_access_matrix")
    print("This report was generated with an older version of the analyzer.")
    print("Run the analyzer again to generate a new report with the access control matrix.")
    sys.exit(1)

matrix = auth_agent['evidence']['proposed_access_matrix']
current_matrix = auth_agent['evidence']['defense_usage_matrix']

# ANSI color codes
RESET = '\033[0m'
BOLD = '\033[1m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BLUE = '\033[94m'

# =============================================================================
# CURRENT DEFENSE DEPLOYMENT MATRIX
# =============================================================================
print(f'\n{BOLD}{YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}')
print(f'{BOLD}{YELLOW}║                  CURRENT DEFENSE DEPLOYMENT MATRIX                           ║{RESET}')
print(f'{BOLD}{YELLOW}║                (Shows which role checks are currently applied)              ║{RESET}')
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
# PROPOSED DEFENSE DEPLOYMENT MATRIX
# =============================================================================
print(f'\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}')
print(f'{BOLD}{CYAN}║                 PROPOSED DEFENSE DEPLOYMENT MATRIX                           ║{RESET}')
print(f'{BOLD}{CYAN}║               (Shows which role checks should be applied)                    ║{RESET}')
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

# Build map of current protection by endpoint
current_protection = {}
for i, endpoint_name in enumerate(current_rows):
    is_protected = current_protected[i] if i < len(current_protected) else False
    if is_protected and i < len(current_data):
        # Get which roles are currently assigned
        current_roles = []
        for j, has_role in enumerate(current_data[i]):
            if has_role and j < len(current_columns):
                current_roles.append(current_columns[j])
        current_protection[endpoint_name] = current_roles
    else:
        current_protection[endpoint_name] = None

# Build matrix data
matrix_data = []
for ep in classifications:
    endpoint_name = ep['endpoint']
    row = {'endpoint': endpoint_name, 'rationale': ep['rationale']}

    # Get current protection status
    current_roles = current_protection.get(endpoint_name)
    is_currently_protected = current_roles is not None

    # Check what auth is suggested
    if ep['suggested_auth'] == 'PUBLIC':
        # PUBLIC endpoints should have no protection
        row['PUBLIC'] = ('✓', 'green') if not is_currently_protected else ('✓', 'red')
        row['AUTH'] = ''
        for role in proposed_roles:
            row[role] = ''
    elif ep['suggested_auth'] == 'AUTHENTICATED':
        row['PUBLIC'] = ''
        # Check if currently has AUTH (any protection)
        has_auth = is_currently_protected
        row['AUTH'] = ('✓', 'green') if has_auth else ('✓', 'red')
        for role in proposed_roles:
            row[role] = ''
    elif ep['suggested_auth'] == 'ROLE_SPECIFIC':
        row['PUBLIC'] = ''
        row['AUTH'] = ('✓', 'green') if is_currently_protected else ('✓', 'red')

        suggested_role = ep['suggested_role']
        # Handle both single role (string) and multiple roles (list)
        if isinstance(suggested_role, list):
            suggested_roles_list = suggested_role
        else:
            suggested_roles_list = [suggested_role] if suggested_role else []

        for role in proposed_roles:
            if role in suggested_roles_list:
                # Check if this role is currently assigned
                has_role = current_roles and role in current_roles
                row[role] = ('✓', 'green') if has_role else ('✓', 'red')
            else:
                row[role] = ''

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
        if isinstance(val, tuple):
            # Colored checkmark: (symbol, color)
            symbol, color = val
            color_code = GREEN if color == 'green' else RED
            line += f"{color_code}{symbol:^{col_width}}{RESET}"
        elif val == '✓':
            # Legacy: treat as green
            line += f"{GREEN}{val:^{col_width}}{RESET}"
        else:
            line += f"{val:^{col_width}}"
    line += f"{rationale:<{rationale_width}}"
    print(line)

# Legend
print(f'\n{BOLD}Legend:{RESET}')
print(f"  {GREEN}✓{RESET} = Defense ALREADY APPLIED (present in current implementation)")
print(f"  {RED}✓{RESET} = Defense NEEDS TO BE ADDED (missing, proposed by analysis)")
print(f"  PUBLIC = No authentication required - configure at framework/HTTP layer (NOT a role)")
print(f"  AUTH = Any authenticated user - requires authentication but no specific role")
print(f"  Role columns = Check for specific role - requires authentication + role check")
print(f"\n{BOLD}Implementation Notes:{RESET}")
print(f"  • Focus on {RED}red checkmarks{RESET} - these are the gaps to close")
print(f"  • PUBLIC endpoints: Configure in framework's allowlist, do NOT add role checks")
print(f"  • Role hierarchy (e.g., ADMIN accessing everything) configured separately in framework")
print(f"  • This matrix shows WHICH defenses to DEPLOY, not who ultimately has access\n")
