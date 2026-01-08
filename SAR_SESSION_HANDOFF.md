# SAR Project Session Handoff Document
**Last Updated:** 2026-01-08

## Project Overview
SAR (Security Architecture Recommendations) is an AI-powered defense analysis system that provides strategic security recommendations, NOT vulnerability scanning. It uses an agent-based architecture where specialized agents analyze different defense areas.

## Critical Architectural Rules (MUST FOLLOW)

1. **Defense Analyzer Must Remain Generic**
   - defense_analyzer.py is ONLY an orchestration framework
   - NO language/framework-specific logic anywhere in the code
   - All specifics delegated to AI

2. **Pydantic Models Are Source of Truth**
   - defense_report_schema.py defines the contract
   - All agents must return validated Pydantic data
   - Break compatibility rather than maintain old structures

3. **AI Handles Discovery**
   - Standard patterns found via framework JSON files in sar/frameworks/
   - Custom patterns discovered by AI
   - Never hardcode patterns like "@PreAuthorize" or "Spring Security"

## What Was Done Today

### 1. Schema Updates ✅
- Added `dimension` field to CoverageMetrics for two-dimension metrics (policy_coverage vs restrictiveness)
- Added `defense_id` to DefenseMetadata for machine-readable IDs
- Updated agent to use AgentRecommendation Pydantic model for validation
- Updated defense_analyzer to use DefenseReport Pydantic model

### 2. Model Upgrades ✅
- Updated SAR AI client to use Opus 4.5:
  - Bedrock: `global.anthropic.claude-opus-4-5-20251101-v1:0`
  - Anthropic API: `claude-opus-4-5-20250805`
- Updated PAI agents from Sonnet to Opus 4.5
- Updated both .claude/settings.json files to opus-4.5

### 3. Documentation Created ✅
- Created `/Users/jeffwilliams/git/sar/claude.md` with architectural rules
- This document for session continuity

## Remaining Work from IMPLEMENTATION_PLAN_METRICS.md

### Phase 2: Effective Authorization Calculation
- **Status:** Partially complete (endpoint_builder.py has the method)
- **Location:** sar/agents/endpoint_builder.py has `_compute_effective_authorization`
- **Need:** Verify it properly calculates effective auth across layers

### Phase 3: Two-Dimension HTTP Metrics
- **Status:** Schema ready, agent needs implementation
- **Location:** sar/agents/endpoint_authorization.py ~line 2554
- **Need:** Update `_build_defense_sections` to output both dimensions:
  - policy_coverage: Does HTTP Security make a decision? (permitAll=YES)
  - restrictiveness: Does it restrict access? (permitAll=NO)

### Phase 5: Narrative Data Consistency
- **Status:** Not started
- **Location:** sar/agents/endpoint_authorization.py ~line 3075
- **Need:** Update AI prompts in `_build_recommendation_prompt` to:
  - Correctly interpret two-dimension metrics
  - Ensure narrative matches matrix data
  - Explain permitAll=100% policy but 0% restrictiveness

### Phase 6: Framework Version Detection
- **Status:** Not started
- **Location:** sar/agents/endpoint_authorization.py ~line 2844
- **Need:** Update `_build_framework_context` to:
  - Detect Spring Security version
  - Recommend SecurityFilterChain for 6.0+
  - Mark WebSecurityConfigurerAdapter deprecated for 5.7+

## Key Technical Details

### Correct Model IDs for Opus 4.5
- **Bedrock:** `global.anthropic.claude-opus-4-5-20251101-v1:0` (needs global endpoint)
- **Anthropic API:** `claude-opus-4-5-20250805`
- **Claude settings:** `"model": "opus-4.5"`

### Testing Commands
```bash
# Activate virtual environment
source .venv/bin/activate

# Test AI connection
python3 -c "from sar.ai_client import AIClient; client = AIClient(debug=True); client.test_connection()"

# Regenerate schema after changes
python3 sar/defense_report_schema.py generate-schema

# Validate a report
python3 sar/defense_report_schema.py validate output/reports/some-report.json
```

### File Locations
- **Main orchestrator:** defense_analyzer.py
- **Schema:** sar/defense_report_schema.py
- **AI client:** sar/ai_client.py
- **Main agent:** sar/agents/endpoint_authorization.py
- **Endpoint builder:** sar/agents/endpoint_builder.py
- **Framework definitions:** sar/frameworks/*.json
- **Architectural rules:** /Users/jeffwilliams/git/sar/claude.md

## Important Gotchas

1. **Overall Coverage Bug:** Was showing 0 because it was looking in wrong place. Now agent provides it directly in its response.

2. **HTTP Security Metrics:** Currently backwards - permitAll shows as 100% coverage. Need two dimensions to fix this.

3. **No Hardcoding:** Even agents must NOT contain framework-specific logic. Everything goes through AI or framework JSON files.

4. **Pydantic Validation:** Always use Pydantic models, never raw dicts. Let validation catch issues early.

5. **Model Limits:** AI client has token limits. Keep prompts focused.

## Session State
- Virtual environment: .venv (Python 3.14)
- AWS authenticated via SSO (./login.sh)
- All tests passing with Opus 4.5
- Git status: Multiple modified files, not committed

## Next Steps
1. Implement Phase 3: Two-dimension HTTP metrics in agent
2. Implement Phase 5: Fix AI prompts for narrative consistency
3. Implement Phase 6: Version-aware framework recommendations
4. Test with a real project (spring-petclinic recommended)
5. Commit changes once tested

## Contact
Jeff Williams (jeff@contraxt.xyz)
Project: Security Architecture Recommendations (SAR)
Goal: Strategic security design guidance, not vulnerability scanning