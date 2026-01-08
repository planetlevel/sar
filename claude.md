# SAR Project - Critical Architectural Rules

## STRICT RULES - DO NOT VIOLATE

### 1. Defense Analyzer Must Remain Generic
- **defense_analyzer.py is ONLY an orchestration framework**
- It must NOT contain any language-specific or framework-specific logic
- It must NOT know about specific metrics like "effective_authorization" or "restrictiveness"
- It simply runs agents and consolidates their results

### 2. No Framework/Language Specifics ANYWHERE in Code
- **ALL framework/language-specific questions must be delegated to AI**
- This includes defense_analyzer.py, all agents, and all utilities
- The system must work on ANY project (Java, Python, Go, etc.)
- Framework detection happens by using searches defined in local framework json files
- Never hardcode patterns like "Spring Security" or "@PreAuthorize"
- Agents discover patterns by asking AI, not by looking for specific strings

### 3. Pydantic Models Are Source of Truth
- **The defense_report_schema.py Pydantic models define the contract**
- All agents must return data that validates against these models
- The schema drives the implementation, not the other way around
- Use Pydantic validation to ensure data consistency

### 4. No Backward Compatibility Compromises
- **Break things rather than maintain old structures**
- Clean code is more important than compatibility
- When improving, make the right change even if it breaks existing code
- Don't accumulate technical debt for compatibility

### 5. AI Handles Discovery
- Standard security defenses are discovered using patterns in local framework json files
- Custom security patterns are discovered by AI, not hardcoded
- AI adapts to project-specific implementations
- The system learns from each codebase rather than assuming patterns

## Implementation Notes

### Agent Output
Agents should:
1. Import the Pydantic models from defense_report_schema
2. Build their response using the AgentRecommendation model
3. Validate the data through Pydantic
4. Return model.model_dump() for the orchestrator

### Defense Analyzer
The defense_analyzer should:
1. Import the DefenseReport model
2. Build the report using the model
3. Validate through Pydantic before returning
4. Let the schema drive what fields are available

### Schema Changes
When updating schema:
1. Update the Pydantic models first
2. Regenerate the JSON schema
3. Update agents to match the new models
4. Let validation catch any mismatches

## Remember
- Generic orchestration, specific implementation in agents
- Pydantic models define the truth
- AI handles language/framework specifics
- Break compatibility for cleaner code
