     ENDPOINT AUTHORIZATION AGENT - ANALYSIS FLOW
     ================================================================================

     MAIN ENTRY POINT
     --------------------------------------------------------------------------------
     run()                        Main execution - orchestrates all 3 phases
     analyze()                    Alias for run() - called by defense analyzer

     PHASE 1: MECHANISM DISCOVERY
     --------------------------------------------------------------------------------
     _discover_standard_mechanisms()
         → Queries CPG for standard auth annotations (@PreAuthorize, @Secured)
         → Uses framework definitions to find patterns
         → Returns list of mechanisms with behaviors

     _detect_authorization_pattern()
         → Analyzes WHERE standard defenses exist
         → Identifies architecture pattern (endpoint/service/mixed layer)
         → Uses AI to understand the pattern

     _run_ai_analysis()
         → AI investigates authorization architecture
         → Looks for custom patterns not in frameworks
         → Returns AI insights about the system

     PHASE 1.5: CUSTOM DEFENSE DISCOVERY (NEW!)
     --------------------------------------------------------------------------------
     _discover_custom_defenses()
         → Main orchestrator for finding custom auth patterns
         → Samples unprotected exposures
         → Reads code and uses AI to identify patterns

     _sample_exposures_for_analysis()
         → Selects ~30 unprotected exposures to analyze
         → Prioritizes high-risk (DELETE, admin operations)
         → Adds random samples for diversity

     _read_exposure_source_code()
         → Reads actual source files for sampled exposures
         → Gets ~30 lines of context around each method
         → Returns code samples for AI analysis

     _ai_identify_custom_patterns()
         → Gives ALL code samples to AI in one prompt
         → AI identifies custom auth patterns (annotations, manual checks, etc.)
         → Returns list of discovered patterns

     _query_custom_patterns()
         → Takes patterns identified by AI
         → Queries CPG to find all instances
         → Returns custom mechanisms in standard format

     _query_custom_annotation()
         → Joern query for methods with custom annotation
         → E.g., find all @Superadmin usages

     _query_class_level_authorization()
         → Joern query for class-level annotations
         → Finds all methods in classes with auth annotation

     PHASE 2: ARCHITECTURE EVALUATION
     --------------------------------------------------------------------------------
     _evaluate_architecture()
         → Evaluates quality across 4 dimensions
         → Returns assessment of authorization architecture

     _evaluate_consistency()
         → Are defenses applied consistently?

     _evaluate_centralization()
         → Are defenses centralized or scattered?

     _evaluate_boundaries()
         → Are defenses at appropriate architectural boundaries?

     _evaluate_maintainability()
         → Is the authorization approach maintainable?

     PHASE 3: FINDING GENERATION
     --------------------------------------------------------------------------------
     _build_evidence()
         → Collects all evidence for recommendation
         → Builds defense usage matrix
         → Runs Phase 1.5 custom defense discovery here
         → Returns comprehensive evidence package

     _generate_ai_coverage_metrics()
         → Calculates coverage metrics using AI
         → Discovers ALL exposures (populates self.discovered_exposures)
         → Returns opportunities/protected/coverage stats

     _ask_ai_for_metrics()
         → Queries for ALL exposures based on pattern
         → Counts protected vs unprotected
         → Uses AI to validate and explain metrics

     _generate_recommendation()
         → Uses AI to generate actionable recommendation
         → Analyzes evidence and creates strategic guidance
         → Returns recommendation with rationale

     _build_recommendation_prompt()
         → Constructs detailed prompt for AI
         → Includes all evidence, patterns, metrics

     _parse_ai_response()
         → Extracts JSON recommendation from AI response
         → Handles formatting and errors

     ================================================================================
     KEY INSIGHT: Phase 1.5 (Custom Defense Discovery)
     ================================================================================

     The NEW Phase 1.5 runs DURING Phase 3 (_build_evidence), right after exposures
     are discovered. It's AI-driven and simple:

     1. Sample ~30 unprotected exposures (high-risk + random)
     2. Read source code for ALL of them
     3. Give all code to AI: "What authorization patterns do you see?"
     4. AI returns custom patterns (@Superadmin, manual checks, etc.)
     5. Query CPG to find all instances of those patterns
     6. Add to mechanisms and recalculate matrix

     This discovers defenses that standard framework definitions miss!
