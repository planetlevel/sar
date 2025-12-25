#!/usr/bin/env python3
"""Analyze TeamServer report to understand the issues"""

import json
import sys

def main():
    with open('output/reports/defense_report_20251221_221442.json') as f:
        report = json.load(f)

    print("="*80)
    print("TEAMSERVER ANALYSIS REPORT")
    print("="*80)

    print("\n📊 SUMMARY:")
    summary = report['summary']
    print(f"  Agents ran: {summary['agents_ran']}")
    print(f"  Agents skipped: {summary['agents_skipped']}")
    print(f"  Total recommendations: {summary['total_recommendations']}")
    print(f"  Overall coverage: {summary['overall_coverage']}%")

    print("\n" + "="*80)
    for i, rec in enumerate(report.get('recommendations', []), 1):
        print(f"\n🔍 RECOMMENDATION {i}")
        print(f"  Agent: {rec.get('agent_name')}")
        print(f"  Agent ID: {rec.get('agent_id')}")
        print(f"  Ran: {rec.get('ran')}")

        if rec.get('metrics'):
            metrics = rec['metrics']
            print(f"\n  📈 METRICS:")
            for k, v in metrics.items():
                print(f"    {k}: {v}")

        if rec.get('recommendation') and rec['recommendation'].get('data'):
            data = rec['recommendation']['data']

            if data.get('existing_matrix'):
                existing = data['existing_matrix']
                print(f"\n  📋 EXISTING ACCESS CONTROL MATRIX:")
                print(f"    Total endpoints: {existing.get('total_endpoints', 0)}")
                print(f"    Current roles: {existing.get('current_roles', [])}")
                if existing.get('endpoints'):
                    print(f"    Sample endpoints ({len(existing['endpoints'])} total):")
                    for endpoint in existing['endpoints'][:5]:
                        print(f"      - {endpoint.get('method')} {endpoint.get('controller')}.{endpoint.get('handler')}")

            if data.get('proposed_matrix'):
                proposed = data['proposed_matrix']
                print(f"\n  🎯 PROPOSED ACCESS CONTROL MATRIX:")
                print(f"    Total endpoints: {proposed.get('total_endpoints', 0)}")
                print(f"    Currently protected: {proposed.get('currently_protected', 0)}")
                print(f"    Suggested PUBLIC: {proposed.get('suggested_public', 0)}")
                print(f"    Suggested AUTHENTICATED: {proposed.get('suggested_authenticated', 0)}")
                print(f"    Suggested ROLE_SPECIFIC: {proposed.get('suggested_role_specific', 0)}")
                print(f"    Proposed roles: {proposed.get('proposed_roles', [])}")

                if proposed.get('endpoints'):
                    print(f"\n    Sample endpoints ({len(proposed['endpoints'])} total):")
                    for endpoint in proposed['endpoints'][:10]:
                        print(f"      - {endpoint.get('endpoint')}")
                        print(f"        Protected: {endpoint.get('protected')}")
                        print(f"        Access: {endpoint.get('access_level')}")

        if rec.get('evidence'):
            evidence = rec['evidence']
            print(f"\n  📄 EVIDENCE:")
            if isinstance(evidence, dict):
                for k, v in evidence.items():
                    if isinstance(v, (list, dict)):
                        print(f"    {k}: {type(v).__name__} with {len(v)} items")
                    else:
                        print(f"    {k}: {v}")

if __name__ == '__main__':
    main()
