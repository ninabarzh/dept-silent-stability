#!/usr/bin/env python3
"""
Complete BGP threat modelling workflow example.
"""

from threat_modeller import *
import json

# 1. Extract scenarios
print("Extracting threat scenarios...")
extractor = ScenarioThreatModelExtractor()

scenario1 = extractor.extract_playbook1_scenario([])
scenario2 = extractor.extract_playbook2_scenario([])
scenario3 = extractor.extract_playbook3_scenario([])

scenarios = [scenario1, scenario2, scenario3]

# 2. Generate threat reports
print("Generating threat model reports...")
for scenario in scenarios:
    report = extractor.generate_threat_model_report(scenario)
    filename = f"{scenario.scenario_name.replace(' ', '_').lower()}_report.txt"
    with open(filename, 'w') as f:
        f.write(report)
    print(f"  ✓ {filename}")

# 3. Map to MITRE ATT&CK
print("\nMapping to MITRE ATT&CK...")
mapper = MITREATTACKMapper()

# Generate Navigator layer
nav_layer = mapper.generate_attack_navigator_layer(
    scenarios,
    layer_name="BGP Hijacking Campaign Analysis"
)
with open('attack_navigator.json', 'w') as f:
    json.dump(nav_layer, f, indent=2)
print("  ✓ attack_navigator.json")

# Generate detection matrix
det_matrix = mapper.generate_detection_matrix(scenarios)
with open('detection_matrix.json', 'w') as f:
    json.dump(det_matrix, f, indent=2)
print("  ✓ detection_matrix.json")

# 4. Build attack trees
print("\nBuilding attack trees...")
tree_gen = AttackTreeGenerator()

p2_tree = tree_gen.build_playbook2_attack_tree()
p3_tree = tree_gen.build_playbook3_attack_tree()

tree_gen.export_attack_tree_json(p2_tree, 'playbook2_tree.json')
tree_gen.export_attack_tree_json(p3_tree, 'playbook3_tree.json')

with open('playbook2_tree.dot', 'w') as f:
    f.write(tree_gen.generate_attack_tree_dot(p2_tree))
with open('playbook3_tree.dot', 'w') as f:
    f.write(tree_gen.generate_attack_tree_dot(p3_tree))

print("  ✓ Attack trees exported (JSON + DOT)")

# Analyse paths
p2_analysis = tree_gen.analyze_attack_paths(p2_tree)
p3_analysis = tree_gen.analyze_attack_paths(p3_tree)

print(f"\nPlaybook 2: {p2_analysis['total_paths']} attack paths")
print(f"  Easiest path cost: {p2_analysis['easiest_path']['total_cost']:.1f}")
print(f"  Hardest path cost: {p2_analysis['hardest_path']['total_cost']:.1f}")

print(f"\nPlaybook 3: {p3_analysis['total_paths']} attack paths")
print(f"  Easiest path cost: {p3_analysis['easiest_path']['total_cost']:.1f}")

# 5. Analyse detection gaps
print("\nAnalysing detection coverage...")
gap_Analyser = DetectionGapAnalyser()

# Configure your environment
gap_analyser.set_available_capabilities(
    data_sources=[
        'Authentication logs',
        'BGP monitoring',
        'Network traffic'
    ],
    detection_rules=[
        'suspicious_login_detection',
        'bgp_announcement_monitor'
    ],
    monitored_systems=[
        'edge_routers',
        'tacacs_server'
    ]
)

coverage = gap_analyser.generate_coverage_report(scenarios)

print(f"\nDetection Coverage: {coverage['coverage_percentage']:.1f}%")
print(f"  Fully Covered: {coverage['statistics']['covered_techniques']}")
print(f"  Partially Covered: {coverage['statistics']['partially_covered']}")
print(f"  Uncovered: {coverage['statistics']['uncovered_techniques']}")

# Generate gap report
gap_report = gap_analyser.generate_gap_report(coverage['gaps'])
with open('detection_gaps.txt', 'w') as f:
    f.write(gap_report)
print("\n  ✓ detection_gaps.txt")

# 6. Create comprehensive summary
print("\nGenerating comprehensive summary...")
summary = {
    'timestamp': datetime.now().isoformat(),
    'scenarios_analysed': len(scenarios),
    'attack_techniques_identified': len(det_matrix),
    'detection_coverage_pct': coverage['coverage_percentage'],
    'critical_gaps': coverage['statistics']['gaps_by_severity']['critical'],
    'high_gaps': coverage['statistics']['gaps_by_severity']['high'],
    'attack_tree_paths': {
        'playbook2': p2_analysis['total_paths'],
        'playbook3': p3_analysis['total_paths']
    },
    'recommendations': []
}

# Add recommendations based on gaps
for gap in coverage['gaps']:
    if gap.severity in ['critical', 'high']:
        summary['recommendations'].extend(gap.recommended_actions)

with open('threat_model_summary.json', 'w') as f:
    json.dump(summary, f, indent=2)

print("\n" + "="*60)
print("Threat modelling complete!")
print("="*60)
print(f"\nReview the following files:")
print("  • threat_model_summary.json - Executive summary")
print("  • detection_gaps.txt - Prioritised gap analysis")
print("  • attack_navigator.json - Import to ATT&CK Navigator")
print("  • *_tree.dot - Visualise with Graphviz")
