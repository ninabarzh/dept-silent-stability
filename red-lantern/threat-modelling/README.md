# BGP Threat Modelling Framework

A comprehensive threat modelling system for BGP hijacking scenarios, inspired by the methodical approach of the Ankh-Morpork City Watch. This framework extracts threat intelligence from BGP simulator scenarios, maps them to MITRE ATT&CK techniques, builds attack trees, and identifies detection gaps.

## Features

### Scenario-based threat modelling

- Extract structured threat models from BGP simulator logs
- Analyse attack phases, techniques, and tactics
- Generate human-readable threat reports
- Track indicators of compromise (IOCs) and success indicators

### MITRE ATT&CK integration

- Map BGP hijacking scenarios to ATT&CK techniques
- Generate ATT&CK Navigator layer files for visualisation
- Create detection coverage matrices
- Identify applicable data sources and detection methods

### Attack tree generation

- Build hierarchical attack trees showing all possible attack paths
- Calculate attack costs and detectability scores
- Export to JSON and Graphviz DOT formats
- Analyse easiest and hardest attack paths

### Detection gap analysis

- Compare required vs. available data sources
- Identify missing detection rules and blind spots
- Generate severity-based gap reports
- Calculate detection coverage percentages

## Requirements

- Python 3.12 or higher
- No external dependencies for core functionality
- Optional: Graphviz (for attack tree visualisation)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/bgp-threat-modeller.git
cd bgp-threat-modeller

# No additional installation needed - pure Python!
python threat_modeller.py
```

## Quick start

### Basic usage

```
from threat_modeller import (
    ScenarioThreatModelExtractor,
    MITREATTACKMapper,
    AttackTreeGenerator,
    DetectionGapAnalyser
)

# Extract threat scenarios from simulator logs
extractor = ScenarioThreatModelExtractor()
scenario = extractor.extract_playbook2_scenario(log_lines)

# Generate human-readable report
report = extractor.generate_threat_model_report(scenario)
print(report)

# Map to MITRE ATT&CK
mapper = MITREATTACKMapper()
techniques = mapper.map_scenario_to_attack(scenario)

# Build attack tree
tree_gen = AttackTreeGenerator()
attack_tree = tree_gen.build_playbook2_attack_tree()

# Analyse detection coverage
gap_analyser = DetectionGapAnalyser()
gap_analyser.set_available_capabilities(
    data_sources=['Authentication logs', 'BGP monitoring'],
    detection_rules=['suspicious_login', 'bgp_monitor'],
    monitored_systems=['edge_routers', 'tacacs']
)
coverage = gap_analyser.generate_coverage_report([scenario])
```

### Running the Demo

```bash
python threat_modeller.py
```

This will:

1. Extract all three playbook scenarios
2. Generate threat model reports
3. Map scenarios to MITRE ATT&CK
4. Build and export attack trees
5. Analyse detection coverage
6. Save comprehensive reports

## Supported scenarios

### Playbook 1: Opportunistic Hijack

Attack Goal: Hijack traffic for prefix lacking RPKI protection

Key Characteristics:
- Exploits missing ROA protection
- Low sophistication attacker
- Quick execution (minutes)
- Detection: Monitor for 'not_found' RPKI status

### Playbook 2: Credential Compromise

Attack Goal: Manipulate RPKI infrastructure to legitimise future hijacking

Key Characteristics:
- Compromised credentials via Tor
- Fraudulent ROA creation through legitimate portal
- Sophisticated attacker
- Duration: ~46 minutes
- Detection: Anomalous login locations, ROA change monitoring

### Playbook 3: Sub-Prefix Hijacking

Attack Goal: Hijack traffic using more-specific prefix whilst passing RPKI validation

Key Characteristics:
- Exploits ROA maxLength feature
- Technically sophisticated
- Long-duration attack (85+ minutes)
- Detection: More-specific prefix alerts, traffic pattern analysis

## Output files

When you run the framework, it generates several output files:

### Threat Intelligence

- `threat_model_report.json` - Comprehensive threat model with all analysis results
- `bgp_attack_navigator.json` - MITRE ATT&CK Navigator layer (import at https://mitre-attack.github.io/attack-navigator/)

### Attack Trees
- `playbook2_attack_tree.json` - JSON representation of Playbook 2 attack tree
- `playbook3_attack_tree.json` - JSON representation of Playbook 3 attack tree
- `playbook2_attack_tree.dot` - Graphviz DOT file for visualisation
- `playbook3_attack_tree.dot` - Graphviz DOT file for visualisation

### Visualising Attack Trees

If you have Graphviz installed:

```bash
# Generate PNG images from DOT files
dot -Tpng playbook2_attack_tree.dot -o playbook2_attack_tree.png
dot -Tpng playbook3_attack_tree.dot -o playbook3_attack_tree.png

# Or generate SVG for web use
dot -Tsvg playbook2_attack_tree.dot -o playbook2_attack_tree.svg
```

## Contributing

Contributions welcome! This code is designed to be extended with:

- Additional playbook scenarios
- More ATT&CK technique mappings
- Enhanced detection gap analysis
- Integration with other threat intelligence platforms

## Licence

Unlicensed

## Acknowledgements

- Inspired by the methodical crime-solving approach of Commander Vimes and the Ankh-Morpork City Watch
- MITRE ATT&CK® framework
- BGP security research community
- Terry Pratchett, for showing us that even in a fantasy world, systematic thinking matters

## Support

For issues, questions, or contributions:
- Open an issue
- Consult the API reference above
- Review the example workflow

*"The presence of those seeking the truth is infinitely to be preferred to the presence of those who think they've found it."* — Terry Pratchett, Monstrous Regiment
