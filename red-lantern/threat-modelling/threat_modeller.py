"""
BGP Threat Modelling Code
Threat modelling system for BGP hijacking scenarios with Python 3.12

This module provides:

- Scenario-based threat model extraction
- MITRE ATT&CK technique mapping
- Attack tree generation and visualization
- Detection gap analysis
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import ClassVar

# ============================================================================
# Core Data Structures
# ============================================================================


class AttackPhase(Enum):
    """The stages of a BGP hijacking attack."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENCE_EVASION = "defence_evasion"
    IMPACT = "impact"


@dataclass
class ThreatEvent:
    """A single event within an attack scenario."""

    timestamp: datetime
    phase: AttackPhase
    technique: str
    description: str
    indicators: list[str]
    data_sources: list[str]
    mitigations: list[str]
    log_entry: str


@dataclass
class ThreatScenario:
    """A complete threat scenario extracted from simulator output."""

    scenario_name: str
    attack_goal: str
    threat_actor_profile: str
    events: list[ThreatEvent]
    attack_duration: timedelta
    success_indicators: list[str]
    detection_opportunities: list[str]

    def get_attack_chain(self) -> list[str]:
        """Return the sequence of attack phases."""
        return [event.phase.value for event in self.events]

    def get_ttps(self) -> set[str]:
        """Extract all tactics, techniques, and procedures."""
        return {event.technique for event in self.events}

    def get_critical_events(self) -> list[ThreatEvent]:
        """Identify events that represent points of no return."""
        critical_phases = {AttackPhase.IMPACT, AttackPhase.PERSISTENCE}
        return [e for e in self.events if e.phase in critical_phases]


@dataclass
class ATTACKTechnique:
    """A MITRE ATT&CK technique mapped from scenario events."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection_methods: list[str]
    data_sources: list[str]
    scenario_examples: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "description": self.description,
            "detection_methods": self.detection_methods,
            "data_sources": self.data_sources,
            "scenario_examples": self.scenario_examples,
        }


@dataclass
class AttackTreeNode:
    """A node in an attack tree."""

    name: str
    node_type: str  # 'goal', 'and', 'or', 'leaf'
    description: str
    required: bool = True
    cost: float = 1.0
    detectability: float = 0.5  # 0.0 = undetectable, 1.0 = easily detected
    children: list[AttackTreeNode] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    detection_methods: list[str] = field(default_factory=list)

    def add_child(self, child: AttackTreeNode) -> None:
        """Add a child node to this node."""
        self.children.append(child)

    def calculate_total_cost(self) -> float:
        """Calculate total cost to achieve this node."""
        if not self.children:
            return self.cost

        if self.node_type == "and":
            return self.cost + sum(
                child.calculate_total_cost() for child in self.children
            )
        elif self.node_type == "or":
            return self.cost + min(
                child.calculate_total_cost() for child in self.children
            )
        else:
            return self.cost

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "type": self.node_type,
            "description": self.description,
            "required": self.required,
            "cost": self.cost,
            "detectability": self.detectability,
            "total_cost": self.calculate_total_cost(),
            "mitigations": self.mitigations,
            "detection_methods": self.detection_methods,
            "children": [child.to_dict() for child in self.children],
        }


@dataclass
class DetectionGap:
    """Represents a gap in detection coverage."""

    gap_type: str  # 'missing_data_source', 'no_detection_rule', 'blind_spot'
    technique_id: str
    technique_name: str
    phase: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    affected_scenarios: list[str]
    recommended_actions: list[str]
    required_data_sources: list[str]


# ============================================================================
# Scenario Threat Model Extractor
# ============================================================================


class ScenarioThreatModelExtractor:
    """Extracts threat models from simulator scenario logs."""

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> datetime:
        """Parse timestamp from log line."""
        return datetime.strptime(f"2025 {timestamp_str}", "%Y %b %d %H:%M:%S")

    @staticmethod
    def extract_playbook1_scenario(_log_lines: list[str]) -> ThreatScenario:
        """
        Extract threat model from Playbook 1: Basic prefix announcement without ROA.
        The opportunistic hijacker scenario.
        """
        events = []

        # Event 1: Reconnaissance
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:00:00"
                ),
                phase=AttackPhase.RECONNAISSANCE,
                technique="Network Service Discovery: BGP Monitoring",
                description="Attacker observes BGP announcement for unprotected prefix",
                indicators=[
                    "BGP announcement observed: 203.0.113.0/24 origin AS65003",
                    "No ROA protection detected",
                ],
                data_sources=["BGP feeds", "Route collectors", "Looking glass servers"],
                mitigations=[
                    "Deploy RPKI ROAs for all prefixes",
                    "Monitor for unexpected announcements",
                    "Implement prefix filtering",
                ],
                log_entry="<14>Jan 01 00:00:00 edge-router-01 BGP announcement observed: 203.0.113.0/24 origin AS65003",
            )
        )

        # Event 2: Defence Evasion via Missing ROA
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:01:05"
                ),
                phase=AttackPhase.DEFENCE_EVASION,
                technique="Exploit Public-Facing Application: Missing RPKI Protection",
                description="RPKI validation returns 'not_found' - no ROA exists to protect prefix",
                indicators=[
                    "RPKI validation: not_found",
                    "ROA not found in validator",
                    "Prefix vulnerable to hijacking",
                ],
                data_sources=["RPKI validator logs", "ROA repository queries"],
                mitigations=[
                    "Create ROAs for all owned prefixes",
                    "Enable RPKI validation on all BGP sessions",
                    "Alert on 'not_found' validation results for owned prefixes",
                ],
                log_entry="<30>Jan 01 00:01:05 routinator RPKI validation: 203.0.113.0/24 origin AS65003 -> not_found (ROA not found)",
            )
        )

        return ThreatScenario(
            scenario_name="Playbook 1: Opportunistic Hijack of Unprotected Prefix",
            attack_goal="Hijack traffic for prefix lacking RPKI protection",
            threat_actor_profile="Opportunistic attacker, moderate skill, exploits missing security controls",
            events=events,
            attack_duration=timedelta(minutes=1),
            success_indicators=[
                "No ROA protection present",
                "RPKI validation returns 'not_found'",
                "Announcement would be accepted by non-filtering peers",
            ],
            detection_opportunities=[
                "Monitor for announcements of owned prefixes from unexpected ASNs",
                "Alert on 'not_found' RPKI status for owned prefixes",
                "Track prefix ownership changes via WHOIS",
            ],
        )

    @staticmethod
    def extract_playbook2_scenario(_log_lines: list[str]) -> ThreatScenario:
        """
        Extract threat model from Playbook 2: Credential compromise -> ROA manipulation.
        The inside job scenario.
        """
        events = []

        # Event 1: Initial Access
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:01:00"
                ),
                phase=AttackPhase.INITIAL_ACCESS,
                technique="Valid Accounts: Cloud Accounts",
                description="Attacker accesses TACACS server using compromised credentials from Tor exit node",
                indicators=[
                    "Login from 185.220.101.45 (Tor exit node)",
                    "Account: admin@victim-network.net",
                    "Unusual geographic location",
                    "Authentication from anonymization network",
                ],
                data_sources=["Authentication logs", "Network traffic", "Access logs"],
                mitigations=[
                    "Multi-factor authentication",
                    "Impossible travel detection",
                    "Tor exit node blocking for administrative access",
                    "Privileged account monitoring",
                    "Geofencing for critical accounts",
                ],
                log_entry="Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45",
            )
        )

        # Event 2: Defence Evasion
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:02:00"
                ),
                phase=AttackPhase.DEFENCE_EVASION,
                technique="Use of Legitimate Infrastructure",
                description="Attacker uses legitimate ARIN portal to submit fraudulent ROA",
                indicators=[
                    "ROA creation request for 203.0.113.0/24",
                    "Origin AS64513 (not legitimate owner)",
                    "maxLength /25 allows sub-prefix hijacking",
                    "Request from recently authenticated session",
                ],
                data_sources=[
                    "RPKI repository logs",
                    "ROA creation audit logs",
                    "RIR portal logs",
                ],
                mitigations=[
                    "Out-of-band verification for ROA requests",
                    "Anomaly detection on ROA creation patterns",
                    "Secondary approval for critical prefixes",
                    "Time-delayed ROA publication",
                    "Alert on maxLength changes",
                ],
                log_entry="<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25 by admin@victim-network.net via ARIN",
            )
        )

        # Event 3: Impact - ROA Publication
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:40:00"
                ),
                phase=AttackPhase.IMPACT,
                technique="Resource Hijacking: BGP Route Manipulation",
                description="Fraudulent ROA published to ARIN repository, legitimizing future hijack",
                indicators=[
                    "ROA published in arin repository",
                    "203.0.113.0/24 now claims AS64513 as valid origin",
                    "Fraudulent ROA propagating to validators",
                ],
                data_sources=[
                    "RPKI repository monitoring",
                    "ROA publication feeds",
                    "Validator sync logs",
                ],
                mitigations=[
                    "ROA monitoring and alerting",
                    "Community reporting mechanisms",
                    "Automated ROA validation against WHOIS/IRR",
                    "ROA change notifications to prefix owners",
                ],
                log_entry="<30>Jan 01 00:40:00 arin ROA published: 203.0.113.0/24 origin AS64513 in arin repository",
            )
        )

        # Event 4: Impact - Validator Acceptance
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:45:00"
                ),
                phase=AttackPhase.IMPACT,
                technique="Network Denial of Service: Route Manipulation",
                description="Multiple validators accept fraudulent ROA, enabling widespread hijack",
                indicators=[
                    "routinator validator sync: valid",
                    "cloudflare validator sync: valid",
                    "ripe validator sync: valid",
                    "Consensus achieved across validators",
                ],
                data_sources=[
                    "Validator logs",
                    "RPKI validation status monitoring",
                    "Validator consensus tracking",
                ],
                mitigations=[
                    "Multi-source validation",
                    "Historical ROA comparison",
                    "Anomaly detection on validator consensus changes",
                    "Manual review of validation status changes",
                    "Community validation cross-checking",
                ],
                log_entry="<30>Jan 01 00:45:00 routinator Validator sync: routinator sees 203.0.113.0/24 as valid",
            )
        )

        return ThreatScenario(
            scenario_name="Playbook 2: Credential Compromise to ROA Manipulation",
            attack_goal="Manipulate RPKI infrastructure to legitimize future BGP hijacking",
            threat_actor_profile="Sophisticated attacker with stolen credentials, understands RPKI/BGP, uses anonymization",
            events=events,
            attack_duration=timedelta(minutes=46),
            success_indicators=[
                "ROA published in authoritative repository",
                "Multiple validators accepting fraudulent ROA",
                "No alerts or interventions observed",
                "Attacker maintains access throughout attack",
            ],
            detection_opportunities=[
                "Unusual login location (Tor exit node)",
                "ROA request from compromised account",
                "Sudden validator consensus change",
                "ROA creation without proper authorization workflow",
                "maxLength modification for existing prefixes",
            ],
        )

    @staticmethod
    def extract_playbook3_scenario(_log_lines: list[str]) -> ThreatScenario:
        """
        Extract threat model from Playbook 3: Sub-prefix hijacking with RPKI validation.
        The technically legitimate but morally questionable approach.
        """
        events = []

        # Event 1: Reconnaissance
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:01:00"
                ),
                phase=AttackPhase.RECONNAISSANCE,
                technique="Network Service Discovery: BGP Routing Information",
                description="Attacker announces sub-prefix to test network response",
                indicators=[
                    "BMP ROUTE: prefix 203.0.113.128/25",
                    "AS_PATH [65001, 64513]",
                    "More specific prefix than existing /24",
                    "ORIGIN_AS 64513",
                ],
                data_sources=[
                    "BGP monitoring",
                    "BMP feeds",
                    "Route announcements",
                    "Route collectors",
                ],
                mitigations=[
                    "Prefix filtering policies",
                    "Maximum prefix length enforcement",
                    "Anomaly detection on new announcements",
                    "Alert on more-specific announcements",
                    "Strict ROA maxLength policies",
                ],
                log_entry="BMP ROUTE: prefix 203.0.113.128/25 AS_PATH [65001, 64513] NEXT_HOP 198.51.100.254 ORIGIN_AS 64513",
            )
        )

        # Event 2: Defence Evasion
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:03:00"
                ),
                phase=AttackPhase.DEFENCE_EVASION,
                technique="Subvert Trust Controls: RPKI Validation Bypass",
                description="Sub-prefix passes RPKI validation due to maxLength in legitimate ROA",
                indicators=[
                    "RPKI validation: valid (cloudflare)",
                    "RPKI validation: valid (routinator)",
                    "Sub-prefix covered by parent ROA maxLength /25",
                    "Multiple validators confirm validity",
                ],
                data_sources=[
                    "RPKI validation logs",
                    "Validator decision logs",
                    "ROA evaluation traces",
                ],
                mitigations=[
                    "Strict maxLength policies (maxLength = prefix length)",
                    "Alert on more-specific-than-expected announcements",
                    "ROA specificity enforcement",
                    "Monitor for sub-prefix announcements of owned space",
                    "Community alerting on suspicious specifics",
                ],
                log_entry="<14>Jan 01 00:03:00 edge-router-01 RPKI validation: 203.0.113.128/25 AS64513 -> valid (cloudflare)",
            )
        )

        # Event 3: Impact - Traffic Interception
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 00:07:00"
                ),
                phase=AttackPhase.IMPACT,
                technique="Man-in-the-Middle: BGP Hijacking",
                description="Traffic forwarding established, attacker now intercepts traffic",
                indicators=[
                    "Traffic forwarding established for 203.0.113.128/25",
                    "Method: transparent_proxy",
                    "More specific route preferred by BGP",
                    "Traffic redirection active",
                ],
                data_sources=[
                    "Flow data",
                    "Traffic analysis",
                    "BGP best path selection",
                    "NetFlow/IPFIX",
                ],
                mitigations=[
                    "Flow-based anomaly detection",
                    "Latency monitoring",
                    "Geographic routing validation",
                    "Customer impact monitoring",
                    "AS path validation",
                    "Traffic pattern analysis",
                ],
                log_entry="<12>Jan 01 00:07:00 edge-router-01 Traffic forwarding established for 203.0.113.128/25 -> 203.0.113.128 (method: transparent_proxy)",
            )
        )

        # Event 4: Persistence
        events.append(
            ThreatEvent(
                timestamp=ScenarioThreatModelExtractor.parse_timestamp(
                    "Jan 01 01:32:00"
                ),
                phase=AttackPhase.PERSISTENCE,
                technique="Network Denial of Service: Route Persistence",
                description="Attacker maintains hijack for extended period before withdrawal",
                indicators=[
                    "Route maintained for 85 minutes",
                    "BGP withdrawal after objectives achieved",
                    "Clean exit without detection",
                ],
                data_sources=[
                    "BGP update monitoring",
                    "Route history",
                    "Uptime tracking",
                    "Session logs",
                ],
                mitigations=[
                    "Maximum route announcement duration policies",
                    "Automated route validation",
                    "Community-based blackholing",
                    "Time-based anomaly detection",
                    "Alert on sustained more-specific announcements",
                ],
                log_entry="<13>Jan 01 01:32:00 edge-router-01 BGP withdrawal: 203.0.113.128/25 from AS64513",
            )
        )

        return ThreatScenario(
            scenario_name="Playbook 3: Sub-prefix Hijacking via RPKI Validation",
            attack_goal="Hijack traffic using more-specific prefix while passing RPKI validation",
            threat_actor_profile="Technically sophisticated, exploits RPKI maxLength feature, patient operator",
            events=events,
            attack_duration=timedelta(minutes=91),
            success_indicators=[
                "Sub-prefix passes RPKI validation",
                "Traffic successfully redirected",
                "Maintained for extended period (85 minutes)",
                "Clean withdrawal without detection",
            ],
            detection_opportunities=[
                "More-specific prefix announced than registered",
                "Unusual traffic forwarding patterns",
                "Geographic anomalies in routing",
                "Latency changes in customer paths",
                "Flow volume changes",
                "AS path changes for sub-prefix",
            ],
        )

    @staticmethod
    def generate_threat_model_report(scenario: ThreatScenario) -> str:
        """Generate a human-readable threat model report."""
        report = []
        report.append("=" * 80)
        report.append(f"THREAT MODEL: {scenario.scenario_name}")
        report.append("=" * 80)
        report.append(f"\nAttack Goal: {scenario.attack_goal}")
        report.append(f"Threat Actor: {scenario.threat_actor_profile}")
        report.append(f"Duration: {scenario.attack_duration}")
        report.append(f"\nAttack Chain: {' → '.join(scenario.get_attack_chain())}")

        report.append(f"\n\n{'─' * 80}")
        report.append("ATTACK TIMELINE")
        report.append("─" * 80)

        for i, event in enumerate(scenario.events, 1):
            report.append(
                f"\n[{i}] {event.timestamp.strftime('%H:%M:%S')} - {event.phase.value.upper()}"
            )
            report.append(f"    Technique: {event.technique}")
            report.append(f"    Description: {event.description}")
            report.append("    Indicators:")
            for indicator in event.indicators:
                report.append(f"      • {indicator}")
            report.append(f"    Data Sources: {', '.join(event.data_sources)}")
            report.append("    Mitigations:")
            for mitigation in event.mitigations:
                report.append(f"      • {mitigation}")

        report.append(f"\n\n{'─' * 80}")
        report.append("DETECTION OPPORTUNITIES")
        report.append("─" * 80)
        for i, opportunity in enumerate(scenario.detection_opportunities, 1):
            report.append(f"{i}. {opportunity}")

        report.append(f"\n\n{'─' * 80}")
        report.append("SUCCESS INDICATORS")
        report.append("─" * 80)
        for i, indicator in enumerate(scenario.success_indicators, 1):
            report.append(f"{i}. {indicator}")

        return "\n".join(report)


# ============================================================================
# MITRE ATT&CK Mapper
# ============================================================================


class MITREATTACKMapper:
    """Maps BGP hijacking scenarios to MITRE ATT&CK techniques."""

    # Custom ATT&CK mapping for network/BGP attacks
    TECHNIQUE_DATABASE: ClassVar[dict[str, ATTACKTechnique]] = {
        "T1078.004": ATTACKTechnique(
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            tactic="Initial Access",
            description="Adversaries may obtain and abuse credentials of cloud accounts to gain Initial Access.",
            detection_methods=[
                "Monitor for anomalous account behavior (location, time, volume)",
                "Correlate authentication events with known attack infrastructure",
                "Detect impossible travel scenarios",
                "Monitor for privilege escalation after authentication",
            ],
            data_sources=[
                "Logon Session: Logon Session Creation",
                "User Account: User Account Authentication",
                "Application Log: Application Log Content",
            ],
            scenario_examples=[],
        ),
        "T1584.004": ATTACKTechnique(
            technique_id="T1584.004",
            technique_name="Compromise Infrastructure: Server",
            tactic="Resource Development",
            description="Adversaries may compromise third-party servers for use during targeting.",
            detection_methods=[
                "Monitor BGP announcements for unexpected origin ASNs",
                "Track historical AS ownership for prefixes",
                "Detect anomalous routing changes",
            ],
            data_sources=[
                "Internet Scan: Response Content",
                "Network Traffic: Network Traffic Flow",
            ],
            scenario_examples=[],
        ),
        "T1565.002": ATTACKTechnique(
            technique_id="T1565.002",
            technique_name="Data Manipulation: Transmitted Data Manipulation",
            tactic="Impact",
            description="Adversaries may alter data en route to storage or destination.",
            detection_methods=[
                "Monitor for traffic forwarding to unexpected destinations",
                "Detect transparent proxy configurations",
                "Analyse traffic patterns for redirection",
                "Monitor latency changes",
            ],
            data_sources=[
                "Network Traffic: Network Traffic Flow",
                "Network Traffic: Network Traffic Content",
            ],
            scenario_examples=[],
        ),
        "T1557.002": ATTACKTechnique(
            technique_id="T1557.002",
            technique_name="Man-in-the-Middle: ARP Cache Poisoning",
            tactic="Credential Access",
            description="Adversaries may position themselves between network nodes.",
            detection_methods=[
                "Monitor BGP route changes affecting critical prefixes",
                "Detect unexpected AS path changes",
                "Monitor for more-specific prefix announcements",
                "Track RPKI validation status changes",
            ],
            data_sources=[
                "Network Traffic: Network Traffic Flow",
                "Network Traffic: Network Connection Creation",
            ],
            scenario_examples=[],
        ),
        "T1562.001": ATTACKTechnique(
            technique_id="T1562.001",
            technique_name="Impair Defenses: Disable or Modify Tools",
            tactic="Defense Evasion",
            description="Adversaries may modify or disable security tools to avoid detection.",
            detection_methods=[
                "Monitor ROA creation/modification events",
                "Alert on RPKI validation status changes",
                "Track validator consensus changes",
                "Detect ROA maxLength abuse",
            ],
            data_sources=[
                "Command: Command Execution",
                "Sensor Health: Host Status",
                "Application Log: Application Log Content",
            ],
            scenario_examples=[],
        ),
        "T1498.001": ATTACKTechnique(
            technique_id="T1498.001",
            technique_name="Network Denial of Service: Direct Network Flood",
            tactic="Impact",
            description="Adversaries may attempt to cause denial of service via network-level attacks.",
            detection_methods=[
                "Monitor BGP update frequency",
                "Detect route flapping",
                "Alert on BGP session resets",
                "Track prefix withdrawal/reannouncement patterns",
            ],
            data_sources=[
                "Network Traffic: Network Traffic Flow",
                "Sensor Health: Host Status",
            ],
            scenario_examples=[],
        ),
        "T1608.005": ATTACKTechnique(
            technique_id="T1608.005",
            technique_name="Stage Capabilities: Link Target",
            tactic="Resource Development",
            description="Adversaries may put in place resources to support follow-on operations.",
            detection_methods=[
                "Monitor new ROA registrations",
                "Alert on ROA modifications for existing prefixes",
                "Track ASN authorization changes",
                "Detect anomalous RIR portal activity",
            ],
            data_sources=["Internet Scan: Response Content"],
            scenario_examples=[],
        ),
    }

    @staticmethod
    def map_scenario_to_attack(scenario: ThreatScenario) -> list[ATTACKTechnique]:
        """Map a threat scenario to MITRE ATT&CK techniques."""
        mapped_techniques = []

        # Create mapping of phase/technique combinations to ATT&CK IDs
        phase_technique_mapping = {
            (AttackPhase.INITIAL_ACCESS, "Valid Accounts"): "T1078.004",
            (AttackPhase.RECONNAISSANCE, "Network Service Discovery"): "T1584.004",
            (
                AttackPhase.DEFENCE_EVASION,
                "Use of Legitimate Infrastructure",
            ): "T1562.001",
            (AttackPhase.DEFENCE_EVASION, "Subvert Trust Controls"): "T1562.001",
            (
                AttackPhase.DEFENCE_EVASION,
                "Exploit Public-Facing Application",
            ): "T1562.001",
            (AttackPhase.IMPACT, "Man-in-the-Middle"): "T1557.002",
            (AttackPhase.IMPACT, "Resource Hijacking"): "T1498.001",
            (AttackPhase.IMPACT, "Network Denial of Service"): "T1498.001",
            (AttackPhase.PERSISTENCE, "Network Denial of Service"): "T1498.001",
        }

        # Map events to techniques
        for event in scenario.events:
            for (phase, tech_pattern), tech_id in phase_technique_mapping.items():
                if event.phase == phase and tech_pattern in event.technique:
                    if tech_id in MITREATTACKMapper.TECHNIQUE_DATABASE:
                        technique = MITREATTACKMapper.TECHNIQUE_DATABASE[tech_id]
                        # Create a copy to avoid modifying the database
                        technique_copy = ATTACKTechnique(
                            technique_id=technique.technique_id,
                            technique_name=technique.technique_name,
                            tactic=technique.tactic,
                            description=technique.description,
                            detection_methods=technique.detection_methods.copy(),
                            data_sources=technique.data_sources.copy(),
                            scenario_examples=[scenario.scenario_name],
                        )
                        if technique_copy not in mapped_techniques:
                            mapped_techniques.append(technique_copy)

        return mapped_techniques

    @staticmethod
    def generate_attack_navigator_layer(
        scenarios: list[ThreatScenario], layer_name: str = "BGP Hijacking Scenarios"
    ) -> dict:
        """Generate MITRE ATT&CK Navigator layer JSON."""
        techniques_coverage: dict[str, dict] = {}

        # Collect all techniques from all scenarios
        for scenario in scenarios:
            mapped_techniques = MITREATTACKMapper.map_scenario_to_attack(scenario)
            for technique in mapped_techniques:
                if technique.technique_id not in techniques_coverage:
                    techniques_coverage[technique.technique_id] = {
                        "technique": technique,
                        "scenarios": [],
                    }
                if (
                    scenario.scenario_name
                    not in techniques_coverage[technique.technique_id]["scenarios"]
                ):
                    techniques_coverage[technique.technique_id]["scenarios"].append(
                        scenario.scenario_name
                    )

        # Build Navigator layer
        navigator_layer = {
            "name": layer_name,
            "versions": {"attack": "13", "navigator": "4.8.1", "layer": "4.4"},
            "domain": "enterprise-attack",
            "description": "MITRE ATT&CK techniques observed in BGP hijacking simulator scenarios",
            "filters": {"platforms": ["Network", "Linux", "Windows", "macOS"]},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        # Add techniques to layer
        for tech_id, data in techniques_coverage.items():
            technique = data["technique"]
            scenario_count = len(data["scenarios"])
            score = min(100, scenario_count * 33)

            navigator_layer["techniques"].append(
                {
                    "techniqueID": tech_id,
                    "tactic": technique.tactic.lower().replace(" ", "-"),
                    "color": "",
                    "comment": f"Observed in: {', '.join(data['scenarios'])}",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False,
                    "score": score,
                }
            )

        return navigator_layer

    @staticmethod
    def generate_detection_matrix(scenarios: list[ThreatScenario]) -> dict[str, dict]:
        """Generate detection coverage matrix."""
        detection_matrix: dict[str, dict] = {}

        for scenario in scenarios:
            mapped_techniques = MITREATTACKMapper.map_scenario_to_attack(scenario)
            for technique in mapped_techniques:
                if technique.technique_id not in detection_matrix:
                    detection_matrix[technique.technique_id] = {
                        "technique_name": technique.technique_name,
                        "tactic": technique.tactic,
                        "detection_methods": technique.detection_methods,
                        "data_sources": technique.data_sources,
                        "scenario_count": 0,
                    }
                detection_matrix[technique.technique_id]["scenario_count"] += 1

        return detection_matrix


# ============================================================================
# Attack Tree Generator
# ============================================================================


class AttackTreeGenerator:
    """Generates attack trees from threat scenarios."""

    @staticmethod
    def build_playbook2_attack_tree() -> AttackTreeNode:
        """Build attack tree for Playbook 2: Credential compromise to ROA manipulation."""

        # Root goal
        root = AttackTreeNode(
            name="Manipulate RPKI to Enable BGP Hijacking",
            node_type="goal",
            description="Attacker's ultimate objective: create fraudulent ROA to legitimize future BGP hijacks",
            cost=0.0,
            detectability=0.0,
        )

        # High-level OR: Two paths to achieve the goal
        path_choice = AttackTreeNode(
            name="Choose Attack Path",
            node_type="or",
            description="Attacker can compromise credentials OR exploit system vulnerability",
            cost=0.0,
            detectability=0.0,
        )
        root.add_child(path_choice)

        # Path 1: Credential Compromise (the path taken in scenario)
        credential_path = AttackTreeNode(
            name="Credential Compromise Path",
            node_type="and",
            description="Gain access through stolen credentials",
            cost=1.0,
            detectability=0.6,
        )
        path_choice.add_child(credential_path)

        # Credential Path Steps
        obtain_creds = AttackTreeNode(
            name="Obtain Valid Credentials",
            node_type="or",
            description="Multiple methods to acquire credentials",
            cost=2.0,
            detectability=0.3,
            mitigations=[
                "Strong password policies",
                "MFA enforcement",
                "Credential monitoring",
            ],
            detection_methods=[
                "Failed login attempts",
                "Credential stuffing detection",
                "Dark web monitoring",
            ],
        )
        credential_path.add_child(obtain_creds)

        # Credential acquisition methods
        phishing = AttackTreeNode(
            name="Phishing Attack",
            node_type="leaf",
            description="Send phishing emails to target administrators",
            cost=1.0,
            detectability=0.5,
            mitigations=[
                "Security awareness training",
                "Email filtering",
                "Anti-phishing tools",
            ],
            detection_methods=[
                "Email security gateways",
                "User reporting",
                "Suspicious link detection",
            ],
        )
        obtain_creds.add_child(phishing)

        credential_stuffing = AttackTreeNode(
            name="Credential Stuffing",
            node_type="leaf",
            description="Use leaked credentials from other breaches",
            cost=0.5,
            detectability=0.7,
            mitigations=[
                "Password reuse policies",
                "Breach monitoring",
                "Account lockout policies",
            ],
            detection_methods=[
                "Failed login monitoring",
                "Impossible travel",
                "Anomalous auth patterns",
            ],
        )
        obtain_creds.add_child(credential_stuffing)

        insider_threat = AttackTreeNode(
            name="Insider Threat",
            node_type="leaf",
            description="Recruit or coerce insider with access",
            cost=5.0,
            detectability=0.2,
            mitigations=[
                "Background checks",
                "Insider threat program",
                "Behavioral analytics",
            ],
            detection_methods=[
                "User behavior analytics",
                "Privilege escalation monitoring",
            ],
        )
        obtain_creds.add_child(insider_threat)

        # Access from anonymized network
        anonymized_access = AttackTreeNode(
            name="Access via Anonymization Network",
            node_type="leaf",
            description="Use Tor or VPN to hide origin",
            cost=0.5,
            detectability=0.8,
            mitigations=[
                "Block Tor exit nodes",
                "Geofencing",
                "Risk-based authentication",
            ],
            detection_methods=[
                "Tor exit node detection",
                "VPN/proxy detection",
                "Geographic anomalies",
            ],
        )
        credential_path.add_child(anonymized_access)

        # Submit fraudulent ROA
        submit_roa = AttackTreeNode(
            name="Submit Fraudulent ROA Request",
            node_type="leaf",
            description="Use compromised account to request ROA for target prefix",
            cost=0.5,
            detectability=0.7,
            mitigations=[
                "Out-of-band verification",
                "Secondary approval",
                "ROA change monitoring",
            ],
            detection_methods=[
                "Anomalous ROA requests",
                "Prefix ownership validation",
                "Request source analysis",
            ],
        )
        credential_path.add_child(submit_roa)

        # Wait for ROA publication
        roa_publication = AttackTreeNode(
            name="ROA Published to Repository",
            node_type="leaf",
            description="RIR publishes ROA without detecting fraud",
            cost=0.0,
            detectability=0.6,
            mitigations=[
                "Manual review process",
                "Automated validation",
                "Community review period",
            ],
            detection_methods=[
                "ROA publication monitoring",
                "Anomaly detection on new ROAs",
            ],
        )
        credential_path.add_child(roa_publication)

        # Validator acceptance
        validator_sync = AttackTreeNode(
            name="Validators Accept Fraudulent ROA",
            node_type="leaf",
            description="RPKI validators sync and validate fraudulent ROA",
            cost=0.0,
            detectability=0.5,
            mitigations=[
                "Multi-source validation",
                "Historical comparison",
                "Community alerting",
            ],
            detection_methods=[
                "Validator consensus monitoring",
                "ROA change detection",
                "Validation status tracking",
            ],
        )
        credential_path.add_child(validator_sync)

        # Path 2: System Vulnerability (alternative path, not in scenario)
        vuln_path = AttackTreeNode(
            name="System Vulnerability Path",
            node_type="and",
            description="Exploit vulnerability in RIR system",
            cost=3.0,
            detectability=0.4,
        )
        path_choice.add_child(vuln_path)

        find_vuln = AttackTreeNode(
            name="Discover RIR System Vulnerability",
            node_type="leaf",
            description="Find exploitable vulnerability in ROA portal",
            cost=5.0,
            detectability=0.3,
            mitigations=[
                "Regular security audits",
                "Penetration testing",
                "Bug bounty program",
            ],
            detection_methods=[
                "Intrusion detection",
                "Unusual API calls",
                "System log analysis",
            ],
        )
        vuln_path.add_child(find_vuln)

        exploit_vuln = AttackTreeNode(
            name="Exploit Vulnerability",
            node_type="leaf",
            description="Exploit vulnerability to inject fraudulent ROA",
            cost=2.0,
            detectability=0.6,
            mitigations=["WAF", "Input validation", "Security patches"],
            detection_methods=[
                "IDS/IPS alerts",
                "Anomalous database writes",
                "Audit log analysis",
            ],
        )
        vuln_path.add_child(exploit_vuln)

        return root

    @staticmethod
    def build_playbook3_attack_tree() -> AttackTreeNode:
        """Build attack tree for Playbook 3: Sub-prefix hijacking."""

        root = AttackTreeNode(
            name="Hijack Traffic via Sub-prefix Announcement",
            node_type="goal",
            description="Intercept traffic using more-specific BGP announcement",
            cost=0.0,
            detectability=0.0,
        )

        # Main attack sequence (AND)
        attack_sequence = AttackTreeNode(
            name="Execute Sub-prefix Hijack",
            node_type="and",
            description="All steps required for successful hijack",
            cost=0.0,
            detectability=0.0,
        )
        root.add_child(attack_sequence)

        # Step 1: Identify target
        identify_target = AttackTreeNode(
            name="Identify Target Prefix with Weak ROA",
            node_type="leaf",
            description="Find prefix with ROA that has permissive maxLength",
            cost=1.0,
            detectability=0.3,
            mitigations=["Strict maxLength policies", "ROA auditing"],
            detection_methods=["RPKI monitoring", "ROA analysis tools"],
        )
        attack_sequence.add_child(identify_target)

        # Step 2: Obtain BGP peering
        obtain_peering = AttackTreeNode(
            name="Obtain BGP Peering Capability",
            node_type="or",
            description="Need ability to announce BGP routes",
            cost=0.0,
            detectability=0.0,
        )
        attack_sequence.add_child(obtain_peering)

        own_asn = AttackTreeNode(
            name="Control Legitimate ASN",
            node_type="leaf",
            description="Own or compromise an ASN with BGP capabilities",
            cost=5.0,
            detectability=0.4,
            mitigations=["ASN verification", "Peer vetting"],
            detection_methods=[
                "ASN reputation monitoring",
                "Historical behavior analysis",
            ],
        )
        obtain_peering.add_child(own_asn)

        compromise_router = AttackTreeNode(
            name="Compromise BGP Router",
            node_type="leaf",
            description="Hack into router with BGP peering",
            cost=4.0,
            detectability=0.7,
            mitigations=["Router hardening", "Access controls", "Monitoring"],
            detection_methods=[
                "Configuration change detection",
                "Unauthorized access alerts",
            ],
        )
        obtain_peering.add_child(compromise_router)

        # Step 3: Announce sub-prefix
        announce_prefix = AttackTreeNode(
            name="Announce More-Specific Prefix",
            node_type="leaf",
            description="BGP announce /25 within target /24",
            cost=0.5,
            detectability=0.8,
            mitigations=[
                "Prefix filtering",
                "Anomaly detection",
                "Alert on more-specifics",
            ],
            detection_methods=[
                "BGP monitoring",
                "Route announcement detection",
                "BMP feeds",
            ],
        )
        attack_sequence.add_child(announce_prefix)

        # Step 4: Pass RPKI validation
        pass_rpki = AttackTreeNode(
            name="Pass RPKI Validation",
            node_type="leaf",
            description="Sub-prefix validates due to parent ROA maxLength",
            cost=0.0,
            detectability=0.5,
            mitigations=["Strict maxLength", "Alert on validation changes"],
            detection_methods=["Validator monitoring", "RPKI status tracking"],
        )
        attack_sequence.add_child(pass_rpki)

        # Step 5: Intercept traffic
        intercept_traffic = AttackTreeNode(
            name="Intercept and Forward Traffic",
            node_type="leaf",
            description="Receive traffic, inspect/modify, forward to legitimate destination",
            cost=1.0,
            detectability=0.6,
            mitigations=["Flow monitoring", "Latency detection", "Path validation"],
            detection_methods=[
                "Traffic pattern analysis",
                "Latency monitoring",
                "Geographic anomalies",
            ],
        )
        attack_sequence.add_child(intercept_traffic)

        # Step 6: Maintain persistence
        maintain_hijack = AttackTreeNode(
            name="Maintain Hijack",
            node_type="leaf",
            description="Keep announcement stable to avoid detection",
            cost=0.5,
            detectability=0.5,
            mitigations=["Time-based alerts", "Sustained announcement detection"],
            detection_methods=["Route duration monitoring", "Stability analysis"],
        )
        attack_sequence.add_child(maintain_hijack)

        return root

    @staticmethod
    def export_attack_tree_json(tree: AttackTreeNode, filename: str) -> None:
        """Export attack tree to JSON file."""
        with open(filename, "w") as f:
            json.dump(tree.to_dict(), f, indent=2)

    @staticmethod
    def generate_attack_tree_dot(tree: AttackTreeNode) -> str:
        """Generate Graphviz DOT format for visualization."""
        dot_lines = ["digraph AttackTree {"]
        dot_lines.append("  rankdir=TB;")
        dot_lines.append("  node [shape=box, style=filled];")

        node_counter = [0]  # Mutable counter

        def add_node(node: AttackTreeNode, parent_id: str | None = None) -> str:
            node_id = f"node{node_counter[0]}"
            node_counter[0] += 1

            # Determine color based on node type
            color_map = {
                "goal": "lightblue",
                "and": "lightgreen",
                "or": "lightyellow",
                "leaf": "lightgray",
            }
            color = color_map.get(node.node_type, "white")

            # Create label with cost and detectability
            label = f"{node.name}\\n"
            label += f"Type: {node.node_type.upper()}\\n"
            label += f"Cost: {node.cost:.1f} | Detect: {node.detectability:.1f}"

            dot_lines.append(f'  {node_id} [label="{label}", fillcolor="{color}"];')

            if parent_id:
                dot_lines.append(f"  {parent_id} -> {node_id};")

            for child in node.children:
                add_node(child, node_id)

            return node_id

        add_node(tree)
        dot_lines.append("}")

        return "\n".join(dot_lines)

    @staticmethod
    def analyse_attack_paths(tree: AttackTreeNode) -> dict:
        """Analyse all possible attack paths through the tree."""
        paths = []

        def find_paths(node: AttackTreeNode, current_path: list[str]) -> None:
            current_path = current_path + [node.name]

            if not node.children:
                # Leaf node - path complete
                paths.append(
                    {
                        "path": current_path.copy(),
                        "total_cost": sum(
                            n.cost for n in _get_nodes_in_path(tree, current_path)
                        ),
                        "min_detectability": min(
                            (
                                n.detectability
                                for n in _get_nodes_in_path(tree, current_path)
                            ),
                            default=0.0,
                        ),
                    }
                )
                return

            if node.node_type == "and":
                # Must traverse all children
                for child in node.children:
                    find_paths(child, current_path)
            elif node.node_type == "or":
                # Can choose any child
                for child in node.children:
                    find_paths(child, current_path)
            else:
                # Other node types - traverse all children
                for child in node.children:
                    find_paths(child, current_path)

        def _get_nodes_in_path(
            root: AttackTreeNode, path_names: list[str]
        ) -> list[AttackTreeNode]:
            """Helper to get actual nodes from path names."""
            nodes = []

            def traverse(node: AttackTreeNode) -> None:
                if node.name in path_names:
                    nodes.append(node)
                for child in node.children:
                    traverse(child)

            traverse(root)
            return nodes

        find_paths(tree, [])

        # Sort paths by cost (lowest first) and detectability (lowest first)
        paths.sort(key=lambda p: (p["total_cost"], p["min_detectability"]))

        return {
            "total_paths": len(paths),
            "paths": paths,
            "easiest_path": paths[0] if paths else None,
            "hardest_path": paths[-1] if paths else None,
        }


# ============================================================================
# Detection Gap Analyser
# ============================================================================


class DetectionGapAnalyser:
    """Analyses detection coverage and identifies gaps."""

    def __init__(self):
        self.available_data_sources: set[str] = set()
        self.available_detection_rules: set[str] = set()
        self.monitored_systems: set[str] = set()

    def set_available_capabilities(
        self,
        data_sources: list[str],
        detection_rules: list[str],
        monitored_systems: list[str],
    ) -> None:
        """Configure what detection capabilities are available."""
        self.available_data_sources = set(data_sources)
        self.available_detection_rules = set(detection_rules)
        self.monitored_systems = set(monitored_systems)

    def analyse_scenario_coverage(self, scenario: ThreatScenario) -> list[DetectionGap]:
        """Analyse detection coverage for a scenario and identify gaps."""
        gaps = []

        for event in scenario.events:
            # Check for missing data sources
            required_sources = set(event.data_sources)
            missing_sources = required_sources - self.available_data_sources

            if missing_sources:
                gaps.append(
                    DetectionGap(
                        gap_type="missing_data_source",
                        technique_id=self._extract_technique_id(event.technique),
                        technique_name=event.technique,
                        phase=event.phase.value,
                        severity=self._calculate_severity(
                            event.phase, len(missing_sources)
                        ),
                        description=f"Missing data sources for detecting {event.technique}",
                        affected_scenarios=[scenario.scenario_name],
                        recommended_actions=[
                            f"Enable {source} collection" for source in missing_sources
                        ],
                        required_data_sources=list(missing_sources),
                    )
                )

            # Check for missing detection rules
            has_detection = any(
                rule_keyword in " ".join(self.available_detection_rules).lower()
                for rule_keyword in event.technique.lower().split()
            )

            if not has_detection and self.available_data_sources.intersection(
                required_sources
            ):
                gaps.append(
                    DetectionGap(
                        gap_type="no_detection_rule",
                        technique_id=self._extract_technique_id(event.technique),
                        technique_name=event.technique,
                        phase=event.phase.value,
                        severity=self._calculate_severity(event.phase, 1),
                        description=f"Data available but no detection rule for {event.technique}",
                        affected_scenarios=[scenario.scenario_name],
                        recommended_actions=[
                            f"Create detection rule for {event.technique}",
                            f"Implement alerting on: {', '.join(event.indicators[:2])}",
                        ],
                        required_data_sources=list(
                            required_sources.intersection(self.available_data_sources)
                        ),
                    )
                )

            # Check for complete blind spots
            if not missing_sources and not has_detection:
                gaps.append(
                    DetectionGap(
                        gap_type="blind_spot",
                        technique_id=self._extract_technique_id(event.technique),
                        technique_name=event.technique,
                        phase=event.phase.value,
                        severity=(
                            "critical"
                            if event.phase
                            in {AttackPhase.INITIAL_ACCESS, AttackPhase.IMPACT}
                            else "high"
                        ),
                        description=f"Complete blind spot: no data collection or detection for {event.technique}",
                        affected_scenarios=[scenario.scenario_name],
                        recommended_actions=[
                            f"PRIORITY: Enable data sources: {', '.join(required_sources)}",
                            "Create detection rules immediately",
                            "Implement compensating controls",
                        ],
                        required_data_sources=list(required_sources),
                    )
                )

        return gaps

    @staticmethod
    def _extract_technique_id(technique_name: str) -> str:
        """Extract or generate technique ID from technique name."""
        # Simplified - in production would map to actual ATT&CK IDs
        return technique_name.replace(" ", "_").replace(":", "_").upper()

    @staticmethod
    def _calculate_severity(phase: AttackPhase, gap_count: int) -> str:
        """Calculate gap severity based on attack phase and gap count."""
        critical_phases = {AttackPhase.INITIAL_ACCESS, AttackPhase.IMPACT}
        high_phases = {AttackPhase.DEFENCE_EVASION, AttackPhase.PERSISTENCE}

        if phase in critical_phases:
            return "critical" if gap_count > 1 else "high"
        elif phase in high_phases:
            return "high" if gap_count > 1 else "medium"
        else:
            return "medium" if gap_count > 1 else "low"

    def generate_coverage_report(self, scenarios: list[ThreatScenario]) -> dict:
        """Generate comprehensive coverage report across all scenarios."""
        all_gaps = []
        coverage_stats = {
            "total_techniques": 0,
            "covered_techniques": 0,
            "partially_covered": 0,
            "uncovered_techniques": 0,
            "gaps_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "gaps_by_phase": defaultdict(int),
        }

        technique_coverage = {}

        for scenario in scenarios:
            scenario_gaps = self.analyse_scenario_coverage(scenario)
            all_gaps.extend(scenario_gaps)

            for event in scenario.events:
                tech_key = event.technique
                if tech_key not in technique_coverage:
                    technique_coverage[tech_key] = {
                        "data_sources_available": 0,
                        "data_sources_required": len(event.data_sources),
                        "has_detection_rule": False,
                        "phases": set(),
                    }

                # Check coverage
                available = len(
                    set(event.data_sources).intersection(self.available_data_sources)
                )
                technique_coverage[tech_key]["data_sources_available"] = max(
                    technique_coverage[tech_key]["data_sources_available"], available
                )
                technique_coverage[tech_key]["phases"].add(event.phase.value)

        # Calculate statistics
        coverage_stats["total_techniques"] = len(technique_coverage)

        for _tech, cov in technique_coverage.items():
            if (
                cov["data_sources_available"] == cov["data_sources_required"]
                and cov["has_detection_rule"]
            ):
                coverage_stats["covered_techniques"] += 1
            elif cov["data_sources_available"] > 0:
                coverage_stats["partially_covered"] += 1
            else:
                coverage_stats["uncovered_techniques"] += 1

        # Count gaps
        for gap in all_gaps:
            coverage_stats["gaps_by_severity"][gap.severity] += 1
            coverage_stats["gaps_by_phase"][gap.phase] += 1

        return {
            "statistics": coverage_stats,
            "gaps": all_gaps,
            "technique_coverage": technique_coverage,
            "coverage_percentage": (
                (
                    coverage_stats["covered_techniques"]
                    / coverage_stats["total_techniques"]
                    * 100
                )
                if coverage_stats["total_techniques"] > 0
                else 0.0
            ),
        }

    @staticmethod
    def generate_gap_report(gaps: list[DetectionGap]) -> str:
        """Generate human-readable gap analysis report."""
        report = []
        report.append("=" * 80)
        report.append("DETECTION GAP ANALYSIS REPORT")
        report.append("=" * 80)

        # Group gaps by severity
        by_severity = defaultdict(list)
        for gap in gaps:
            by_severity[gap.severity].append(gap)

        for severity in ["critical", "high", "medium", "low"]:
            if severity not in by_severity:
                continue

            report.append(f"\n{'─' * 80}")
            report.append(
                f"{severity.upper()} SEVERITY GAPS ({len(by_severity[severity])})"
            )
            report.append("─" * 80)

            for i, gap in enumerate(by_severity[severity], 1):
                report.append(f"\n[{i}] {gap.technique_name}")
                report.append(f"    Type: {gap.gap_type}")
                report.append(f"    Phase: {gap.phase}")
                report.append(f"    Description: {gap.description}")
                report.append(
                    f"    Affected Scenarios: {', '.join(gap.affected_scenarios)}"
                )
                report.append("    Required Data Sources:")
                for ds in gap.required_data_sources:
                    report.append(f"      • {ds}")
                report.append("    Recommended Actions:")
                for action in gap.recommended_actions:
                    report.append(f"      • {action}")

        return "\n".join(report)


# ============================================================================
# Main Example Usage
# ============================================================================


def main():
    """Demonstrate the complete threat modelling framework."""

    print("BGP Threat Modelling Framework Demo")
    print("=" * 80)

    # Initialize extractor
    extractor = ScenarioThreatModelExtractor()

    # Extract scenarios
    print("\n1. Extracting Threat Scenarios...")
    scenario1 = extractor.extract_playbook1_scenario([])
    scenario2 = extractor.extract_playbook2_scenario([])
    scenario3 = extractor.extract_playbook3_scenario([])

    scenarios = [scenario1, scenario2, scenario3]

    # Generate threat model reports
    print("\n2. Generating Threat Model Reports...")
    for scenario in scenarios:
        report = extractor.generate_threat_model_report(scenario)
        print(f"\n{report}\n")

    # MITRE ATT&CK Mapping
    print("\n3. Mapping to MITRE ATT&CK...")
    mapper = MITREATTACKMapper()

    for scenario in scenarios:
        techniques = mapper.map_scenario_to_attack(scenario)
        print(f"\n{scenario.scenario_name}:")
        for tech in techniques:
            print(f"  • {tech.technique_id}: {tech.technique_name} ({tech.tactic})")

    # Generate ATT&CK Navigator layer
    navigator_layer = mapper.generate_attack_navigator_layer(scenarios)
    with open("bgp_attack_navigator.json", "w") as f:
        json.dump(navigator_layer, f, indent=2)
    print("\nATT&CK Navigator layer saved to bgp_attack_navigator.json")

    # Generate detection matrix
    detection_matrix = mapper.generate_detection_matrix(scenarios)
    print(f"\nDetection Matrix: {len(detection_matrix)} techniques mapped")

    # Build Attack Trees
    print("\n4. Building Attack Trees...")
    tree_gen = AttackTreeGenerator()

    playbook2_tree = tree_gen.build_playbook2_attack_tree()
    playbook3_tree = tree_gen.build_playbook3_attack_tree()

    # Export trees
    tree_gen.export_attack_tree_json(playbook2_tree, "playbook2_attack_tree.json")
    tree_gen.export_attack_tree_json(playbook3_tree, "playbook3_attack_tree.json")
    print("Attack trees saved to JSON files")

    # Generate DOT files for visualization
    with open("playbook2_attack_tree.dot", "w") as f:
        f.write(tree_gen.generate_attack_tree_dot(playbook2_tree))
    with open("playbook3_attack_tree.dot", "w") as f:
        f.write(tree_gen.generate_attack_tree_dot(playbook3_tree))
    print("Attack tree DOT files generated (use Graphviz to visualize)")

    # Analyse attack paths
    print("\n5. Analysing Attack Paths...")
    playbook2_analysis = tree_gen.analyse_attack_paths(playbook2_tree)
    print(f"\nPlaybook 2: {playbook2_analysis['total_paths']} possible attack paths")
    if playbook2_analysis["easiest_path"]:
        print(
            f"Easiest path cost: {playbook2_analysis['easiest_path']['total_cost']:.1f}"
        )

    # Detection Gap Analysis
    print("\n6. Analysing Detection Gaps...")
    gap_analyser = DetectionGapAnalyser()

    # Configure available capabilities (example)
    gap_analyser.set_available_capabilities(
        data_sources=["Authentication logs", "BGP monitoring", "Network traffic"],
        detection_rules=["suspicious_login", "bgp_announcement_monitor"],
        monitored_systems=["edge_routers", "tacacs_server"],
    )

    # Analyse coverage
    coverage_report = gap_analyser.generate_coverage_report(scenarios)
    print(f"\nCoverage: {coverage_report['coverage_percentage']:.1f}%")
    print(f"Total Techniques: {coverage_report['statistics']['total_techniques']}")
    print(f"Covered: {coverage_report['statistics']['covered_techniques']}")
    print(f"Partially Covered: {coverage_report['statistics']['partially_covered']}")
    print(f"Uncovered: {coverage_report['statistics']['uncovered_techniques']}")

    # Generate gap report
    gap_report = gap_analyser.generate_gap_report(coverage_report["gaps"])
    print(f"\n{gap_report}")

    # Save comprehensive report
    with open("threat_model_report.json", "w") as f:
        json.dump(
            {
                "scenarios": [
                    {
                        "name": s.scenario_name,
                        "goal": s.attack_goal,
                        "actor_profile": s.threat_actor_profile,
                        "duration_minutes": s.attack_duration.total_seconds() / 60,
                        "attack_chain": s.get_attack_chain(),
                        "ttps": list(s.get_ttps()),
                    }
                    for s in scenarios
                ],
                "attack_navigator_layer": navigator_layer,
                "detection_matrix": detection_matrix,
                "coverage_report": {
                    "statistics": coverage_report["statistics"],
                    "coverage_percentage": coverage_report["coverage_percentage"],
                    "gaps": [
                        {
                            "type": g.gap_type,
                            "technique": g.technique_name,
                            "severity": g.severity,
                            "description": g.description,
                            "recommended_actions": g.recommended_actions,
                        }
                        for g in coverage_report["gaps"]
                    ],
                },
                "attack_tree_analysis": {
                    "playbook2": playbook2_analysis,
                    "playbook3": tree_gen.analyse_attack_paths(playbook3_tree),
                },
            },
            f,
            indent=2,
        )

    print("\n" + "=" * 80)
    print("Complete threat model report saved to threat_model_report.json")
    print("=" * 80)


if __name__ == "__main__":
    main()
