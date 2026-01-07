"""
Disclaimer:

All code in this module that generates IOCs (Indicators of Compromise) is intended
solely for simulation and testing within the simulator environment. It is not
guaranteed to reflect real-world threat feeds or operational accuracy.

While the generated IOCs can be useful for learning, experimentation, and
getting started with real-world threat analysis, they should never be used as
the sole basis for production security decisions.

Use at your own risk. Always validate and supplement with trusted, real-world
sources when applying threat intelligence in operational environments.
"""

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class MaliciousASN:
    """An ASN engaged in nefarious activities, documented for posterity."""

    asn: str
    first_seen: datetime
    last_seen: datetime
    attack_types: set[str]
    associated_prefixes: set[str]
    confidence: str  # high, medium, low
    evidence: list[str]

    def to_dict(self) -> dict:
        return {
            "asn": self.asn,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "attack_types": list(self.attack_types),
            "associated_prefixes": list(self.associated_prefixes),
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class ASNIOCExtractor:
    """Extracts malicious ASN indicators from scenario logs."""

    def __init__(self):
        self.malicious_asns: dict[str, MaliciousASN] = {}

    def extract_from_logs(self, log_lines: list[str]) -> list[MaliciousASN]:
        """
        Parse logs and extract malicious ASN indicators.
        Rather like sorting through evidence at the Watch House.
        """
        for line in log_lines:
            self._process_log_line(line)

        return list(self.malicious_asns.values())

    def _process_log_line(self, line: str):
        """Process a single log line for ASN indicators."""
        timestamp = self._extract_timestamp(line)

        # Pattern 1: Fraudulent ROA requests
        # <29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513
        if "FRAUDULENT" in line or (
            "ROA creation request" in line and "AS64513" in line
        ):
            asn_match = re.search(r"AS(\d+)", line)
            prefix_match = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line
            )

            if asn_match:
                asn = f"AS{asn_match.group(1)}"
                prefix = prefix_match.group(1) if prefix_match else "unknown"

                self._add_or_update_asn(
                    asn=asn,
                    timestamp=timestamp,
                    attack_type="fraudulent_roa",
                    prefix=prefix,
                    confidence="high",
                    evidence=line,
                )

        # Pattern 2: Rejected validation tests
        # <13>Jan 01 00:51:00 edge-router-01 Validation test AMER: Announcement 198.51.100.0/24 AS64514 - peer rejected
        if "peer rejected" in line or "ATTACK SUCCEEDING" in line:
            asn_match = re.search(r"AS(\d+)", line)
            prefix_match = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line
            )

            if asn_match:
                asn = f"AS{asn_match.group(1)}"
                prefix = prefix_match.group(1) if prefix_match else "unknown"

                self._add_or_update_asn(
                    asn=asn,
                    timestamp=timestamp,
                    attack_type="suspicious_announcement",
                    prefix=prefix,
                    confidence="medium",
                    evidence=line,
                )

    def _add_or_update_asn(
        self,
        asn: str,
        timestamp: datetime,
        attack_type: str,
        prefix: str,
        confidence: str,
        evidence: str,
    ):
        """Add new or update existing malicious ASN record."""
        if asn not in self.malicious_asns:
            self.malicious_asns[asn] = MaliciousASN(
                asn=asn,
                first_seen=timestamp,
                last_seen=timestamp,
                attack_types={attack_type},
                associated_prefixes={prefix},
                confidence=confidence,
                evidence=[evidence],
            )
        else:
            record = self.malicious_asns[asn]
            record.last_seen = max(record.last_seen, timestamp)
            record.attack_types.add(attack_type)
            record.associated_prefixes.add(prefix)
            record.evidence.append(evidence)

            # Upgrade confidence if we see multiple attack types
            if len(record.attack_types) > 1:
                record.confidence = "high"

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line."""
        match = re.search(r"(\w+ \d+ \d+:\d+:\d+)", line)
        if match:
            return datetime.strptime(f"2025 {match.group(1)}", "%Y %b %d %H:%M:%S")
        return datetime.now()


# Example: Extract from playbook2 scenario
extractor = ASNIOCExtractor()
playbook2_logs = [
    "<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25 by admin@victim-network.net via ARIN",
    "<10>Jan 01 00:02:00 edge-router-01 ROA creation request for 203.0.113.0/24 (origin AS64513, maxLength /25) - FRAUDULENT",
    "<10>Jan 01 00:04:00 edge-router-01 ROA creation accepted for 203.0.113.0/24 by ARIN - ATTACK SUCCEEDING",
    "<13>Jan 01 00:51:00 edge-router-01 Validation test AMER: Announcement 198.51.100.0/24 AS64514 - peer rejected",
]

malicious_asns = extractor.extract_from_logs(playbook2_logs)
