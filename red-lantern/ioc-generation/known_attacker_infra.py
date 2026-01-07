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
class AttackerInfrastructure:
    """Infrastructure associated with BGP attacks."""

    ip_address: str
    infrastructure_type: str  # tor_exit, command_control, login_source
    first_seen: datetime
    last_seen: datetime
    associated_attacks: list[str]
    geolocation: dict[str, str]
    confidence: str
    evidence: list[str]

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "infrastructure_type": self.infrastructure_type,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "associated_attacks": self.associated_attacks,
            "geolocation": self.geolocation,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class InfrastructureIOCExtractor:
    """Extracts attacker infrastructure indicators."""

    # Known Tor exit node ranges (example)
    TOR_RANGES = ["185.220.101.0/24", "185.220.102.0/24"]

    def __init__(self):
        self.infrastructure: dict[str, AttackerInfrastructure] = {}

    def extract_from_logs(self, log_lines: list[str]) -> list[AttackerInfrastructure]:
        """Extract infrastructure indicators."""
        for line in log_lines:
            self._process_log_line(line)

        return list(self.infrastructure.values())

    def _process_log_line(self, line: str):
        """Process log line for infrastructure indicators."""
        timestamp = self._extract_timestamp(line)

        # Pattern: Suspicious logins
        # Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45
        if "login from" in line:
            match = re.search(r"login from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if match:
                ip_address = match.group(1)
                infra_type = self._classify_ip(ip_address)

                # Extract associated account
                account_match = re.search(r"(\S+@\S+)", line)
                attack_context = (
                    f"Login as {account_match.group(1)}"
                    if account_match
                    else "Suspicious login"
                )

                self._add_or_update_infrastructure(
                    ip_address=ip_address,
                    infra_type=infra_type,
                    timestamp=timestamp,
                    attack_context=attack_context,
                    evidence=line,
                )

    def _classify_ip(self, ip_address: str) -> str:
        """Classify IP address type based on known ranges."""
        import ipaddress

        ip = ipaddress.ip_address(ip_address)

        # Check if it's a Tor exit node
        for tor_range in self.TOR_RANGES:
            if ip in ipaddress.ip_network(tor_range):
                return "tor_exit_node"

        # Check if it's a known VPN or proxy range (simplified)
        if ip_address.startswith("185."):
            return "suspicious_hosting"

        return "unknown"

    def _add_or_update_infrastructure(
        self,
        ip_address: str,
        infra_type: str,
        timestamp: datetime,
        attack_context: str,
        evidence: str,
    ):
        """Add or update infrastructure record."""
        if ip_address not in self.infrastructure:
            confidence = "high" if infra_type == "tor_exit_node" else "medium"

            self.infrastructure[ip_address] = AttackerInfrastructure(
                ip_address=ip_address,
                infrastructure_type=infra_type,
                first_seen=timestamp,
                last_seen=timestamp,
                associated_attacks=[attack_context],
                geolocation=self._lookup_geolocation(ip_address),
                confidence=confidence,
                evidence=[evidence],
            )
        else:
            record = self.infrastructure[ip_address]
            record.last_seen = max(record.last_seen, timestamp)
            record.associated_attacks.append(attack_context)
            record.evidence.append(evidence)

    def _lookup_geolocation(self, ip_address: str) -> dict[str, str]:
        """Lookup geolocation (simplified for demonstration)."""
        # In reality, you'd use MaxMind GeoIP or similar
        if ip_address.startswith("185.220.101"):
            return {"country": "Unknown", "isp": "Tor Exit Node", "asn": "AS000"}
        return {"country": "Unknown", "isp": "Unknown", "asn": "Unknown"}

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line."""
        match = re.search(r"(\w+ \d+ \d+:\d+:\d+)", line)
        if match:
            return datetime.strptime(f"2025 {match.group(1)}", "%Y %b %d %H:%M:%S")
        return datetime.now()
