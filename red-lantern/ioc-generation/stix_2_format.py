import json
from datetime import datetime, timezone
import uuid

from extracting_attacker_asns import MaliciousASN, ASNIOCExtractor
from suspicious_prefix_announcements import SuspiciousPrefix, PrefixIOCExtractor
from known_attacker_infra import AttackerInfrastructure, InfrastructureIOCExtractor

class STIXThreatFeedGenerator:
    """Generates STIX 2.1 formatted threat feeds."""

    def __init__(self, identity_name: str = "BGP Hijacking Research Lab"):
        self.identity_name = identity_name
        self.identity_id = f"identity--{uuid.uuid4()}"

    def generate_bundle(self,
                        malicious_asns: list[MaliciousASN],
                        suspicious_prefixes: list[SuspiciousPrefix],
                        infrastructure: list[AttackerInfrastructure]) -> dict:
        """Generate a complete STIX 2.1 bundle."""

        bundle_objects = []

        # Add identity object
        bundle_objects.append(self._create_identity())

        # Add malicious ASN indicators
        for asn in malicious_asns:
            bundle_objects.extend(self._create_asn_indicators(asn))

        # Add suspicious prefix indicators
        for prefix in suspicious_prefixes:
            bundle_objects.extend(self._create_prefix_indicators(prefix))

        # Add infrastructure indicators
        for infra in infrastructure:
            bundle_objects.append(self._create_infrastructure_indicator(infra))

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": bundle_objects
        }

    def _create_identity(self) -> dict:
        """Create identity object for the threat feed producer."""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": self.identity_name,
            "identity_class": "organization",
            "sectors": ["technology"],
            "description": "Research organisation tracking BGP hijacking campaigns"
        }

    def _create_asn_indicators(self, asn: MaliciousASN) -> list[dict]:
        """Create STIX indicators for a malicious ASN."""
        indicator_id = f"indicator--{uuid.uuid4()}"

        # Main indicator
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": asn.first_seen.isoformat() + "Z",
            "modified": asn.last_seen.isoformat() + "Z",
            "created_by_ref": self.identity_id,
            "name": f"Malicious ASN: {asn.asn}",
            "description": f"ASN {asn.asn} observed in BGP hijacking activities. Attack types: {', '.join(asn.attack_types)}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[autonomous-system:number = '{asn.asn.replace('AS', '')}']",
            "pattern_type": "stix",
            "valid_from": asn.first_seen.isoformat() + "Z",
            "valid_until": (asn.last_seen.replace(year=asn.last_seen.year + 1)).isoformat() + "Z",
            "confidence": self._confidence_to_int(asn.confidence),
            "labels": list(asn.attack_types),
            "external_references": [
                {
                    "source_name": "simulator_evidence",
                    "description": evidence
                } for evidence in asn.evidence[:3]  # Limit to first 3 pieces of evidence
            ]
        }

        # Create observable for each associated prefix
        observables = []
        for prefix in asn.associated_prefixes:
            obs_id = f"observed-data--{uuid.uuid4()}"
            observable = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": asn.first_seen.isoformat() + "Z",
                "modified": asn.last_seen.isoformat() + "Z",
                "created_by_ref": self.identity_id,
                "first_observed": asn.first_seen.isoformat() + "Z",
                "last_observed": asn.last_seen.isoformat() + "Z",
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "ipv4-addr",
                        "value": prefix.split('/')[0]
                    },
                    "1": {
                        "type": "autonomous-system",
                        "number": int(asn.asn.replace('AS', ''))
                    }
                }
            }
            observables.append(observable)

            # Create relationship
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": asn.first_seen.isoformat() + "Z",
                "modified": asn.last_seen.isoformat() + "Z",
                "created_by_ref": self.identity_id,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": obs_id
            }
            observables.append(relationship)

        return [indicator] + observables

    def _create_prefix_indicators(self, prefix: SuspiciousPrefix) -> list[dict]:
        """Create STIX indicators for suspicious prefix announcements."""
        indicator_id = f"indicator--{uuid.uuid4()}"

        pattern_parts = [
            f"[ipv4-addr:value = '{prefix.prefix.split('/')[0]}']",
            f"[autonomous-system:number = '{prefix.origin_asn.replace('AS', '')}']"
        ]

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": prefix.first_seen.isoformat() + "Z",
            "modified": prefix.last_seen.isoformat() + "Z",
            "created_by_ref": self.identity_id,
            "name": f"Suspicious BGP Announcement: {prefix.prefix}",
            "description": f"Prefix {prefix.prefix} announced by {prefix.origin_asn} with RPKI status: {prefix.rpki_status}. Indicators: {', '.join(prefix.indicators)}",
            "indicator_types": ["anomalous-activity"],
            "pattern": " AND ".join(pattern_parts),
            "pattern_type": "stix",
            "valid_from": prefix.first_seen.isoformat() + "Z",
            "confidence": self._confidence_to_int(prefix.confidence),
            "labels": list(prefix.indicators) + [f"rpki_{prefix.rpki_status}"],
            "x_rpki_status": prefix.rpki_status,
            "x_as_path": prefix.announcement_path
        }

        return [indicator]

    def _create_infrastructure_indicator(self, infra: AttackerInfrastructure) -> dict:
        """Create STIX indicator for attacker infrastructure."""
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": infra.first_seen.isoformat() + "Z",
            "modified": infra.last_seen.isoformat() + "Z",
            "created_by_ref": self.identity_id,
            "name": f"Attacker Infrastructure: {infra.ip_address}",
            "description": f"{infra.infrastructure_type} at {infra.ip_address}. Associated with: {', '.join(infra.associated_attacks[:3])}",
            "indicator_types": ["anonymization", "malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{infra.ip_address}']",
            "pattern_type": "stix",
            "valid_from": infra.first_seen.isoformat() + "Z",
            "confidence": self._confidence_to_int(infra.confidence),
            "labels": [infra.infrastructure_type],
            "x_geolocation": infra.geolocation
        }

    def _confidence_to_int(self, confidence: str) -> int:
        """Convert confidence string to STIX integer (0-100)."""
        mapping = {'low': 30, 'medium': 60, 'high': 90}
        return mapping.get(confidence.lower(), 50)

    def save_to_file(self, bundle: dict, filename: str):
        """Save STIX bundle to file."""
        with open(filename, 'w') as f:
            json.dump(bundle, f, indent=2)
        print(f"STIX bundle saved to {filename}")


# Example usage
stix_gen = STIXThreatFeedGenerator("BGP Defence League")

# Extract IOCs from scenarios
asn_extractor = ASNIOCExtractor()
prefix_extractor = PrefixIOCExtractor()
infra_extractor = InfrastructureIOCExtractor()

# Process logs (from your scenarios)
all_logs = [
    "Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45",
    "<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25",
    "<10>Jan 01 00:02:00 edge-router-01 ROA creation request for 203.0.113.0/24 (origin AS64513, maxLength /25) - FRAUDULENT",
]

malicious_asns = asn_extractor.extract_from_logs(all_logs)
suspicious_prefixes = prefix_extractor.extract_from_logs(all_logs)
infrastructure = infra_extractor.extract_from_logs(all_logs)

# Generate STIX bundle
stix_bundle = stix_gen.generate_bundle(malicious_asns, suspicious_prefixes, infrastructure)
stix_gen.save_to_file(stix_bundle, 'bgp_hijacking_indicators.json')
