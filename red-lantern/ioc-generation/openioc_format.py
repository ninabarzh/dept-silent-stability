import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, UTC
import uuid
from typing import List

from extracting_attacker_asns import MaliciousASN, ASNIOCExtractor
from suspicious_prefix_announcements import SuspiciousPrefix, PrefixIOCExtractor
from known_attacker_infra import AttackerInfrastructure, InfrastructureIOCExtractor


class OpenIOCGenerator:
    """Generates OpenIOC formatted indicators with modern Python patterns."""

    def __init__(self, ioc_id: str | None = None, name: str = "BGP Hijacking Campaign"):
        self.ioc_id = ioc_id or str(uuid.uuid4())
        self.name = name

    @property
    def _current_time(self) -> str:
        """Get current UTC time in ISO format with Z suffix."""
        return datetime.now(UTC).isoformat().replace('+00:00', 'Z')

    def generate_ioc(self,
                     malicious_asns: List[MaliciousASN],
                     suspicious_prefixes: List[SuspiciousPrefix],
                     infrastructure: List[AttackerInfrastructure]) -> str:
        """Generate OpenIOC XML."""

        # Root IOC element
        ioc = ET.Element('ioc', {
            'id': self.ioc_id,
            'last-modified': self._current_time,
            'xmlns': 'http://openioc.org/schemas/OpenIOC_1.1'
        })

        # Add metadata section
        self._add_metadata(ioc)

        # Add criteria section with all indicators
        self._add_criteria(ioc, malicious_asns, suspicious_prefixes, infrastructure)

        # Pretty print XML
        return self._pretty_xml(ioc)

    def _add_metadata(self, ioc: ET.Element) -> None:
        """Add metadata section to IOC."""
        metadata = ET.SubElement(ioc, 'metadata')

        metadata_fields = {
            'short_description': self.name,
            'description': 'IOCs extracted from BGP hijacking simulation scenarios',
            'authored_by': 'BGP Defence League',
            'authored_date': self._current_time
        }

        for tag, text in metadata_fields.items():
            ET.SubElement(metadata, tag).text = text

    def _add_criteria(self,
                      ioc: ET.Element,
                      malicious_asns: List[MaliciousASN],
                      suspicious_prefixes: List[SuspiciousPrefix],
                      infrastructure: List[AttackerInfrastructure]) -> None:
        """Add criteria section with all indicator items."""
        criteria = ET.SubElement(ioc, 'criteria')
        indicator_group = ET.SubElement(criteria, 'Indicator', {'operator': 'OR'})

        # Add ASN indicators
        for asn in malicious_asns:
            self._add_asn_indicator(indicator_group, asn)

        # Add prefix indicators
        for prefix in suspicious_prefixes:
            self._add_prefix_indicator(indicator_group, prefix)

        # Add infrastructure indicators
        for infra in infrastructure:
            self._add_infrastructure_indicator(indicator_group, infra)

    def _add_asn_indicator(self, parent: ET.Element, asn: MaliciousASN) -> None:
        """Add ASN indicator item."""
        asn_item = ET.SubElement(parent, 'IndicatorItem', {
            'id': str(uuid.uuid4()),
            'condition': 'is'
        })

        ET.SubElement(asn_item, 'Context', {
            'document': 'Network',
            'search': 'Network/ASN'
        })

        ET.SubElement(asn_item, 'Content', {'type': 'string'}).text = asn.asn

        attack_types = ', '.join(asn.attack_types) if asn.attack_types else "Unknown attack types"
        ET.SubElement(asn_item, 'Comment').text = f"Malicious ASN: {attack_types}"

    def _add_prefix_indicator(self, parent: ET.Element, prefix: SuspiciousPrefix) -> None:
        """Add prefix indicator item."""
        prefix_item = ET.SubElement(parent, 'IndicatorItem', {
            'id': str(uuid.uuid4()),
            'condition': 'is'
        })

        ET.SubElement(prefix_item, 'Context', {
            'document': 'Network',
            'search': 'Network/IPRange'
        })

        ET.SubElement(prefix_item, 'Content', {'type': 'IP'}).text = prefix.prefix

        comment = (f"Suspicious announcement from {prefix.origin_asn}, "
                   f"RPKI: {prefix.rpki_status}")
        ET.SubElement(prefix_item, 'Comment').text = comment

    def _add_infrastructure_indicator(self, parent: ET.Element, infra: AttackerInfrastructure) -> None:
        """Add infrastructure indicator item."""
        ip_item = ET.SubElement(parent, 'IndicatorItem', {
            'id': str(uuid.uuid4()),
            'condition': 'is'
        })

        ET.SubElement(ip_item, 'Context', {
            'document': 'Network',
            'search': 'Network/IP'
        })

        ET.SubElement(ip_item, 'Content', {'type': 'IP'}).text = infra.ip_address

        attacks = ', '.join(infra.associated_attacks[:2]) if infra.associated_attacks else "Unknown attacks"
        comment = f"{infra.infrastructure_type}: {attacks}"
        ET.SubElement(ip_item, 'Comment').text = comment

    def _pretty_xml(self, element: ET.Element) -> str:
        """Convert XML element to pretty-printed string."""
        rough_string = ET.tostring(element, 'utf-8')
        parsed = minidom.parseString(rough_string)
        return parsed.toprettyxml(indent="  ")

    def save_to_file(self, xml_content: str, filename: str) -> None:
        """Save OpenIOC to file."""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        print(f"OpenIOC saved to {filename}")


def main():
    """Example usage with proper log extraction."""

    # Create generator
    openioc_gen = OpenIOCGenerator(name="BGP Hijacking Campaign - Playbook 2")

    # Extract IOCs from scenarios (similar to STIX example)
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

    # Generate OpenIOC XML
    openioc_xml = openioc_gen.generate_ioc(malicious_asns, suspicious_prefixes, infrastructure)

    # Save to file
    openioc_gen.save_to_file(openioc_xml, 'bgp_hijacking.ioc')


if __name__ == "__main__":
    main()