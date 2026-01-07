import csv
from typing import List

from extracting_attacker_asns import MaliciousASN, ASNIOCExtractor
from suspicious_prefix_announcements import SuspiciousPrefix, PrefixIOCExtractor
from known_attacker_infra import AttackerInfrastructure, InfrastructureIOCExtractor


class CSVThreatFeedGenerator:
    """Generates CSV threat feeds suitable for ingestion by various systems."""

    @staticmethod
    def generate_asn_feed(malicious_asns: List[MaliciousASN], filename: str) -> None:
        """Generate CSV feed of malicious ASNs."""
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            # Header
            writer.writerow([
                'asn', 'first_seen', 'last_seen', 'attack_types',
                'associated_prefixes', 'confidence', 'evidence_count'
            ])

            # Data rows
            for asn in malicious_asns:
                writer.writerow([
                    asn.asn,
                    asn.first_seen.isoformat(),
                    asn.last_seen.isoformat(),
                    ';'.join(asn.attack_types) if asn.attack_types else '',
                    ';'.join(asn.associated_prefixes) if asn.associated_prefixes else '',
                    asn.confidence,
                    len(asn.evidence) if hasattr(asn, 'evidence') else 0
                ])

        print(f"ASN feed saved to {filename}")

    @staticmethod
    def generate_prefix_feed(suspicious_prefixes: List[SuspiciousPrefix], filename: str) -> None:
        """Generate CSV feed of suspicious prefixes."""
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            # Header
            writer.writerow([
                'prefix', 'origin_asn', 'first_seen', 'last_seen',
                'indicators', 'rpki_status', 'as_path', 'confidence'
            ])

            # Data rows
            for prefix in suspicious_prefixes:
                writer.writerow([
                    prefix.prefix,
                    prefix.origin_asn,
                    prefix.first_seen.isoformat(),
                    prefix.last_seen.isoformat(),
                    ';'.join(prefix.indicators) if prefix.indicators else '',
                    prefix.rpki_status,
                    ','.join(prefix.announcement_path) if hasattr(prefix, 'announcement_path') else '',
                    prefix.confidence
                ])

        print(f"Prefix feed saved to {filename}")

    @staticmethod
    def generate_infrastructure_feed(infrastructure: List[AttackerInfrastructure], filename: str) -> None:
        """Generate CSV feed of attacker infrastructure."""
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            # Header
            writer.writerow([
                'ip_address', 'infrastructure_type', 'first_seen', 'last_seen',
                'attack_count', 'country', 'asn', 'confidence'
            ])

            # Data rows
            for infra in infrastructure:
                geolocation = getattr(infra, 'geolocation', {})
                writer.writerow([
                    infra.ip_address,
                    infra.infrastructure_type,
                    infra.first_seen.isoformat(),
                    infra.last_seen.isoformat(),
                    len(infra.associated_attacks) if infra.associated_attacks else 0,
                    geolocation.get('country', 'Unknown') if isinstance(geolocation, dict) else 'Unknown',
                    geolocation.get('asn', 'Unknown') if isinstance(geolocation, dict) else 'Unknown',
                    infra.confidence
                ])

        print(f"Infrastructure feed saved to {filename}")

    @staticmethod
    def generate_combined_feed(malicious_asns: List[MaliciousASN],
                               suspicious_prefixes: List[SuspiciousPrefix],
                               infrastructure: List[AttackerInfrastructure],
                               filename: str) -> None:
        """Generate a combined CSV feed with all IOC types."""
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            # Header
            writer.writerow([
                'indicator_type', 'indicator_value', 'first_seen', 'last_seen',
                'confidence', 'context', 'tags'
            ])

            # ASN rows
            for asn in malicious_asns:
                associated_prefixes = list(asn.associated_prefixes) if hasattr(asn, 'associated_prefixes') else []
                writer.writerow([
                    'asn',
                    asn.asn,
                    asn.first_seen.isoformat(),
                    asn.last_seen.isoformat(),
                    asn.confidence,
                    f"Prefixes: {', '.join(associated_prefixes[:3])}" if associated_prefixes else "No associated prefixes",
                    ';'.join(asn.attack_types) if asn.attack_types else ''
                ])

            # Prefix rows
            for prefix in suspicious_prefixes:
                writer.writerow([
                    'prefix',
                    prefix.prefix,
                    prefix.first_seen.isoformat(),
                    prefix.last_seen.isoformat(),
                    prefix.confidence,
                    f"Origin: {prefix.origin_asn}, RPKI: {prefix.rpki_status}",
                    ';'.join(prefix.indicators) if prefix.indicators else ''
                ])

            # Infrastructure rows
            for infra in infrastructure:
                writer.writerow([
                    'ipv4',
                    infra.ip_address,
                    infra.first_seen.isoformat(),
                    infra.last_seen.isoformat(),
                    infra.confidence,
                    f"Type: {infra.infrastructure_type}",
                    f"attacks:{len(infra.associated_attacks)}" if infra.associated_attacks else "attacks:0"
                ])

        print(f"Combined feed saved to {filename}")


def main():
    """Example usage with proper log extraction."""

    # Extract IOCs from scenarios
    asn_extractor = ASNIOCExtractor()
    prefix_extractor = PrefixIOCExtractor()
    infra_extractor = InfrastructureIOCExtractor()

    # Process logs
    all_logs = [
        "Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45",
        "<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25",
        "<10>Jan 01 00:02:00 edge-router-01 ROA creation request for 203.0.113.0/24 (origin AS64513, maxLength /25) - FRAUDULENT",
    ]

    malicious_asns = asn_extractor.extract_from_logs(all_logs)
    suspicious_prefixes = prefix_extractor.extract_from_logs(all_logs)
    infrastructure = infra_extractor.extract_from_logs(all_logs)

    # Generate all CSV feeds
    CSVThreatFeedGenerator.generate_asn_feed(malicious_asns, 'malicious_asns.csv')
    CSVThreatFeedGenerator.generate_prefix_feed(suspicious_prefixes, 'suspicious_prefixes.csv')
    CSVThreatFeedGenerator.generate_infrastructure_feed(infrastructure, 'attacker_infrastructure.csv')
    CSVThreatFeedGenerator.generate_combined_feed(
        malicious_asns, suspicious_prefixes, infrastructure, 'bgp_iocs_combined.csv'
    )


if __name__ == "__main__":
    main()