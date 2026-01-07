from __future__ import annotations
from typing import List
import csv
from datetime import datetime, timezone

from extracting_attacker_asns import MaliciousASN


class SplunkLookupUpdater:
    """Updates Splunk lookup tables with IOCs."""

    def __init__(self, lookup_dir: str = '/opt/splunk/etc/apps/bgp_defence/lookups'):
        self.lookup_dir = lookup_dir

    def update_malicious_asn_lookup(self, malicious_asns: List[MaliciousASN]) -> None:
        """Update malicious ASN lookup table."""
        lookup_file = f"{self.lookup_dir}/malicious_asns.csv"

        with open(lookup_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['asn', 'threat_level', 'attack_types', 'last_updated'])

            for asn in malicious_asns:
                threat_level = {
                    'high': '90',
                    'medium': '60',
                    'low': '30'
                }.get(getattr(asn, 'confidence', '').lower(), '50')

                attack_types = getattr(asn, 'attack_types', [])
                last_seen = getattr(asn, 'last_seen', None)
                if last_seen is None:
                    # timezone-aware UTC datetime
                    last_seen = datetime.now(timezone.utc)

                writer.writerow([
                    str(asn.asn).replace('AS', ''),
                    threat_level,
                    ','.join(attack_types) if attack_types else '',
                    last_seen.isoformat()
                ])

        print(f"Updated Splunk lookup: {lookup_file}")

    @staticmethod
    def generate_splunk_search() -> str:
        """Generate Splunk search using lookup tables."""
        return r'''
index=bgp sourcetype=rpki 
| rex field=_raw "AS(?<asn>\d+)"
| lookup malicious_asns.csv asn OUTPUT threat_level attack_types
| where isnotnull(threat_level)
| eval risk_score=threat_level
| stats count values(attack_types) as attack_types max(risk_score) as max_risk by asn
| where max_risk > 60
| sort -max_risk
'''
