from __future__ import annotations
import csv
import hashlib
import io
import json
from pathlib import Path
from datetime import datetime, timezone

# IOC extraction imports
from extracting_attacker_asns import ASNIOCExtractor
from suspicious_prefix_announcements import PrefixIOCExtractor
from known_attacker_infra import InfrastructureIOCExtractor

# Feed generators
from stix_2_format import STIXThreatFeedGenerator
from csv_format import CSVThreatFeedGenerator


class ThreatFeedManager:
    """Manages threat feed lifecycle including updates and distribution."""

    def __init__(self, feed_directory: str = '/var/threat_feeds'):
        self.feed_directory = Path(feed_directory)
        self.feed_directory.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.feed_directory / 'feed_metadata.json'
        self.metadata: dict[str, list[dict]] = self._load_metadata()

    def _load_metadata(self) -> dict[str, list[dict]]:
        """Load feed metadata."""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _save_metadata(self) -> None:
        """Save feed metadata."""
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)

    def _calculate_checksum(self, filepath: Path) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def publish_feed(
        self,
        feed_name: str,
        feed_content: str,
        feed_format: str,
        version: str = None
    ) -> dict:
        """
        Publish a new threat feed version.
        Returns metadata about the published feed.
        """
        if version is None:
            version = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')

        filename = f"{feed_name}_v{version}.{feed_format}"
        filepath = self.feed_directory / filename

        # Write feed content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(feed_content)

        # Calculate checksum
        checksum = self._calculate_checksum(filepath)

        feed_metadata = {
            'name': feed_name,
            'version': version,
            'format': feed_format,
            'filename': filename,
            'published_at': datetime.now(timezone.utc).isoformat(),
            'checksum_sha256': checksum,
            'size_bytes': filepath.stat().st_size
        }

        if feed_name not in self.metadata:
            self.metadata[feed_name] = []

        self.metadata[feed_name].append(feed_metadata)
        self._save_metadata()

        # Create "latest" symlink
        latest_link = self.feed_directory / f"{feed_name}_latest.{feed_format}"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(filename)

        print(f"Published feed: {filename}")
        print(f"Checksum: {checksum}")

        return feed_metadata

    def get_feed_updates(self, feed_name: str, since_version: str = None) -> list[dict]:
        """Get feed updates since specified version."""
        if feed_name not in self.metadata:
            return []

        versions = self.metadata[feed_name]

        if since_version is None:
            return versions

        return [v for v in versions if v['version'] > since_version]

    def verify_feed_integrity(self, feed_name: str, version: str) -> bool:
        """Verify feed integrity using checksum."""
        if feed_name not in self.metadata:
            return False

        version_info = next((v for v in self.metadata[feed_name] if v['version'] == version), None)
        if not version_info:
            return False

        filepath = self.feed_directory / version_info['filename']
        if not filepath.exists():
            return False

        current_checksum = self._calculate_checksum(filepath)
        return current_checksum == version_info['checksum_sha256']

    def cleanup_old_versions(self, feed_name: str, keep_latest: int = 5) -> None:
        """Remove old feed versions, keeping only the most recent."""
        if feed_name not in self.metadata:
            return

        versions = sorted(self.metadata[feed_name], key=lambda x: x['version'], reverse=True)

        for old_version in versions[keep_latest:]:
            filepath = self.feed_directory / old_version['filename']
            if filepath.exists():
                filepath.unlink()
                print(f"Removed old version: {old_version['filename']}")

        self.metadata[feed_name] = versions[:keep_latest]
        self._save_metadata()

    def generate_feed_manifest(self) -> dict:
        """Generate a manifest of all available feeds."""
        manifest = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'feeds': []
        }

        for feed_name, versions in self.metadata.items():
            if not versions:
                continue

            latest = max(versions, key=lambda x: x['version'])
            manifest['feeds'].append({
                'name': feed_name,
                'latest_version': latest['version'],
                'latest_published': latest['published_at'],
                'format': latest['format'],
                'download_url': f"/feeds/{latest['filename']}",
                'checksum_sha256': latest['checksum_sha256'],
                'total_versions': len(versions)
            })

        return manifest


# ========================================
# Example workflow
# ========================================
feed_manager = ThreatFeedManager()

# Extract IOCs from scenario logs
asn_extractor = ASNIOCExtractor()
prefix_extractor = PrefixIOCExtractor()
infra_extractor = InfrastructureIOCExtractor()

all_scenario_logs = [
    "<14>Jan 01 00:00:00 edge-router-01 BGP announcement observed: 203.0.113.0/24 origin AS65003",
    "<30>Jan 01 00:01:05 routinator RPKI validation: 203.0.113.0/24 origin AS65003 -> not_found",
    "Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45",
    "<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25",
    "<10>Jan 01 00:02:00 edge-router-01 ROA creation request for 203.0.113.0/24 (origin AS64513, maxLength /25) - FRAUDULENT",
    "<30>Jan 01 00:40:00 arin ROA published: 203.0.113.0/24 origin AS64513 in arin repository",
    "BMP ROUTE: prefix 203.0.113.128/25 AS_PATH [65001, 64513] NEXT_HOP 198.51.100.254 ORIGIN_AS 64513",
    "<14>Jan 01 00:01:00 edge-router-01 BGP announcement: 203.0.113.128/25 from AS64513, RPKI validation: valid",
    "<13>Jan 01 00:51:00 edge-router-01 Validation test AMER: Announcement 198.51.100.0/24 AS64514 - peer rejected",
]

malicious_asns = asn_extractor.extract_from_logs(all_scenario_logs)
suspicious_prefixes = prefix_extractor.extract_from_logs(all_scenario_logs)
infrastructure = infra_extractor.extract_from_logs(all_scenario_logs)

# Generate STIX feed
stix_gen = STIXThreatFeedGenerator()
stix_bundle = stix_gen.generate_bundle(malicious_asns, suspicious_prefixes, infrastructure)
stix_content = json.dumps(stix_bundle, indent=2)
feed_manager.publish_feed('bgp_hijacking_stix', stix_content, 'json')

# Generate CSV feed
csv_gen = CSVThreatFeedGenerator()
csv_buffer = io.StringIO()
writer = csv.writer(csv_buffer)
writer.writerow(['indicator_type', 'indicator_value', 'first_seen', 'confidence', 'tags'])
for asn in malicious_asns:
    writer.writerow(['asn', asn.asn, asn.first_seen.isoformat(), asn.confidence, ';'.join(asn.attack_types)])
for prefix in suspicious_prefixes:
    writer.writerow(['prefix', prefix.prefix, prefix.first_seen.isoformat(), prefix.confidence, ';'.join(prefix.indicators)])

csv_content = csv_buffer.getvalue()
feed_manager.publish_feed('bgp_hijacking_indicators', csv_content, 'csv')

# Feed manifest
manifest = feed_manager.generate_feed_manifest()
print("\n" + "="*70)
print("THREAT FEED MANIFEST")
print("="*70)
print(json.dumps(manifest, indent=2))

# Cleanup old versions
feed_manager.cleanup_old_versions('bgp_hijacking_stix', keep_latest=5)
feed_manager.cleanup_old_versions('bgp_hijacking_indicators', keep_latest=5)
