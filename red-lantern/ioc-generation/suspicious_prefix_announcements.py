import re
from typing import Dict, List, Set
from datetime import datetime
from dataclasses import dataclass


@dataclass
class SuspiciousPrefix:
    """A prefix involved in questionable routing activities."""
    prefix: str
    origin_asn: str
    first_seen: datetime
    last_seen: datetime
    indicators: Set[str]
    rpki_status: str
    announcement_path: List[str]
    confidence: str
    evidence: List[str]

    def to_dict(self) -> Dict:
        return {
            'prefix': self.prefix,
            'origin_asn': self.origin_asn,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'indicators': list(self.indicators),
            'rpki_status': self.rpki_status,
            'announcement_path': self.announcement_path,
            'confidence': self.confidence,
            'evidence': self.evidence
        }


class PrefixIOCExtractor:
    """Extracts suspicious prefix announcements from scenarios."""

    def __init__(self):
        self.suspicious_prefixes: Dict[str, SuspiciousPrefix] = {}

    def extract_from_logs(self, log_lines: List[str]) -> List[SuspiciousPrefix]:
        """Extract suspicious prefix indicators."""
        for line in log_lines:
            self._process_log_line(line)

        return list(self.suspicious_prefixes.values())

    def _process_log_line(self, line: str):
        """Process a single log line for prefix indicators."""
        timestamp = self._extract_timestamp(line)

        # Pattern 1: BMP ROUTE announcements
        # BMP ROUTE: prefix 203.0.113.128/25 AS_PATH [65001, 64513] NEXT_HOP 198.51.100.254 ORIGIN_AS 64513
        if 'BMP ROUTE:' in line:
            match = re.search(
                r'prefix (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}).*AS_PATH \[([^]]+)].*ORIGIN_AS (\d+)',
                line
            )
            if match:
                prefix, as_path, origin_as = match.groups()
                self._add_or_update_prefix(
                    prefix=prefix,
                    origin_asn=f"AS{origin_as}",
                    timestamp=timestamp,
                    indicator='bmp_announcement',
                    rpki_status='unknown',
                    as_path=as_path.split(', '),
                    evidence=line
                )

        # Pattern 2: RPKI validation failures
        # <30>Jan 01 00:01:05 routinator RPKI validation: 203.0.113.0/24 origin AS65003 -> not_found (ROA not found)
        if 'RPKI validation:' in line and ('not_found' in line or 'invalid' in line):
            match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) origin AS(\d+) -> (\w+)',
                line
            )
            if match:
                prefix, origin_as, status = match.groups()
                self._add_or_update_prefix(
                    prefix=prefix,
                    origin_asn=f"AS{origin_as}",
                    timestamp=timestamp,
                    indicator='rpki_validation_failure',
                    rpki_status=status,
                    as_path=[],
                    evidence=line
                )

        # Pattern 3: Fraudulent ROA publication
        # <10>Jan 01 00:40:00 edge-router-01 FRAUDULENT ROA published for 203.0.113.0/24 in arin repository
        if 'FRAUDULENT ROA published' in line:
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
            if match:
                prefix = match.group(1)
                # Find the origin ASN from context
                asn_match = re.search(r'AS(\d+)', line)
                origin_asn = f"AS{asn_match.group(1)}" if asn_match else "unknown"

                self._add_or_update_prefix(
                    prefix=prefix,
                    origin_asn=origin_asn,
                    timestamp=timestamp,
                    indicator='fraudulent_roa',
                    rpki_status='fraudulent',
                    as_path=[],
                    evidence=line,
                    confidence='high'
                )

    def _add_or_update_prefix(self, prefix: str, origin_asn: str,
                              timestamp: datetime, indicator: str,
                              rpki_status: str, as_path: List[str],
                              evidence: str, confidence: str = 'medium'):
        """Add new or update existing suspicious prefix record."""
        key = f"{prefix}_{origin_asn}"

        if key not in self.suspicious_prefixes:
            self.suspicious_prefixes[key] = SuspiciousPrefix(
                prefix=prefix,
                origin_asn=origin_asn,
                first_seen=timestamp,
                last_seen=timestamp,
                indicators={indicator},
                rpki_status=rpki_status,
                announcement_path=as_path,
                confidence=confidence,
                evidence=[evidence]
            )
        else:
            record = self.suspicious_prefixes[key]
            record.last_seen = max(record.last_seen, timestamp)
            record.indicators.add(indicator)
            if rpki_status != 'unknown':
                record.rpki_status = rpki_status
            if as_path:
                record.announcement_path = as_path
            record.evidence.append(evidence)

            # Escalate confidence for multiple indicators
            if len(record.indicators) >= 2:
                record.confidence = 'high'

    @staticmethod
    def _extract_timestamp(line: str) -> datetime:
        """Extract timestamp from log line."""
        match = re.search(r'(\w+ \d+ \d+:\d+:\d+)', line)
        if match:
            return datetime.strptime(f"2025 {match.group(1)}", "%Y %b %d %H:%M:%S")
        return datetime.now()
