from collections import defaultdict
from datetime import datetime, timedelta


class BGPAttackCorrelator:
    """
    A custom correlation engine for detecting BGP hijacking attempts.
    Inspired by the methodical approach of the Ankh-Morpork City Watch.
    """

    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_buffer = defaultdict(list)
        self.attack_patterns = []

    def parse_event(self, log_line: str) -> dict | None:
        """Parse a log line into structured event data."""
        import re

        # Example: <29>Jan 01 00:02:00 ARIN ROA creation request...
        pattern = r"<(\d+)>(\w+ \d+ \d+:\d+:\d+) (\S+) (.+)"
        match = re.match(pattern, log_line)

        if not match:
            return None

        priority, timestamp_str, source, message = match.groups()

        return {
            "priority": int(priority),
            "timestamp": datetime.strptime(
                f"2025 {timestamp_str}", "%Y %b %d %H:%M:%S"
            ),
            "source": source,
            "message": message,
            "is_fraudulent": "FRAUDULENT" in message,
            "event_type": self._classify_event(message),
        }

    def _classify_event(self, message: str) -> str:
        """Classify event type, rather like sorting evidence at Pseudopolis Yard."""
        if "login from" in message:
            return "suspicious_login"
        elif "ROA creation request" in message:
            return "roa_request"
        elif "ROA published" in message:
            return "roa_published"
        elif "Validator sync" in message:
            return "validator_sync"
        elif "BGP announcement" in message:
            return "bgp_announcement"
        elif "Validation test" in message:
            return "validation_test"
        return "unknown"

    def correlate_attack_chain(self, events: list[dict]) -> list[dict]:
        """
        Correlate events to detect attack chains.
        Returns a list of detected attack sequences.
        """
        attacks = []

        # Group events by prefix
        prefix_events = defaultdict(list)
        for event in sorted(events, key=lambda x: x["timestamp"]):
            prefix = self._extract_prefix(event["message"])
            if prefix:
                prefix_events[prefix].append(event)

        # Analyse each prefix for attack patterns
        for prefix, prefix_event_list in prefix_events.items():
            attack = self._detect_attack_sequence(prefix, prefix_event_list)
            if attack:
                attacks.append(attack)

        return attacks

    def _extract_prefix(self, message: str) -> str | None:
        """Extract IP prefix from message."""
        import re

        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", message)
        return match.group(1) if match else None

    def _detect_attack_sequence(
        self, prefix: str, events: list[dict]
    ) -> dict | None:
        """
        Detect if events form an attack sequence.
        The signs are there if one knows where to look, as Vimes would say.
        """
        sequence = {
            "suspicious_login": None,
            "roa_request": None,
            "roa_published": None,
            "validator_sync": [],
            "validation_test": [],
        }

        for event in events:
            event_type = event["event_type"]
            if event_type in sequence:
                if isinstance(sequence[event_type], list):
                    sequence[event_type].append(event)
                else:
                    sequence[event_type] = event

        # Check for attack indicators
        is_attack = False
        severity = "low"

        # Pattern 1: Fraudulent ROA request followed by publication
        if (
            sequence["roa_request"]
            and sequence["roa_request"]["is_fraudulent"]
            and sequence["roa_published"]
        ):
            is_attack = True
            severity = "high"

        # Pattern 2: Suspicious login before ROA request
        if (
            sequence["suspicious_login"]
            and sequence["roa_request"]
            and self._within_time_window(
                sequence["suspicious_login"]["timestamp"],
                sequence["roa_request"]["timestamp"],
                timedelta(minutes=5),
            )
        ):
            is_attack = True
            severity = "critical"

        # Pattern 3: Multiple validators accepting questionable ROA
        if len(sequence["validator_sync"]) >= 3:
            if is_attack:
                severity = "critical"
            else:
                is_attack = True
                severity = "medium"

        if not is_attack:
            return None

        return {
            "prefix": prefix,
            "severity": severity,
            "start_time": events[0]["timestamp"],
            "end_time": events[-1]["timestamp"],
            "duration_minutes": (
                events[-1]["timestamp"] - events[0]["timestamp"]
            ).total_seconds()
            / 60,
            "sequence": sequence,
            "event_count": len(events),
            "description": self._generate_attack_description(sequence, prefix),
        }

    def _within_time_window(
        self, time1: datetime, time2: datetime, window: timedelta
    ) -> bool:
        """Check if two times are within specified window."""
        return abs(time2 - time1) <= window

    def _generate_attack_description(self, sequence: dict, prefix: str) -> str:
        """Generate a human-readable description of the attack."""
        parts = [f"BGP hijacking attempt detected for prefix {prefix}."]

        if sequence["suspicious_login"]:
            parts.append("Suspicious login preceded ROA manipulation.")

        if sequence["roa_request"] and sequence["roa_request"]["is_fraudulent"]:
            parts.append("Fraudulent ROA creation request observed.")

        if sequence["roa_published"]:
            parts.append("Fraudulent ROA successfully published to repository.")

        validator_count = len(sequence["validator_sync"])
        if validator_count > 0:
            parts.append(
                f"{validator_count} validator(s) accepting the fraudulent ROA."
            )

        return " ".join(parts)


# Example usage with playbook2 scenario
if __name__ == "__main__":
    correlator = BGPAttackCorrelator(time_window_minutes=60)

    # Sample events from playbook2
    log_lines = [
        "Jan 01 00:01:00 tacacs-server admin@victim-network.net login from 185.220.101.45",
        "<29>Jan 01 00:02:00 ARIN ROA creation request: 203.0.113.0/24 origin AS64513 maxLength /25 by admin@victim-network.net via ARIN",
        "<10>Jan 01 00:02:00 edge-router-01 ROA creation request for 203.0.113.0/24 (origin AS64513, maxLength /25) - FRAUDULENT",
        "<10>Jan 01 00:04:00 edge-router-01 ROA creation accepted for 203.0.113.0/24 by ARIN - ATTACK SUCCEEDING",
        "<30>Jan 01 00:40:00 arin ROA published: 203.0.113.0/24 origin AS64513 in arin repository",
        "<30>Jan 01 00:45:00 routinator Validator sync: routinator sees 203.0.113.0/24 as valid",
        "<30>Jan 01 00:46:00 cloudflare Validator sync: cloudflare sees 203.0.113.0/24 as valid",
        "<30>Jan 01 00:47:00 ripe Validator sync: ripe sees 203.0.113.0/24 as valid",
    ]

    events = [correlator.parse_event(line) for line in log_lines]
    events = [e for e in events if e]  # Remove None values

    attacks = correlator.correlate_attack_chain(events)

    for attack in attacks:
        print(f"\n{'=' * 70}")
        print(f"ATTACK DETECTED - Severity: {attack['severity'].upper()}")
        print(f"{'=' * 70}")
        print(f"Prefix: {attack['prefix']}")
        print(f"Duration: {attack['duration_minutes']:.1f} minutes")
        print(f"Event count: {attack['event_count']}")
        print(f"\nDescription: {attack['description']}")
