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

from __future__ import annotations

import subprocess

from extracting_attacker_asns import MaliciousASN
from known_attacker_infra import AttackerInfrastructure
from suspicious_prefix_announcements import SuspiciousPrefix


class WazuhRuleUpdater:
    """Updates Wazuh rules with fresh IOCs from threat feeds."""

    def __init__(self, rules_file: str = "/var/ossec/etc/rules/bgp_iocs.xml"):
        self.rules_file = rules_file

    def generate_rule_file(
        self,
        malicious_asns: list[MaliciousASN],
        suspicious_prefixes: list[SuspiciousPrefix],
        infrastructure: list[AttackerInfrastructure],
    ) -> None:
        """Generate Wazuh rule file with IOC-based detection."""

        rules = ['<group name="bgp,threat_intel">']

        # ASN-based rules
        if malicious_asns:
            # Ensure asn values are strings for Wazuh regex
            asn_list = "|".join([str(asn.asn) for asn in malicious_asns])
            rules.append(
                f"""
  <rule id="100200" level="10">
    <decoded_as>bgp</decoded_as>
    <regex>AS({asn_list.replace("AS", "")})</regex>
    <description>BGP activity from known malicious ASN</description>
    <group>threat_intel,bgp_hijacking</group>
  </rule>"""
            )

        # Prefix-based rules (limit 50)
        for i, prefix in enumerate(suspicious_prefixes[:50], start=100300):
            # Escape dots in IPv4 prefix
            prefix_regex = prefix.prefix.replace(".", r"\.")
            rules.append(
                f"""
  <rule id="{i}" level="8">
    <decoded_as>bgp</decoded_as>
    <regex>{prefix_regex}</regex>
    <description>BGP announcement for known suspicious prefix: {prefix.prefix}</description>
    <group>threat_intel,suspicious_prefix</group>
  </rule>"""
            )

        # Infrastructure-based rules
        if infrastructure:
            ip_list = "|".join(
                [str(infra.ip_address).replace(".", r"\.") for infra in infrastructure]
            )
            rules.append(
                f"""
  <rule id="100400" level="12">
    <match>login from</match>
    <regex>({ip_list})</regex>
    <description>Login from known attacker infrastructure</description>
    <group>threat_intel,attacker_infrastructure</group>
  </rule>"""
            )

        rules.append("</group>")

        # Write to file
        with open(self.rules_file, "w", encoding="utf-8") as f:
            f.write("\n".join(rules))

        print(f"Wazuh rules updated: {self.rules_file}")
        print(
            f"Generated {len(rules) - 2} detection rules"
        )  # Exclude <group> and </group>

    @staticmethod
    def reload_wazuh() -> None:
        """Reload Wazuh to apply new rules."""
        try:
            subprocess.run(["/var/ossec/bin/wazuh-control", "restart"], check=True)
            print("Wazuh restarted successfully")
        except subprocess.CalledProcessError as e:
            print(f"Failed to restart Wazuh: {e}")


# Usage
# WazuhRuleUpdater.reload_wazuh()
