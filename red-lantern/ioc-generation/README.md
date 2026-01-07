# IOC generation

## Disclaimer

All code in this module that generates IOCs (Indicators of Compromise) is intended
solely for simulation and testing within the simulator environment. It is not
guaranteed to reflect real-world threat feeds or operational accuracy.

While the generated IOCs can be useful for learning, experimentation, and
getting started with real-world threat analysis, they should never be used as
the sole basis for production security decisions.

Use at your own risk. Always validate and supplement with trusted, real-world
sources when applying threat intelligence in operational environments.

## Code

- [Extracting attacker ASNs from playbook scenarios](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/extracting_attacker_asns.py)
- [Prefix announcements are the calling cards of BGP hijackers](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/suspicious_prefix_announcements.py) 
- [The infrastructure behind attacks](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/known_attacker_infra.py)
- [STIX (Structured Threat Information Expression) is rather like the official City Watch crime reports](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/stix_2_format.py)
- [OpenIOC is the more practical, working-class format](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/openioc_format.py)
- [CSV feeds are universally readable and splendidly practical](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/csv_format.py)
- [Wazuh updater](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/wazuh_updater.py)
- [Splunk lookup updater.py](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/splunk_lookup_updater.py)
- [Feed update system ](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/feed_update_system.py)
- [Feed distribution](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/feed_distribution_http_api.py)
- [Feed ingestion](https://github.com/ninabarzh/dept-silent-stability/blob/main/red-lantern/ioc-generation/threat_feed_client.py)

