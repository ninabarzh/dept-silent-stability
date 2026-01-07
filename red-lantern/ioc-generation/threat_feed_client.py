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

import requests


class ThreatFeedClient:
    """Client for consuming threat feeds from the distribution API."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {"X-API-Key": api_key}

    def get_manifest(self) -> dict:
        """Retrieve feed manifest."""
        response = requests.get(
            f"{self.base_url}/api/v1/feeds/manifest", headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def download_latest_feed(self, feed_name: str, output_path: str) -> bool:
        """Download the latest version of a feed."""
        response = requests.get(
            f"{self.base_url}/api/v1/feeds/{feed_name}/latest",
            headers=self.headers,
            stream=True,
        )
        response.raise_for_status()

        # Ensure parent directory exists
        from pathlib import Path

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:  # filter out keep-alive chunks
                    f.write(chunk)

        print(f"Downloaded {feed_name} to {output_path}")
        return True

    def check_for_updates(self, feed_name: str, current_version: str) -> dict | None:
        """Check if a newer version of the feed is available."""
        response = requests.get(
            f"{self.base_url}/api/v1/feeds/{feed_name}/versions", headers=self.headers
        )
        response.raise_for_status()
        data = response.json()
        versions: list[dict] = data.get("versions", [])

        if not versions:
            return None

        latest = max(versions, key=lambda x: x["version"])
        if latest["version"] > current_version:
            return latest

        return None

    def auto_update_feeds(self, feed_configs: list[dict]) -> None:
        """
        Automatically update feeds based on configuration.
        Feed configs should contain: {feed_name, local_path, current_version}
        """
        print("Checking for feed updates...")

        for config in feed_configs:
            feed_name: str = config["feed_name"]
            local_path: str = config["local_path"]
            current_version: str = config.get("current_version", "0")

            update = self.check_for_updates(feed_name, current_version)

            if update:
                print(f"Update available for {feed_name}: {update['version']}")
                self.download_latest_feed(feed_name, local_path)
                config["current_version"] = update["version"]
                print(f"Updated {feed_name} to version {update['version']}")
            else:
                print(f"{feed_name} is up to date (version: {current_version})")


# ========================================
# Example: Automated feed consumption
# ========================================
if __name__ == "__main__":
    client = ThreatFeedClient(
        base_url="http://threat-feeds.example.com", api_key="your-api-key-here"
    )

    feed_configs: list[dict] = [
        {
            "feed_name": "bgp_hijacking_stix",
            "local_path": "/etc/threat_intel/bgp_stix.json",
            "current_version": "20250101120000",
        },
        {
            "feed_name": "bgp_hijacking_indicators",
            "local_path": "/etc/threat_intel/bgp_indicators.csv",
            "current_version": "20250101120000",
        },
    ]

    client.auto_update_feeds(feed_configs)

    manifest = client.get_manifest()
    print("\nAvailable feeds:")
    for feed in manifest.get("feeds", []):
        print(f"  - {feed['name']}: v{feed['latest_version']} ({feed['format']})")
