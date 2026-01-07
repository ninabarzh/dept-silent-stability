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

from functools import wraps
from pathlib import Path

from feed_update_system import ThreatFeedManager
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
feed_manager = ThreatFeedManager()


def require_api_key(f):
    """Decorator to require API key authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != "your-secret-api-key":
            return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)

    return decorated_function


@app.route("/api/v1/feeds/manifest", methods=["GET"])
@require_api_key
def get_manifest():
    """Get manifest of all available feeds."""
    manifest: dict = feed_manager.generate_feed_manifest()
    return jsonify(manifest)


@app.route("/api/v1/feeds/<feed_name>/latest", methods=["GET"])
@require_api_key
def get_latest_feed(feed_name: str):
    """Download the latest version of a feed."""
    if feed_name not in feed_manager.metadata or not feed_manager.metadata[feed_name]:
        return jsonify({"error": "Feed not found"}), 404

    latest: dict = max(feed_manager.metadata[feed_name], key=lambda x: x["version"])
    filepath: Path = feed_manager.feed_directory / latest["filename"]

    if not filepath.exists():
        return jsonify({"error": "Feed file not found"}), 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/v1/feeds/<feed_name>/versions", methods=["GET"])
@require_api_key
def get_feed_versions(feed_name: str):
    """List all versions of a feed."""
    if feed_name not in feed_manager.metadata or not feed_manager.metadata[feed_name]:
        return jsonify({"error": "Feed not found"}), 404

    return jsonify(
        {"feed_name": feed_name, "versions": feed_manager.metadata[feed_name]}
    )


@app.route("/api/v1/feeds/<feed_name>/version/<version>", methods=["GET"])
@require_api_key
def get_feed_version(feed_name: str, version: str):
    """Download a specific version of a feed."""
    if feed_name not in feed_manager.metadata or not feed_manager.metadata[feed_name]:
        return jsonify({"error": "Feed not found"}), 404

    version_info: dict | None = next(
        (v for v in feed_manager.metadata[feed_name] if v["version"] == version), None
    )

    if not version_info:
        return jsonify({"error": "Version not found"}), 404

    filepath: Path = feed_manager.feed_directory / version_info["filename"]
    if not filepath.exists():
        return jsonify({"error": "Feed file not found"}), 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/v1/feeds/<feed_name>/verify/<version>", methods=["GET"])
@require_api_key
def verify_feed(feed_name: str, version: str):
    """Verify the integrity of a feed version."""
    is_valid: bool = feed_manager.verify_feed_integrity(feed_name, version)
    return jsonify(
        {"feed_name": feed_name, "version": version, "integrity_valid": is_valid}
    )


if __name__ == "__main__":
    print("Starting BGP Threat Feed Distribution API...")
    print("Available endpoints:")
    print("  GET /api/v1/feeds/manifest")
    print("  GET /api/v1/feeds/<feed_name>/latest")
    print("  GET /api/v1/feeds/<feed_name>/versions")
    print("  GET /api/v1/feeds/<feed_name>/version/<version>")
    print("  GET /api/v1/feeds/<feed_name>/verify/<version>")
    app.run(host="0.0.0.0", port=5000)
