"""Resume/checkpoint support for interrupted scans."""

import hashlib
import json
import os

CHECKPOINT_FILE = ".corsbuster_checkpoint.json"


def _config_hash(config) -> str:
    """Hash the scan config so we can verify resume is for the same scan."""
    key = f"{sorted(t.url for t in config.targets)}:{config.threads}:{config.timeout}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def save_checkpoint(scanned_urls: list, config):
    """Save current progress to checkpoint file."""
    data = {
        "config_hash": _config_hash(config),
        "scanned_urls": list(scanned_urls),
    }
    try:
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump(data, f)
    except OSError:
        pass


def load_checkpoint(config) -> set:
    """Load checkpoint and return set of already-scanned URLs.

    Returns empty set if no checkpoint, or if config doesn't match.
    """
    if not os.path.exists(CHECKPOINT_FILE):
        return set()

    try:
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return set()

    # verify it's the same scan
    if data.get("config_hash") != _config_hash(config):
        return set()

    return set(data.get("scanned_urls", []))


def delete_checkpoint():
    """Remove checkpoint file after successful completion."""
    try:
        os.remove(CHECKPOINT_FILE)
    except OSError:
        pass
