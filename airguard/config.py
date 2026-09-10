"""Configuration loader — YAML or JSON, with stdlib fallback.

Accepts .yaml/.yml/.json files.  If PyYAML is unavailable, falls back to a
JSON subset for YAML files and warns.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

try:  # pragma: no cover - environment dependent
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False

DEFAULTS: Dict[str, Any] = {
    "airguard": {
        "version": "1.0.0",
        "mode": "offline",
    },
    "wids": {
        "deauth_flood_threshold": 5,
        "deauth_flood_window_sec": 10.0,
        "evil_twin_min_beacons": 2,
        "allowlist_ssids": ["lab-corp-secure", "lab-internal"],
        "allowlist_bssids": [],
    },
    "beacon_anomaly": {
        "homoglyph_ssid_flag": True,
        "zero_info_flag": True,
        "channel_hop_threshold": 3,
    },
    "spectrum": {
        "jammer_power_threshold_dbm": -30.0,
        "noise_floor_dbm": -90.0,
    },
    "survey": {
        "wpa3_indicators": ["SAE", "FT-SAE"],
        "weak_score_threshold": 50,
    },
    "rfhealth": {
        "interference_threshold_dbm": -40.0,
        "contention_min_clients": 3,
    },
}


def load_config(path: str | Path | None = None) -> dict:
    """Load config from a YAML/JSON file, merged over defaults."""
    config = json.loads(json.dumps(DEFAULTS))  # deep copy
    if path is None:
        # Look for config.yaml in cwd or package root
        for candidate in ("config.yaml", "config.yml", "config.json"):
            for base in (Path.cwd(), Path(__file__).parent.parent):
                p = base / candidate
                if p.is_file():
                    path = p
                    break
            if path is not None:
                break

    if path is None:
        return config

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config not found: {path}")

    text = path.read_text()
    loaded: dict = {}

    if path.suffix == ".json":
        loaded = json.loads(text)
    elif _HAS_YAML:
        loaded = _yaml.safe_load(text) or {}
    else:
        # Fallback: try JSON parse of YAML subset (flat keys accepted)
        loaded = json.loads(text)

    _deep_merge(config, loaded)
    return config


def _deep_merge(base: dict, overlay: dict) -> None:
    """Recursively merge overlay into base (overlay wins)."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value