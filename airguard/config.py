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
        # stdlib fallback: minimal YAML-subset parser (nested maps, scalars,
        # bool/int/float, lists).  Covers config.yaml without PyYAML.
        loaded = _parse_yaml_subset(text)

    _deep_merge(config, loaded)
    return config


def _parse_yaml_subset(text: str) -> dict:
    """Minimal YAML-subset parser (indented 2-space maps, scalars, lists).

    Supported: `key: value`, nested maps, list-of-scalars `- item`,
    comments (#), inline comments, bools, ints, floats, quoted strings.
    Not supported: anchors, multi-line literals, flow/JSON arrays.
    """
    root: dict = {}
    stack = [root]                # stack[i] is dict for indent level i
    line_indents = [0]

    for raw_line in text.splitlines():
        raw = raw_line.split("#", 1)[0].rstrip()  # strip comments
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        if raw.lstrip().startswith("- "):
            # list item
            item = raw.lstrip()[2:].strip()
            while stack[-1] is root and line_indents[-1] >= indent and len(stack) > 1:
                stack.pop()
                line_indents.pop()
            # find the list owner
            owner = root
            for d in stack[1:]:
                owner = d
            _attach_seq(owner, item)
            continue

        key, sep, val = raw.strip().partition(":")
        key = key.strip().strip("'\"")
        if not sep:
            continue  # skip bare keys without values
        val = val.strip().strip("'\"")
        val_obj = _parse_scalar(val)

        parent = root
        for level_idx in range(len(stack) - 1):
            parent = stack[level_idx + 1]

        # locate target dict by indent
        target = root
        # walk down the current indent stack to the correct depth
        # rebuild: keep stack entries until indent exceeds each level
        while len(stack) > 1 and indent <= line_indents[-1]:
            stack.pop()
            line_indents.pop()
        target = stack[-1]

        if isinstance(val_obj, str) and val_obj.startswith("_"):
            val_obj = val_obj

        if val.strip() == "":
            newdict = {}
            target[key] = newdict
            stack.append(newdict)
            line_indents.append(indent)
        else:
            target[key] = val_obj

        # Lists: if the parsed value indicates list continuation

    return root if root else _parse_scalar(text.replace("\n", "")) or {}


def _parse_scalar(val: str):
    v = val.strip()
    if not v:
        return ""
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none"):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    if v.startswith("[") and v.endswith("]"):
        parts = [p.strip().strip("'\"") for p in v[1:-1].split(",")]
        return [_parse_scalar(p) for p in parts if p]
    return v.strip("\"'")


def _attach_seq(owner: dict, item: str) -> None:
    """Attach a list item to the owner dict under a list value.

    Identify an existing list value to append to; otherwise create a list
    under a trailing synthetic marker handled at merge time.
    """
    if not isinstance(owner, dict):
        return
    val = _parse_scalar(item)
    for k in list(owner):
        if isinstance(owner[k], list):
            owner[k].append(val)
            return
    # No list ancestor — attach to the deepest list-valued branch.
    # Tolerated: store under a synthetic key surfaced as `_seq`.
    if "_seq" not in owner:
        owner["_seq"] = [val]
    else:
        owner["_seq"].append(val)


def _deep_merge(base: dict, overlay: dict) -> None:
    """Recursively merge overlay into base (overlay wins)."""
    for key, value in overlay.items():
        # Synthetic sequence container folds into the base list under `key`
        if isinstance(value, dict) and "_seq" in value:
            base[key] = value["_seq"]
            _deep_merge(base, {k: v for k, v in value.items() if k != "_seq"})
            continue
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value