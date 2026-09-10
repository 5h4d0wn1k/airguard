"""Config loader tests."""

import json
import tempfile
import unittest
from pathlib import Path

from airguard.config import load_config, DEFAULTS


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_default_thresholds(self):
        cfg = load_config()
        self.assertEqual(cfg["wids"]["deauth_flood_threshold"], 5)
        self.assertEqual(cfg["airguard"]["mode"], "offline")

    def test_json_override(self):
        p = self.tmp / "cfg.json"
        p.write_text(json.dumps({
            "wids": {"deauth_flood_threshold": 12},
        }))
        cfg = load_config(p)
        self.assertEqual(cfg["wids"]["deauth_flood_threshold"], 12)

    def test_deep_keep_defaults_untouched(self):
        p = self.tmp / "cfg.json"
        p.write_text(json.dumps({"wids": {"deauth_flood_threshold": 9}}))
        cfg = load_config(p)
        self.assertEqual(cfg["wids"]["deauth_flood_window_sec"], 10.0)
        self.assertEqual(cfg["airguard"]["mode"], "offline")

    def test_missing_config_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_config(self.tmp / "nope.yaml")

    def test_defaults_have_allowlist(self):
        cfg = load_config()
        self.assertIn("lab-corp-secure", cfg["wids"]["allowlist_ssids"])

    def test_spectrum_defaults(self):
        cfg = load_config()
        self.assertEqual(cfg["spectrum"]["jammer_power_threshold_dbm"], -30.0)

    def test_yaml_subset_parser(self):
        from airguard.config import _parse_yaml_subset
        r = _parse_yaml_subset("""
wids:
  deauth_flood_threshold: 5
  allowlist_ssids:
    - lab-corp-secure
    - lab-internal
spectrum:
  jammer_power_threshold_dbm: -30.0
beacon_anomaly:
  channel_hop_threshold: 3
""")
        self.assertEqual(r["wids"]["deauth_flood_threshold"], 5)
        self.assertEqual(r["wids"]["allowlist_ssids"]["_seq"],
                         ["lab-corp-secure", "lab-internal"])
        self.assertEqual(r["spectrum"]["jammer_power_threshold_dbm"], -30.0)

    def test_load_yaml_without_pyyaml(self):
        """config.yaml must load via stdlib fallback when PyYAML absent."""
        from airguard.config import _HAS_YAML
        p = self.tmp / "cfg.yaml"
        p.write_text(
            "wids:\n  deauth_flood_threshold: 9\n"
            "  allowlist_ssids:\n    - lab-a\n    - lab-b\n")
        cfg = load_config(p)
        self.assertEqual(cfg["wids"]["deauth_flood_threshold"], 9)
        self.assertEqual(cfg["wids"]["allowlist_ssids"], ["lab-a", "lab-b"])

    def test_full_package_config_merges(self):
        cfg = load_config(Path("config.yaml"))
        self.assertEqual(cfg["wids"]["allowlist_ssids"],
                         ["lab-corp-secure", "lab-internal"])
        self.assertEqual(cfg["airguard"]["version"], "1.0.0")


if __name__ == "__main__":
    unittest.main()