"""WIDS engine tests — attacks fire, clean stays clean."""

import unittest
from pathlib import Path

from airguard.fixtures.generate import (
    build_beacon, build_deauth, build_probe_req,
)
from airguard.frames import parse_raw_frames
from airguard.wids import (
    detect_deauth_flood, detect_evil_twin, detect_rogue_ap,
    detect_beacon_anomaly, detect_client_misassociation, run_wids,
)

FIX = Path("airguard/fixtures")


def _parse(rel: str):
    return parse_raw_frames((FIX / rel).read_bytes())


class TestDeauthFlood(unittest.TestCase):
    def test_flood_fires(self):
        dets = detect_deauth_flood(_parse("deauth_flood/attack.bin"),
                                   threshold=5)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].category, "deauth-flood")
        self.assertEqual(dets[0].severity, "critical")

    def test_flood_fires_second_bssid(self):
        dets = detect_deauth_flood(_parse("deauth_flood/attack2.bin"),
                                   threshold=5)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].bssid, "00:11:22:33:44:66")

    def test_under_threshold_no_fire(self):
        from airguard.frames import parse_frame
        frames = [parse_frame(build_deauth(
            "aa:bb:cc:dd:ee:99", "00:11:22:33:44:55",
            "00:11:22:33:44:55", reason=7, seq=i))
            for i in range(2)]
        dets = detect_deauth_flood(frames, threshold=5)
        self.assertEqual(dets, [])

    def test_no_fire_on_clean(self):
        dets = detect_deauth_flood(_parse("clean/set.bin"), threshold=5)
        self.assertEqual(dets, [])


class TestEvilTwin(unittest.TestCase):
    def test_same_ssid_diff_bssid(self):
        dets = detect_evil_twin(_parse("evil_twin/attack.bin"))
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].category, "evil-twin")
        self.assertEqual(dets[0].severity, "critical")

    def test_bssid_conflict(self):
        dets = detect_evil_twin(_parse("evil_twin/bssid_conflict.bin"))
        self.assertTrue(any("BSSID conflict" in d.title for d in dets))

    def test_no_fire_on_clean(self):
        dets = detect_evil_twin(_parse("clean/set.bin"))
        self.assertEqual(dets, [])

    def test_single_bssid_no_twin(self):
        from airguard.frames import parse_frame
        frames = [parse_frame(build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid="lab-office-1", channel=6)) for _ in range(3)]
        dets = detect_evil_twin(frames, min_beacons=2)
        self.assertEqual(dets, [])


class TestRogueAP(unittest.TestCase):
    def test_rogue_fires(self):
        dets = detect_rogue_ap(
            _parse("rogue_ap/attack.bin"),
            allowlist_ssids=["lab-corp-secure"])
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].category, "rogue-ap")
        self.assertEqual(dets[0].bssid, "aa:bb:cc:dd:ee:03")

    def test_no_rogue_when_not_allowlisted(self):
        frames = _parse("rogue_ap/attack.bin")
        dets = detect_rogue_ap(frames, allowlist_ssids=["lab-internal"])
        self.assertEqual(dets, [])

    def test_clean_not_flagged(self):
        # Clean set has no allowlisted (corporate/lab) SSID → no rogue AP
        dets = detect_rogue_ap(
            _parse("clean/set.bin"),
            allowlist_ssids=["lab-corp-secure"])
        self.assertEqual(dets, [])


class TestBeaconAnomaly(unittest.TestCase):
    def test_homoglyph_flagged(self):
        dets = detect_beacon_anomaly(_parse("beacon_anomaly/attack.bin"))
        homoglyph = [d for d in dets if "Homoglyph" in d.title]
        self.assertEqual(len(homoglyph), 1)
        self.assertIn("\u0430", homoglyph[0].title)  # Cyrillic a

    def test_zero_info_flagged(self):
        dets = detect_beacon_anomaly(_parse("beacon_anomaly/attack.bin"))
        zero = [d for d in dets if "Zero-info" in d.title]
        self.assertGreaterEqual(len(zero), 1)

    def test_channel_hopping_flagged(self):
        dets = detect_beacon_anomaly(_parse("beacon_anomaly/attack.bin"))
        hop = [d for d in dets if "Channel hopping" in d.title]
        self.assertEqual(len(hop), 1)

    def test_clean_no_anomaly(self):
        dets = detect_beacon_anomaly(_parse("clean/set.bin"))
        self.assertEqual(dets, [])


class TestClientMisassociation(unittest.TestCase):
    def test_probe_sweep_flagged(self):
        dets = detect_client_misassociation(
            _parse("beacon_anomaly/client_probes.bin"))
        sweep = [d for d in dets if "probe sweep" in d.title.lower()]
        self.assertGreaterEqual(len(sweep), 1)

    def test_clean_no_probe_issue(self):
        dets = detect_client_misassociation(_parse("clean/set.bin"))
        self.assertEqual(dets, [])


class TestWidsAggregate(unittest.TestCase):
    def test_clean_no_detections(self):
        result = run_wids(_parse("clean/set.bin"), {
            "wids": {"allowlist_ssids": ["lab-corp-secure"]},
            "beacon_anomaly": {},
        })
        self.assertEqual(result.count, 0)

    def test_attack_fixtures_fire(self):
        for rel, expected in [
            ("deauth_flood/attack.bin", 1),
            ("deauth_flood/attack2.bin", 1),
            ("evil_twin/attack.bin", 1),
            ("rogue_ap/attack.bin", 1),
            ("beacon_anomaly/attack.bin", 3),
        ]:
            result = run_wids(_parse(rel), {
                "wids": {"allowlist_ssids": ["lab-corp-secure"]},
                "beacon_anomaly": {},
            })
            self.assertEqual(result.count, expected, rel)

    def test_by_category(self):
        result = run_wids(_parse("deauth_flood/attack.bin"), {
            "beacon_anomaly": {},
        })
        self.assertEqual(len(result.by_category("deauth-flood")), 1)


if __name__ == "__main__":
    unittest.main()