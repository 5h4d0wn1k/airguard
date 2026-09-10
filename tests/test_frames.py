"""Frame parser tests — byte-exact 802.11 parsing."""

import struct
import unittest

from airguard.fixtures.generate import (
    build_auth, build_beacon, build_deauth, build_probe_req, build_assoc_req,
    WPA2_CCMP, WPA2_PSK, GCMP_128, WPA3_SAE, WPA3_OWE,
)
from airguard.frames import parse_frame, parse_raw_frames, parse_pcap


class TestBeaconParsing(unittest.TestCase):
    def setUp(self):
        self.raw = build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid="lab-office-1", channel=6, seq=42,
        )
        self.frame = parse_frame(self.raw)

    def test_frame_type_beacon(self):
        self.assertEqual(self.frame.frame_type, "beacon")

    def test_ssid_extracted(self):
        self.assertEqual(self.frame.ssid, "lab-office-1")

    def test_bssid_matches(self):
        self.assertEqual(self.frame.bssid, "00:11:22:33:44:55")

    def test_src_mac_matches(self):
        self.assertEqual(self.frame.src_mac, "00:11:22:33:44:55")

    def test_dst_is_broadcast(self):
        self.assertEqual(self.frame.dst_mac, "ff:ff:ff:ff:ff:ff")

    def test_channel_extracted(self):
        self.assertEqual(self.frame.channel, 6)

    def test_beacon_interval(self):
        self.assertEqual(self.frame.beacon_interval_tu, 100)

    def test_sequence_number(self):
        self.assertEqual(self.frame.sequence_number, 42)

    def test_rates_exact(self):
        expected = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0,
                    24.0, 36.0, 48.0, 54.0]
        self.assertEqual(self.frame.rates, expected)

    def test_country_extracted(self):
        self.assertEqual(self.frame.country, "US")


class TestRSNParsing(unittest.TestCase):
    def test_wpa2_akm(self):
        raw = build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid="lab-wpa2", channel=6,
            rsn_data=b"",  # replaced below by direct build
        )
        # Rebuild with real RSN tag
        from airguard.fixtures.generate import _tag_rsn
        rt = _radio = raw[:8]
        # Simpler: build beacon with RSN via fixture helper
        raw = build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid="lab-wpa2", channel=6,
            rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP], [WPA2_PSK]),
        )
        frame = parse_frame(raw)
        self.assertIsNotNone(frame.rsn)
        self.assertEqual(frame.rsn.akm_suites, ["WPA2-PSK"])
        self.assertEqual(frame.rsn.pairwise_ciphers, ["CCMP"])

    def test_wpa3_sae_akm(self):
        from airguard.fixtures.generate import _tag_rsn
        raw = build_beacon(
            src="00:11:22:33:44:60", bssid="00:11:22:33:44:60",
            ssid="lab-wpa3", channel=1,
            rsn_data=_tag_rsn(1, GCMP_128, [GCMP_128], [WPA3_SAE]),
        )
        frame = parse_frame(raw)
        self.assertEqual(frame.rsn.akm_suites, ["SAE"])

    def test_wpa3_owe_akm(self):
        from airguard.fixtures.generate import _tag_rsn
        raw = build_beacon(
            src="00:11:22:33:44:64", bssid="00:11:22:33:44:64",
            ssid="lab-owe", channel=44,
            rsn_data=_tag_rsn(1, GCMP_128, [GCMP_128], [WPA3_OWE]),
        )
        frame = parse_frame(raw)
        self.assertIn("OWE", frame.rsn.akm_suites)

    def test_no_rsn_returns_none(self):
        raw = build_beacon(
            src="00:11:22:33:44:65", bssid="00:11:22:33:44:65",
            ssid="lab-open", channel=36)
        frame = parse_frame(raw)
        self.assertIsNone(frame.rsn)

    def test_group_cipher_ccmp(self):
        from airguard.fixtures.generate import _tag_rsn
        raw = build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid="lab-wpa2", channel=6,
            rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP], [WPA2_PSK]),
        )
        frame = parse_frame(raw)
        self.assertEqual(frame.rsn.group_cipher, "CCMP")


class TestOtherFrameTypes(unittest.TestCase):
    def test_deauth_reason(self):
        raw = build_deauth("aa:bb:cc:dd:ee:99", "00:11:22:33:44:55",
                           "00:11:22:33:44:55", reason=7)
        frame = parse_frame(raw)
        self.assertEqual(frame.frame_type, "deauth")
        self.assertEqual(frame.deauth_reason, 7)
        self.assertIn("class3", frame.deauth_reason_text)

    def test_probe_request(self):
        raw = build_probe_req("02:00:00:00:00:01", "lab-office-1", 6)
        frame = parse_frame(raw)
        self.assertEqual(frame.frame_type, "probe-request")
        self.assertEqual(frame.ssid, "lab-office-1")

    def test_auth_frame(self):
        raw = build_auth("02:00:00:00:00:01", "00:11:22:33:44:55",
                         "00:11:22:33:44:55")
        frame = parse_frame(raw)
        self.assertEqual(frame.frame_type, "auth")

    def test_association_request(self):
        raw = build_assoc_req("02:00:00:00:00:01", "00:11:22:33:44:55",
                              "lab-office-1", 6)
        frame = parse_frame(raw)
        self.assertEqual(frame.frame_type, "association-request")
        self.assertEqual(frame.ssid, "lab-office-1")


class TestByteExactness(unittest.TestCase):
    def test_parser_matches_crafted_bytes(self):
        """Parsed fields must round-trip the exact crafted bytes."""
        ssid = "lab-byte-exact"
        raw = build_beacon(
            src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
            ssid=ssid, channel=11, seq=7,
        )
        frame = parse_frame(raw)
        self.assertEqual(frame.ssid, ssid)
        self.assertEqual(frame.channel, 11)
        self.assertEqual(frame.sequence_number, 7)
        # SSID tag must appear in the raw bytes verbatim
        self.assertIn(ssid.encode(), raw)


class TestErrorHandling(unittest.TestCase):
    def test_short_frame_raises(self):
        with self.assertRaises(ValueError):
            parse_frame(b"\x00\x00")

    def test_invalid_radiotap_length_raises(self):
        bad = b"\x00\x00" + struct.pack("<H", 9999) + b"\x00" * 30
        with self.assertRaises(ValueError):
            parse_frame(bad)


class TestContainerParsing(unittest.TestCase):
    def test_length_prefixed_raw_parse(self):
        from pathlib import Path
        data = Path("airguard/fixtures/clean/set.bin").read_bytes()
        frames = parse_raw_frames(data)
        types = {f.frame_type for f in frames}
        self.assertIn("beacon", types)
        self.assertIn("probe-request", types)

    def test_pcap_rejects_bad_magic(self):
        from pathlib import Path
        import tempfile, os
        tmp = Path(tempfile.mkdtemp())
        bad = tmp / "bad.pcap"
        bad.write_bytes(b"\x00" * 24)
        with self.assertRaises(ValueError):
            parse_pcap(bad)


if __name__ == "__main__":
    unittest.main()