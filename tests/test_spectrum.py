"""Spectrum analysis tests."""

import unittest

from airguard.spectrum import analyze_spectrum

FIX = "airguard/fixtures/spectrum"


class TestJammerDetection(unittest.TestCase):
    def test_jammer_detected(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        self.assertTrue(result.jammer_detected)

    def test_jammer_on_ch6(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        self.assertEqual(result.jammer_channels, [6])

    def test_clean_no_jammer(self):
        result = analyze_spectrum(f"{FIX}/clean.json")
        self.assertFalse(result.jammer_detected)

    def test_all_jammed_channel_marked(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        ch6 = next(c for c in result.channels if c.channel == 6)
        self.assertTrue(ch6.is_jammed)
        other = next(c for c in result.channels if c.channel != 6)
        self.assertFalse(other.is_jammed)


class TestMetrics(unittest.TestCase):
    def test_noise_floor_negative(self):
        result = analyze_spectrum(f"{FIX}/clean.json")
        self.assertLess(result.overall_noise_floor_dbm, 0)

    def test_jammer_avg_power_high(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        ch6 = next(c for c in result.channels if c.channel == 6)
        self.assertGreaterEqual(ch6.avg_power_dbm, -30.0)

    def test_utilization_pct_range(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        for c in result.channels:
            self.assertTrue(0 <= c.utilization_pct <= 100)

    def test_as_dict(self):
        result = analyze_spectrum(f"{FIX}/jammer.json")
        d = result.as_dict()
        self.assertEqual(d["jammer_channels"], [6])
        self.assertTrue(d["jammer_detected"])


if __name__ == "__main__":
    unittest.main()