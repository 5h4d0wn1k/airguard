"""RF health tests."""

import unittest

from airguard.rfhealth import assess_rf_health

FIX = "airguard/fixtures/rfhealth"


class TestRFHealthAnalysis(unittest.TestCase):
    def test_clean_low_interference(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        self.assertLess(result.overall_interference, 30.0)

    def test_congested_high_interference(self):
        result = assess_rf_health(f"{FIX}/congested.json")
        self.assertGreater(result.overall_interference, 60.0)

    def test_environment_name_clean(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        self.assertEqual(result.environment, "lab-clean")

    def test_environment_name_congested(self):
        result = assess_rf_health(f"{FIX}/congested.json")
        self.assertEqual(result.environment, "lab-congested")

    def test_recommended_channel_in_range(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        self.assertTrue(1 <= result.recommended_channel <= 180)

    def test_summary_present(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        self.assertTrue(result.summary)

    def test_clean_summary_low(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        self.assertIn("Clean", result.summary)

    def test_congested_summary_severe(self):
        result = assess_rf_health(f"{FIX}/congested.json")
        self.assertIn("Severe", result.summary)

    def test_as_dict(self):
        result = assess_rf_health(f"{FIX}/clean.json")
        d = result.as_dict()
        self.assertEqual(d["environment"], "lab-clean")
        self.assertIn("recommended_channel", d)


if __name__ == "__main__":
    unittest.main()