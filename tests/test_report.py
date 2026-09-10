"""Report generator tests."""

import json
import tempfile
import unittest
from pathlib import Path

from airguard.report import build_report
from airguard.wids import Detection


def _sample_detections():
    return [
        Detection("deauth-flood", "critical", "Flood test", "detail"),
        Detection("evil-twin", "critical", "Twin test", "detail"),
        Detection("rogue-ap", "high", "Rogue test", "detail"),
        Detection("beacon-anomaly", "medium", "Anomaly test", "detail"),
    ]


class TestReportStructure(unittest.TestCase):
    def setUp(self):
        self.report = build_report(_sample_detections(), version="1.0.0")

    def test_severity_counts(self):
        self.assertEqual(self.report.critical_count, 2)
        self.assertEqual(self.report.high_count, 1)
        self.assertEqual(self.report.medium_count, 1)
        self.assertEqual(self.report.low_count, 0)

    def test_total_detections(self):
        self.assertEqual(len(self.report.detections), 4)

    def test_symbols_safe(self):
        self.assertTrue(self.report.simulated_only)

    def test_version(self):
        self.assertEqual(self.report.version, "1.0.0")

    def test_timestamp_iso(self):
        self.assertIn("T", self.report.timestamp)

    def test_remediation_for_deauth(self):
        self.assertIn("deauth-flood", {
            d.category for d in self.report.detections})
        data = self.report.as_dict()
        self.assertIn("remediations", data)


class TestReportIO(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.report = build_report(_sample_detections())

    def test_json_valid(self):
        p = self.report.write_json(self.tmp / "r.json")
        parsed = json.loads(p.read_text())
        self.assertEqual(parsed["detection_summary"]["total"], 4)

    def test_json_has_detections(self):
        p = self.report.write_json(self.tmp / "r.json")
        parsed = json.loads(p.read_text())
        self.assertEqual(len(parsed["detections"]), 4)

    def test_markdown_well_formed(self):
        p = self.report.write_markdown(self.tmp / "r.md")
        text = p.read_text()
        self.assertIn("# airguard Wireless Defense Report", text)
        self.assertIn("## Detection Summary", text)
        self.assertIn("## Detections", text)

    def test_markdown_remediation(self):
        p = self.report.write_markdown(self.tmp / "r.md")
        self.assertIn("Remediation", p.read_text())

    def test_markdown_simulated_declared(self):
        p = self.report.write_markdown(self.tmp / "r.md")
        self.assertIn("Simulation only:** yes", p.read_text())


class TestOptionalSections(unittest.TestCase):
    def test_report_includes_survey_when_given(self):
        from airguard.survey import SurveyResult, APSurveyEntry
        survey = SurveyResult(
            entries=[APSurveyEntry(
                bssid="00:11:22:33:44:55", ssid="lab-wpa3",
                channel=6, security_mode="WPA3-SAE", akm_suites=["SAE"],
                pairwise_ciphers=["GCMP-128"], group_cipher="GCMP-128",
                posture_score=97, posture_label="strong",
            )],
            overall_score=97.0,
        )
        report = build_report([], survey=survey)
        data = report.as_dict()
        self.assertIn("survey", data)
        self.assertEqual(data["survey"]["overall_score"], 97.0)

    def test_report_includes_spectrum_when_given(self):
        from airguard.spectrum import SpectrumResult, ChannelAnalysis
        spectrum = SpectrumResult(
            channels=[ChannelAnalysis(
                channel=6, readings=[-25.0], avg_power_dbm=-25.0,
                noise_floor_dbm=-25.0, variance_dbm=0.0,
                peak_power_dbm=-25.0, utilization_pct=100.0,
                is_jammed=True, jammer_reason="constant",
            )],
            jammer_detected=True, jammer_channels=[6],
            overall_noise_floor_dbm=-90.0, mean_variance_dbm=0.0,
        )
        report = build_report([], spectrum=spectrum)
        data = report.as_dict()
        self.assertIn("spectrum", data)
        self.assertEqual(data["spectrum"]["jammer_channels"], [6])

    def test_report_includes_rfhealth_when_given(self):
        from airguard.rfhealth import RFHealthResult
        rf = RFHealthResult(
            environment="lab-clean",
            channels=[], overall_interference=20.0,
            recommended_channel=10, summary="Clean",
        )
        report = build_report([], rfhealth=rf)
        data = report.as_dict()
        self.assertIn("rfhealth", data)
        self.assertEqual(data["rfhealth"]["recommended_channel"], 10)


if __name__ == "__main__":
    unittest.main()