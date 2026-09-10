"""WPA3 survey tests."""

import unittest
from pathlib import Path

from airguard.fixtures.generate import build_beacon, _tag_rsn, WPA2_CCMP, WPA2_PSK
from airguard.frames import parse_raw_frames
from airguard.survey import run_survey, survey_ap

FIX = Path("airguard/fixtures")


def _parse(rel: str):
    return parse_raw_frames((FIX / rel).read_bytes())


class TestSurveyClassification(unittest.TestCase):
    def test_wpa3_sae(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        sae = next(e for e in survey.entries if e.ssid == "lab-wpa3-only")
        self.assertEqual(sae.security_mode, "WPA3-SAE")
        self.assertEqual(sae.posture_score, 97)
        self.assertEqual(sae.posture_label, "strong")

    def test_transition_detected(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        trans = next(e for e in survey.entries
                     if e.ssid == "lab-wpa3-transition")
        self.assertEqual(trans.security_mode, "WPA3-TRANSITION")

    def test_wpa2_psk(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        wpa2 = next(e for e in survey.entries if e.ssid == "lab-wpa2-only")
        self.assertEqual(wpa2.security_mode, "WPA2-PSK")

    def test_open_flagged(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        open_ap = next(e for e in survey.entries if e.ssid == "lab-open")
        self.assertEqual(open_ap.security_mode, "OPEN")
        self.assertEqual(open_ap.posture_score, 10)
        self.assertEqual(open_ap.posture_label, "critical")
        self.assertTrue(any("No RSN" in w for w in open_ap.warnings))

    def test_owe_detected(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        owe = next(e for e in survey.entries if e.ssid == "lab-owe")
        self.assertEqual(owe.security_mode, "WPA3-OWE")

    def test_tkip_penalty(self):
        from airguard.frames import parse_frame
        raw = build_beacon(
            src="00:11:22:33:44:80", bssid="00:11:22:33:44:80",
            ssid="lab-tkip", channel=1,
            rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP, b"\x00\x0f\xac\x02"],
                              [WPA2_PSK]),
        )
        entry = survey_ap(parse_frame(raw))
        self.assertEqual(entry.posture_score, 25)
        self.assertTrue(any("TKIP" in w for w in entry.warnings))


class TestPostureDifferentiation(unittest.TestCase):
    def test_weak_strong_scores_differ(self):
        weak = run_survey(_parse("wpa3_survey/weak.bin"))
        strong = run_survey(_parse("wpa3_survey/survey.bin"))
        self.assertLess(weak.overall_score, strong.overall_score)

    def test_weak_is_38(self):
        weak = run_survey(_parse("wpa3_survey/weak.bin"))
        self.assertAlmostEqual(weak.overall_score, 38.0)

    def test_overall_score_bound(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        self.assertTrue(0 <= survey.overall_score <= 100)

    def test_survey_only_counts_distinct_bssids(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        bssids = [e.bssid for e in survey.entries]
        self.assertEqual(len(bssids), len(set(bssids)))

    def test_survey_as_dict(self):
        survey = run_survey(_parse("wpa3_survey/survey.bin"))
        d = survey.as_dict()
        self.assertEqual(len(d["entries"]), 5)
        self.assertIn("overall_score", d)


if __name__ == "__main__":
    unittest.main()