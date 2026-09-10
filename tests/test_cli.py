"""CLI tests — demo, subcommands, sim gate."""

import subprocess
import sys
import unittest

from airguard.cli import main


class TestCLI(unittest.TestCase):
    def test_version_flag(self):
        with self.assertRaises(SystemExit) as exc:
            main(["--version"])
        self.assertEqual(exc.exception.code, 0)

    def test_demo_exit_zero(self):
        code = main(["--demo"])
        self.assertEqual(code, 0)

    def test_no_command_prints_help(self):
        code = main([])
        self.assertEqual(code, 0)

    def test_frames_subcommand(self):
        code = main(["frames", "airguard/fixtures/clean/beacon.bin"])
        self.assertEqual(code, 0)

    def test_wids_subcommand(self):
        code = main(["wids", "airguard/fixtures/deauth_flood/attack.bin"])
        self.assertEqual(code, 0)

    def test_survey_subcommand(self):
        code = main(["survey", "airguard/fixtures/wpa3_survey/survey.bin"])
        self.assertEqual(code, 0)

    def test_spectrum_subcommand(self):
        code = main(["spectrum", "airguard/fixtures/spectrum/jammer.json"])
        self.assertEqual(code, 0)

    def test_rfhealth_subcommand(self):
        code = main(["rfhealth", "airguard/fixtures/rfhealth/clean.json"])
        self.assertEqual(code, 0)

    def test_report_subcommand(self):
        code = main([
            "report",
            "airguard/fixtures/deauth_flood/attack.bin",
            "--survey", "airguard/fixtures/wpa3_survey/survey.bin",
            "--spectrum", "airguard/fixtures/spectrum/jammer.json",
            "--json-out", "/tmp/opencode/cli_report.json",
            "--md-out", "/tmp/opencode/cli_report.md",
        ])
        self.assertEqual(code, 0)

    def test_sim_gate_refused_on_bare_sim(self):
        code = main(["sim", "anything", "00:11:22:33:44:55"])
        self.assertNotEqual(code, 0)


class TestCLISubprocess(unittest.TestCase):
    def test_demo_green_exit(self):
        result = subprocess.run(
            [sys.executable, "-m", "airguard", "--demo"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Demo complete. Exit 0.", result.stdout)

    def test_demo_never_transmits(self):
        result = subprocess.run(
            [sys.executable, "-m", "airguard", "--demo"],
            capture_output=True, text=True)
        self.assertIn("No live RF transmission occurred", result.stdout)


if __name__ == "__main__":
    unittest.main()