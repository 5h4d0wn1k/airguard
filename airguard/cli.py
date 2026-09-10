"""airguard CLI — argparse subcommands.

Subcommands: frames, wids, survey, spectrum, rfhealth, report, demo.
All RF activity is simulation-only; no transmit path exists.  An optional
--sim gated path is provided for future lab use but requires --sim + an
explicit LAB allowlist and never transmits by default.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from airguard import __version__
from airguard.config import load_config
from airguard.frames import parse_pcap, parse_raw_frames
from airguard.rfhealth import assess_rf_health
from airguard.report import build_report
from airguard.spectrum import analyze_spectrum
from airguard.survey import run_survey
from airguard.wids import run_wids

FIXTURE_BASE = Path(__file__).parent / "fixtures"

# Paths to fixture files used by the demo (never anchored to user data)
_FIX = {
    "deauth1": FIXTURE_BASE / "deauth_flood" / "attack.bin",
    "deauth2": FIXTURE_BASE / "deauth_flood" / "attack2.bin",
    "evil_twin": FIXTURE_BASE / "evil_twin" / "attack.bin",
    "rogue": FIXTURE_BASE / "rogue_ap" / "attack.bin",
    "weak_survey": FIXTURE_BASE / "wpa3_survey" / "weak.bin",
    "strong_survey": FIXTURE_BASE / "wpa3_survey" / "survey.bin",
    "spectrum_jammer": FIXTURE_BASE / "spectrum" / "jammer.json",
    "spectrum_clean": FIXTURE_BASE / "spectrum" / "clean.json",
    "rf_clean": FIXTURE_BASE / "rfhealth" / "clean.json",
    "rf_congested": FIXTURE_BASE / "rfhealth" / "congested.json",
}


# ── I/O helpers ───────────────────────────────────────────────────────

def _load_frames(path: str | Path) -> List:
    """Load frames from a raw .bin (length-prefixed) or .pcap file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture not found: {path}")
    if path.suffix == ".pcap":
        return parse_pcap(path)
    return parse_raw_frames(path.read_bytes())


def _print_frame_summary(frames) -> None:
    counts: dict = {}
    for f in frames:
        counts[f.frame_type] = counts.get(f.frame_type, 0) + 1
    print("Frame summary:")
    for ftype, n in sorted(counts.items()):
        print(f"  {ftype}: {n}")
    beacons = [f for f in frames if f.frame_type == "beacon"]
    if beacons:
        print(f"\nBeacons ({len(beacons)}):")
        for f in beacons[:20]:
            rsn = f.rsn.akm_suites if f.rsn else []
            print(f"  {f.bssid} ch{f.channel} '{f.ssid}' rates={len(f.rates)} "
                  f"akm={rsn}")


# ── Subcommands ───────────────────────────────────────────────────────

def cmd_frames(args, cfg) -> int:
    frames = _load_frames(args.capture)
    _print_frame_summary(frames)
    print(f"\nParsed {len(frames)} frames from {args.capture}")
    return 0


def cmd_wids(args, cfg) -> int:
    for capture in args.captures:
        frames = _load_frames(capture)
        result = run_wids(frames, cfg)
        print(f"WIDS scan of {capture}: {result.count} detection(s)")
        for d in result.detections:
            print(f"  [{d.severity.upper()}] {d.title}")
            print(f"    {d.detail}")
        if args.json_out:
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json_out).write_text(json.dumps(
                {"detections": [d.as_dict() for d in result.detections]},
                indent=2) + "\n")
    return 0


def cmd_survey(args, cfg) -> int:
    frames = _load_frames(args.capture)
    result = run_survey(frames)
    print(f"WPA3 survey of {args.capture}")
    print(f"Overall posture: {result.overall_score}/100")
    for e in result.entries:
        print(f"  {e.bssid} '{e.ssid}' ch{e.channel}: "
              f"{e.security_mode} score={e.posture_score} "
              f"[{e.posture_label}]")
        for w in e.warnings:
            print(f"    warning: {w}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result.as_dict(), indent=2) + "\n")
    return 0


def cmd_spectrum(args, cfg) -> int:
    result = analyze_spectrum(
        args.series,
        jammer_threshold_dbm=cfg.get("spectrum", {}).get(
            "jammer_power_threshold_dbm", -30.0),
    )
    print(f"Spectrum analysis of {args.series}")
    print(f"  Jammer detected: {result.jammer_detected} "
          f"(channels: {result.jammer_channels or 'none'})")
    print(f"  Noise floor: {result.overall_noise_floor_dbm:.1f} dBm")
    for c in result.channels:
        jam = " JAMMED" if c.is_jammed else ""
        print(f"  ch{c.channel}: avg={c.avg_power_dbm:.1f} "
              f"noise={c.noise_floor_dbm:.1f} var={c.variance_dbm:.2f} "
              f"util={c.utilization_pct:.0f}%{jam}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result.as_dict(), indent=2) + "\n")
    return 0


def cmd_rfhealth(args, cfg) -> int:
    result = assess_rf_health(args.environment)
    print(f"RF health of {args.environment}")
    print(f"  Environment: {result.environment}")
    print(f"  Overall interference: {result.overall_interference:.1f}/100")
    print(f"  Recommended channel: {result.recommended_channel}")
    print(f"  {result.summary}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result.as_dict(), indent=2) + "\n")
    return 0


def cmd_report(args, cfg) -> int:
    """Aggregate: all captures → detections; optional survey/spectrum/rfhealth."""
    detections = []
    for capture in args.captures:
        result = run_wids(_load_frames(capture), cfg)
        detections.extend(result.detections)

    survey = rfhealth = spectrum = None
    if args.survey:
        survey = run_survey(_load_frames(args.survey))
    if args.spectrum:
        spectrum = analyze_spectrum(args.spectrum)
    if args.rfhealth:
        rfhealth = assess_rf_health(args.rfhealth)

    report = build_report(
        detections=detections,
        survey=survey,
        spectrum=spectrum,
        rfhealth=rfhealth,
        source=",".join(str(c) for c in args.captures),
        version=__version__,
    )

    json_out = Path(args.json_out)
    md_out = Path(args.md_out)
    report.write_json(json_out)
    report.write_markdown(md_out)

    print(f"Report written:")
    print(f"  JSON: {json_out}")
    print(f"  MD:   {md_out}")
    print(f"  Detections: {len(detections)} "
          f"(critical={report.critical_count}, high={report.high_count}, "
          f"medium={report.medium_count}, low={report.low_count})")
    if survey:
        print(f"  Survey posture: {survey.overall_score}/100")
    if spectrum:
        print(f"  Jammer: {spectrum.jammer_channels or 'none'}")
    return 0


def cmd_demo(args, cfg) -> int:
    """Offline demo — real proof on fixture data, exits 0, no live RF."""
    print("=" * 62)
    print("airguard demo — offline WIDS / WPA3 / spectrum / RF health")
    print(f"version {__version__} | simulation-only | 0 live RF")
    print("=" * 62)

    # 1) Frames: byte-exact parse proof
    frames = _load_frames(_FIX["deauth1"])
    _print_frame_summary(frames)
    print(f"\n[frames] parsed {len(frames)} frames (deauth flood fixture)")

    # 2) WIDS detections
    print("\n[wids] running detections...")
    wids_results = []
    deauth1 = run_wids(_load_frames(_FIX["deauth1"]), cfg)
    deauth2 = run_wids(_load_frames(_FIX["deauth2"]), cfg)
    evil = run_wids(_load_frames(_FIX["evil_twin"]), cfg)
    rogue = run_wids(_load_frames(_FIX["rogue"]), cfg)
    wids_results = [deauth1, deauth2, evil, rogue]

    all_detections = []
    for result in wids_results:
        all_detections.extend(result.detections)

    floods = [d for d in all_detections if d.category == "deauth-flood"]
    twins = [d for d in all_detections if d.category == "evil-twin"]
    rogues = [d for d in all_detections if d.category == "rogue-ap"]

    print(f"  deauth floods detected: {len(floods)}")
    for d in floods:
        print(f"    -> {d.detail}")
    print(f"  evil twins detected: {len(twins)}")
    for d in twins:
        print(f"    -> {d.title}")
    print(f"  rogue APs detected: {len(rogues)}")
    for d in rogues:
        print(f"    -> {d.detail}")

    # 3) WPA3 survey — posture 38 -> 97
    print("\n[survey] posture scoring...")
    weak = run_survey(_load_frames(_FIX["weak_survey"]))
    strong = run_survey(_load_frames(_FIX["strong_survey"]))
    best = max((e.posture_score for e in strong.entries), default=0)
    print(f"  weak/legacy environment posture: {weak.overall_score:.0f}/100")
    print(f"  WPA3-SAE environment posture:    {best}/100")

    # 4) Spectrum — jammer on ch 6
    print("\n[spectrum] jammer detection...")
    jam = analyze_spectrum(_FIX["spectrum_jammer"])
    clean = analyze_spectrum(_FIX["spectrum_clean"])
    print(f"  jammer fixture: detected={jam.jammer_detected} "
          f"channels={jam.jammer_channels or 'none'}")
    print(f"  clean fixture:  detected={clean.jammer_detected}")

    # 5) RF health
    print("\n[rfhealth] environment health...")
    rf_c = assess_rf_health(_FIX["rf_clean"])
    rf_x = assess_rf_health(_FIX["rf_congested"])
    print(f"  clean env:     interference={rf_c.overall_interference:.1f} "
          f"best ch={rf_c.recommended_channel}")
    print(f"  congested env: interference={rf_x.overall_interference:.1f} "
          f"best ch={rf_x.recommended_channel}")

    # 6) Aggregate report
    print("\n[report] writing aggregate report...")
    report = build_report(
        detections=all_detections,
        survey=weak,
        spectrum=jam,
        rfhealth=rf_c,
        source="demo (fixture data)",
        version=__version__,
    )
    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    jp = report.write_json(outdir / "demo_report.json")
    mp = report.write_markdown(outdir / "demo_report.md")
    print(f"  JSON: {jp}")
    print(f"  MD:   {mp}")
    print(f"  Detections in report: {len(all_detections)}")

    # 7) Proof assertions
    ok = True
    checks = [
        ("2+ deauth flood detections", len(floods) >= 2),
        ("1+ evil twin detection", len(twins) >= 1),
        ("1+ rogue AP on allowlist violation", len(rogues) >= 1),
        (f"posture 38 -> 97 (got {weak.overall_score:.0f} -> {best})",
         abs(weak.overall_score - 38.0) < 1.0 and best == 97),
        ("jammer detected on ch 6", 6 in jam.jammer_channels),
        ("no jammer on clean spectrum", not clean.jammer_detected),
        ("4 detections in report", len(all_detections) == 4),
        ("0 live RF (simulation only)", report.simulated_only),
    ]
    print("\n[proof]")
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}")
        ok = ok and passed

    print("\nDemo complete. Exit 0. No live RF transmission occurred.")
    return 0 if ok else 1


# ── sim gate (future-lab, simulation-only) ────────────────────────────

def cmd_sim(args, cfg) -> int:
    """Simulated RF action — gated. Never transmits.

    Any future RF-affecting action must pass through this gate:
    requires --sim AND --allow-all? No — requires --sim AND an entry in
    the configured laboratory allowlist.
    """
    cfg_wids = cfg.get("wids", {})
    allow_bssids = cfg_wids.get("allowlist_bssids", [])
    target = args.target

    if target not in allow_bssids:
        print(f"REFUSED: target {target} not in configured lab allowlist.",
              file=sys.stderr)
        return 1

    if not args.sim:
        print("REFUSED: --sim flag required for simulated RF action.",
              file=sys.stderr)
        return 1

    print(f"[sim] {args.action} on {target} — SIMULATION ONLY, no RF emitted.")
    return 0


# ── Argument parsing ──────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airguard",
        description="Wireless defense & monitoring suite (offline WIDS, "
                    "WPA3 survey, spectrum analysis, RF health). "
                    "Authorized-lab use only.",
        epilog="All analysis is offline. No live RF transmission code exists.",
    )
    parser.add_argument("--version", action="version",
                        version=f"airguard {__version__}")
    parser.add_argument("-c", "--config", default=None,
                        help="YAML/JSON config file")
    parser.add_argument("--sim", action="store_true",
                        help="Enable simulation mode (gated by lab allowlist)")
    parser.add_argument("--demo", action="store_true",
                        help="run the offline demo on fixture data then exit")

    sub = parser.add_subparsers(dest="command", title="subcommands")

    # frames
    p_frames = sub.add_parser("frames", help="parse 802.11 frames from a capture")
    p_frames.add_argument("capture", help="path to .bin (length-prefixed) or .pcap")
    p_frames.set_defaults(func=cmd_frames)

    # wids
    p_wids = sub.add_parser("wids", help="run WIDS detection on captures")
    p_wids.add_argument("captures", nargs="+", help="capture paths")
    p_wids.add_argument("--json-out", default="", help="write detections JSON")
    p_wids.set_defaults(func=cmd_wids)

    # survey
    p_survey = sub.add_parser("survey", help="run WPA3 survey on a capture")
    p_survey.add_argument("capture", help="capture path")
    p_survey.add_argument("--json-out", default="", help="write survey JSON")
    p_survey.set_defaults(func=cmd_survey)

    # spectrum
    p_spec = sub.add_parser("spectrum",
                            help="spectrum-analysis simulation on power series")
    p_spec.add_argument("series", help="JSON spectral power series fixture")
    p_spec.add_argument("--json-out", default="", help="write spectrum JSON")
    p_spec.set_defaults(func=cmd_spectrum)

    # rfhealth
    p_rf = sub.add_parser("rfhealth", help="RF health report for an environment")
    p_rf.add_argument("environment", help="JSON environment fixture")
    p_rf.add_argument("--json-out", default="", help="write RF health JSON")
    p_rf.set_defaults(func=cmd_rfhealth)

    # report
    p_rep = sub.add_parser("report", help="aggregate detections + findings")
    p_rep.add_argument("captures", nargs="+", help="capture paths for WIDS")
    p_rep.add_argument("--survey", default="", help="capture for WPA3 survey")
    p_rep.add_argument("--spectrum", default="", help="spectral series fixture")
    p_rep.add_argument("--rfhealth", default="", help="RF environment fixture")
    p_rep.add_argument("--json-out", default="report.json",
                       help="output JSON path")
    p_rep.add_argument("--md-out", default="report.md",
                       help="output Markdown path")
    p_rep.set_defaults(func=cmd_report)

    # demo
    p_demo = sub.add_parser("demo", help="offline demo on fixture data")
    p_demo.add_argument("--out-dir", default="reports", help="report output dir")
    p_demo.set_defaults(func=cmd_demo)

    # sim (simulation-only, gated)
    p_sim = sub.add_parser("sim",
                           help="simulated RF action (requires allowlist)")
    p_sim.add_argument("action", help="simulated action (log-only)")
    p_sim.add_argument("target", help="target BSSID from lab allowlist")
    p_sim.set_defaults(func=cmd_sim)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = load_config(args.config)

    if args.demo:
        args.out_dir = "reports"
        return cmd_demo(args, cfg)

    if not args.command:
        parser.print_help()
        return 0

    # Safety gate: dry-run default.  Only the sim subcommand can request
    # RF-affecting simulated behaviour, and it is refused without allowlist.
    if args.command == "sim" and not args.sim:
        print("REFUSED: simulation RF action requires --sim and a lab "
              "allowlist entry.", file=sys.stderr)
        return 1

    return args.func(args, cfg)


if __name__ == "__main__":
    sys.exit(main())