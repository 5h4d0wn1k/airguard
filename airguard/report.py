"""Report — aggregate detections, survey, spectrum, RF health.

Produces JSON and Markdown reports with severity, timeline, remediations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from airguard.survey import SurveyResult
from airguard.spectrum import SpectrumResult
from airguard.rfhealth import RFHealthResult
from airguard.wids import Detection, WIDSResult


# ── Remediation guidance ──────────────────────────────────────────────

_REMEDIATIONS = {
    "deauth-flood": (
        "Enable 802.11w (PMF) management-frame protection; deploy "
        "WIDS sensor on wired+wireless aggregation; rate-limit deauth "
        "handling on APs; investigate source MAC hop."
    ),
    "evil-twin": (
        "Deploy 802.1X/EAP-TLS with server cert pinning; monitor for "
        "SSID duplication; use WPA3-SAE where possible; client-side "
        "policy to require EAP."
    ),
    "rogue-ap": (
        "Add BSSID to deny-list; run rogue-AP containment (wireless "
        "deauth is simulation-only here); audit physical ports; "
        "strengthen corporate SSID password policy."
    ),
    "beacon-anomaly": (
        "Validate SSID character sets; block confusable SSIDs at client "
        "policy; investigate zero-info beacons; monitor BSSID channel "
        "stability."
    ),
    "client-misassociation": (
        "Audit client configs for hidden-SSID probing; deploy targeted "
        "SSID allowlists; disable legacy probe behaviors; review probe "
        "privacy settings on endpoints."
    ),
}


@dataclass
class AggregateReport:
    """Full aggregate report for an analysis run."""
    version: str
    timestamp: str
    source: str = ""
    detections: List[Detection] = field(default_factory=list)
    survey: Optional[SurveyResult] = None
    spectrum: Optional[SpectrumResult] = None
    rfhealth: Optional[RFHealthResult] = None
    simulated_only: bool = True

    # ── Derived properties ──
    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == "low")

    # ── Serialization ──
    def as_dict(self) -> dict:
        data = {
            "airguard_version": self.version,
            "report_timestamp": self.timestamp,
            "source": self.source,
            "simulated_only": self.simulated_only,
            "detection_summary": {
                "total": len(self.detections),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "detections": [d.as_dict() for d in self.detections],
            "remediations": {
                cat: _REMEDIATIONS.get(cat, "Investigate and remediate.")
                for cat in {d.category for d in self.detections}
            },
        }
        if self.survey:
            data["survey"] = self.survey.as_dict()
        if self.spectrum:
            data["spectrum"] = self.spectrum.as_dict()
        if self.rfhealth:
            data["rfhealth"] = self.rfhealth.as_dict()
        return data

    # ── Writers ──
    def write_json(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2) + "\n")
        return path

    def write_markdown(self, path: str | Path) -> Path:
        """Write a human-readable Markdown report."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# airguard Wireless Defense Report",
            "",
            f"- **airguard version:** {self.version}",
            f"- **Report time:** {self.timestamp}",
            f"- **Source:** {self.source or 'n/a'}",
            f"- **Simulation only:** {'yes' if self.simulated_only else 'no'}",
            "",
            "## Detection Summary",
            "",
            f"| Severity | Count |",
            "| --- | --- |",
            f"| Critical | {self.critical_count} |",
            f"| High | {self.high_count} |",
            f"| Medium | {self.medium_count} |",
            f"| Low | {self.low_count} |",
            f"| **Total** | **{len(self.detections)}** |",
        ]

        if self.detections:
            lines += ["", "## Detections", ""]
            for i, d in enumerate(self.detections, 1):
                lines += [
                    f"### {i}. [{d.severity.upper()}] {d.title}",
                    "",
                    f"- **Category:** {d.category}",
                    f"- **BSSID:** {d.bssid or 'n/a'}",
                    f"- **Source MAC:** {d.src_mac or 'n/a'}",
                    "",
                    d.detail,
                    "",
                    f"**Remediation:** {_REMEDIATIONS.get(d.category, 'Investigate.')}",
                ]

        if self.survey:
            lines += ["", "## WPA3 Survey", ""]
            lines += [
                f"**Overall posture score:** {self.survey.overall_score}/100",
                "",
                "| AP | SSID | Channel | Mode | Score |",
                "| --- | --- | --- | --- | --- |",
            ]
            for e in self.survey.entries:
                lines.append(
                    f"| {e.bssid} | {e.ssid or '(hidden)'} | {e.channel} "
                    f"| {e.security_mode} | {e.posture_score} |"
                )

        if self.spectrum:
            lines += ["", "## Spectrum Analysis", ""]
            jam = ", ".join(str(c) for c in self.spectrum.jammer_channels) or "none"
            lines += [
                f"- **Noise floor:** {self.spectrum.overall_noise_floor_dbm:.1f} dBm",
                f"- **Jammer detected:** {self.spectrum.jammer_detected} "
                f"(channels: {jam})",
                "",
                "| Ch | Avg (dBm) | Noise floor | Util % | Jammed |",
                "| --- | --- | --- | --- | --- |",
            ]
            for c in self.spectrum.channels:
                lines.append(
                    f"| {c.channel} | {c.avg_power_dbm:.1f} | "
                    f"{c.noise_floor_dbm:.1f} | {c.utilization_pct:.0f} "
                    f"| {'YES' if c.is_jammed else ''} |"
                )

        if self.rfhealth:
            lines += ["", "## RF Health", ""]
            lines += [
                f"- **Environment:** {self.rfhealth.environment}",
                f"- **Overall interference:** "
                f"{self.rfhealth.overall_interference:.1f}/100",
                f"- **Recommended channel:** {self.rfhealth.recommended_channel}",
                f"- **Summary:** {self.rfhealth.summary}",
            ]

        lines += ["", "---", "Generated by airguard — authorized lab use only."]

        path.write_text("\n".join(lines) + "\n")
        return path


def build_report(detections: List[Detection],
                 survey: Optional[SurveyResult] = None,
                 spectrum: Optional[SpectrumResult] = None,
                 rfhealth: Optional[RFHealthResult] = None,
                 source: str = "",
                 simulated_only: bool = True,
                 version: str = "1.0.0") -> AggregateReport:
    """Assemble an aggregate report from all module outputs."""
    return AggregateReport(
        version=version,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source=source,
        detections=detections,
        survey=survey,
        spectrum=spectrum,
        rfhealth=rfhealth,
        simulated_only=simulated_only,
    )