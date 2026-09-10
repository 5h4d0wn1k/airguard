"""WPA3 Survey — RSN capability analysis and posture scoring.

Parses RSN elements from beacons to determine WPA2/WPA3/OWE/transition
mode and computes a posture score per AP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from airguard.frames import ParsedFrame, RSNInfo


# ── Posture scoring constants ─────────────────────────────────────────

# Base scores for different security configurations
_SCORE_RSN_MAP = {
    "WPA3-SAE": 97,
    "WPA3-FT-SAE": 95,
    "WPA3-OWE": 90,
    "WPA3-TRANSITION": 75,   # WPA2+WPA3 mixed
    "WPA2-EAP": 65,
    "WPA2-PSK": 55,
    "WPA2-TKIP": 25,
    "OPEN": 10,
}


@dataclass
class APSurveyEntry:
    """Survey result for a single AP."""
    bssid: str
    ssid: str
    channel: int
    security_mode: str
    akm_suites: List[str]
    pairwise_ciphers: List[str]
    group_cipher: str
    posture_score: int
    posture_label: str
    rsn_raw: Optional[RSNInfo] = None
    warnings: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "security_mode": self.security_mode,
            "akm_suites": self.akm_suites,
            "pairwise_ciphers": self.pairwise_ciphers,
            "group_cipher": self.group_cipher,
            "posture_score": self.posture_score,
            "posture_label": self.posture_label,
            "warnings": self.warnings,
        }


@dataclass
class SurveyResult:
    """Aggregate WPA3 survey results."""
    entries: List[APSurveyEntry] = field(default_factory=list)
    overall_score: float = 0.0

    def as_dict(self) -> dict:
        return {
            "entries": [e.as_dict() for e in self.entries],
            "overall_score": self.overall_score,
        }


# ── Classification logic ──────────────────────────────────────────────

def _classify_security(rsn: Optional[RSNInfo]) -> str:
    """Determine security mode from RSN info."""
    if rsn is None or not rsn.akm_suites:
        return "OPEN"

    akm_set = set(rsn.akm_suites)

    # WPA3-only indicators
    if "SAE" in akm_set and "WPA2-PSK" not in akm_set and "WPA2-EAP" not in akm_set:
        if "FT-SAE" in akm_set:
            return "WPA3-FT-SAE"
        return "WPA3-SAE"

    if "OWE" in akm_set and "OWE-TRANSITION" not in akm_set:
        return "WPA3-OWE"

    # Transition modes (WPA2 + WPA3)
    if "SAE" in akm_set and ("WPA2-PSK" in akm_set or "WPA2-EAP" in akm_set):
        return "WPA3-TRANSITION"

    if "OWE-TRANSITION" in akm_set:
        return "WPA3-TRANSITION"

    # WPA2 only
    if "WPA2-EAP" in akm_set:
        return "WPA2-EAP"
    if "WPA2-PSK" in akm_set:
        return "WPA2-PSK"

    return "UNKNOWN"


def _score_posture(mode: str, pairwise: List[str], warnings: List[str]) -> int:
    """Compute posture score 0-100."""
    base = _SCORE_RSN_MAP.get(mode, 30)

    # Cipher penalties
    if "TKIP" in pairwise:
        base = min(base, 25)
        warnings.append("TKIP cipher detected — severely deprecated")

    # No RSN at all
    if mode == "OPEN":
        base = 10
        warnings.append("No RSN element — open network")

    return max(0, min(100, base))


def _posture_label(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 70:
        return "moderate"
    if score >= 50:
        return "weak"
    return "critical"


# ── Public API ────────────────────────────────────────────────────────

def survey_ap(frame: ParsedFrame) -> Optional[APSurveyEntry]:
    """Survey a single beacon frame for WPA3/security posture."""
    if frame.frame_type != "beacon":
        return None

    warnings: List[str] = []
    mode = _classify_security(frame.rsn)
    pairwise = frame.rsn.pairwise_ciphers if frame.rsn else []
    akm = frame.rsn.akm_suites if frame.rsn else []
    group = frame.rsn.group_cipher if frame.rsn else ""
    score = _score_posture(mode, pairwise, warnings)

    return APSurveyEntry(
        bssid=frame.bssid,
        ssid=frame.ssid,
        channel=frame.channel,
        security_mode=mode,
        akm_suites=akm,
        pairwise_ciphers=pairwise,
        group_cipher=group,
        posture_score=score,
        posture_label=_posture_label(score),
        rsn_raw=frame.rsn,
        warnings=warnings,
    )


def run_survey(frames: List[ParsedFrame]) -> SurveyResult:
    """Survey all beacon frames in a capture."""
    entries: List[APSurveyEntry] = []
    seen_bssids: set[str] = set()

    for f in frames:
        if f.frame_type == "beacon" and f.bssid not in seen_bssids:
            entry = survey_ap(f)
            if entry:
                entries.append(entry)
                seen_bssids.add(f.bssid)

    overall = 0.0
    if entries:
        overall = sum(e.posture_score for e in entries) / len(entries)

    return SurveyResult(entries=entries, overall_score=round(overall, 1))
