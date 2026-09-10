"""RF Health — interference score, channel contention, recommended channel.

Document-driven analysis of per-channel spectral/environment data:
interference score (0-100), channel contention, and the recommended
channel for the environment.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ChannelHealth:
    """Health assessment for one channel."""
    channel: int
    avg_power_dbm: float
    client_count: int
    utilization_pct: float
    interference_score: float
    contention_score: float

    def as_dict(self) -> dict:
        return {
            "channel": self.channel,
            "avg_power_dbm": self.avg_power_dbm,
            "client_count": self.client_count,
            "utilization_pct": self.utilization_pct,
            "interference_score": round(self.interference_score, 1),
            "contention_score": round(self.contention_score, 1),
        }


@dataclass
class RFHealthResult:
    """Aggregate RF health report."""
    environment: str = ""
    channels: List[ChannelHealth] = field(default_factory=list)
    overall_interference: float = 0.0
    recommended_channel: int = 0
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "environment": self.environment,
            "channels": [c.as_dict() for c in self.channels],
            "overall_interference": round(self.overall_interference, 1),
            "recommended_channel": self.recommended_channel,
            "summary": self.summary,
        }


def _load_env(path: str | Path) -> dict:
    path = Path(path)
    return json.loads(path.read_text())


def _interference_from_power(dbm: float) -> float:
    """Map avg power dBm to interference score 0-100.

    -100 dBm → 0 (quiet), -40 dBm → 80 (very noisy), -20 → 100
    """
    clamped = max(-100.0, min(-20.0, dbm))
    return (clamped + 100.0) / 80.0 * 100.0


def assess_rf_health(path: str | Path) -> RFHealthResult:
    """Assess RF health from an environment fixture (per-channel metrics).

    Interference score: weighted blend of absolute power and utilization.
    Contention score: clients relative to absorption of 5 GHz vs 2.4 GHz.
    Recommended channel: lowest interference score.
    """
    raw = _load_env(path)
    env = raw.get("environment", "unknown")
    chan_data: Dict[int, dict] = raw.get("channels", {})

    healths: List[ChannelHealth] = []

    for ch_str in sorted(chan_data, key=lambda s: int(s)):
        info = chan_data[ch_str]
        ch = int(ch_str)
        avg_p = float(info.get("avg_power_dbm", -90.0))
        clients = int(info.get("client_count", 0))
        util = float(info.get("utilization_pct", 0.0))

        power_score = _interference_from_power(avg_p)
        util_score = min(100.0, util / 85.0 * 100.0)
        # Interference: 60% power, 40% utilization
        interference = 0.6 * power_score + 0.4 * util_score

        # Contention: clients → heavier in 2.4 GHz (fewer channels, legacy)
        if ch < 14:
            contention = min(100.0, clients * 12.0)
        else:
            contention = min(100.0, clients * 5.0)

        healths.append(ChannelHealth(
            channel=ch,
            avg_power_dbm=avg_p,
            client_count=clients,
            utilization_pct=util,
            interference_score=interference,
            contention_score=contention,
        ))

    if not healths:
        raise ValueError(f"No channel data in {path}")

    overall = statistics.fmean(h.interference_score for h in healths)
    recommended = min(healths, key=lambda h: h.interference_score + h.contention_score)

    if overall < 30:
        summary = "Clean RF environment. Low interference."
    elif overall < 55:
        summary = "Moderate interference. Acceptable for normal operations."
    elif overall < 75:
        summary = "High interference. CSI mitigation recommended."
    else:
        summary = "Severe interference. Coexistence/jamming investigation advised."

    return RFHealthResult(
        environment=env,
        channels=healths,
        overall_interference=overall,
        recommended_channel=recommended.channel,
        summary=summary,
    )