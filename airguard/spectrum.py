"""Spectrum analysis simulation — offline analysis of spectral power series.

Parses fixture spectral-power series (dBm per channel over time) to compute
noise floor, channel utilization, and detect constant-power jammer patterns.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ChannelAnalysis:
    """Analysis of one channel's spectral power series."""
    channel: int
    readings: List[float]
    avg_power_dbm: float
    noise_floor_dbm: float
    variance_dbm: float
    peak_power_dbm: float
    utilization_pct: float
    is_jammed: bool = False
    jammer_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "channel": self.channel,
            "avg_power_dbm": round(self.avg_power_dbm, 1),
            "noise_floor_dbm": round(self.noise_floor_dbm, 1),
            "variance_dbm": round(self.variance_dbm, 2),
            "peak_power_dbm": round(self.peak_power_dbm, 1),
            "utilization_pct": round(self.utilization_pct, 1),
            "is_jammed": self.is_jammed,
            "jammer_reason": self.jammer_reason,
        }


@dataclass
class SpectrumResult:
    """Aggregate spectrum-analysis result."""
    channels: List[ChannelAnalysis] = field(default_factory=list)
    overall_noise_floor_dbm: float = 0.0
    jammer_detected: bool = False
    jammer_channels: List[int] = field(default_factory=list)
    mean_variance_dbm: float = 0.0

    def as_dict(self) -> dict:
        return {
            "channels": [c.as_dict() for c in self.channels],
            "overall_noise_floor_dbm": round(self.overall_noise_floor_dbm, 1),
            "jammer_detected": self.jammer_detected,
            "jammer_channels": self.jammer_channels,
            "mean_variance_dbm": round(self.mean_variance_dbm, 2),
        }


def _load_series(path: str | Path) -> Dict[int, List[float]]:
    """Load spectral power series from JSON fixture."""
    path = Path(path)
    raw = json.loads(path.read_text())
    channels: Dict[int, List[float]] = {}
    for ch_str, info in raw.get("channels", {}).items():
        ch = int(ch_str)
        readings = [float(v) for v in info.get("readings_dbm", [])]
        if readings:
            channels[ch] = readings
    if not channels:
        raise ValueError(f"No channel data in {path}")
    return channels


def analyze_spectrum(path: str | Path,
                     jammer_threshold_dbm: float = -30.0) -> SpectrumResult:
    """Analyze spectral-power series for noise floor, utilization, jammer.

    Jammer detection (simulation): a channel with sustained high avg power
    AND very low variance (constant high-power pattern) is flagged.
    """
    channels = _load_series(path)

    result = SpectrumResult()
    all_noise: List[float] = []
    all_variances: List[float] = []

    for ch in sorted(channels):
        readings = channels[ch]
        avg = statistics.fmean(readings)
        noise_floor = min(readings)
        variance = statistics.pstdev(readings)
        peak = max(readings)

        # Utilization: fraction of readings above noise floor + 10 dB
        ref = noise_floor + 10
        utilization = 100.0 * sum(1 for r in readings if r >= ref) / len(readings)

        chan = ChannelAnalysis(
            channel=ch,
            readings=readings,
            avg_power_dbm=avg,
            noise_floor_dbm=noise_floor,
            variance_dbm=variance,
            peak_power_dbm=peak,
            utilization_pct=utilization,
        )

        # Jammer: constant high power (high avg, very low variance)
        if avg >= jammer_threshold_dbm and variance <= 1.5 and peak - noise_floor <= 3:
            chan.is_jammed = True
            chan.jammer_reason = (
                f"sustained power {avg:.1f} dBm (>= {jammer_threshold_dbm} dBm) "
                f"with variance {variance:.2f} dB — constant-power pattern"
            )

        result.channels.append(chan)
        all_noise.append(noise_floor)
        all_variances.append(variance)

    if all_noise:
        result.overall_noise_floor_dbm = statistics.fmean(all_noise)
    if all_variances:
        result.mean_variance_dbm = statistics.fmean(all_variances)

    result.jammer_channels = [c.channel for c in result.channels if c.is_jammed]
    result.jammer_detected = bool(result.jammer_channels)
    return result