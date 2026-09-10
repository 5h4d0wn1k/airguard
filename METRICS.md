# Metrics

Measured on a fresh `airguard` 1.0.0 build, offline (no live RF).

## Test coverage

| Metric | Value |
| --- | --- |
| Unit tests (`python -m unittest discover -s tests`) | **104** passing, 0 failures |
| Test modules | 8 (frames, wids, survey, spectrum, rfhealth, report, cli, config) |
| Suite wall time | ~5.4 s |

## Demo proof (`airguard --demo`, exit 0)

| Check | Result |
| --- | --- |
| Deauth flood detections | 2 (BSSID 00:11:22:33:44:55 · 10 frames; 00:11:22:33:44:66 · 12 frames) |
| Evil twin detections | 1 (SSID `lab-office-1` on 2 BSSIDs) |
| Rogue AP (allowlist violation) | 1 (BSSID aa:bb:cc:dd:ee:03 on `lab-corp-secure`) |
| Posture weak environment | 38/100 |
| Posture WPA3-SAE environment | 97/100 |
| Spectrum jammer | detected on channel 6; clean spectrum not flagged |
| Aggregate report detections | 4 (3 critical · 1 high) |
| Live RF | 0 |

> Report severity mix in demo: 2 deauth floods (critical) · 1 evil twin
> (critical) · 1 rogue AP (high) = 4 detections, JSON + Markdown artefacts
> written to `reports/`.

## Module accuracy (fixture ground truth)

| Module | Fixture truth | airguard result |
| --- | --- | --- |
| frames parser | crafted bytes (SSID, ch, rates, RSN) | round-trip exact |
| WIDS deauth flood (attack/clean) | fire / no-fire | fire / no false positive |
| WIDS evil twin (attack/clean) | fire / no-fire | fire / no false positive |
| WIDS rogue AP (attack/clean) | fire / no-fire | fire / no false positive |
| WIDS beacon anomaly | homoglyph·zero-info·channel-hop | 3 detections; clean → 0 |
| Survey weak vs strong | 38 vs 97 | 38.0 vs 97 |
| Spectrum jammer (ch 6) | planted -25 dBm constant | flagged, clean unflagged |
| RF health clean vs congested | interference | 21.6 vs 79.7, distinct channels |

## Engineering notes

- EOF: py_compile clean across all modules and tests.
- Demo guard rails: 8/8 proof checks PASS, exit code 0, "No live RF transmission
  occurred" asserted.
- No token-shaped literals in the tree (AKIA/xoxb/ghp_/sk_live/eyJ scan clean).
- Git history: feature-by-feature commits, signed-off, never pushed.