# airguard

Wireless defense & monitoring suite — WIDS sensor, deauth/evil-twin/rogue-AP
detection, beacon anomaly scan, spectrum-analysis simulation, WPA3 survey, RF
health reporting. Pure **byte-level offline** 802.11 analysis. **Defensive.**

- **Flag:** #22 · Wave 4 (BLUE) of a 24-tool portfolio
- **Version:** 1.0.0
- **Author:** 5h4d0wn1k
- **License:** MIT

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

## Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

## Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

## Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

## Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

## No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

## Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Capabilities

| Command | What it does |
| --- | --- |
| `airguard frames <capture>` | Byte-level 802.11 parser — beacon/probe/auth/deauth/assoc, SSID, BSSID, channel, rates, country, RSN elements (WPA2/WPA3/SAE/OWE), FCS-lite validation |
| `airguard wids <caps...>` | Deauth flood, evil twin (SSID/BSSID), rogue AP (allowlist), beacon anomalies (homoglyph/zero-info/channel-hop), client misassociation |
| `airguard survey <capture>` | WPA3 survey — RSN capability parse, WPA2/WPA3/OWE/transition detection, posture score per AP |
| `airguard spectrum <series>` | Spectrum-analysis sim — noise floor, channel utilization, constant-power jammer detection (fixtures only) |
| `airguard rfhealth <env>` | RF health report — interference score, channel contention, recommended channel |
| `airguard report <caps...>` | Aggregate detections + severity + timeline + remediation + RF health; JSON + Markdown |
| `airguard --demo` | Offline proof run over fixture data; exits 0; 0 live RF |

**No live radio transmit code exists in this repository.** Any hypothetical RF
action would require `--sim` **and** a LAB allowlist entry, and is refused otherwise.

## Quickstart

```bash
python3 -m pip install -e .
airguard --help
airguard --demo          # offline, exits 0, real proof on fixtures
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

*Run only inside your own laboratory — never against third-party networks.*

Document what to run and the expected proof output:

1. **Capture a beacon flood in your lab**
   - Run: `airguard frames lab/captures/beacons.pcap`
   - Expect: each AP listed with BSSID, SSID, channel, rates, RSN/AKM.
2. **WIDS on lab fixture / capture**
   - Run: `airguard wids captures/deauth_flood.pcap captures/evil_twin.pcap captures/rogue.pcap`
   - Expect: deauth-flood, evil-twin, rogue-ap detections with severity labels.
   - Add your known AP BSSIDs to `config.yaml` → `wids.allowlist_bssids` to cut
     false positives on your real corporate SSID.
3. **WPA3 posture sweep of your lab**
   - Run: `airguard survey captures/wpa3_sweep.pcap --json-out reports/survey.json`
   - Expect: per-AP posture score 0–100; weak PSK-only APs flagged; WPA3 transition
     mode listed explicitly.
4. **Spectrum sim on your lab's power series**
   - Run: `airguard spectrum captures/spectral_power.json`
   - Expect: noise floor, per-channel utilization, jammer flag on channels with a
     constant high-power pattern.
5. **RF planning**
   - Run: `airguard rfhealth environments/rf_floor.json`
   - Expect: interference score and a recommended channel; re-run after your AP
     move to confirm improvement.
6. **Aggregate**
   - Run: `airguard report caps... --survey ... --spectrum ... --rfhealth ... \
     --json-out reports/r.json --md-out reports/r.md`
   - Expect: JSON + Markdown with severity summary, remediations, timeline.

## Metrics

See [METRICS.md](METRICS.md) for measured values (tests, posture, detections,
procedure timings) — updated after each feature.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the DCO, house style, and test
requirements.

---

*Generated by airguard — authorized lab use only.*