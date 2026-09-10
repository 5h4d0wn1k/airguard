"""Generate binary 802.11 fixtures for airguard tests.

Produces byte-exact management frames (beacon, deauth, probe, auth,
association) with tagged parameters (SSID, rates, RSN, country).
All data is lab-only: SSID lab-*, BSSID 00:11:22:33:44:55, RFC5737.
"""

from __future__ import annotations

import struct
from pathlib import Path

FIXTURES = Path(__file__).parent


# ── Low-level frame builders ──────────────────────────────────────────

def _radio_tap_header() -> bytes:
    """Minimal radiotap header (8 bytes, no present flags)."""
    return struct.pack("<BBHI", 0, 0, 8, 0)


def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _mgmt_hdr(subtype: int, src: str, dst: str, bssid: str, seq: int = 0) -> bytes:
    """Build a 24-byte 802.11 management header."""
    fc = 0x00 | (TYPE_MGMT << 2) | (subtype << 4)
    hdr = struct.pack("<H", fc)
    hdr += b"\x00\x00"  # Duration
    hdr += _mac_bytes(dst)  # addr1 receiver
    hdr += _mac_bytes(src)  # addr2 transmitter
    hdr += _mac_bytes(bssid)  # addr3 BSSID
    seq_ctrl = (seq & 0xFFF) << 4
    hdr += struct.pack("<H", seq_ctrl)
    return hdr


TYPE_MGMT = 0
SUBTYPE_BEACON = 8
SUBTYPE_PROBE_REQ = 4
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12
SUBTYPE_ASSOC_REQ = 0


# ── Tagged parameter builders ─────────────────────────────────────────

def _tag_ssid(ssid: str) -> bytes:
    data = ssid.encode("utf-8")
    return struct.pack("BB", 0, len(data)) + data


def _tag_supported_rates(rates: list[float]) -> bytes:
    data = bytes([int(r * 2) | 0x80 for r in rates[:-1]])
    data += bytes([int(rates[-1] * 2)])  # basic rate not set on last
    return struct.pack("BB", 1, len(data)) + data


def _tag_ds_param(channel: int) -> bytes:
    return struct.pack("BBB", 3, 1, channel)


def _tag_country(code: str, first_channel: int = 1, num_channels: int = 11) -> bytes:
    data = code.encode("ascii")[:2]
    data += bytes([first_channel, num_channels, 0])  # first, count, max power
    return struct.pack("BB", 7, len(data)) + data


def _tag_rsn(version: int, group_cipher: bytes, pairwise: list[bytes],
             akm: list[bytes], caps: int = 0) -> bytes:
    data = struct.pack("<H", version)
    data += group_cipher
    data += struct.pack("<H", len(pairwise))
    for c in pairwise:
        data += c
    data += struct.pack("<H", len(akm))
    for a in akm:
        data += a
    data += struct.pack("<H", caps)
    return struct.pack("BB", 48, len(data)) + data


# OUI+type selectors
WPA2_CCMP = b"\x00\x0f\xac\x02"
WPA2_TKIP = b"\x00\x0f\xac\x04"
WPA2_PSK = b"\x00\x0f\xac\x02"
WPA2_EAP = b"\x00\x0f\xac\x01"
WPA3_SAE = b"\x00\x0f\xac\x08"
WPA3_FT_SAE = b"\x00\x0f\xac\x08"  # AKM 8 = FT-SAE
WPA3_SAE_AKM = b"\x00\x0f\xac\x09"  # AKM 9 = SAE
WPA3_OWE = b"\x00\x0f\xac\x11"
WPA3_OWE_TRANS = b"\x00\x0f\xac\x12"
GCMP_128 = b"\x00\x0f\xac\x06"


def _tag_empty_ssid() -> bytes:
    return struct.pack("BB", 0, 0)


def _tag_hidden_ssid_zero() -> bytes:
    """SSID with length 0 — hidden/zero-length."""
    return struct.pack("BB", 0, 0)


def _frame_length(raw: bytes) -> bytes:
    """4-byte LE length prefix."""
    return struct.pack("<I", len(raw))


# ── Frame builders ────────────────────────────────────────────────────

def build_beacon(src: str, bssid: str, ssid: str, channel: int,
                 rates: list[float] | None = None, rsn_data: bytes | None = None,
                 country: str = "US", seq: int = 0, ts: int = 0) -> bytes:
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
    rt = _radio_tap_header()
    hdr = _mgmt_hdr(SUBTYPE_BEACON, src, "ff:ff:ff:ff:ff:ff", bssid, seq)
    body = struct.pack("<Q", ts)  # timestamp
    body += struct.pack("<H", 100)  # beacon interval TU
    body += struct.pack("<H", 0x0431)  # capability info (ESS + short-preamble + spectrum)
    body += _tag_ssid(ssid)
    if rates:
        body += _tag_supported_rates(rates)
    if channel:
        body += _tag_ds_param(channel)
    body += _tag_country(country)
    if rsn_data:
        body += rsn_data
    return rt + hdr + body


def build_deauth(src: str, dst: str, bssid: str, reason: int = 7,
                 seq: int = 0) -> bytes:
    rt = _radio_tap_header()
    hdr = _mgmt_hdr(SUBTYPE_DEAUTH, src, dst, bssid, seq)
    body = struct.pack("<H", reason)
    return rt + hdr + body


def build_probe_req(src: str, ssid: str, channel: int,
                    seq: int = 0) -> bytes:
    rt = _radio_tap_header()
    hdr = _mgmt_hdr(SUBTYPE_PROBE_REQ, src, "ff:ff:ff:ff:ff:ff",
                     "ff:ff:ff:ff:ff:ff", seq)
    body = _tag_ssid(ssid)
    body += _tag_supported_rates([1.0, 2.0, 5.5, 11.0])
    body += _tag_ds_param(channel)
    return rt + hdr + body


def build_auth(src: str, dst: str, bssid: str, seq: int = 0) -> bytes:
    rt = _radio_tap_header()
    hdr = _mgmt_hdr(SUBTYPE_AUTH, src, dst, bssid, seq)
    body = struct.pack("<HHI", 0, 1, 0)  # algo=0, seq=1, status=0
    return rt + hdr + body


def build_assoc_req(src: str, bssid: str, ssid: str, channel: int,
                    seq: int = 0) -> bytes:
    rt = _radio_tap_header()
    hdr = _mgmt_hdr(SUBTYPE_ASSOC_REQ, src, "ff:ff:ff:ff:ff:ff", bssid, seq)
    body = struct.pack("<H", 0x0431)  # capability
    body += struct.pack("<H", 10)  # listen interval
    body += _tag_ssid(ssid)
    body += _tag_supported_rates([1.0, 2.0, 5.5, 11.0])
    body += _tag_ds_param(channel)
    return rt + hdr + body


def _pack_frames(*frames: bytes) -> bytes:
    """Pack multiple frames with 4-byte LE length prefix each."""
    out = b""
    for f in frames:
        out += _frame_length(f) + f
    return out


# ── Fixture generators ────────────────────────────────────────────────

def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def gen_clean_beacon():
    """Single clean beacon — lab-office-1 on ch 6."""
    b = build_beacon(
        src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
        ssid="lab-office-1", channel=6,
        rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP], [WPA2_PSK]),
        seq=1,
    )
    _write(FIXTURES / "clean" / "beacon.bin", _pack_frames(b))


def gen_clean_set():
    """Set of clean beacons — no attacks."""
    frames = [
        build_beacon(src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
                     ssid="lab-office-1", channel=6, seq=i)
        for i in range(5)
    ]
    frames.append(build_beacon(src="aa:bb:cc:dd:ee:01", bssid="aa:bb:cc:dd:ee:01",
                               ssid="lab-guest", channel=1, seq=10))
    frames.append(build_probe_req(src="02:00:00:00:00:01", ssid="lab-office-1",
                                  channel=6, seq=20))
    _write(FIXTURES / "clean" / "set.bin", _pack_frames(*frames))


def gen_deauth_flood():
    """Deauth flood: 10 deauths from same src to same BSSID."""
    frames = []
    for i in range(10):
        frames.append(build_deauth(
            src="aa:bb:cc:dd:ee:99", dst="00:11:22:33:44:55",
            bssid="00:11:22:33:44:55", reason=7, seq=i,
        ))
    # Mix in normal traffic
    frames.append(build_beacon(src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
                               ssid="lab-office-1", channel=6, seq=50))
    _write(FIXTURES / "deauth_flood" / "attack.bin", _pack_frames(*frames))


def gen_evil_twin():
    """Two beacons with same SSID, different BSSIDs."""
    frames = [
        build_beacon(src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
                     ssid="lab-office-1", channel=6, seq=1),
        build_beacon(src="aa:bb:cc:dd:ee:02", bssid="aa:bb:cc:dd:ee:02",
                     ssid="lab-office-1", channel=6, seq=2),
    ]
    _write(FIXTURES / "evil_twin" / "attack.bin", _pack_frames(*frames))


def gen_evil_twin_bssid_conflict():
    """Same BSSID broadcasting different SSIDs."""
    frames = [
        build_beacon(src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
                     ssid="lab-office-1", channel=6, seq=1),
        build_beacon(src="00:11:22:33:44:55", bssid="00:11:22:33:44:55",
                     ssid="lab-evil", channel=6, seq=2),
    ]
    _write(FIXTURES / "evil_twin" / "bssid_conflict.bin", _pack_frames(*frames))


def gen_rogue_ap():
    """Unknown BSSID broadcasting lab-corp-secure (allowlisted SSID)."""
    frames = [
        build_beacon(src="aa:bb:cc:dd:ee:03", bssid="aa:bb:cc:dd:ee:03",
                     ssid="lab-corp-secure", channel=1, seq=1),
    ]
    _write(FIXTURES / "rogue_ap" / "attack.bin", _pack_frames(*frames))


def gen_beacon_anomaly():
    """Beacon anomalies: homoglyph SSID, zero-info beacon, channel hopping."""
    frames = [
        # Homoglyph SSID (looks like lab-office-1 but uses Cyrillic 'а')
        build_beacon(src="aa:bb:cc:dd:ee:10", bssid="aa:bb:cc:dd:ee:10",
                     ssid="l\u0430b-office-1", channel=6, seq=1),
        # Zero-info beacon (empty SSID, no rates, no channel)
        build_beacon(src="aa:bb:cc:dd:ee:11", bssid="aa:bb:cc:dd:ee:11",
                     ssid="", channel=0, rates=[], seq=2),
        # Same BSSID hopping channels rapidly
        build_beacon(src="aa:bb:cc:dd:ee:12", bssid="aa:bb:cc:dd:ee:12",
                     ssid="lab-hopper", channel=1, seq=3),
        build_beacon(src="aa:bb:cc:dd:ee:12", bssid="aa:bb:cc:dd:ee:12",
                     ssid="lab-hopper", channel=6, seq=4),
        build_beacon(src="aa:bb:cc:dd:ee:12", bssid="aa:bb:cc:dd:ee:12",
                     ssid="lab-hopper", channel=11, seq=5),
        build_beacon(src="aa:bb:cc:dd:ee:12", bssid="aa:bb:cc:dd:ee:12",
                     ssid="lab-hopper", channel=36, seq=6),
    ]
    _write(FIXTURES / "beacon_anomaly" / "attack.bin", _pack_frames(*frames))


def gen_wpa3_survey():
    """APs with various WPA configs for survey."""
    frames = [
        # WPA3-SAE only (strong)
        build_beacon(src="00:11:22:33:44:60", bssid="00:11:22:33:44:60",
                     ssid="lab-wpa3-only", channel=1, seq=1,
                     rsn_data=_tag_rsn(1, GCMP_128, [GCMP_128], [WPA3_SAE_AKM])),
        # WPA3-SAE transition mode (WPA2+WPA3)
        build_beacon(src="00:11:22:33:44:61", bssid="00:11:22:33:44:61",
                     ssid="lab-wpa3-transition", channel=6, seq=2,
                     rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP],
                                        [WPA2_PSK, WPA3_SAE_AKM])),
        # WPA2 only (moderate)
        build_beacon(src="00:11:22:33:44:62", bssid="00:11:22:33:44:62",
                     ssid="lab-wpa2-only", channel=11, seq=3,
                     rsn_data=_tag_rsn(1, WPA2_CCMP, [WPA2_CCMP], [WPA2_PSK])),
        # No RSN / open (weak)
        build_beacon(src="00:11:22:33:44:63", bssid="00:11:22:33:44:63",
                     ssid="lab-open", channel=36, seq=4),
        # WPA3-OWE
        build_beacon(src="00:11:22:33:44:64", bssid="00:11:22:33:44:64",
                     ssid="lab-owe", channel=44, seq=5,
                     rsn_data=_tag_rsn(1, GCMP_128, [GCMP_128], [WPA3_OWE])),
    ]
    _write(FIXTURES / "wpa3_survey" / "survey.bin", _pack_frames(*frames))


def gen_clean_spectrum():
    """Clean spectrum — no jammer, normal noise floor."""
    # Series of dBm readings per channel (2.4 GHz ch 1-11)
    # Normal: noise around -85 to -75 dBm, ch 6 slightly busy
    import json
    data = {
        "channels": {},
        "sample_rate_hz": 1000,
        "duration_sec": 10,
    }
    base_noise = {-88, -86, -84, -85, -83, -78, -82, -87, -85, -84, -86}
    for ch, noise in zip(range(1, 12), base_noise):
        data["channels"][str(ch)] = {
            "readings_dbm": [noise + i for i in range(5)],
        }
    _write(FIXTURES / "spectrum" / "clean.json",
           json.dumps(data, indent=2).encode())


def gen_jammer_spectrum():
    """Spectrum with planted jammer on channel 6 — constant high power."""
    import json
    data = {
        "channels": {},
        "sample_rate_hz": 1000,
        "duration_sec": 10,
    }
    for ch in range(1, 12):
        if ch == 6:
            # Jammer: constant high power -25 dBm
            data["channels"][str(ch)] = {
                "readings_dbm": [-25, -25, -25, -25, -25, -25, -25, -25],
            }
        else:
            data["channels"][str(ch)] = {
                "readings_dbm": [-85, -86, -84, -85, -83, -82, -87, -85],
            }
    _write(FIXTURES / "spectrum" / "jammer.json",
           json.dumps(data, indent=2).encode())


def gen_rfhealth_clean():
    """RF health fixture — clean environment."""
    import json
    data = {
        "environment": "lab-clean",
        "channels": {},
    }
    for ch in range(1, 12):
        data["channels"][str(ch)] = {
            "avg_power_dbm": -80 - (ch % 3),
            "client_count": 2 + (ch % 2),
            "utilization_pct": 10 + (ch % 5) * 3,
        }
    _write(FIXTURES / "rfhealth" / "clean.json",
           json.dumps(data, indent=2).encode())


def gen_rfhealth_congested():
    """RF health fixture — congested environment."""
    import json
    data = {
        "environment": "lab-congested",
        "channels": {},
    }
    for ch in range(1, 12):
        data["channels"][str(ch)] = {
            "avg_power_dbm": -50 + (ch % 4) * 5,
            "client_count": 5 + ch,
            "utilization_pct": 60 + ch * 3,
        }
    _write(FIXTURES / "rfhealth" / "congested.json",
           json.dumps(data, indent=2).encode())


def gen_client_misassoc():
    """Client probe-request leakage + sweeping."""
    frames = []
    # Client probing many channels
    for ch in range(1, 12):
        frames.append(build_probe_req(
            src="02:00:00:00:00:01", ssid="lab-office-1", channel=ch, seq=ch))
    # Client probing hidden SSID
    frames.append(build_probe_req(src="02:00:00:00:00:02", ssid="", channel=6, seq=20))
    _write(FIXTURES / "beacon_anomaly" / "client_probes.bin",
           _pack_frames(*frames))


def gen_all():
    """Generate all fixtures."""
    gen_clean_beacon()
    gen_clean_set()
    gen_deauth_flood()
    gen_evil_twin()
    gen_evil_twin_bssid_conflict()
    gen_rogue_ap()
    gen_beacon_anomaly()
    gen_wpa3_survey()
    gen_clean_spectrum()
    gen_jammer_spectrum()
    gen_rfhealth_clean()
    gen_rfhealth_congested()
    gen_client_misassoc()
    print("All fixtures generated.")


if __name__ == "__main__":
    gen_all()
