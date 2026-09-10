"""802.11 frame parser — pure byte-level analysis.

Parses beacon, probe, auth, deauth, association frames from raw bytes
(radio-tap + 802.11 header + body).  No live RF — offline only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ── Frame-type constants ──────────────────────────────────────────────
TYPE_MGMT = 0
SUBTYPE_BEACON = 8
SUBTYPE_PROBE_REQ = 4
SUBTYPE_PROBE_RESP = 5
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_ASSOC_RESP = 1

FRAME_TYPE_NAMES = {
    (TYPE_MGMT, SUBTYPE_BEACON): "beacon",
    (TYPE_MGMT, SUBTYPE_PROBE_REQ): "probe-request",
    (TYPE_MGMT, SUBTYPE_PROBE_RESP): "probe-response",
    (TYPE_MGMT, SUBTYPE_AUTH): "auth",
    (TYPE_MGMT, SUBTYPE_DEAUTH): "deauth",
    (TYPE_MGMT, SUBTYPE_ASSOC_REQ): "association-request",
    (TYPE_MGMT, SUBTYPE_ASSOC_RESP): "association-response",
}

# Reason codes for deauth/disassoc
REASON_CODES = {
    1: "unspecified",
    2: "auth-no-longer-valid",
    3: "deauth-sta-leaving",
    4: "disassoc-inactivity",
    5: "disassoc-busy",
    6: "class2-frame-from-nonauth-sta",
    7: "class3-frame-from-nonassoc-sta",
    8: "disassoc-sta-left",
    9: "sta-not-auth",
}


@dataclass
class RSNInfo:
    """Parsed RSN (WPA2/WPA3) element."""
    version: int = 0
    group_cipher: str = ""
    pairwise_ciphers: List[str] = field(default_factory=list)
    akm_suites: List[str] = field(default_factory=list)
    rsn_capabilities: int = 0
    pmkid_count: int = 0


@dataclass
class TaggedParam:
    """Single tagged parameter from a management frame."""
    tag_number: int
    tag_length: int
    data: bytes


@dataclass
class ParsedFrame:
    """Result of parsing one 802.11 management frame."""
    frame_type: str
    subtype: int
    src_mac: str = ""
    dst_mac: str = ""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    rates: List[float] = field(default_factory=list)
    country: str = ""
    rsn: Optional[RSNInfo] = None
    tagged_params: List[TaggedParam] = field(default_factory=list)
    raw_bytes: bytes = b""
    fcs_valid: Optional[bool] = None
    deauth_reason: int = 0
    deauth_reason_text: str = ""
    beacon_interval_tu: int = 0
    capability_info: int = 0
    sequence_number: int = 0
    timestamp: int = 0


# ── Helpers ───────────────────────────────────────────────────────────

def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6])


def _find_channel_from_dse(tagged: List[TaggedParam]) -> int:
    """Extract channel from DS Parameter Set (tag 3)."""
    for t in tagged:
        if t.tag_number == 3 and t.tag_length >= 1:
            return t.data[0]
    return 0


def _parse_rates(tag_data: bytes) -> List[float]:
    rates = []
    for byte in tag_data:
        rate_val = (byte & 0x7F) * 0.5
        rates.append(rate_val)
    return rates


def _parse_rsn(tag_data: bytes) -> Optional[RSNInfo]:
    if len(tag_data) < 2:
        return None
    rsn = RSNInfo()
    rsn.version = struct.unpack_from("<H", tag_data, 0)[0]
    offset = 2
    # Group cipher (4 bytes OUI + type)
    if offset + 4 <= len(tag_data):
        rsn.group_cipher = _oui_cipher(tag_data[offset:offset + 4])
        offset += 4
    # Pairwise cipher count + ciphers
    if offset + 2 <= len(tag_data):
        pw_count = struct.unpack_from("<H", tag_data, offset)[0]
        offset += 2
        for _ in range(pw_count):
            if offset + 4 <= len(tag_data):
                rsn.pairwise_ciphers.append(_oui_cipher(tag_data[offset:offset + 4]))
                offset += 4
    # AKM count + suites
    if offset + 2 <= len(tag_data):
        akm_count = struct.unpack_from("<H", tag_data, offset)[0]
        offset += 2
        for _ in range(akm_count):
            if offset + 4 <= len(tag_data):
                rsn.akm_suites.append(_oui_akm(tag_data[offset:offset + 4]))
                offset += 4
    # RSN capabilities
    if offset + 2 <= len(tag_data):
        rsn.rsn_capabilities = struct.unpack_from("<H", tag_data, offset)[0]
        offset += 2
    # PMKID count
    if offset + 2 <= len(tag_data):
        rsn.pmkid_count = struct.unpack_from("<H", tag_data, offset)[0]
    return rsn


def _oui_cipher(b: bytes) -> str:
    """Decode OUI+type cipher selector."""
    if len(b) < 4:
        return "unknown"
    oui = b[:3]
    ctype = b[3]
    if oui == b"\x00\x0f\xac":
        names = {1: "TKIP", 2: "CCMP", 3: "WRAP", 4: "GCMP-128", 6: "GCMP-256"}
        return names.get(ctype, f"00-0f-ac-{ctype}")
    return f"{oui[0]:02x}:{oui[1]:02x}:{oui[2]:02x}-{ctype}"


def _oui_akm(b: bytes) -> str:
    """Decode OUI+type AKM suite selector."""
    if len(b) < 4:
        return "unknown"
    oui = b[:3]
    atype = b[3]
    if oui == b"\x00\x0f\xac":
        names = {
            1: "WPA2-EAP", 2: "WPA2-PSK", 3: "FT-EAP",
            4: "FT-PSK", 5: "WPA2-EAP-SHA256", 6: "WPA2-PSK-SHA256",
            8: "FT-SAE", 9: "SAE", 10: "FT-SAE-FT",
            11: "OWE", 12: "OWE-TRANSITION",
            17: "OWE", 18: "OWE-TRANSITION",
            18: "WPA3-EAP", 19: "WPA3-PSK",
        }
        return names.get(atype, f"00-0f-ac-{atype}")
    return f"{oui[0]:02x}:{oui[1]:02x}:{oui[2]:02x}-{atype}"


# ── Main parser ───────────────────────────────────────────────────────

def _parse_tagged_params(body: bytes, start: int) -> List[TaggedParam]:
    params = []
    off = start
    while off + 2 <= len(body):
        tnum = body[off]
        tlen = body[off + 1]
        if off + 2 + tlen > len(body):
            break
        data = body[off + 2:off + 2 + tlen]
        params.append(TaggedParam(tag_number=tnum, tag_length=tlen, data=data))
        off += 2 + tlen
    return params


def parse_frame(raw: bytes) -> ParsedFrame:
    """Parse one raw radio-tap + 802.11 management frame.

    Returns a ParsedFrame with fields populated as far as the data allows.
    """
    if len(raw) < 4:
        raise ValueError("Frame too short for radio-tap header")

    # Radio-tap header: version(1) + pad(1) + length(2)
    rt_len = struct.unpack_from("<H", raw, 2)[0]
    if rt_len < 8 or rt_len > len(raw):
        raise ValueError(f"Invalid radio-tap length: {rt_len}")

    # 802.11 header starts at rt_len
    hdr_off = rt_len
    if hdr_off + 24 > len(raw):
        raise ValueError("Frame too short for 802.11 header")

    # Frame Control (2 bytes)
    fc = struct.unpack_from("<H", raw, hdr_off)[0]
    protocol = fc & 0x03
    frame_type = (fc >> 2) & 0x03
    subtype = (fc >> 4) & 0x0F
    to_ds = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    retry = (fc >> 11) & 1

    # Duration / ID (2 bytes) — skip
    # Addresses (6 bytes each, potentially repeated for DS)
    addr1 = raw[hdr_off + 4:hdr_off + 10]   # Receiver
    addr2 = raw[hdr_off + 10:hdr_off + 16]  # Transmitter
    addr3 = raw[hdr_off + 16:hdr_off + 22]  # BSSID / SA / DA

    # Sequence Control (2 bytes)
    seq_ctrl = struct.unpack_from("<H", raw, hdr_off + 22)[0]
    seq_num = (seq_ctrl >> 4) & 0xFFF

    # Determine src, dst, bssid from DS flags
    if not to_ds and not from_ds:
        # No DS (ad-hoc / management)
        src = _mac(addr2)
        dst = _mac(addr1)
        bssid = _mac(addr3)
    elif to_ds and not from_ds:
        src = _mac(addr2)
        dst = _mac(addr3)
        bssid = _mac(addr1)
    elif not to_ds and from_ds:
        src = _mac(addr3)
        dst = _mac(addr1)
        bssid = _mac(addr2)
    else:
        src = _mac(addr2)
        dst = _mac(addr1)
        bssid = _mac(addr3)

    ftype_name = FRAME_TYPE_NAMES.get((frame_type, subtype), f"unknown-{frame_type}-{subtype}")

    frame = ParsedFrame(
        frame_type=ftype_name,
        subtype=subtype,
        src_mac=src,
        dst_mac=dst,
        bssid=bssid,
        raw_bytes=raw,
        sequence_number=seq_num,
    )

    if frame_type != TYPE_MGMT:
        return frame

    body_off = hdr_off + 24

    # ── Beacon / Probe Response specifics ──
    if subtype in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP):
        if body_off + 12 > len(raw):
            return frame
        frame.timestamp = struct.unpack_from("<Q", raw, body_off)[0]
        frame.beacon_interval_tu = struct.unpack_from("<H", raw, body_off + 8)[0]
        frame.capability_info = struct.unpack_from("<H", raw, body_off + 10)[0]
        frame.tagged_params = _parse_tagged_params(raw, body_off + 12)
        _extract_tag_fields(frame)

    # ── Probe Request ──
    elif subtype == SUBTYPE_PROBE_REQ:
        frame.tagged_params = _parse_tagged_params(raw, body_off)
        _extract_tag_fields(frame)

    # ── Auth ──
    elif subtype == SUBTYPE_AUTH:
        pass  # minimal parsing; auth algo/seq not critical for WIDS

    # ── Deauth ──
    elif subtype == SUBTYPE_DEAUTH:
        if body_off + 2 <= len(raw):
            frame.deauth_reason = struct.unpack_from("<H", raw, body_off)[0]
            frame.deauth_reason_text = REASON_CODES.get(
                frame.deauth_reason, f"unknown-{frame.deauth_reason}"
            )

    # ── Association Request ──
    elif subtype == SUBTYPE_ASSOC_REQ:
        if body_off + 4 <= len(raw):
            frame.capability_info = struct.unpack_from("<H", raw, body_off)[0]
            # Listen interval (2 bytes) at body_off+2
        frame.tagged_params = _parse_tagged_params(raw, body_off + 4)
        _extract_tag_fields(frame)

    return frame


def _extract_tag_fields(frame: ParsedFrame) -> None:
    """Populate SSID, rates, country, RSN from tagged params."""
    for tp in frame.tagged_params:
        if tp.tag_number == 0:  # SSID
            try:
                frame.ssid = tp.data.decode("utf-8", errors="replace")
            except Exception:
                frame.ssid = ""
        elif tp.tag_number == 1:  # Supported Rates
            frame.rates = _parse_rates(tp.data)
        elif tp.tag_number == 3:  # DS Parameter Set (Channel)
            if tp.tag_length >= 1:
                frame.channel = tp.data[0]
        elif tp.tag_number == 7:  # Country
            if tp.tag_length >= 3:
                frame.country = tp.data[:2].decode("ascii", errors="replace")
        elif tp.tag_number == 48:  # RSN
            frame.rsn = _parse_rsn(tp.data)


# ── File-level parsing ───────────────────────────────────────────────

def parse_pcap(path: str | Path) -> List[ParsedFrame]:
    """Parse all 802.11 management frames from a pcap file.

    Supports pcap global header → per-packet headers.
    Only parses packets with link-type 127 (IEEE 802.11 Radiotap).
    """
    path = Path(path)
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("File too short for pcap header")

    # Global pcap header
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        raise ValueError(f"Not a valid pcap file (magic: {magic:#x})")

    link_type = struct.unpack_from(endian + "I", data, 20)[0]
    if link_type != 127:
        raise ValueError(f"Unsupported link-type {link_type}; expected 127 (Radiotap)")

    frames = []
    offset = 24  # after global header

    while offset + 16 <= len(data):
        # Per-packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
        _ts_sec = struct.unpack_from(endian + "I", data, offset)[0]
        _ts_usec = struct.unpack_from(endian + "I", data, offset + 4)[0]
        incl_len = struct.unpack_from(endian + "I", data, offset + 8)[0]
        _orig_len = struct.unpack_from(endian + "I", data, offset + 12)[0]
        offset += 16

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset:offset + incl_len]
        offset += incl_len

        try:
            frame = parse_frame(pkt_data)
            frames.append(frame)
        except (ValueError, struct.error):
            continue

    return frames


def parse_raw_frames(data: bytes) -> List[ParsedFrame]:
    """Parse a sequence of raw radio-tap frames concatenated in a buffer.

    Each frame is preceded by a 4-byte little-endian length prefix.
    """
    frames = []
    off = 0
    while off + 4 <= len(data):
        frame_len = struct.unpack_from("<I", data, off)[0]
        off += 4
        if frame_len > len(data) - off:
            break
        pkt = data[off:off + frame_len]
        off += frame_len
        try:
            frames.append(parse_frame(pkt))
        except (ValueError, struct.error):
            continue
    return frames
