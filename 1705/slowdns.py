#!/usr/bin/env python3
import asyncio
import base64
from collections import deque
from datetime import datetime
import os
import struct
import subprocess
import time
from typing import Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from config import (
    DNS_BASE_RTO,
    DNS_EDNS_RECOVERY_INTERVAL,
    DNS_LEGACY_DOWNLINK_CHUNK,
    DNS_MAX_DOWNLINK_CHUNK,
    DNS_MAX_INFLIGHT,
    DNS_MAX_UPLINK_CHUNK,
    DNS_NULL_MAX_DOWNLINK_CHUNK,
    DNS_QTYPE_NULL,
    DNS_QTYPE_PRIVATE,
    DNS_QTYPE_TXT,
    EDNS0_LEGACY_PAYLOAD_SIZE,
    EDNS0_UDP_PAYLOAD_SIZE,
    FLAG_DNS_CARRIER,
    PROTOCOL_BANNER,
    TYPE_DNS_BATCH,
    TYPE_DNS_POLL,
    TYPE_STREAM_DATA,
)
from crypto import AWPv3Crypto


def _vts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# =====================================================================
# SLOWDNS ENGINE: MULTI-QTYPE RFC 1035/6891, PER-RESOLVER AIMD & SACK ARQ
# =====================================================================
class DnsCodec:
    """Encoder/decoder paket wire DNS TXT & NULL/PRIVATE (RFC 1035 & EDNS0 RFC 6891)."""

    ANYCAST_RESOLVER_POOL = [
        "8.8.8.8",
        "1.1.1.1",
        "8.8.4.4",
        "1.0.0.1",
    ]

    RCODE_NAMES = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }

    @classmethod
    def describe_dns_response(cls, data: bytes) -> str:
        if len(data) < 12:
            return f"short={len(data)}B"
        _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        rcode = flags & 0x000F
        tc = (flags >> 9) & 1
        rname = cls.RCODE_NAMES.get(rcode, f"RCODE_{rcode}")
        return f"rcode={rname} tc={tc} qd={qd} an={an} ns={ns} ar={ar}"

    @staticmethod
    def apply_0x20_case(label: str) -> str:
        """Acak huruf besar/kecil (DNS 0x20 bit encoding) untuk mencegah cache palsu."""
        if not label:
            return label
        entropy = os.urandom(len(label))
        out = []
        for ch, rnd in zip(label, entropy):
            if "a" <= ch <= "z":
                out.append(ch.upper() if (rnd & 1) else ch)
            elif "A" <= ch <= "Z":
                out.append(ch.lower() if (rnd & 1) else ch)
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def skip_dns_name(data: bytes, pos: int) -> Optional[int]:
        hops = 0
        while pos < len(data):
            ln = data[pos]
            if ln == 0:
                return pos + 1
            if (ln & 0xC0) == 0xC0:
                return pos + 2 if pos + 1 < len(data) else None
            pos += 1 + ln
            hops += 1
            if hops > 64:
                return None
        return None

    @staticmethod
    def max_dns_uplink_arq_bytes(zone_labels: List[str]) -> int:
        zone_wire_len = sum(1 + len(z) for z in zone_labels) + 1
        avail_qname = max(62, 250 - zone_wire_len)
        full_labels = avail_qname // 61
        rem = avail_qname % 61
        max_b32 = (full_labels * 60) + max(0, rem - 1)
        max_raw_wire = (max_b32 * 5) // 8
        # 49B = AWP v4.7 stateless crypto envelope
        return max(48, max_raw_wire - 49)

    @staticmethod
    def calc_downlink_arq_budget(
        edns_size: int, question_len: int, qtype: int = DNS_QTYPE_TXT
    ) -> int:
        is_binary_rr = qtype in (DNS_QTYPE_NULL, DNS_QTYPE_PRIVATE)
        if edns_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
            # 12B DNS hdr + question + 12B RR hdr = 24 + question_len; total <= 508B
            max_rdata = max(64, 508 - (24 + question_len))
            if is_binary_rr:
                max_ctrl_wire = max_rdata
            else:
                max_b64 = (max_rdata * 250) // 251
                max_ctrl_wire = (max_b64 * 3) // 4
            # -2B control hdr, -49B AWP crypto envelope
            return max(48, max_ctrl_wire - 51)

        # 12B DNS hdr + question + 12B RR hdr + 11B OPT RR = 35 + question_len
        safe_udp_cap = max(512, edns_size - 16)
        max_rdata = max(128, safe_udp_cap - (35 + question_len))
        if is_binary_rr:
            max_ctrl_wire = max_rdata
            chunk_cap = DNS_NULL_MAX_DOWNLINK_CHUNK
        else:
            max_b64 = (max_rdata * 250) // 251
            max_ctrl_wire = (max_b64 * 3) // 4
            chunk_cap = DNS_MAX_DOWNLINK_CHUNK

        hard_cap = (
            DnsArqEngine.ARQ_HDR_SIZE
            + DnsArqEngine.SUB_HDR_SIZE
            + chunk_cap
        )
        return max(48, min(hard_cap, max_ctrl_wire - 51))

    @classmethod
    def detect_system_dns_resolvers(cls) -> List[str]:
        found: List[str] = []
        try:
            for prop in ("net.dns1", "net.dns2"):
                out = (
                    subprocess.check_output(
                        ["getprop", prop], stderr=subprocess.DEVNULL, timeout=1.5
                    )
                    .decode()
                    .strip()
                )
                if out and "." in out and not out.startswith("127.") and out not in found:
                    found.append(out)
        except Exception:
            pass

        for path in (
            "/etc/resolv.conf",
            "/data/data/com.termux/files/usr/etc/resolv.conf",
        ):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[0] == "nameserver":
                            ip = parts[1]
                            if "." in ip and not ip.startswith("127.") and ip not in found:
                                found.append(ip)
            except Exception:
                pass

        for ip in cls.ANYCAST_RESOLVER_POOL:
            if ip not in found:
                found.append(ip)

        return found

    @classmethod
    def build_dns_txt_query(
        cls,
        tx_id: int,
        wire_bytes: bytes,
        zone_labels: List[str],
        edns_udp_size: int = EDNS0_LEGACY_PAYLOAD_SIZE,
        qtype: int = DNS_QTYPE_TXT,
        use_0x20: bool = True,
    ) -> bytes:
        b32_str = base64.b32encode(wire_bytes).decode("ascii").rstrip("=").lower()
        qname = bytearray()
        for i in range(0, len(b32_str), 60):
            lbl_str = b32_str[i : i + 60]
            if use_0x20:
                lbl_str = cls.apply_0x20_case(lbl_str)
            lbl = lbl_str.encode("ascii")
            qname.append(len(lbl))
            qname.extend(lbl)
        for zlbl in zone_labels:
            z_str = cls.apply_0x20_case(zlbl) if use_0x20 else zlbl
            zb = z_str.encode("ascii")
            qname.append(len(zb))
            qname.extend(zb)
        qname.append(0)

        header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 1)
        question = bytes(qname) + struct.pack("!HH", qtype, 1)
        adv_size = max(
            EDNS0_LEGACY_PAYLOAD_SIZE, min(EDNS0_UDP_PAYLOAD_SIZE, edns_udp_size)
        )
        opt_rr = b"\x00" + struct.pack("!HHIH", 41, adv_size, 0, 0)
        return header + question + opt_rr

    @classmethod
    def parse_dns_query(
        cls, data: bytes
    ) -> Optional[Tuple[int, List[str], bytes, int, int, int]]:
        if len(data) < 17:
            return None
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", data[:12]
        )
        if (flags & 0x8000) != 0 or qdcount < 1:
            return None

        idx = 12
        labels: List[str] = []
        jumped = False
        end_idx = idx
        hops = 0

        while idx < len(data):
            length = data[idx]
            if length == 0:
                if not jumped:
                    end_idx = idx + 1
                break
            if (length & 0xC0) == 0xC0:
                if idx + 1 >= len(data):
                    return None
                if not jumped:
                    end_idx = idx + 2
                idx = ((length & 0x3F) << 8) | data[idx + 1]
                jumped = True
                hops += 1
                if hops > 10:
                    return None
                continue
            idx += 1
            if idx + length > len(data):
                return None
            labels.append(data[idx : idx + length].decode("ascii", errors="ignore"))
            idx += length
            if not jumped:
                end_idx = idx

        if end_idx + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[end_idx : end_idx + 4])
        question_wire = data[12 : end_idx + 4]

        edns_udp_size = 0
        scan_pos = end_idx + 4
        for _ in range(qdcount - 1):
            nxt = cls.skip_dns_name(data, scan_pos)
            if nxt is None or nxt + 4 > len(data):
                scan_pos = len(data)
                break
            scan_pos = nxt + 4

        for _ in range(ancount + nscount):
            nxt = cls.skip_dns_name(data, scan_pos)
            if nxt is None or nxt + 10 > len(data):
                scan_pos = len(data)
                break
            _, _, _, rdlen = struct.unpack("!HHIH", data[nxt : nxt + 10])
            scan_pos = nxt + 10 + rdlen

        for _ in range(arcount):
            nxt = cls.skip_dns_name(data, scan_pos)
            if nxt is None or nxt + 10 > len(data):
                break
            rtype, rclass, _, rdlen = struct.unpack("!HHIH", data[nxt : nxt + 10])
            if rtype == 41:
                edns_udp_size = max(512, min(EDNS0_UDP_PAYLOAD_SIZE, rclass))
                break
            scan_pos = nxt + 10 + rdlen

        return tx_id, labels, question_wire, qtype, qclass, edns_udp_size

    @staticmethod
    def build_dns_txt_response(
        tx_id: int,
        question_wire: bytes,
        payload_bytes: bytes,
        has_more: bool,
        backlog_hint: int = 0,
        edns_udp_size: int = EDNS0_LEGACY_PAYLOAD_SIZE,
        qtype: int = DNS_QTYPE_TXT,
    ) -> bytes:
        flags_byte = 0x01 if has_more else 0x00
        hint_byte = max(0, min(255, backlog_hint))
        control_blob = bytes([flags_byte, hint_byte]) + payload_bytes

        if qtype in (DNS_QTYPE_NULL, DNS_QTYPE_PRIVATE):
            # Raw binary RDATA tanpa overhead Base64 & string-length prefix
            rdata_bytes = control_blob
            ans_type = qtype
        else:
            b64_ascii = base64.b64encode(control_blob)
            rdata = bytearray()
            for i in range(0, len(b64_ascii), 250):
                chunk = b64_ascii[i : i + 250]
                rdata.append(len(chunk))
                rdata.extend(chunk)
            rdata_bytes = bytes(rdata)
            ans_type = DNS_QTYPE_TXT

        use_edns = edns_udp_size > 512
        arcount = 1 if use_edns else 0
        header = struct.pack("!HHHHHH", tx_id, 0x8400, 1, 1, 0, arcount)
        answer_rr = struct.pack("!HHHLH", 0xC00C, ans_type, 1, 0, len(rdata_bytes)) + rdata_bytes
        if use_edns:
            opt_rr = b"\x00" + struct.pack(
                "!HHIH", 41, min(EDNS0_UDP_PAYLOAD_SIZE, edns_udp_size), 0, 0
            )
            return header + question_wire + answer_rr + opt_rr
        return header + question_wire + answer_rr

    @classmethod
    def response_has_edns_opt(cls, data: bytes) -> bool:
        if len(data) < 12:
            return False
        _, _, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        if arcount < 1:
            return False
        idx = 12
        for _ in range(qdcount):
            nxt = cls.skip_dns_name(data, idx)
            if nxt is None or nxt + 4 > len(data):
                return False
            idx = nxt + 4
        for _ in range(ancount + nscount):
            nxt = cls.skip_dns_name(data, idx)
            if nxt is None or nxt + 10 > len(data):
                return False
            _, _, _, rdlen = struct.unpack("!HHIH", data[nxt : nxt + 10])
            idx = nxt + 10 + rdlen
        for _ in range(arcount):
            nxt = cls.skip_dns_name(data, idx)
            if nxt is None or nxt + 10 > len(data):
                return False
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[nxt : nxt + 10])
            if rtype == 41:
                return True
            idx = nxt + 10 + rdlen
        return False

    @classmethod
    def parse_dns_txt_response(
        cls, data: bytes, expected_tx_id: int
    ) -> Optional[Tuple[bool, int, bytes]]:
        if len(data) < 12:
            return None
        tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if tx_id != expected_tx_id or (flags & 0x8000) == 0 or ancount < 1:
            return None
        idx = 12
        for _ in range(qdcount):
            nxt = cls.skip_dns_name(data, idx)
            if nxt is None or nxt + 4 > len(data):
                return None
            idx = nxt + 4

        b64_buf = bytearray()
        raw_bin_buf = bytearray()
        for _ in range(ancount):
            nxt = cls.skip_dns_name(data, idx)
            if nxt is None or nxt + 10 > len(data):
                return None
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[nxt : nxt + 10])
            rdata_start = nxt + 10
            rdata_end = rdata_start + rdlen
            if rdata_end > len(data):
                return None
            if rtype in (DNS_QTYPE_NULL, DNS_QTYPE_PRIVATE):
                raw_bin_buf.extend(data[rdata_start:rdata_end])
            elif rtype == DNS_QTYPE_TXT:
                pos = rdata_start
                while pos < rdata_end:
                    slen = data[pos]
                    pos += 1
                    if pos + slen > rdata_end:
                        break
                    b64_buf.extend(data[pos : pos + slen])
                    pos += slen
            idx = rdata_end

        if raw_bin_buf:
            decoded = bytes(raw_bin_buf)
        elif b64_buf:
            try:
                decoded = base64.b64decode(bytes(b64_buf))
            except Exception:
                return None
        else:
            return None

        if len(decoded) < 2:
            return None
        has_more = (decoded[0] & 0x01) != 0
        backlog_hint = decoded[1]
        return has_more, backlog_hint, decoded[2:]


class _SingleResolverPacer:
    """AIMD rate-limiter independen untuk satu endpoint resolver/DoH."""

    def __init__(self, base_qps: float, max_qps: float):
        self.base_qps = max(4.0, float(base_qps))
        self.max_qps = max(self.base_qps, float(max_qps))
        self.current_qps = self.base_qps
        self.next_slot = time.monotonic()
        self.last_penalty_ts = 0.0

    async def acquire(self):
        interval = 1.0 / max(4.0, self.current_qps)
        now = time.monotonic()
        if now >= self.next_slot:
            self.next_slot = now + interval
            return
        wait_time = self.next_slot - now
        if wait_time > 0.8:
            self.next_slot = now + interval
            return
        self.next_slot += interval
        await asyncio.sleep(wait_time)

    def on_success(self, rtt_ms: float):
        if rtt_ms < 950.0 and self.current_qps < self.max_qps:
            step = 0.30 if rtt_ms < 450.0 else 0.14
            self.current_qps = min(self.max_qps, self.current_qps + step)

    def on_loss(self):
        now = time.monotonic()
        if (now - self.last_penalty_ts) >= 0.75:
            self.last_penalty_ts = now
            floor_qps = max(6.0, self.base_qps * 0.45)
            self.current_qps = max(floor_qps, self.current_qps * 0.88)


class PerResolverQpsPacer:
    """
    Pool AIMD QPS Pacer per-IP resolver agar gangguan atau rate-limit pada satu
    resolver tidak menurunkan kapasitas QPS resolver lain yang sehat.
    """

    def __init__(
        self,
        base_qps: float = 34.0,
        max_qps: float = 56.0,
        resolvers: Optional[List[str]] = None,
    ):
        self.total_base_qps = max(8.0, min(200.0, float(base_qps)))
        self.total_max_qps = max(self.total_base_qps, min(250.0, float(max_qps)))
        self.pacers: Dict[str, _SingleResolverPacer] = {}
        if resolvers:
            self.configure_resolvers(resolvers)

    def configure_resolvers(self, resolvers: List[str]):
        n = max(1, len(resolvers))
        # Setiap resolver diberi jatah dasar + headroom burst 1.45x
        per_base = max(6.0, (self.total_base_qps / n) * 1.25)
        per_max = max(per_base, (self.total_max_qps / n) * 1.45)
        for r in resolvers:
            if r not in self.pacers:
                self.pacers[r] = _SingleResolverPacer(per_base, per_max)

    def _get(self, resolver_key: str) -> _SingleResolverPacer:
        if resolver_key not in self.pacers:
            n = max(1, len(self.pacers) + 1)
            per_base = max(6.0, self.total_base_qps / n)
            per_max = max(per_base, self.total_max_qps / n)
            self.pacers[resolver_key] = _SingleResolverPacer(per_base, per_max)
        return self.pacers[resolver_key]

    @property
    def current_qps(self) -> float:
        if not self.pacers:
            return self.total_base_qps
        return min(self.total_max_qps, sum(p.current_qps for p in self.pacers.values()))

    def qps_for(self, resolver_key: str) -> float:
        return self._get(resolver_key).current_qps

    async def acquire(self, resolver_key: str = "global"):
        await self._get(resolver_key).acquire()

    def on_success(self, rtt_ms: float, resolver_key: str = "global"):
        self._get(resolver_key).on_success(rtt_ms)

    def on_loss(self, resolver_key: str = "global"):
        self._get(resolver_key).on_loss()


# Alias kompatibilitas mundur
AdaptiveGlobalQpsPacer = PerResolverQpsPacer


class DnsArqEngine:
    """
    Mesin 64-bit Selective-ACK, Multi-Segment Coalescing, Tail-Loss Probe & Dynamic Re-Slicing.
    Format Wire ARQ:
      [ack_seq:4B][sack_mask:8B][min_valid:4B][cap_code:1B] (17B)
      + 0..N sub-segmen: [dns_seq:4B][ftype:1B][sid:2B][data_len:2B][data...] (9B + data)
    cap_code:
      0 = EDNS0 1232B TXT (640B)
      1 = EDNS0 512B Legacy (205B)
      2 = EDNS0 1232B Binary NULL/DoH (920B)
    """

    ARQ_HDR_STRUCT = "!IQIB"
    ARQ_HDR_SIZE = 17
    SUB_HDR_STRUCT = "!IBHH"
    SUB_HDR_SIZE = 9

    def __init__(
        self,
        crypto: AWPv3Crypto,
        is_server: bool,
        initial_edns: int = EDNS0_LEGACY_PAYLOAD_SIZE,
        max_inflight: int = DNS_MAX_INFLIGHT,
        uplink_chunk: int = DNS_MAX_UPLINK_CHUNK,
        base_rto: float = DNS_BASE_RTO,
        verbose: bool = False,
        binary_downlink: bool = False,
    ):
        self.crypto = crypto
        self.is_server = is_server
        self.verbose = verbose
        self.edns_size = initial_edns
        self.binary_downlink = binary_downlink
        self.client_chunk_cap = self._max_chunk_for_mode(initial_edns, binary_downlink)
        self.max_inflight = max_inflight
        self.uplink_chunk = uplink_chunk
        self.base_rto = base_rto
        self.last_edns_fallback_ts: float = 0.0

        # Jacobson/Karels SRTT & RTTVAR
        self.srtt: float = 0.35
        self.rttvar: float = 0.12

        self.rx_lock = asyncio.Lock()
        self.tx_seq: int = 0
        self.stream_queues: Dict[int, Deque[Tuple[int, bytes]]] = {}
        self.stream_rr: Deque[int] = deque()
        # unacked[seq] = [last_sent_ts, ftype, sid, chunk_bytes, retry_count, sack_strikes]
        self.unacked: Dict[int, list] = {}
        self.rx_next_seq: int = 1
        self.rx_ooo: Dict[int, Tuple[int, int, bytes]] = {}
        self.retransmit_count: int = 0
        self.coalesced_packets: int = 0
        self.unacked_rx_ticks: int = 0

    @staticmethod
    def _max_chunk_for_mode(edns_size: int, binary_downlink: bool) -> int:
        if edns_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
            return DNS_LEGACY_DOWNLINK_CHUNK
        return DNS_NULL_MAX_DOWNLINK_CHUNK if binary_downlink else DNS_MAX_DOWNLINK_CHUNK

    def _vlog(self, msg: str):
        if self.verbose:
            side = "SRV" if self.is_server else "CLI"
            print(f"[{_vts()}][VERBOSE][ARQ-{side}] {msg}")

    def update_rtt_ms(self, rtt_ms: float):
        sample = max(0.04, min(2.2, rtt_ms / 1000.0))
        err = abs(sample - self.srtt)
        self.rttvar = (0.75 * self.rttvar) + (0.25 * err)
        self.srtt = (0.875 * self.srtt) + (0.125 * sample)

    def current_rto(self) -> float:
        est = (1.90 * self.srtt) + (3.2 * self.rttvar)
        return max(self.base_rto, min(2.4, est))

    def downlink_chunk_limit(self) -> int:
        edns_cap = self._max_chunk_for_mode(self.edns_size, self.binary_downlink)
        return min(edns_cap, self.client_chunk_cap)

    def tx_chunk_limit(self) -> int:
        return self.downlink_chunk_limit() if self.is_server else self.uplink_chunk

    def cap_code(self) -> int:
        if self.edns_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
            return 1
        return 2 if self.binary_downlink else 0

    def should_probe_edns_recovery(self) -> bool:
        if self.is_server or self.edns_size > EDNS0_LEGACY_PAYLOAD_SIZE:
            return False
        if self.last_edns_fallback_ts <= 0.0:
            return False
        return (time.monotonic() - self.last_edns_fallback_ts) >= DNS_EDNS_RECOVERY_INTERVAL

    def resegment_oversized_unacked(self, max_allowed_chunk: int):
        """
        Pecah ulang segmen unacked yang melebihi limit baru setelah fallback EDNS0
        dengan mempertahankan urutan FIFO penuh (mencegah CLOSE mendahului DATA).
        """
        oversized_seqs = [
            s for s in sorted(self.unacked.keys()) if len(self.unacked[s][3]) > max_allowed_chunk
        ]
        if not oversized_seqs:
            return
        first_bad = oversized_seqs[0]
        seqs_to_requeue = [s for s in sorted(self.unacked.keys()) if s >= first_bad]
        requeued_sids: List[int] = []

        for seq in reversed(seqs_to_requeue):
            entry = self.unacked.pop(seq)
            _, ftype, sid, data, _, _ = entry
            if sid not in self.stream_queues:
                self.stream_queues[sid] = deque()
            if sid not in requeued_sids:
                requeued_sids.append(sid)
            q = self.stream_queues[sid]
            if ftype == TYPE_STREAM_DATA and len(data) > max_allowed_chunk:
                parts = [
                    data[i : i + max_allowed_chunk]
                    for i in range(0, len(data), max_allowed_chunk)
                ]
                for part in reversed(parts):
                    q.appendleft((ftype, part))
            else:
                q.appendleft((ftype, data))

        for sid in requeued_sids:
            if sid in self.stream_rr:
                try:
                    self.stream_rr.remove(sid)
                except ValueError:
                    pass
            self.stream_rr.appendleft(sid)

        self._vlog(
            f"Re-sliced {len(seqs_to_requeue)} unacked segments (from seq={first_bad}) "
            f"to max {max_allowed_chunk}B"
        )

    def apply_peer_cap_code(self, cap_code: int, token_hex: str = ""):
        if not self.is_server:
            return
        prev_limit = self.downlink_chunk_limit()
        if cap_code == 1:
            self.client_chunk_cap = DNS_LEGACY_DOWNLINK_CHUNK
            self.edns_size = EDNS0_LEGACY_PAYLOAD_SIZE
            self.binary_downlink = False
        elif cap_code == 2:
            self.binary_downlink = True
            self.edns_size = EDNS0_UDP_PAYLOAD_SIZE
            self.client_chunk_cap = DNS_NULL_MAX_DOWNLINK_CHUNK
        else:
            self.binary_downlink = False
            self.edns_size = EDNS0_UDP_PAYLOAD_SIZE
            self.client_chunk_cap = DNS_MAX_DOWNLINK_CHUNK

        new_limit = self.downlink_chunk_limit()
        if new_limit < prev_limit:
            self.resegment_oversized_unacked(new_limit)
            if token_hex:
                print(
                    f"[{PROTOCOL_BANNER}] DNS-ARQ CHUNK LOCK -> Token={token_hex} "
                    f"| Chunk={prev_limit}B->{new_limit}B"
                )
        elif new_limit > prev_limit and token_hex:
            print(
                f"[{PROTOCOL_BANNER}] DNS-ARQ CHUNK UPGRADE -> Token={token_hex} "
                f"| Chunk={prev_limit}B->{new_limit}B"
            )

    def queued_count(self) -> int:
        return sum(len(q) for q in self.stream_queues.values())

    def has_pending_work(self) -> bool:
        return bool(self.unacked) or any(len(q) > 0 for q in self.stream_queues.values())

    def can_send_more(self) -> bool:
        has_queued = any(len(q) > 0 for q in self.stream_queues.values())
        return has_queued and (len(self.unacked) < self.max_inflight)

    def needs_immediate_ack(self) -> bool:
        return bool(self.rx_ooo) or (self.unacked_rx_ticks >= 2)

    def min_valid_seq(self) -> int:
        return min(self.unacked.keys()) if self.unacked else (self.tx_seq + 1)

    def ack_state(self) -> Tuple[int, int]:
        ack_seq = self.rx_next_seq - 1
        sack_mask = 0
        for bit in range(64):
            if (self.rx_next_seq + 1 + bit) in self.rx_ooo:
                sack_mask |= 1 << bit
        return ack_seq, sack_mask

    def process_peer_ack(self, ack_seq: int, sack_mask: int):
        if ack_seq > 0:
            for s in [s for s in self.unacked if s <= ack_seq]:
                self.unacked.pop(s, None)

        total_sacks = 0
        if sack_mask:
            total_sacks = bin(sack_mask).count("1")
            for bit in range(64):
                if (sack_mask >> bit) & 1:
                    self.unacked.pop(ack_seq + 2 + bit, None)

        missing_seq = ack_seq + 1
        if missing_seq in self.unacked and total_sacks >= 2:
            entry = self.unacked[missing_seq]
            last_strikes = entry[5] if len(entry) > 5 else 0
            if entry[0] > 0.0 and total_sacks >= (last_strikes + 2):
                entry[0] = 0.01
                if len(entry) > 5:
                    entry[5] = total_sacks
                self._vlog(
                    f"SACK Fast-Retx armed for missing seq={missing_seq} (sacks={total_sacks})"
                )

    def purge_stream(self, stream_id: int):
        """
        Hapus antrean stream yang sudah ditutup, dan ubah segmen unacked miliknya
        menjadi tombstone TYPE_DNS_POLL kosong agar sequence ARQ tidak macet.
        """
        if stream_id <= 0:
            return
        self.stream_queues.pop(stream_id, None)
        for seq, entry in list(self.unacked.items()):
            if entry[2] == stream_id:
                entry[1] = TYPE_DNS_POLL
                entry[2] = 0
                entry[3] = b""

    def enqueue(
        self,
        frame_type: int,
        stream_id: int,
        payload: bytes,
        wake_event: Optional[asyncio.Event] = None,
    ):
        max_chunk = self.tx_chunk_limit()
        if stream_id not in self.stream_queues:
            self.stream_queues[stream_id] = deque()
            self.stream_rr.append(stream_id)

        q = self.stream_queues[stream_id]
        if not payload:
            q.append((frame_type, b""))
            if wake_event:
                wake_event.set()
            return

        offset = 0
        if (
            frame_type == TYPE_STREAM_DATA
            and q
            and q[-1][0] == TYPE_STREAM_DATA
            and len(q[-1][1]) < max_chunk
        ):
            prev_type, prev_data = q.pop()
            need = max_chunk - len(prev_data)
            q.append((prev_type, prev_data + payload[:need]))
            offset = need

        while offset < len(payload):
            q.append((frame_type, payload[offset : offset + max_chunk]))
            offset += max_chunk

        if wake_event:
            wake_event.set()

    def _pop_rr_item_fitting(self, max_data_bytes: int) -> Optional[Tuple[int, int, bytes]]:
        if max_data_bytes < 0:
            return None
        checked = 0
        total_streams = len(self.stream_rr)
        while self.stream_rr and checked < total_streams:
            checked += 1
            sid = self.stream_rr.popleft()
            q = self.stream_queues.get(sid)
            if not q:
                self.stream_queues.pop(sid, None)
                continue
            ftype, chunk = q[0]
            if len(chunk) <= max_data_bytes:
                q.popleft()
                if q:
                    self.stream_rr.append(sid)
                else:
                    self.stream_queues.pop(sid, None)
                return ftype, sid, chunk
            if max_data_bytes >= 20 and ftype == TYPE_STREAM_DATA:
                q.popleft()
                head = chunk[:max_data_bytes]
                q.appendleft((ftype, chunk[max_data_bytes:]))
                self.stream_rr.append(sid)
                return ftype, sid, head
            self.stream_rr.append(sid)
        return None

    def pop_next_wire(
        self, emit_idle_poll: bool, max_arq_bytes_override: Optional[int] = None
    ) -> Tuple[bytes, bool]:
        now = time.monotonic()
        ack_seq, sack_mask = self.ack_state()
        min_valid = self.min_valid_seq()
        ccode = self.cap_code()
        base_rto = self.current_rto()

        default_budget = self.ARQ_HDR_SIZE + self.SUB_HDR_SIZE + self.tx_chunk_limit()
        budget = max_arq_bytes_override if max_arq_bytes_override is not None else default_budget

        body_buf = bytearray()
        segments_packed = 0
        retx_packed = 0
        retx_seqs = set()

        # 1. Retransmisi terukur (maks 2 segmen per paket DNS + exponential backoff)
        for seq in sorted(self.unacked.keys()):
            if retx_packed >= 2:
                break
            entry = self.unacked[seq]
            eff_rto = base_rto * min(3.2, 1.35 ** entry[4])
            if entry[0] > 0.0 and (now - entry[0]) >= eff_rto:
                needed = self.SUB_HDR_SIZE + len(entry[3])
                if self.ARQ_HDR_SIZE + len(body_buf) + needed <= budget:
                    entry[0] = now
                    entry[4] += 1
                    self.retransmit_count += 1
                    body_buf.extend(
                        struct.pack(
                            self.SUB_HDR_STRUCT, seq, entry[1], entry[2], len(entry[3])
                        )
                    )
                    body_buf.extend(entry[3])
                    segments_packed += 1
                    retx_packed += 1
                    retx_seqs.add(seq)
                    self._vlog(
                        f"RTO RETX seq={seq} sid={entry[2]} len={len(entry[3])}B "
                        f"retry={entry[4]} eff_rto={eff_rto:.2f}s"
                    )

        # 2. Isi sisa ruang paket DNS dengan segmen baru dari antrean round-robin
        while len(self.unacked) < self.max_inflight:
            rem_data_space = budget - (
                self.ARQ_HDR_SIZE + len(body_buf) + self.SUB_HDR_SIZE
            )
            if rem_data_space < 0:
                break
            item = self._pop_rr_item_fitting(rem_data_space)
            if item is None:
                break
            ftype, sid, chunk = item
            self.tx_seq += 1
            seq = self.tx_seq
            self.unacked[seq] = [now, ftype, sid, chunk, 0, 0]
            body_buf.extend(
                struct.pack(self.SUB_HDR_STRUCT, seq, ftype, sid, len(chunk))
            )
            body_buf.extend(chunk)
            segments_packed += 1

        # 3. Proactive Tail-Loss / Window-Stall Probe
        has_queued = any(len(q) > 0 for q in self.stream_queues.values())
        if (
            segments_packed == 0
            and self.unacked
            and (len(self.unacked) >= self.max_inflight or not has_queued)
        ):
            oldest_seq = min(self.unacked.keys())
            if oldest_seq not in retx_seqs:
                entry = self.unacked[oldest_seq]
                tlp_delay = max(0.32, min(0.85, self.srtt * 1.15))
                if entry[0] > 0.0 and (now - entry[0]) >= tlp_delay:
                    needed = self.SUB_HDR_SIZE + len(entry[3])
                    if self.ARQ_HDR_SIZE + len(body_buf) + needed <= budget:
                        entry[0] = now
                        entry[4] += 1
                        self.retransmit_count += 1
                        body_buf.extend(
                            struct.pack(
                                self.SUB_HDR_STRUCT,
                                oldest_seq,
                                entry[1],
                                entry[2],
                                len(entry[3]),
                            )
                        )
                        body_buf.extend(entry[3])
                        segments_packed += 1
                        self._vlog(
                            f"TLP PROBE seq={oldest_seq} sid={entry[2]} len={len(entry[3])}B "
                            f"retry={entry[4]} delay={tlp_delay:.2f}s"
                        )

        if segments_packed > 1:
            self.coalesced_packets += 1

        if segments_packed > 0:
            self.unacked_rx_ticks = 0
            min_valid = self.min_valid_seq()
            arq_hdr = struct.pack(
                self.ARQ_HDR_STRUCT, ack_seq, sack_mask, min_valid, ccode
            )
            wire_pkt, _, _ = self.crypto.encode_frame(
                TYPE_DNS_BATCH,
                0,
                arq_hdr + bytes(body_buf),
                flags=FLAG_DNS_CARRIER,
                min_pad=1,
                max_pad=1,
            )
            more_hint = (
                True
                if not self.is_server
                else (self.can_send_more() or bool(self.unacked))
            )
            return wire_pkt, more_hint

        # 4. Kirim ACK/Poll kosong jika diperlukan
        if (
            emit_idle_poll
            or ack_seq > 0
            or sack_mask > 0
            or self.has_pending_work()
            or min_valid > 1
        ):
            self.unacked_rx_ticks = 0
            arq_hdr = struct.pack(
                self.ARQ_HDR_STRUCT, ack_seq, sack_mask, min_valid, ccode
            )
            wire_pkt, _, _ = self.crypto.encode_frame(
                TYPE_DNS_POLL,
                0,
                arq_hdr,
                flags=FLAG_DNS_CARRIER,
                min_pad=1,
                max_pad=1,
            )
            more_hint = (
                False
                if not self.is_server
                else (self.can_send_more() or bool(self.unacked))
            )
            return wire_pkt, more_hint

        return b"", False

    def peek_ack_header(self, payload: bytes) -> Optional[Tuple[int, int, int, int]]:
        if len(payload) < self.ARQ_HDR_SIZE:
            return None
        return struct.unpack(self.ARQ_HDR_STRUCT, payload[: self.ARQ_HDR_SIZE])

    async def ingest_incoming(
        self,
        payload: bytes,
        deliver_cb: Callable[[int, int, bytes], Awaitable[None]],
        token_hex: str = "",
    ):
        if len(payload) < self.ARQ_HDR_SIZE:
            return
        async with self.rx_lock:
            peer_ack, peer_sack_mask, peer_min_valid, peer_cap = struct.unpack(
                self.ARQ_HDR_STRUCT, payload[: self.ARQ_HDR_SIZE]
            )
            self.apply_peer_cap_code(peer_cap, token_hex)
            self.process_peer_ack(peer_ack, peer_sack_mask)

            if peer_min_valid > self.rx_next_seq:
                self._vlog(
                    f"Peer min_valid={peer_min_valid} > rx_next_seq={self.rx_next_seq}, advancing"
                )
                for s in [s for s in self.rx_ooo if s < peer_min_valid]:
                    self.rx_ooo.pop(s, None)
                self.rx_next_seq = peer_min_valid
                while self.rx_next_seq in self.rx_ooo:
                    o_type, o_sid, o_data = self.rx_ooo.pop(self.rx_next_seq)
                    self.rx_next_seq += 1
                    if o_type != TYPE_DNS_POLL:
                        await deliver_cb(o_type, o_sid, o_data)

            pos = self.ARQ_HDR_SIZE
            received_any_data = False
            while pos + self.SUB_HDR_SIZE <= len(payload):
                dns_seq, ftype, stream_id, dlen = struct.unpack(
                    self.SUB_HDR_STRUCT, payload[pos : pos + self.SUB_HDR_SIZE]
                )
                pos += self.SUB_HDR_SIZE
                if pos + dlen > len(payload):
                    break
                raw_data = payload[pos : pos + dlen]
                pos += dlen

                if dns_seq == 0 or dns_seq < self.rx_next_seq:
                    received_any_data = True
                    continue

                received_any_data = True
                if dns_seq > self.rx_next_seq and dns_seq not in self.rx_ooo:
                    self._vlog(
                        f"OOO seg seq={dns_seq} (expected={self.rx_next_seq}, ooo_buf={len(self.rx_ooo)+1})"
                    )
                self.rx_ooo[dns_seq] = (ftype, stream_id, raw_data)

            if received_any_data:
                self.unacked_rx_ticks += 1

            while self.rx_next_seq in self.rx_ooo:
                o_type, o_sid, o_data = self.rx_ooo.pop(self.rx_next_seq)
                self.rx_next_seq += 1
                if o_type != TYPE_DNS_POLL:
                    await deliver_cb(o_type, o_sid, o_data)
