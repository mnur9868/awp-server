#!/usr/bin/env python3
import os
import struct
from typing import Dict, List, Optional, Set, Tuple
import zlib

from config import (
    FEC_GROUP_SIZE,
    FLAG_COMPRESSED,
    TYPE_FEC_PARITY,
    TYPE_STREAM_DATA,
)


# =====================================================================
# KAMUFLASE QUIC v1 & MESIN XOR FORWARD ERROR CORRECTION (FEC)
# =====================================================================
class QuicCamouflage:
    """Encoder/decoder header kamuflase QUIC v1 untuk datagram UDP."""

    @staticmethod
    def wrap_quic_mimic(payload: bytes, is_initial: bool = False) -> bytes:
        if is_initial:
            hdr = (
                b"\xc3\x00\x00\x00\x01\x08"
                + os.urandom(8)
                + b"\x08"
                + os.urandom(8)
                + b"\x00"
            )
            return hdr + payload
        return b"\x43" + os.urandom(8) + os.urandom(2) + payload

    @staticmethod
    def unwrap_quic_mimic(datagram: bytes) -> bytes:
        if len(datagram) < 12:
            return datagram
        first = datagram[0]
        if (
            (first & 0x80) != 0
            and len(datagram) >= 24
            and datagram[1:5] == b"\x00\x00\x00\x01"
        ):
            dcid_len = datagram[5]
            pos = 6 + dcid_len
            if pos < len(datagram):
                scid_len = datagram[pos]
                pos += 1 + scid_len
                if pos < len(datagram) and datagram[pos] == 0:
                    return datagram[pos + 1 :]
        if (first & 0xC0) == 0x40 and len(datagram) > 11:
            return datagram[11:]
        return datagram


class FecEngine:
    """XOR Forward Error Correction dengan penghitung pemulihan paket."""

    def __init__(self, group_size: int = FEC_GROUP_SIZE):
        self.group_size = group_size
        self.tx_batch: List[bytes] = []
        self.tx_base_seq: int = 1
        self.rx_frames: Dict[int, Dict[int, bytes]] = {}
        self.rx_parity: Dict[int, bytes] = {}
        self.rx_seen_seqs: Set[int] = set()
        self.recovered_count: int = 0

    def build_tx_parity_if_ready(self, seq_num: int, clean_frame: bytes) -> Optional[bytes]:
        if not self.tx_batch:
            self.tx_base_seq = seq_num
        self.tx_batch.append(clean_frame)
        if len(self.tx_batch) < self.group_size:
            return None

        parity = bytearray()
        for f in self.tx_batch:
            framed = struct.pack("!H", len(f)) + f
            for i, b in enumerate(framed):
                if i < len(parity):
                    parity[i] ^= b
                else:
                    parity.append(b)
        blob = struct.pack("!IB", self.tx_base_seq, len(self.tx_batch)) + bytes(parity)
        self.tx_batch.clear()
        return blob

    def _try_recover_group(self, group_id: int) -> Optional[dict]:
        if group_id not in self.rx_parity or group_id not in self.rx_frames:
            return None
        frames_map = self.rx_frames[group_id]
        if len(frames_map) != self.group_size - 1:
            return None

        parity_data = bytearray(self.rx_parity.pop(group_id))
        self.rx_frames.pop(group_id, None)
        for f in frames_map.values():
            framed = struct.pack("!H", len(f)) + f
            for i, b in enumerate(framed):
                if i < len(parity_data):
                    parity_data[i] ^= b

        if len(parity_data) < 2:
            return None
        orig_len = struct.unpack("!H", parity_data[:2])[0]
        if 2 + orig_len > len(parity_data):
            return None

        clean = bytes(parity_data[2 : 2 + orig_len])
        if len(clean) < 10:
            return None
        r_flags, r_type, r_sid, r_seq, _ = struct.unpack("!BBHIH", clean[:10])
        if r_seq in self.rx_seen_seqs:
            return None
        self.rx_seen_seqs.add(r_seq)
        self.recovered_count += 1

        r_payload = clean[10:]
        if r_flags & FLAG_COMPRESSED:
            r_payload = zlib.decompress(r_payload)
        return {
            "flags": r_flags,
            "type": r_type,
            "stream_id": r_sid,
            "seq": r_seq,
            "payload": r_payload,
            "clean_frame": clean,
        }

    def process_rx_frame(self, frame: dict) -> Tuple[bool, Optional[dict]]:
        ftype = frame["type"]
        seq_num = frame["seq"]
        payload = frame["payload"]

        if ftype == TYPE_FEC_PARITY:
            if len(payload) > 5:
                base_seq, _ = struct.unpack("!IB", payload[:5])
                gid = (base_seq - 1) // self.group_size
                self.rx_parity[gid] = payload[5:]
                return True, self._try_recover_group(gid)
            return True, None

        if seq_num in self.rx_seen_seqs:
            return True, None
        self.rx_seen_seqs.add(seq_num)
        if len(self.rx_seen_seqs) > 4096:
            self.rx_seen_seqs = set(sorted(self.rx_seen_seqs)[-2048:])

        if ftype == TYPE_STREAM_DATA:
            gid = (seq_num - 1) // self.group_size
            grp = self.rx_frames.setdefault(gid, {})
            grp[seq_num] = frame["clean_frame"]
            if len(self.rx_frames) > 64:
                oldest = min(self.rx_frames.keys())
                self.rx_frames.pop(oldest, None)
                self.rx_parity.pop(oldest, None)
            return False, self._try_recover_group(gid)

        return False, None
