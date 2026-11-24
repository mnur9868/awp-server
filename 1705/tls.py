#!/usr/bin/env python3
import asyncio
import os
import struct
from typing import Optional, Tuple

from crypto import SPACodec
from ws import WebSocketCamouflage


# =====================================================================
# KAMUFLASE TLS 1.3 & UNIFIED TCP STREAM FRAMING DISPATCHER
# =====================================================================
class TLSCamouflage:
    """Encoder/decoder kamuflase TLS 1.3 & dispatcher framing TCP (TLS / WS)."""

    @staticmethod
    def wrap_tls_client_hello(spa_pkt: bytes, sni_host: str = "") -> bytes:
        extensions = bytearray()
        if sni_host:
            sni_bytes = sni_host.encode("ascii")
            sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
            sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
            extensions.extend(struct.pack("!HH", 0x0000, len(sni_list)) + sni_list)

        groups = struct.pack("!HHH", 4, 0x001D, 0x0017)
        extensions.extend(struct.pack("!HH", 0x000A, len(groups)) + groups)
        extensions.extend(struct.pack("!HHBB", 0x000B, 2, 1, 0))

        sig_algs = struct.pack("!HHHH", 6, 0x0403, 0x0804, 0x0401)
        extensions.extend(struct.pack("!HH", 0x000D, len(sig_algs)) + sig_algs)

        sup_ver = struct.pack("!BHH", 4, 0x0304, 0x0303)
        extensions.extend(struct.pack("!HH", 0x002B, len(sup_ver)) + sup_ver)
        extensions.extend(struct.pack("!HHBB", 0x002D, 2, 1, 1))

        ks_entry = struct.pack("!HH", 0x001D, 32) + os.urandom(32)
        ks_list = struct.pack("!H", len(ks_entry)) + ks_entry
        extensions.extend(struct.pack("!HH", 0x0033, len(ks_list)) + ks_list)

        extensions.extend(struct.pack("!HH", 0x0023, len(spa_pkt)) + spa_pkt)

        ch_body = (
            b"\x03\x03"
            + os.urandom(32)
            + b"\x20"
            + os.urandom(32)
            + b"\x00\x06\x13\x01\x13\x02\x13\x03"
            + b"\x01\x00"
            + struct.pack("!H", len(extensions))
            + bytes(extensions)
        )
        hs_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
        return b"\x16\x03\x01" + struct.pack("!H", len(hs_msg)) + hs_msg

    @classmethod
    def extract_spa_from_tls_client_hello(
        cls, psk: str, hs_payload: bytes
    ) -> Optional[Tuple[bytes, int]]:
        if len(hs_payload) < 44 or hs_payload[0] != 0x01:
            return None
        try:
            pos = 4 + 2 + 32
            sid_len = hs_payload[pos]
            pos += 1 + sid_len
            cs_len = struct.unpack("!H", hs_payload[pos : pos + 2])[0]
            pos += 2 + cs_len
            cm_len = hs_payload[pos]
            pos += 1 + cm_len
            ext_total = struct.unpack("!H", hs_payload[pos : pos + 2])[0]
            pos += 2
            end_ext = min(len(hs_payload), pos + ext_total)
            while pos + 4 <= end_ext:
                ext_type, ext_len = struct.unpack("!HH", hs_payload[pos : pos + 4])
                pos += 4
                if pos + ext_len > end_ext:
                    break
                if ext_type == 0x0023:
                    res = SPACodec.verify_spa_packet(psk, hs_payload[pos : pos + ext_len])
                    if res is not None:
                        return res
                pos += ext_len
        except Exception:
            pass
        return None

    @staticmethod
    def build_tls_server_hello_with_ack(ack_wire: bytes) -> bytes:
        ext_ver = struct.pack("!HHH", 0x002B, 2, 0x0304)
        sh_body = (
            b"\x03\x03"
            + os.urandom(32)
            + b"\x20"
            + os.urandom(32)
            + b"\x13\x01\x00"
            + struct.pack("!H", len(ext_ver))
            + ext_ver
        )
        hs_msg = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
        rec_sh = b"\x16\x03\x03" + struct.pack("!H", len(hs_msg)) + hs_msg
        rec_ccs = b"\x14\x03\x03\x00\x01\x01"
        rec_app = b"\x17\x03\x03" + struct.pack("!H", len(ack_wire)) + ack_wire
        return rec_sh + rec_ccs + rec_app

    @classmethod
    def wrap_tcp_stream_frame(
        cls, framing_mode: str, wire_pkt: bytes, is_client: bool
    ) -> bytes:
        if framing_mode == "ws":
            return WebSocketCamouflage.encode_ws_frame(wire_pkt, mask=is_client)
        return b"\x17\x03\x03" + struct.pack("!H", len(wire_pkt)) + wire_pkt

    @classmethod
    async def read_tcp_stream_frame(
        cls, framing_mode: str, reader: asyncio.StreamReader
    ) -> bytes:
        if framing_mode == "ws":
            return await WebSocketCamouflage.read_ws_frame(reader)
        while True:
            rec_hdr = await reader.readexactly(5)
            rec_type, _, _, body_len = struct.unpack("!BBBH", rec_hdr)
            if body_len > 65535:
                raise ValueError("Record TLS-TCP melebihi batas")
            rec_body = await reader.readexactly(body_len)
            if rec_type == 0x17:
                return rec_body
            if rec_type == 0x15:
                raise EOFError("TLS alert received")
